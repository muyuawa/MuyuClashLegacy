#!/usr/bin/env python3
"""Verify the native adapter against the independently built Hysteria server."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
CLIENT = ROOT / '.build/stream/host/test-hy2'
LOCK = next(d for d in json.loads((ROOT / 'third_party/manifest-protocol-tests.json').read_text())['dependencies'] if d['name'] == 'hysteria')
SERVER = ROOT / '.deps/protocol-tests' / LOCK['archive']


def fixture_server():
    if not SERVER.exists():
        SERVER.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(LOCK['url'], timeout=60) as response:
            SERVER.write_bytes(response.read())
    if hashlib.sha256(SERVER.read_bytes()).hexdigest() != LOCK['sha256']:
        raise RuntimeError('Hysteria test server checksum mismatch')
    SERVER.chmod(0o755)


def run_case(directory, name, *, sni='localhost', trust=True, password='fixture-secret',
             obfs='', client_obfs=None, pin=None, reject=False, fallback=False):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as candidate:
        candidate.bind(('127.0.0.1', 0))
        port = candidate.getsockname()[1]
    certificate, key = directory / 'cert.pem', directory / 'key.pem'
    configuration = {'listen': f'127.0.0.1:{port}',
                     'tls': {'cert': str(certificate), 'key': str(key)},
                     'auth': {'type': 'password', 'password': 'fixture-secret'}}
    if obfs:
        configuration['obfs'] = {'type': 'salamander', 'salamander': {'password': obfs}}
    config = directory / (name + '-server.json')
    config.write_text(json.dumps(configuration))
    log = (directory / (name + '.log')).open('wb')
    server = subprocess.Popen([str(SERVER), '--disable-update-check', 'server', '-c', str(config)], stdout=log, stderr=subprocess.STDOUT)
    target = socket.socket()
    target.bind(('127.0.0.1', 0)); target.listen(1); target.settimeout(12)
    def echo():
        try:
            with target.accept()[0] as peer:
                peer.settimeout(12)
                while True:
                    chunk = peer.recv(16384)
                    if not chunk: break
                    peer.sendall(chunk)
        except (OSError, TimeoutError):
            pass
    worker = threading.Thread(target=echo, daemon=True)
    worker.start()
    try:
        time.sleep(0.3)
        if server.poll() is not None:
            log.close()
            raise RuntimeError((directory / (name + '.log')).read_text())
        node = {'type': 'hysteria2', 'server': 'localhost' if fallback else '127.0.0.1', 'port': port,
                'password': password, 'sni': sni, 'alpn': ['h3'], 'client-fingerprint': 'chrome'}
        if obfs or client_obfs:
            node.update({'obfs': 'salamander', 'obfs-password': client_obfs if client_obfs is not None else obfs})
        if pin: node['fingerprint'] = pin
        source = directory / (name + '-node.json'); source.write_text(json.dumps(node))
        env = dict(os.environ, MLSTREAM_CA_FILE=str(certificate if trust else ROOT / 'resources/cacert.pem'))
        result = subprocess.run([str(CLIENT), str(source), str(target.getsockname()[1]),
                                 'reject' if reject else 'success', 'fallback' if fallback else 'unused'],
                                env=env, text=True, capture_output=True, timeout=18)
        if result.returncode:
            log.flush()
            raise AssertionError(name + ': ' + result.stdout + result.stderr + '\n' + (directory / (name + '.log')).read_text())
        assert 'Hysteria2 client-fingerprint is compatibility metadata' in result.stderr, result.stderr
        print(name, result.stdout.strip(), flush=True)
    finally:
        server.terminate()
        try: server.wait(timeout=3)
        except subprocess.TimeoutExpired: server.kill(); server.wait()
        log.close(); target.close()


def main():
    fixture_server()
    with tempfile.TemporaryDirectory(prefix='hy2-', dir=ROOT / '.build/stream') as temporary:
        directory = Path(temporary)
        subprocess.run(['/usr/bin/openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(directory / 'key.pem'), '-out', str(directory / 'cert.pem'),
                        '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run_case(directory, 'trusted')
        run_case(directory, 'unreachable-ipv6-fallback', fallback=True)
        run_case(directory, 'salamander', obfs='fixture-obfuscation')
        run_case(directory, 'hostname-rejected', sni='wrong.invalid', reject=True)
        run_case(directory, 'untrusted-rejected', trust=False, reject=True)
        run_case(directory, 'authentication-rejected', password='wrong-secret', reject=True)
        run_case(directory, 'obfuscation-rejected', obfs='fixture-obfuscation', client_obfs='wrong-obfuscation', reject=True)
    print('PASS independent Hysteria QUIC TCP transfer/FIN, TLS/name/auth/obfs failures')

if __name__ == '__main__':
    main()
