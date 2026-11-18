#!/usr/bin/env python3
"""Exercise native HTTPUpgrade TCP and UDP against the locked Xray server."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from protocol_fixtures import ensure

ROOT = Path(__file__).resolve().parent.parent
UUID = '00112233-4455-6677-8899-aabbccddeeff'


def tcp_echo(listener):
    try:
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(10)
                while (data := connection.recv(8192)):
                    connection.sendall(data)
    except OSError:
        pass


def udp_echo(peer, received):
    try:
        while True:
            data, address = peer.recvfrom(8192)
            received.append(len(data))
            peer.sendto(data, address)
    except OSError:
        pass


def proxy_config(directory, certificate, key):
    inbounds, nodes, port_reservations = [], [], []
    try:
        for kind, tls in [('vless', False), ('vless', True), ('vmess', False), ('vmess', True), ('trojan', True)]:
            address = socket.socket()
            port_reservations.append(address)
            address.bind(('127.0.0.1', 0))
            port = address.getsockname()[1]

            node = {'type': kind, 'server': '127.0.0.1', 'port': port, 'network': 'ws', 'udp': True}
            node['ws-opts'] = {'path': '/upgrade?q=1', 'v2ray-http-upgrade': True}
            upgrade_settings = {'path': '/upgrade'}
            if kind == 'vless' and tls:
                # This Host participates in certificate verification when SNI is omitted.
                node['ws-opts']['headers'] = {'Host': 'localhost:8443'}
                upgrade_settings['host'] = 'localhost'
            elif tls or kind == 'vless':
                node['ws-opts']['headers'] = {'Host': 'upgrade.test'}
                upgrade_settings['host'] = 'upgrade.test'
                if tls:
                    node['servername'] = 'localhost'
            else:
                upgrade_settings['host'] = '127.0.0.1'

            settings = {'clients': [{'id': UUID}]}
            if kind == 'vless':
                settings['decryption'] = 'none'
            if kind == 'trojan':
                node['password'] = 'fixture-password'
                settings = {'clients': [{'password': 'fixture-password'}]}
            else:
                node['uuid'] = UUID

            stream = {'network': 'httpupgrade', 'httpupgradeSettings': upgrade_settings}
            if tls:
                if kind != 'trojan':
                    node['tls'] = True
                stream['security'] = 'tls'
                stream['tlsSettings'] = {'alpn': ['http/1.1'], 'certificates': [
                    {'certificateFile': str(certificate), 'keyFile': str(key)}]}
            inbounds.append({'listen': '127.0.0.1', 'port': port, 'protocol': kind,
                             'settings': settings, 'streamSettings': stream})
            path = directory / f'{kind}-{tls}.json'
            path.write_text(json.dumps(node))
            nodes.append((kind, tls, port, path))
    finally:
        for reservation in port_reservations:
            reservation.close()
    return inbounds, nodes


def client(*command, env, log):
    result = subprocess.run([str(part) for part in command], env=env, capture_output=True,
                            text=True, timeout=25)
    if result.returncode != 0:
        raise AssertionError((command, result.returncode, result.stdout, result.stderr, log.read_text()))
    return result.stdout.strip()


def coalesced_peer(listener, destination_port):
    listener.settimeout(10)
    connection, _ = listener.accept()
    with connection, connection.makefile('rb') as reader:
        connection.settimeout(10)
        assert reader.readline() == b'GET / HTTP/1.1\r\n'
        headers = {}
        while (line := reader.readline()) != b'\r\n':
            key, value = line.split(b':', 1)
            headers[key.lower()] = value.strip().lower()
        assert headers == {b'host': b'127.0.0.1', b'connection': b'upgrade', b'upgrade': b'websocket'}
        connection.sendall(b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n'
                           b'Upgrade: websocket\r\n\r\n\0\0')
        assert reader.read(26) == (b'\0' + bytes.fromhex(UUID.replace('-', '')) + b'\0\x01' +
                                   destination_port.to_bytes(2, 'big') + b'\x01\x7f\0\0\x01')
        while (data := reader.read1(8192)):
            connection.sendall(data)


def check_coalesced(directory, executable, destination_port, env, log):
    with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as peer:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        config = {'type': 'vless', 'server': '127.0.0.1', 'port': listener.getsockname()[1],
                  'uuid': UUID, 'network': 'ws', 'ws-opts': {'v2ray-http-upgrade': True}}
        path = directory / 'coalesced.json'
        path.write_text(json.dumps(config))
        fixture = peer.submit(coalesced_peer, listener, destination_port)
        result = client(executable, path, destination_port, 'coalesced', env=env, log=log)
        fixture.result(timeout=2)
        print(f'HTTPUpgrade coalesced VLESS response: {result}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clients', type=Path, default=ROOT / '.build/stream/host')
    args = parser.parse_args()
    clients = args.clients.resolve()
    binary = ensure('xray')
    with tempfile.TemporaryDirectory(prefix='http-upgrade-', dir=clients) as temporary, \
            socket.socket() as tcp_peer, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_peer:
        directory = Path(temporary)
        certificate, key = directory / 'cert.pem', directory / 'key.pem'
        subprocess.run(['/usr/bin/openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(certificate), '-days', '1', '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
        tcp_peer.bind(('127.0.0.1', 0))
        tcp_peer.listen()
        udp_peer.bind(('127.0.0.1', 0))
        tcp_port, udp_port = tcp_peer.getsockname()[1], udp_peer.getsockname()[1]
        received = []
        threading.Thread(target=tcp_echo, args=(tcp_peer,), daemon=True).start()
        threading.Thread(target=udp_echo, args=(udp_peer, received), daemon=True).start()

        inbounds, nodes = proxy_config(directory, certificate, key)
        config = {'log': {'loglevel': 'warning'}, 'inbounds': inbounds, 'outbounds': [
            {'protocol': 'freedom', 'settings': {'finalRules': [
                {'action': 'allow', 'ip': ['127.0.0.1'], 'port': port} for port in (tcp_port, udp_port)]}}]}
        config_path, log_path = directory / 'server.json', directory / 'server.log'
        config_path.write_text(json.dumps(config))
        env = dict(os.environ, MLSTREAM_CA_FILE=str(certificate))
        with log_path.open('wb') as log:
            server = subprocess.Popen([str(binary), 'run', '-c', str(config_path)], stdout=log,
                                      stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    if server.poll() is not None:
                        raise AssertionError(log_path.read_text())
                    try:
                        with socket.create_connection(('127.0.0.1', nodes[0][2]), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.03)
                else:
                    raise AssertionError(f'Xray did not start: {log_path.read_text()}')
                for kind, tls, _, path in nodes:
                    tcp = client(clients / 'test-xray', path, tcp_port, 'plain', env=env, log=log_path)
                    received.clear()
                    udp = client(clients / 'test-datagram-xray', path, udp_port, env=env, log=log_path)
                    assert received == [1, 1400, 1500] * 5, (kind, tls, received)
                    print(f'{kind} HTTPUpgrade TLS={tls}: {tcp}. {udp}', flush=True)
                chain = directory / 'chain.json'
                chain.write_text(json.dumps([{'type': 'direct'}, json.loads(nodes[1][3].read_text())]))
                result = client(clients / 'test-xray', chain, tcp_port, 'plain', env=env, log=log_path)
                print(f'HTTPUpgrade through a lower stream: {result}', flush=True)
                check_coalesced(directory, clients / 'test-xray', tcp_port, env, log_path)
            finally:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == '__main__':
    main()
