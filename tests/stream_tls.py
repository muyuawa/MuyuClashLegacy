"""Certificate and wire interoperability tests against an independent loopback TLS peer."""
import concurrent.futures
import base64
import hashlib
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
CLIENT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / '.build/host/test-stream'


def read_exact(peer, length):
    result = bytearray()
    while len(result) < length:
        chunk = peer.recv(length - len(result))
        assert chunk
        result.extend(chunk)
    return bytes(result)


def serve(listener, context, should_reject):
    with listener.accept()[0] as peer:
        peer.settimeout(5)
        try:
            tunnel = context.wrap_socket(peer, server_side=True)
        except ssl.SSLError:
            if should_reject:
                return
            raise
        with tunnel:
            assert not should_reject
            header = (hashlib.sha224(b'test password').hexdigest().encode() +
                      b'\r\n\x01\x03\x0bexample.com\x01\xbb\r\n')
            assert read_exact(tunnel, len(header)) == header
            assert read_exact(tunnel, 4) == b'ping'
            tunnel.sendall(b'pong')
            tunnel.unwrap().close()


def ws_message(peer, opcode):
    head = read_exact(peer, 2)
    assert head[0] == 0x80 | opcode and head[1] & 0x80
    length = head[1] & 0x7f
    if length == 126:
        length = int.from_bytes(read_exact(peer, 2), 'big')
    mask = read_exact(peer, 4)
    return bytes(byte ^ mask[index % 4] for index, byte in enumerate(read_exact(peer, length)))


def serve_ws(listener, context):
    with listener.accept()[0] as peer:
        peer.settimeout(5)
        connection = context.wrap_socket(peer, server_side=True) if context else peer
        with connection:
            request = bytearray()
            while not request.endswith(b'\r\n\r\n'):
                request.extend(read_exact(connection, 1))
            if context:
                assert request.startswith(b'GET / HTTP/1.1\r\n')
                header = (hashlib.sha224(b'test password').hexdigest().encode() +
                          b'\r\n\x01\x03\x0bexample.com\x01\xbb\r\n')
            else:
                assert request.startswith(b'GET /test?x=1 HTTP/1.1\r\nHost: proxy.test\r\n')
                header = bytes.fromhex('0000112233445566778899aabbccddeeff000101bb020b') + b'example.com'
            key = re.search(rb'^Sec-WebSocket-Key: (.+)\r$', request, re.MULTILINE).group(1)
            token = base64.b64encode(hashlib.sha1(key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
            connection.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                               b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + token + b'\r\n\r\n')
            assert ws_message(connection, 2) == header
            assert ws_message(connection, 2) == b'ping'
            connection.sendall(b'\x89\x01x')
            assert ws_message(connection, 10) == b'x'
            prefix = b'' if context else b'\0\0'
            connection.sendall(b'\x02' + bytes([len(prefix) + 2]) + prefix + b'po' + b'\x80\x02ng')
            assert ws_message(connection, 8) == b''
            connection.sendall(b'\x88\x00')


with tempfile.TemporaryDirectory(prefix='muyu-stream-tls-') as directory:
    key = Path(directory) / 'key.pem'
    certificate = Path(directory) / 'certificate.pem'
    subprocess.run(['/usr/bin/openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048',
                    '-nodes', '-keyout', key, '-out', certificate, '-days', '2', '-subj',
                    '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True,
                   capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
        for name, trust, rejected in [('localhost', True, False), ('wrong.invalid', True, True),
                                      ('localhost', False, True)]:
            with socket.create_server(('127.0.0.1', 0)) as listener:
                listener.settimeout(5)
                result = worker.submit(serve, listener, context, rejected)
                env = dict(os.environ)
                env['MLSTREAM_CA_FILE'] = str(certificate if trust else ROOT / 'resources/cacert.pem')
                subprocess.run([CLIENT, 'trojan', str(listener.getsockname()[1]), name,
                                str(int(rejected))], env=env, check=True, timeout=8)
                result.result()
        for name, server_context in [('vless-ws', None), ('trojan-wss', context)]:
            with socket.create_server(('127.0.0.1', 0)) as listener:
                listener.settimeout(5)
                result = worker.submit(serve_ws, listener, server_context)
                env = dict(os.environ, MLSTREAM_CA_FILE=str(certificate))
                subprocess.run([CLIENT, name, str(listener.getsockname()[1]), 'localhost', '0'],
                               env=env, check=True, timeout=8)
                result.result()

print('Trojan TLS trust, VLESS WebSocket and Trojan TLS WebSocket loopback checks passed')
