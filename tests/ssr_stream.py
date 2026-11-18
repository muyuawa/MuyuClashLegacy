#!/usr/bin/env python3
"""Drive MLStream and MLDatagram over loopback against the pinned SSR plugins."""

import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile

from ssr_codec import PASSWORD, encrypt, load_peer_crypto, make_peer


PAYLOAD = (bytes(range(251)) * 1045)[:262144]
TARGET_PORT = 5403
TARGET = b"\x01\x7f\x00\x00\x01" + struct.pack("!H", TARGET_PORT)


def run_tcp(binary, path, method, protocol, user, masking):
    with socket.socket() as listener:
        listener.settimeout(8)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        options = node(listener, method, protocol, user, masking)
        path.write_text(json.dumps(options))
        with subprocess.Popen([binary, path, str(TARGET_PORT), "plain"], stdout=subprocess.PIPE) as client:
            try:
                cipher, outer, framing = make_peer(method, protocol, user, masking)
                missing_iv = encrypt.encrypt_iv_len(method)
                pending = bytearray()
                received = bytearray()
                with listener.accept()[0] as peer:
                    peer.settimeout(8)
                    while len(received) < len(TARGET) + len(PAYLOAD):
                        transport = peer.recv(4096)
                        assert transport, "client closed before sending its full request"
                        decoded, use_cipher, _ = outer.server_decode(transport)
                        assert use_cipher
                        if missing_iv:
                            pending += decoded
                            if len(pending) < missing_iv:
                                continue
                            framing.get_server_info().recv_iv = bytes(pending[:missing_iv])
                            decoded, missing_iv = bytes(pending), 0
                            pending.clear()
                        received += framing.server_post_decrypt(cipher.decrypt(decoded))[0]
                    assert received == TARGET + PAYLOAD
                    response = outer.server_encode(cipher.encrypt(framing.server_pre_encrypt(PAYLOAD)))
                    for first, last in ((0, 2), (2, 7), (7, 19), (19, 67)):
                        peer.sendall(response[first:last])
                    peer.sendall(response[67:])
                    peer.shutdown(socket.SHUT_WR)
                    check(client)
            finally:
                if client.poll() is None:
                    client.kill()


def run_udp(binary, path, method, protocol, user, masking):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.settimeout(8)
        listener.bind(("127.0.0.1", 0))
        options = node(listener, method, protocol, user, masking)
        options["udp"] = True
        path.write_text(json.dumps(options))
        with subprocess.Popen([binary, path, str(TARGET_PORT)], stdout=subprocess.PIPE) as client:
            try:
                _, _, framing = make_peer(method, protocol, user, masking)
                iv_len = encrypt.encrypt_iv_len(method)
                seen = set()
                for index in range(15):
                    wire, sender = listener.recvfrom(2048)
                    framing.get_server_info().recv_iv = wire[:iv_len]
                    if iv_len:
                        assert wire[:iv_len] not in seen
                        seen.add(wire[:iv_len])
                    decoded, uid = framing.server_udp_post_decrypt(
                        encrypt.encrypt_all(PASSWORD, method, 0, wire)
                    )
                    size = (1, 1400, 1500)[index % 3]
                    assert decoded == TARGET + bytes((i + index) % 251 for i in range(size))
                    encoded = framing.server_udp_pre_encrypt(decoded, uid)
                    listener.sendto(encrypt.encrypt_all(PASSWORD, method, 1, encoded), sender)
                check(client)
            finally:
                if client.poll() is None:
                    client.kill()


def node(listener, method, protocol, user, masking):
    result = {
        "type": "ssr", "server": "127.0.0.1", "port": listener.getsockname()[1],
        "cipher": method, "password": PASSWORD.decode(), "protocol": protocol, "obfs": masking,
    }
    if user:
        result["protocol-param"] = user
    if masking != "plain":
        result["obfs-param"] = "test.example"
    return result


def check(client):
    output, _ = client.communicate(timeout=10)
    assert client.returncode == 0, (client.returncode, output)
    print(output.decode().strip(), flush=True)


def main():
    load_peer_crypto()
    stream, datagram = sys.argv[1:]
    cases = [
        ("aes-128-cfb", "origin", "", "plain"),
        ("aes-256-ctr", "auth_sha1_v4", "", "http_simple"),
        ("chacha20-ietf", "auth_aes128_md5", "", "http_post"),
        ("rc4-md5", "auth_aes128_sha1", "42:peer-password", "plain"),
    ]
    with tempfile.TemporaryDirectory(prefix="muyu-ssr-") as temporary:
        path = Path(temporary) / "node.json"
        for case in cases:
            run_tcp(stream, path, *case)
            run_udp(datagram, path, *case)
    print("SSR unified TCP and UDP interoperability passed (four variants)")


if __name__ == "__main__":
    main()
