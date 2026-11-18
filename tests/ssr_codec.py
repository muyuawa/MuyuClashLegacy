#!/usr/bin/env python3
"""Exercise the C codec against pinned original ShadowsocksR server plugins."""

from pathlib import Path
import itertools
import io
import os
import struct
import subprocess
import sys

from shadowsocks import encrypt, obfs
from shadowsocks.crypto import openssl


PASSWORD = b"ssr-test-password"
DOMAIN = b"destination.test"
REQUEST = bytes([3, len(DOMAIN)]) + DOMAIN + b"\x01\xbb"
REQUEST_IP = b"\x01\x7f\x00\x00\x01\x01\xbb"
PAYLOAD = b"client data" + bytes(range(256)) * 16
RESPONSE = b"peer data" + bytes(range(255, -1, -1)) * 38


def read_packet(source):
    size, = struct.unpack("!H", source.read(2))
    return source.read(size)


def make_peer(method, protocol, user, masking="plain", auth_data=None):
    cipher = encrypt.Encryptor(PASSWORD, method)
    key = cipher.cipher_key if method != "none" else encrypt.encrypt_key(PASSWORD, "aes-128-cfb")
    outer, framing = obfs.obfs(masking), obfs.obfs(protocol)
    for plugin in (outer, framing):
        info = obfs.server_info(auth_data if auth_data is not None and plugin is framing else plugin.init_data())
        info.key, info.iv, info.recv_iv = key, cipher.cipher_iv, b""
        info.host, info.port, info.head_len = "127.0.0.1", 8443, 30
        info.obfs_param = "" if masking == "plain" else "test.example"
        info.protocol_param, info.buffer_size, info.tcp_mss = "", 32768, 1460
        info.client, info.client_port = "127.0.0.1", 12345
        info.users, info.update_user_func = {}, lambda uid: None
        if user:
            uid, password = user.split(":")
            info.users[struct.pack("<I", int(uid))] = password.encode()
        plugin.set_server_info(info)
    return cipher, outer, framing


def exchange(binary, method, protocol, user, masking, scenario="complete"):
    process = subprocess.Popen(
        [binary, method, protocol, user, masking, scenario],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        blocks = [read_packet(process.stdout) for _ in range(3)]
        cipher, outer, framing = make_peer(method, protocol, user, masking)
        received = bytearray()
        for i, block in enumerate(blocks):
            if i == 0 and masking != "plain":
                assert block.startswith((b"POST" if masking == "http_post" else b"GET") + b" /%")
                assert b"\r\nHost: test.example:8443\r\n" in block
            decoded, decrypt, _ = outer.server_decode(block)
            assert decrypt
            if i == 0:
                framing.get_server_info().recv_iv = decoded[:encrypt.encrypt_iv_len(method)]
            received += framing.server_post_decrypt(cipher.decrypt(decoded))[0]
        assert received == REQUEST + PAYLOAD, (method, protocol, user, masking)
        response = bytearray(outer.server_encode(cipher.encrypt(framing.server_pre_encrypt(RESPONSE))))
        if scenario == "corrupt":
            response[-1] ^= 1
        elif scenario == "truncate":
            response = response[:-1]
        output, _ = process.communicate(response)
        assert process.returncode == 0
        if scenario == "complete":
            assert output == RESPONSE
        else:
            assert len(output) < len(RESPONSE) and RESPONSE.startswith(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()


def stable_auth_identity(binary):
    method, protocol = "aes-128-cfb", "auth_sha1_v4"
    out = subprocess.check_output([binary, method, protocol, "", "plain", "identities"])
    source = io.BytesIO(out)
    auth_data = obfs.obfs(protocol).init_data()
    for _ in range(70):
        request = read_packet(source)
        cipher, _, framing = make_peer(method, protocol, "", auth_data=auth_data)
        framing.get_server_info().recv_iv = request[:encrypt.encrypt_iv_len(method)]
        assert framing.server_post_decrypt(cipher.decrypt(request))[0] == REQUEST
    assert len(auth_data.client_id) == 1


def udp_exchange(binary, method, protocol, user, numeric=False):
    process = subprocess.Popen(
        [binary, method, protocol, user, "plain", "udp-numeric" if numeric else "udp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        requests = [read_packet(process.stdout) for _ in range(2)]
        _, _, framing = make_peer(method, protocol, user)
        iv_len = encrypt.encrypt_iv_len(method)
        if iv_len:
            assert requests[0][:iv_len] != requests[1][:iv_len]
        responses = []
        for wire in requests:
            framing.get_server_info().recv_iv = wire[:iv_len]
            decoded, uid = framing.server_udp_post_decrypt(encrypt.encrypt_all(PASSWORD, method, 0, wire))
            assert decoded == (REQUEST_IP if numeric else REQUEST) + b"client data"
            response = REQUEST_IP + b"peer data"
            responses.append(encrypt.encrypt_all(PASSWORD, method, 1, framing.server_udp_pre_encrypt(response, uid)))

        invalid = bytearray(responses[0])
        # An encrypted copy replays the previous response IV.
        if not iv_len:
            if protocol in ("auth_aes128_md5", "auth_aes128_sha1"):
                invalid[-1] ^= 1
            else:
                invalid[0] = 0
        wrong_address = bytearray(REQUEST_IP)
        wrong_address[4 if numeric else 6] ^= 1
        wrong = encrypt.encrypt_all(PASSWORD, method, 1, framing.server_udp_pre_encrypt(bytes(wrong_address) + b"peer data", uid))
        packets = (responses[0], invalid, wrong, responses[1])
        output, _ = process.communicate(b"".join(struct.pack("!H", len(p)) + p for p in packets))
        assert process.returncode == 0 and output == b"peer datapeer data"
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()


def load_peer_crypto():
    # OpenSSL 3 exposes the reference implementation's legacy RC4 through its
    # legacy provider. The test process enables it solely for the reference peer.
    openssl.load_openssl()
    provider = getattr(openssl.libcrypto, "OSSL_PROVIDER_load", None)
    if provider:
        from ctypes import c_char_p, c_void_p
        provider.argtypes, provider.restype = (c_void_p, c_char_p), c_void_p
        assert provider(None, b"default")
        assert provider(None, b"legacy")
    if os.environ.get("MLSSR_SODIUM_LIBRARY"):
        from ctypes import CDLL
        from shadowsocks.crypto import util
        find_library = util.find_library
        util.find_library = lambda names, *args: (
            CDLL(os.environ["MLSSR_SODIUM_LIBRARY"]) if "sodium" in names else find_library(names, *args)
        )


def main():
    binary = str(Path(sys.argv[1]).resolve())
    load_peer_crypto()
    variants = [
        ("origin", ""),
        ("auth_sha1_v4", ""),
        ("auth_aes128_md5", ""),
        ("auth_aes128_sha1", "42:peer-password"),
    ]
    for (protocol, user), masking in itertools.product(variants, ("plain", "http_simple", "http_post")):
        exchange(binary, "aes-128-cfb", protocol, user, masking)
    for cipher in ("aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr",
                   "aes-256-ctr", "rc4-md5", "none", "chacha20", "chacha20-ietf"):
        exchange(binary, cipher, "auth_aes128_md5", "", "plain")
    for protocol in ("auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1"):
        for scenario in ("truncate", "corrupt"):
            exchange(binary, "aes-128-cfb", protocol, "", "http_simple", scenario)
    stable_auth_identity(binary)
    for (protocol, user), method in itertools.product(variants, ("aes-128-cfb", "chacha20-ietf", "none")):
        udp_exchange(binary, method, protocol, user)
    udp_exchange(binary, "aes-128-cfb", "auth_aes128_sha1", "42:peer-password", numeric=True)
    print("SSR codec interoperability passed (27 TCP exchanges, 70 serial auth connections, 13 UDP exchanges)")


if __name__ == "__main__":
    main()
