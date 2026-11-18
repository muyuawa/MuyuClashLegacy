"""Independent loopback peers for the Shadowsocks and VMess TCP adapters.

Run after building the host test-stream executable. The peers use Python's
standard library and the OpenSSL 3 shared libcrypto from MLSTREAM_OPENSSL_PREFIX.
Only generic AES-GCM operations use OpenSSL. Test framing and key derivation
run in Python and do not call the Senko codecs.
"""
import concurrent.futures
import ctypes
import hashlib
import hmac
from itertools import count
import os
from pathlib import Path
import socket
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
CLIENT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / '.build/host/test-stream'
OPENSSL = Path(os.environ.get('MLSTREAM_OPENSSL_PREFIX', '/opt/local/libexec/openssl3'))
CRYPTO = ctypes.CDLL(str(OPENSSL / 'lib/libcrypto.3.dylib'))
UPLOAD = bytes(index % 91 for index in range(35000))
DOWNLOAD = bytes(index % 97 for index in range(60000))


def function(name, result, *signature):
    operation = getattr(CRYPTO, name)
    operation.restype = result
    operation.argtypes = signature
    return operation


pointer, integer = ctypes.c_void_p, ctypes.c_int
length_pointer = ctypes.POINTER(integer)
new_context = function('EVP_CIPHER_CTX_new', pointer)
free_context = function('EVP_CIPHER_CTX_free', None, pointer)
aes128 = function('EVP_aes_128_gcm', pointer)
control = function('EVP_CIPHER_CTX_ctrl', integer, pointer, integer, integer, pointer)
encrypt_init = function('EVP_EncryptInit_ex', integer, pointer, pointer, pointer, pointer, pointer)
decrypt_init = function('EVP_DecryptInit_ex', integer, pointer, pointer, pointer, pointer, pointer)
encrypt_update = function('EVP_EncryptUpdate', integer, pointer, pointer, length_pointer, pointer, integer)
decrypt_update = function('EVP_DecryptUpdate', integer, pointer, pointer, length_pointer, pointer, integer)
encrypt_final = function('EVP_EncryptFinal_ex', integer, pointer, pointer, length_pointer)
decrypt_final = function('EVP_DecryptFinal_ex', integer, pointer, pointer, length_pointer)
GET_TAG, SET_TAG = 0x10, 0x11


def aead(key, nonce, data, decrypt=False, authenticated=None):
    context = new_context()
    assert context
    payload = data[:-16] if decrypt else data
    output = ctypes.create_string_buffer(len(payload) + 16)
    length, trailing = integer(), integer()
    init, update, finish = ((decrypt_init, decrypt_update, decrypt_final) if decrypt else
                            (encrypt_init, encrypt_update, encrypt_final))
    try:
        assert init(context, aes128(), None, key[:16], nonce[:12]) == 1
        if authenticated is not None:
            assert update(context, None, ctypes.byref(length), authenticated, len(authenticated)) == 1
        assert update(context, output, ctypes.byref(length), payload, len(payload)) == 1
        if decrypt:
            assert control(context, SET_TAG, 16, data[-16:]) == 1
        assert finish(context, ctypes.byref(output, length.value), ctypes.byref(trailing)) == 1
        total = length.value + trailing.value
        if not decrypt:
            assert control(context, GET_TAG, 16, ctypes.byref(output, total)) == 1
            total += 16
        return output.raw[:total]
    finally:
        free_context(context)


def read_exact(peer, length):
    data = bytearray()
    while len(data) < length:
        chunk = peer.recv(length - len(data))
        assert chunk
        data.extend(chunk)
    return bytes(data)


def ss_key(salt):
    master = hashlib.md5(b'fixture-password').digest()
    return hmac.digest(hmac.digest(salt, master, 'sha1'), b'ss-subkey\x01', 'sha1')[:16]


def ss_nonce(index):
    return index.to_bytes(12, 'little')


def serve_ss(peer):
    key = ss_key(read_exact(peer, 16))
    data = bytearray()
    expected = b'\x03\x0bexample.com\x01\xbb' + UPLOAD
    for index in count(step=2):
        size = int.from_bytes(aead(key, ss_nonce(index), read_exact(peer, 18), True), 'big')
        assert 0 < size <= 0x3fff
        data.extend(aead(key, ss_nonce(index + 1), read_exact(peer, size + 16), True))
        if len(data) >= len(expected):
            break
    assert data == expected
    assert peer.recv(1) == b''

    salt = b'independent-salt'
    key = ss_key(salt)
    peer.sendall(salt[:7])
    peer.sendall(salt[7:])
    for index, offset in enumerate(range(0, len(DOWNLOAD), 15000)):
        payload = DOWNLOAD[offset:offset + 15000]
        wire = (aead(key, ss_nonce(2 * index), len(payload).to_bytes(2, 'big')) +
                aead(key, ss_nonce(2 * index + 1), payload))
        peer.sendall(wire[:19])
        peer.sendall(wire[19:])


def vmess_kdf(key, *path):
    def nested(parts, message):
        if not parts:
            return hashlib.sha256(message).digest()
        material = parts[-1].ljust(64, b'\0')
        inner = nested(parts[:-1], bytes(byte ^ 0x36 for byte in material) + message)
        return nested(parts[:-1], bytes(byte ^ 0x5c for byte in material) + inner)

    return nested((b'VMess AEAD KDF',) + path, key)


def vmess_chunks(iv):
    masks = hashlib.shake_128(iv).digest(1024)
    for index in range(len(masks) // 4):
        block = masks[index * 4:index * 4 + 4]
        padding = int.from_bytes(block[:2], 'big') % 64
        mask = int.from_bytes(block[2:], 'big')
        nonce = index.to_bytes(2, 'big') + iv[2:12]
        yield padding, mask, nonce


def serve_vmess(peer):
    uuid = bytes.fromhex('00112233445566778899aabbccddeeff')
    command = hashlib.md5(uuid + b'c48619fe-8f02-49e0-b9e9-edf763e17e21').digest()
    auth = read_exact(peer, 16)
    sealed_size = read_exact(peer, 18)
    path = auth, read_exact(peer, 8)
    size = int.from_bytes(aead(vmess_kdf(command, b'VMess Header AEAD Key_Length', *path),
                               vmess_kdf(command, b'VMess Header AEAD Nonce_Length', *path),
                               sealed_size, True, auth), 'big')
    header = aead(vmess_kdf(command, b'VMess Header AEAD Key', *path),
                  vmess_kdf(command, b'VMess Header AEAD Nonce', *path),
                  read_exact(peer, size + 16), True, auth)
    assert header[0] == 1 and header[34] == 13 and header[35] & 0x0f == 3
    assert header[37:53] == b'\x01\x01\xbb\x02\x0bexample.com'
    iv, key, marker = header[1:17], header[17:33], header[33:34]
    data = bytearray()
    for padding, mask, nonce in vmess_chunks(iv):
        length = int.from_bytes(read_exact(peer, 2), 'big') ^ mask
        assert padding + 16 <= length < 16384
        payload = aead(key, nonce, read_exact(peer, length - padding), True)
        read_exact(peer, padding)
        if not payload:
            break
        data.extend(payload)
    else:
        raise AssertionError('VMess request did not end with an authenticated empty chunk')
    assert data == UPLOAD
    assert peer.recv(1) == b''

    response_key = hashlib.sha256(key).digest()[:16]
    response_iv = hashlib.sha256(iv).digest()[:16]
    response_size = aead(vmess_kdf(response_key, b'AEAD Resp Header Len Key'),
                         vmess_kdf(response_iv, b'AEAD Resp Header Len IV'), b'\0\x04')
    response_header = aead(vmess_kdf(response_key, b'AEAD Resp Header Key'),
                           vmess_kdf(response_iv, b'AEAD Resp Header IV'), marker + b'\0\0\0')
    peer.sendall(response_size[:6])
    peer.sendall(response_size[6:] + response_header)
    for offset, (padding, mask, nonce) in zip(range(0, len(DOWNLOAD) + 1, 6000), vmess_chunks(response_iv)):
        sealed = aead(response_key, nonce, DOWNLOAD[offset:offset + 6000])
        peer.sendall(((len(sealed) + padding) ^ mask).to_bytes(2, 'big') + sealed + bytes(padding))


def run_peer(listener, respond):
    with listener.accept()[0] as peer:
        peer.settimeout(5)
        respond(peer)


def main():
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        for name, respond in [('ss', serve_ss), ('vmess', serve_vmess)]:
            with socket.create_server(('127.0.0.1', 0)) as listener:
                listener.settimeout(5)
                worker = pool.submit(run_peer, listener, respond)
                subprocess.run([CLIENT, name, str(listener.getsockname()[1])], check=True, timeout=8)
                worker.result()
    print('Shadowsocks and VMess AES-128-GCM passed independent TCP framing and half-close checks')


if __name__ == '__main__':
    main()
