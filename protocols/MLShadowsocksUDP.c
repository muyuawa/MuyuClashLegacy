/* Extend the pinned Shadowsocks codec in the same translation unit so UDP
   uses exactly its existing password KDF, HKDF-SHA1 and AEAD primitives. */
#include "shadowsocks_client.c"
#include "MLShadowsocksUDP.h"
#include <errno.h>
#include <stdlib.h>

struct MLShadowsocksUDP {
    ss_cipher_t cipher;
    size_t keyLength, addressLength;
    uint8_t master[32], address[19];
    uint8_t recent[128][32];
    unsigned cursor, count;
};
static int usedSalt(const MLShadowsocksUDP *session, const uint8_t *salt) {
    for (unsigned i = 0; i < session->count; ++i)
        if (!CRYPTO_memcmp(session->recent[i], salt, session->keyLength)) return 1;
    return 0;
}
static void retainSalt(MLShadowsocksUDP *session, const uint8_t *salt) {
    memcpy(session->recent[session->cursor++], salt, session->keyLength);
    session->cursor %= 128; if (session->count < 128) ++session->count;
}
MLShadowsocksUDP *MLShadowsocksUDPOpen(const char *cipher, const char *password, const vless_dest_t *target) {
    if (!cipher || !password || !target || !target->port || (target->atyp != VLESS_ADDR_IPV4 && target->atyp != VLESS_ADDR_IPV6)) { errno = EINVAL; return NULL; }
    MLShadowsocksUDP *session = calloc(1, sizeof *session); if (!session) return NULL;
    session->cipher = ss_cipher_from_name(cipher);
    if (session->cipher == SS_CIPHER_UNKNOWN) { free(session); errno = ENOTSUP; return NULL; }
    session->keyLength = session->cipher == SS_CIPHER_AES_128_GCM ? 16 : 32;
    if (ss_derive_master_key(password, strlen(password), session->master, session->keyLength)) { MLShadowsocksUDPClose(session); errno = EIO; return NULL; }
    size_t length = target->atyp == VLESS_ADDR_IPV4 ? 4 : 16;
    session->address[0] = length == 4 ? 1 : 4; memcpy(session->address + 1, target->host_addr, length);
    session->address[length + 1] = target->port >> 8; session->address[length + 2] = target->port;
    session->addressLength = length + 3; return session;
}
ssize_t MLShadowsocksUDPEncode(MLShadowsocksUDP *session, const uint8_t *data, size_t size, uint8_t *wire, size_t capacity) {
    if (!size || size > 1500 || capacity < session->keyLength + session->addressLength + size + 16) { errno = EMSGSIZE; return -1; }
    uint8_t plain[1519], key[32], nonce[12] = {0}; size_t length = session->addressLength + size;
    memcpy(plain, session->address, session->addressLength); memcpy(plain + session->addressLength, data, size);
    int result = -1;
    if (RAND_bytes(wire, session->keyLength) == 1 && !usedSalt(session, wire) &&
        !ss_hkdf_sha1(session->master, session->keyLength, wire, session->keyLength, (const uint8_t *)"ss-subkey", 9, key, session->keyLength) &&
        !ss_aead_seal(session->cipher, key, nonce, plain, length, wire + session->keyLength, wire + session->keyLength + length)) {
        retainSalt(session, wire); result = session->keyLength + length + 16;
    }
    OPENSSL_cleanse(key, sizeof key); OPENSSL_cleanse(plain, sizeof plain);
    if (result < 0) errno = EIO; return result;
}
ssize_t MLShadowsocksUDPDecode(MLShadowsocksUDP *session, const uint8_t *wire, size_t size, uint8_t *data, size_t capacity) {
    if (size <= session->keyLength + session->addressLength + 16 || size > session->keyLength + 1519 + 16 || usedSalt(session, wire)) { errno = EPROTO; return -1; }
    uint8_t plain[1519], key[32], nonce[12] = {0}; size_t length = size - session->keyLength - 16;
    ssize_t result = -1;
    if (ss_hkdf_sha1(session->master, session->keyLength, wire, session->keyLength, (const uint8_t *)"ss-subkey", 9, key, session->keyLength) ||
        ss_aead_open(session->cipher, key, nonce, wire + session->keyLength, length, wire + size - 16, plain)) errno = EACCES;
    else if (memcmp(plain, session->address, session->addressLength)) errno = EPROTO;
    else {
        retainSalt(session, wire); size_t payload = length - session->addressLength;
        if (payload > capacity) errno = EMSGSIZE;
        else { memcpy(data, plain + session->addressLength, payload); result = payload; }
    }
    OPENSSL_cleanse(key, sizeof key); OPENSSL_cleanse(plain, sizeof plain); return result;
}
void MLShadowsocksUDPClose(MLShadowsocksUDP *session) {
    if (!session) return; OPENSSL_cleanse(session, sizeof *session); free(session);
}
