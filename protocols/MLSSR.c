#include "MLSSR.h"

/* Wire framing is checked against Mihomo v1.19.34 transport/ssr (commit
   0455d0d28c4526937380505153e65a843d8612e8) and the original SSR peer. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rc4.h>
#include <zlib.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

enum {
    SSRHostLimit = 1024,
    SSRHTTPResponseLimit = 16384,
    SSRKeySize = 32,
    SSRIVSize = 16,
    SSRAddressSize = 259,
    SSRRecentIVCount = 64
};

typedef enum { SSRNone, SSREVPCipher, SSRRC4 } SSRCipherKind;
typedef enum { SSROrigin, SSRSHA1V4, SSRAESMD5, SSRAESSHA1 } SSRProtocol;
typedef enum { SSRPlain, SSRHTTPGet, SSRHTTPPost } SSRObfs;

typedef struct {
    const char *name;
    SSRCipherKind kind;
    const EVP_CIPHER *(*evp)(void);
    unsigned keySize, ivSize;
} SSRCipher;

static const SSRCipher ciphers[] = {
    { "none",         SSRNone,      NULL,               16,  0 },
    { "dummy",        SSRNone,      NULL,               16,  0 },
    { "aes-128-cfb",  SSREVPCipher, EVP_aes_128_cfb128, 16, 16 },
    { "aes-192-cfb",  SSREVPCipher, EVP_aes_192_cfb128, 24, 16 },
    { "aes-256-cfb",  SSREVPCipher, EVP_aes_256_cfb128, 32, 16 },
    { "aes-128-ctr",  SSREVPCipher, EVP_aes_128_ctr,    16, 16 },
    { "aes-192-ctr",  SSREVPCipher, EVP_aes_192_ctr,    24, 16 },
    { "aes-256-ctr",  SSREVPCipher, EVP_aes_256_ctr,    32, 16 },
    { "chacha20",     SSREVPCipher, EVP_chacha20,       32,  8 },
    { "chacha20-ietf",SSREVPCipher, EVP_chacha20,       32, 12 },
#ifndef OPENSSL_NO_RC4
    { "rc4-md5",      SSRRC4,       NULL,               16, 16 },
#endif
};

static const char *const protocols[] = { "origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1" };
static const char *const obfuscators[] = { "plain", "http_simple", "http_post" };

typedef struct {
    EVP_CIPHER_CTX *evp;
#ifndef OPENSSL_NO_RC4
    RC4_KEY rc4;
#endif
    uint64_t count;
} SSRCipherState;

struct MLSSR {
    const SSRCipher *cipher;
    const EVP_MD *digest;
    SSRProtocol protocol;
    SSRObfs obfs;
    SSRCipherState tx, rx;
    uint8_t key[SSRKeySize], userKey[SSRKeySize], userID[4];
    uint8_t txIV[SSRIVSize], rxIV[SSRIVSize], address[SSRAddressSize], identity[32];
    unsigned userKeySize;
    size_t addressSize, rxIVSize;
    uint32_t sendID, receiveID;
    char *httpHosts, *httpHeaders;
    uint16_t port;
    size_t httpRead, httpDelimiter, frameSize, frameExpected;
    uint8_t *frame;
    int requested, responseStarted, failed;
};

struct MLSSRUDP {
    MLSSR *codec;
    uint8_t ivs[SSRRecentIVCount][SSRIVSize];
    unsigned recent, cursor;
};

/* SSR servers cap the number of simultaneous client identities. Share the
   identity and advance the connection counter across socket dial workers. */
typedef struct {
    uint8_t endpoint[32], id[4];
    uint32_t sequence;
    uint64_t used;
} SSRIdentity;

static SSRIdentity identities[64];
static pthread_mutex_t identityLock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t identityUse;

static const SSRCipher *findCipher(const char *name) {
    if (name) {
        for (size_t i = 0; i < sizeof ciphers / sizeof ciphers[0]; ++i)
            if (!strcasecmp(name, ciphers[i].name)) return &ciphers[i];
    }
    return NULL;
}

static int findName(const char *name, const char *const *names, size_t count) {
    if (name) {
        for (size_t i = 0; i < count; ++i)
            if (!strcmp(name, names[i])) return (int)i;
    }
    return -1;
}

static int findProtocol(const char *name) {
    return findName(name, protocols, sizeof protocols / sizeof protocols[0]);
}

static int findObfs(const char *name) {
    return findName(name, obfuscators, sizeof obfuscators / sizeof obfuscators[0]);
}

int MLSSRCipher(const char *cipher) { return findCipher(cipher) != NULL; }
int MLSSRProtocol(const char *protocol) { return findProtocol(protocol) >= 0; }
int MLSSRObfs(const char *obfs) { return findObfs(obfs) >= 0; }

static int parseUser(const char *param, uint32_t *id, const char **secret, size_t *size) {
    const char *sep = param ? strchr(param, ':') : NULL;
    if (!sep) return 0;
    if (sep == param) return -1;
    uint32_t value = 0;
    for (const char *p = param; p < sep; ++p) {
        if (*p < '0' || *p > '9' || value > (UINT32_MAX - (unsigned)(*p - '0')) / 10)
            return -1;
        value = value * 10 + (unsigned)(*p - '0');
    }
    *id = value;
    *secret = sep + 1;
    *size = strcspn(*secret, ":");
    return 1;
}

static int validHosts(const char *hosts, size_t length) {
    if (!length || length > SSRHostLimit || hosts[0] == ',' || hosts[length - 1] == ',')
        return 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char ch = (unsigned char)hosts[i];
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || strchr("-._:[]", ch)) continue;
        if (ch != ',' || hosts[i - 1] == ',') return 0;
    }
    return 1;
}

int MLSSRParameters(const char *protocol, const char *protocolParam,
                    const char *obfs, const char *obfsParam) {
    int p = findProtocol(protocol), o = findObfs(obfs);
    if (p < 0 || o < 0) return 0;
    if (p == SSRAESMD5 || p == SSRAESSHA1) {
        uint32_t id;
        const char *secret;
        size_t size;
        if (parseUser(protocolParam, &id, &secret, &size) < 0) return 0;
    }
    if (o != SSRPlain && obfsParam && *obfsParam) {
        if (strlen(obfsParam) > SSRHostLimit) return 0;
        const char *headers = strchr(obfsParam, '#');
        size_t hostLength = headers ? (size_t)(headers - obfsParam) : strlen(obfsParam);
        if (!validHosts(obfsParam, hostLength)) return 0;
        for (const char *p = headers ? headers + 1 : ""; *p; ++p)
            if ((unsigned char)*p < 32 && *p != '\n' && *p != '\t') return 0;
    }
    return 1;
}

static uint16_t read16(const uint8_t *data, int little) {
    return little ? (uint16_t)(data[0] | data[1] << 8) : (uint16_t)(data[0] << 8 | data[1]);
}

static void put16(uint8_t *out, uint16_t value, int little) {
    out[little ? 0 : 1] = (uint8_t)value;
    out[little ? 1 : 0] = (uint8_t)(value >> 8);
}

static void put32(uint8_t *out, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) out[i] = (uint8_t)(value >> (8 * i));
}

static uint32_t get32(const uint8_t *in) {
    return (uint32_t)in[0] | (uint32_t)in[1] << 8 | (uint32_t)in[2] << 16 | (uint32_t)in[3] << 24;
}

static int makeAddress(const vless_dest_t *target, uint8_t *out, size_t *length) {
    if (!target || !target->port) return 0;
    size_t size;
    if (target->atyp == VLESS_ADDR_IPV4 || target->atyp == VLESS_ADDR_IPV6) {
        size = target->atyp == VLESS_ADDR_IPV4 ? 4 : 16;
        out[0] = size == 4 ? 1 : 4;
        memcpy(out + 1, target->host_addr, size);
        ++size;
    } else if (target->atyp == VLESS_ADDR_DOMAIN &&
               (size = strnlen(target->domain, sizeof target->domain)) > 0 && size <= 255) {
        out[0] = 3;
        out[1] = (uint8_t)size;
        memcpy(out + 2, target->domain, size);
        size += 2;
    } else return 0;
    put16(out + size, target->port, 0);
    *length = size + 2;
    return 1;
}

static int deriveKey(const uint8_t *password, size_t length, uint8_t *key, size_t size) {
    uint8_t block[16];
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!context) return 0;
    size_t offset = 0;
    for (; offset < size; offset += sizeof block) {
        if (!EVP_DigestInit_ex(context, EVP_md5(), NULL) ||
            (offset && !EVP_DigestUpdate(context, block, sizeof block)) ||
            !EVP_DigestUpdate(context, password, length) ||
            !EVP_DigestFinal_ex(context, block, NULL)) break;
        size_t remaining = size - offset;
        memcpy(key + offset, block, remaining < sizeof block ? remaining : sizeof block);
    }
    OPENSSL_cleanse(block, sizeof block);
    EVP_MD_CTX_free(context);
    return offset >= size;
}

static int cipherInit(const MLSSR *s, SSRCipherState *state, const uint8_t *iv, int encrypt) {
    if (s->cipher->kind == SSRNone) return 1;
#ifndef OPENSSL_NO_RC4
    if (s->cipher->kind == SSRRC4) {
        uint8_t input[32], derived[16];
        memcpy(input, s->key, 16);
        memcpy(input + 16, iv, 16);
        int ok = EVP_Digest(input, sizeof input, derived, NULL, EVP_md5(), NULL);
        if (ok) RC4_set_key(&state->rc4, sizeof derived, derived);
        OPENSSL_cleanse(derived, sizeof derived);
        OPENSSL_cleanse(input, sizeof input);
        return ok;
    }
#endif
    uint8_t chachaIV[16] = {0};
    if (s->cipher->evp == EVP_chacha20) {
        memcpy(chachaIV + sizeof chachaIV - s->cipher->ivSize, iv, s->cipher->ivSize);
        iv = chachaIV;
    }
    state->evp = EVP_CIPHER_CTX_new();
    return state->evp && EVP_CipherInit_ex(state->evp, s->cipher->evp(), NULL, s->key, iv, encrypt);
}

static int cipherUpdate(const MLSSR *s, SSRCipherState *state, const uint8_t *in,
                        uint8_t *out, size_t size) {
    if (!size) return 1;
    if (s->cipher->kind == SSRNone) {
        memmove(out, in, size);
        return 1;
    }
#ifndef OPENSSL_NO_RC4
    if (s->cipher->kind == SSRRC4) {
        RC4(&state->rc4, size, in, out);
        return 1;
    }
#endif
    if (s->cipher->evp == EVP_chacha20 && s->cipher->ivSize == 12) {
        if (size > (UINT64_C(1) << 38) - state->count) return 0;
        state->count += size;
    }
    int wrote = 0;
    return EVP_CipherUpdate(state->evp, out, &wrote, in, (int)size) && (size_t)wrote == size;
}

static int randomBytes(uint8_t *bytes, size_t length) {
    return !length || RAND_bytes(bytes, (int)length) == 1;
}

static int randomBelow(unsigned bound, unsigned *result) {
    if (bound <= 1) {
        *result = 0;
        return 1;
    }
    uint8_t bytes[2];
    if (!randomBytes(bytes, sizeof bytes)) return 0;
    *result = read16(bytes, 0) % bound;
    return 1;
}

static int setupHTTP(MLSSR *s, const char *server, const char *param) {
    const char *hosts = param && *param ? param : server;
    if (!hosts) { errno = EINVAL; return 0; }
    const char *headers = param && *param ? strchr(hosts, '#') : NULL;
    size_t length = headers ? (size_t)(headers - hosts) : strlen(hosts);
    if (!validHosts(hosts, length)) { errno = EINVAL; return 0; }
    s->httpHosts = strndup(hosts, length);
    if (!s->httpHosts) return 0;
    if (headers && headers[1]) {
        const char *in = headers + 1;
        s->httpHeaders = malloc(strlen(in) * 2 + 1);
        if (!s->httpHeaders) return 0;
        char *out = s->httpHeaders;
        while (*in) {
            if (*in == '\n' || (*in == '\\' && in[1] == 'n')) {
                if (*in == '\\') ++in;
                *out++ = '\r';
                *out++ = '\n';
            } else *out++ = *in;
            ++in;
        }
        *out = 0;
    }
    return 1;
}

static MLSSR *allocateCodec(const SSRCipher *method, const char *password, SSRProtocol protocol,
                            const char *protocolParam, const vless_dest_t *target) {
    MLSSR *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->cipher = method;
    s->protocol = protocol;
    s->digest = s->protocol == SSRAESMD5 ? EVP_md5() : EVP_sha1();
    s->sendID = s->receiveID = 1;
    if (!makeAddress(target, s->address, &s->addressSize)) {
        errno = EINVAL;
        goto fail;
    }
    if (!deriveKey((const uint8_t *)password, strlen(password), s->key, s->cipher->keySize)) goto cryptoFail;
    if (s->protocol == SSRAESMD5 || s->protocol == SSRAESSHA1) {
        uint32_t id;
        const char *secret;
        size_t size;
        if (parseUser(protocolParam, &id, &secret, &size) == 1) {
            put32(s->userID, id);
            if (!EVP_Digest(secret, size, s->userKey, &s->userKeySize, s->digest, NULL)) goto cryptoFail;
        } else {
            if (!randomBytes(s->userID, sizeof s->userID)) goto cryptoFail;
            s->userKeySize = s->cipher->keySize;
            memcpy(s->userKey, s->key, s->userKeySize);
        }
    }
    return s;

cryptoFail:
    errno = EIO;
fail:
    MLSSRClose(s);
    return NULL;
}

static int endpointIdentity(MLSSR *s, const char *server, const char *protocolParam) {
    if (!server) server = "";
    if (!protocolParam) protocolParam = "";
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!context) return 0;
    const char *cipher = s->cipher->name;
    uint8_t fields[] = { (uint8_t)(s->port >> 8), (uint8_t)s->port, (uint8_t)s->protocol };
    int ok = EVP_DigestInit_ex(context, EVP_sha256(), NULL) &&
             EVP_DigestUpdate(context, s->key, s->cipher->keySize) &&
             EVP_DigestUpdate(context, fields, sizeof fields) &&
             EVP_DigestUpdate(context, server, strlen(server) + 1) &&
             EVP_DigestUpdate(context, cipher, strlen(cipher) + 1) &&
             EVP_DigestUpdate(context, protocolParam, strlen(protocolParam)) &&
             EVP_DigestFinal_ex(context, s->identity, NULL);
    EVP_MD_CTX_free(context);
    return ok;
}

MLSSR *MLSSROpen(const char *cipher, const char *password, const char *protocol,
                const char *protocolParam, const char *obfs, const char *obfsParam,
                const char *server, uint16_t port, const vless_dest_t *target) {
    const SSRCipher *method = findCipher(cipher);
    if (!method || !password || !*password || !port ||
        !MLSSRParameters(protocol, protocolParam, obfs, obfsParam)) {
        errno = EINVAL;
        return NULL;
    }
    MLSSR *s = allocateCodec(method, password, (SSRProtocol)findProtocol(protocol), protocolParam, target);
    if (!s) return NULL;
    s->obfs = (SSRObfs)findObfs(obfs);
    s->port = port;
    if (s->obfs != SSRPlain && !setupHTTP(s, server, obfsParam)) goto fail;
    if (s->protocol != SSROrigin) {
        if (!endpointIdentity(s, server, protocolParam)) { errno = EIO; goto fail; }
        s->frame = malloc(ML_SSR_FRAME_LIMIT);
        if (!s->frame) goto fail;
    }
    return s;
fail:
    MLSSRClose(s);
    return NULL;
}

static int mac(const MLSSR *s, const uint8_t *key, size_t keySize, const uint8_t *data,
               size_t size, uint8_t *out, size_t length) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    int ok = HMAC(s->digest, key, (int)keySize, data, size, digest, NULL) != NULL;
    if (ok) memcpy(out, digest, length);
    OPENSSL_cleanse(digest, sizeof digest);
    return ok;
}

static int macMatches(const MLSSR *s, const uint8_t *key, size_t keySize, const uint8_t *data,
                      size_t size, const uint8_t *tag, size_t length) {
    uint8_t expected[10];
    return mac(s, key, keySize, data, size, expected, length) &&
           CRYPTO_memcmp(expected, tag, length) == 0;
}

static int encodePadding(uint8_t *out, unsigned padding, int little) {
    unsigned prefix = padding < 128 ? 1 : 3;
    out[0] = prefix == 1 ? (uint8_t)(padding + 1) : 255;
    if (prefix == 3) put16(out + 1, (uint16_t)(padding + prefix), little);
    return randomBytes(out + prefix, padding);
}

static unsigned sha1PaddingBound(size_t size) {
    return size > 1200 ? 1 : size > 400 ? 256 : 512;
}

static int makeAuthIdentity(const MLSSR *s, uint8_t *out) {
    if (pthread_mutex_lock(&identityLock) != 0) return 0;
    SSRIdentity *entry = &identities[0];
    for (size_t i = 0; i < sizeof identities / sizeof identities[0]; ++i) {
        SSRIdentity *candidate = &identities[i];
        if (candidate->used && !CRYPTO_memcmp(candidate->endpoint, s->identity, sizeof s->identity)) {
            entry = candidate;
            break;
        }
        if (candidate->used < entry->used) entry = candidate;
    }
    int ok = 1;
    if (!entry->used || entry->sequence >= 0xff000000 ||
        CRYPTO_memcmp(entry->endpoint, s->identity, sizeof s->identity)) {
        uint8_t nonce[7];
        ok = randomBytes(nonce, sizeof nonce);
        if (ok) {
            memcpy(entry->endpoint, s->identity, sizeof s->identity);
            memcpy(entry->id, nonce, sizeof entry->id);
            entry->sequence = (uint32_t)nonce[4] | (uint32_t)nonce[5] << 8 | (uint32_t)nonce[6] << 16;
        }
    }
    if (ok) {
        entry->used = ++identityUse;
        put32(out, (uint32_t)time(NULL));
        memcpy(out + 4, entry->id, sizeof entry->id);
        put32(out + 8, ++entry->sequence);
    }
    pthread_mutex_unlock(&identityLock);
    return ok;
}

static int aesAuthBlock(const MLSSR *s, uint8_t *out, uint16_t length, uint16_t padding) {
    uint8_t text[16], key[16], zeroIV[16] = {0};
    uint8_t password[64];
    int size = EVP_EncodeBlock(password, s->userKey, (int)s->userKeySize);
    const char *salt = protocols[s->protocol];
    memcpy(password + size, salt, strlen(salt));
    int ok = 0, written = 0;
    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    if (cipher && makeAuthIdentity(s, text) && deriveKey(password, (size_t)size + strlen(salt), key, sizeof key)) {
        put16(text + 12, length, 1);
        put16(text + 14, padding, 1);
        ok = EVP_EncryptInit_ex(cipher, EVP_aes_128_cbc(), NULL, key, zeroIV) &&
             EVP_CIPHER_CTX_set_padding(cipher, 0) &&
             EVP_EncryptUpdate(cipher, out, &written, text, sizeof text) && written == sizeof text;
    }
    EVP_CIPHER_CTX_free(cipher);
    OPENSSL_cleanse(key, sizeof key);
    OPENSSL_cleanse(text, sizeof text);
    OPENSSL_cleanse(password, sizeof password);
    return ok;
}

static size_t encodeAuth(const MLSSR *s, uint8_t *out) {
    if (s->protocol == SSROrigin) {
        memcpy(out, s->address, s->addressSize);
        return s->addressSize;
    }

    uint8_t macKey[48];
    size_t macKeySize = s->cipher->ivSize + s->cipher->keySize;
    unsigned padding;
    size_t size = 0;
    memcpy(macKey, s->txIV, s->cipher->ivSize);
    memcpy(macKey + s->cipher->ivSize, s->key, s->cipher->keySize);
    if (s->protocol == SSRSHA1V4) {
        uint8_t crcInput[2 + sizeof "auth_sha1_v4" - 1 + 32];
        const char *salt = protocols[s->protocol];
        size_t saltSize = strlen(salt);
        if (!randomBelow(sha1PaddingBound(s->addressSize + 12), &padding)) goto done;
        size_t position = 6 + padding + (padding < 128 ? 1 : 3);
        size_t length = position + 12 + s->addressSize + 10;
        put16(out, (uint16_t)length, 0);
        memcpy(crcInput, out, 2);
        memcpy(crcInput + 2, salt, saltSize);
        memcpy(crcInput + 2 + saltSize, s->key, s->cipher->keySize);
        put32(out + 2, (uint32_t)crc32(0, crcInput, (uInt)(2 + saltSize + s->cipher->keySize)));
        OPENSSL_cleanse(crcInput, sizeof crcInput);
        if (!encodePadding(out + 6, padding, 0) || !makeAuthIdentity(s, out + position)) goto done;
        memcpy(out + position + 12, s->address, s->addressSize);
        if (mac(s, macKey, macKeySize, out, length - 10, out + length - 10, 10)) size = length;
    } else {
        if (!randomBelow(1024, &padding)) goto done;
        size_t length = 35 + padding + s->addressSize;
        memcpy(out + 7, s->userID, sizeof s->userID);
        memcpy(out + 31 + padding, s->address, s->addressSize);
        if (randomBytes(out, 1) && mac(s, macKey, macKeySize, out, 1, out + 1, 6) &&
            aesAuthBlock(s, out + 11, (uint16_t)length, (uint16_t)padding) &&
            mac(s, macKey, macKeySize, out + 7, 20, out + 27, 4) &&
            randomBytes(out + 31, padding) &&
            mac(s, s->userKey, s->userKeySize, out, length - 4, out + length - 4, 4)) size = length;
    }
done:
    OPENSSL_cleanse(macKey, sizeof macKey);
    return size;
}

static void frameKey(const MLSSR *s, uint32_t sequence, uint8_t *key) {
    memcpy(key, s->userKey, s->userKeySize);
    put32(key + s->userKeySize, sequence);
}

static size_t encodeFrame(const MLSSR *s, const uint8_t *data, size_t size, uint8_t *out) {
    const int aes = s->protocol != SSRSHA1V4;
    unsigned bound = sha1PaddingBound(size);
    if (aes) {
        if (size <= 1451) bound = (unsigned)(1451 - size);
        else if (size < 2911) bound = (unsigned)(2911 - size);
        else bound = 32;
    }
    unsigned padding;
    if (!randomBelow(bound, &padding) || !encodePadding(out + 4, padding, aes)) return 0;
    size_t position = 4 + padding + (padding < 128 ? 1 : 3);
    size_t length = position + size + 4;
    put16(out, (uint16_t)length, aes);
    memcpy(out + position, data, size);

    if (aes) {
        uint8_t key[36];
        frameKey(s, s->sendID, key);
        int ok = mac(s, key, s->userKeySize + 4, out, 2, out + 2, 2) &&
                 mac(s, key, s->userKeySize + 4, out, length - 4, out + length - 4, 4);
        OPENSSL_cleanse(key, sizeof key);
        if (!ok) return 0;
    } else {
        put16(out + 2, (uint16_t)crc32(0, out, 2), 1);
        put32(out + length - 4, (uint32_t)adler32(1, out, (uInt)(length - 4)));
    }
    return length;
}

static size_t wrapHTTP(const MLSSR *s, const uint8_t *encrypted, size_t length,
                       uint8_t *wire, size_t capacity) {
    unsigned count = 1, index, extra;
    for (const char *p = s->httpHosts; *p; ++p) if (*p == ',') ++count;
    if (!randomBelow(count, &index) || !randomBelow(65, &extra)) return 0;
    const char *host = s->httpHosts;
    while (index--) host = strchr(host, ',') + 1;
    const char *method = s->obfs == SSRHTTPPost ? "POST /" : "GET /";
    size_t pos = strlen(method), head = s->cipher->ivSize + 30;
    if (length > head + 64) head += extra;
    else head = length;
    if (pos + head * 3 >= capacity) return 0;
    memcpy(wire, method, pos);
    const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < head; ++i) {
        wire[pos++] = '%';
        wire[pos++] = (uint8_t)hex[encrypted[i] >> 4];
        wire[pos++] = (uint8_t)hex[encrypted[i] & 15];
    }

    static const char prefix[] = "Content-Type: multipart/form-data; boundary=";
    char port[7] = "", multipart[sizeof prefix + 32 + 2] = "";
    if (s->port != 80) snprintf(port, sizeof port, ":%u", (unsigned)s->port);
    if (s->obfs == SSRHTTPPost && !s->httpHeaders) {
        uint8_t boundary[16];
        if (!randomBytes(boundary, sizeof boundary)) return 0;
        size_t offset = sizeof prefix - 1;
        memcpy(multipart, prefix, offset);
        for (size_t i = 0; i < sizeof boundary; ++i) {
            multipart[offset++] = hex[boundary[i] >> 4];
            multipart[offset++] = hex[boundary[i] & 15];
        }
        memcpy(multipart + offset, "\r\n", 3);
    }

    const char *fields = s->httpHeaders ? s->httpHeaders : "User-Agent: Mozilla/5.0\r\nAccept: */*\r\n";
    const char *closing = s->httpHeaders ? "\r\n" : "Connection: keep-alive\r\n";
    int header = snprintf((char *)wire + pos, capacity - pos, " HTTP/1.1\r\nHost: %.*s%s\r\n%s%s%s\r\n",
                          (int)strcspn(host, ","), host, port, fields, multipart, closing);
    if (header < 0 || (size_t)header >= capacity - pos) return 0;
    pos += (size_t)header;
    if (length - head > capacity - pos) return 0;
    memcpy(wire + pos, encrypted + head, length - head);
    return pos + length - head;
}

static ssize_t failStream(MLSSR *s, int error) {
    if (s) s->failed = 1;
    errno = error;
    return -1;
}

ssize_t MLSSRRequest(MLSSR *s, uint8_t *wire, size_t capacity) {
    if (!s || !wire || s->requested || s->failed) { errno = EINVAL; return -1; }
    if (capacity < ML_SSR_FRAME_LIMIT) { errno = ENOBUFS; return -1; }
    uint8_t request[16 + 35 + 1023 + 259];
    size_t ivSize = s->cipher->ivSize;
    if (!randomBytes(s->txIV, ivSize) || !cipherInit(s, &s->tx, s->txIV, 1))
        return failStream(s, EIO);
    memcpy(request, s->txIV, ivSize);
    size_t length = encodeAuth(s, request + ivSize);
    if (!length || !cipherUpdate(s, &s->tx, request + ivSize, request + ivSize, length)) {
        OPENSSL_cleanse(request, sizeof request);
        return failStream(s, EIO);
    }
    length += ivSize;
    if (s->obfs != SSRPlain) length = wrapHTTP(s, request, length, wire, capacity);
    else memcpy(wire, request, length);
    OPENSSL_cleanse(request, sizeof request);
    if (!length) return failStream(s, EIO);
    s->requested = 1;
    return (ssize_t)length;
}

ssize_t MLSSRWrite(MLSSR *s, const uint8_t *data, size_t size, uint8_t *wire, size_t capacity) {
    if (!s || (!data && size) || !wire || !s->requested || s->failed) { errno = EINVAL; return -1; }
    if (!size) return 0;
    if (size > ML_SSR_WRITE_LIMIT) { errno = EMSGSIZE; return -1; }
    if (capacity < ML_SSR_FRAME_LIMIT) { errno = ENOBUFS; return -1; }
    if (s->protocol == SSROrigin) {
        if (!cipherUpdate(s, &s->tx, data, wire, size)) return failStream(s, EIO);
        return (ssize_t)size;
    }
    if (s->sendID == UINT32_MAX) return failStream(s, EOVERFLOW);
    size_t length = encodeFrame(s, data, size, wire);
    if (!length || !cipherUpdate(s, &s->tx, wire, wire, length)) return failStream(s, EIO);
    ++s->sendID;
    return (ssize_t)length;
}

static int readHTTP(MLSSR *s, const uint8_t **wire, size_t *size) {
    static const char suffix[] = "\r\n\r\n", prefix[] = "HTTP/1.";
    while (*size && s->httpDelimiter != sizeof suffix - 1) {
        uint8_t ch = **wire;
        ++*wire;
        --*size;
        size_t position = s->httpRead++;
        if (position < sizeof prefix - 1 && ch != (uint8_t)prefix[position]) return 0;
        if (ch == (uint8_t)suffix[s->httpDelimiter]) ++s->httpDelimiter;
        else s->httpDelimiter = ch == '\r' ? 1 : 0;
        if (s->httpRead == SSRHTTPResponseLimit && s->httpDelimiter != sizeof suffix - 1) return 0;
    }
    return 1;
}

static int validateFrameHead(MLSSR *s) {
    const int aes = s->protocol != SSRSHA1V4;
    const uint8_t *frame = s->frame;
    size_t size = read16(frame, aes);
    if (size < 9 || size >= ML_SSR_FRAME_LIMIT) return 0;
    if (aes) {
        uint8_t key[36];
        frameKey(s, s->receiveID, key);
        int ok = macMatches(s, key, s->userKeySize + 4, frame, 2, frame + 2, 2);
        OPENSSL_cleanse(key, sizeof key);
        if (!ok) return 0;
    } else if ((uint16_t)crc32(0, frame, 2) != read16(frame + 2, 1)) return 0;
    s->frameExpected = size;
    return 1;
}

static int validateFrame(MLSSR *s, size_t *offset, size_t *length) {
    const int aes = s->protocol != SSRSHA1V4;
    const uint8_t *frame = s->frame;
    size_t end = s->frameExpected - 4;
    size_t padding = frame[4];
    if (padding == 255) {
        if (end < 7) return 0;
        padding = read16(frame + 5, aes);
        if (padding < 3) return 0;
    }
    if (!padding || 4 + padding > end) return 0;
    if (aes) {
        uint8_t key[36];
        frameKey(s, s->receiveID, key);
        int ok = macMatches(s, key, s->userKeySize + 4, frame, end, frame + end, 4);
        OPENSSL_cleanse(key, sizeof key);
        if (!ok) return 0;
    } else if (adler32(1, frame, (uInt)end) != get32(frame + end)) return 0;
    *offset = 4 + padding;
    *length = end - *offset;
    return 1;
}

ssize_t MLSSRFeed(MLSSR *s, const uint8_t *wire, size_t size, uint8_t *data, size_t capacity) {
    if (!s || (!wire && size) || !data || !s->requested || s->failed) { errno = EINVAL; return -1; }
    if (!size) return 0;
    s->responseStarted = 1;
    if (s->obfs != SSRPlain && !readHTTP(s, &wire, &size)) return failStream(s, EPROTO);
    if (!size) return 0;

    if (s->rxIVSize < s->cipher->ivSize) {
        size_t take = s->cipher->ivSize - s->rxIVSize;
        if (take > size) take = size;
        memcpy(s->rxIV + s->rxIVSize, wire, take);
        s->rxIVSize += take;
        wire += take;
        size -= take;
        if (s->rxIVSize < s->cipher->ivSize) return 0;
        if (CRYPTO_memcmp(s->txIV, s->rxIV, s->cipher->ivSize) == 0) return failStream(s, EPROTO);
        if (!cipherInit(s, &s->rx, s->rxIV, 0)) return failStream(s, EIO);
    }
    if (s->protocol == SSROrigin) {
        if (size > capacity || size > INT32_MAX) return failStream(s, ENOBUFS);
        if (!cipherUpdate(s, &s->rx, wire, data, size)) return failStream(s, EIO);
        return (ssize_t)size;
    }
    size_t written = 0;
    while (size) {
        if (s->receiveID == UINT32_MAX) return failStream(s, EOVERFLOW);
        size_t target = s->frameExpected ? s->frameExpected : 4;
        size_t take = target - s->frameSize;
        if (take > size) take = size;
        if (!cipherUpdate(s, &s->rx, wire, s->frame + s->frameSize, take)) return failStream(s, EIO);
        s->frameSize += take;
        wire += take;
        size -= take;
        if (s->frameSize != target) continue;
        if (!s->frameExpected) {
            if (!validateFrameHead(s)) return failStream(s, EPROTO);
            continue;
        }
        size_t offset, length;
        if (!validateFrame(s, &offset, &length)) return failStream(s, EPROTO);
        if (length > capacity - written) return failStream(s, ENOBUFS);
        memcpy(data + written, s->frame + offset, length);
        written += length;
        s->frameSize = s->frameExpected = 0;
        ++s->receiveID;
    }
    return (ssize_t)written;
}

int MLSSRComplete(const MLSSR *s) {
    return s && s->requested && !s->failed && (!s->responseStarted ||
           ((s->obfs == SSRPlain || s->httpDelimiter == 4) &&
            s->rxIVSize == s->cipher->ivSize && !s->frameSize));
}

void MLSSRClose(MLSSR *s) {
    if (!s) return;
    EVP_CIPHER_CTX_free(s->tx.evp);
    EVP_CIPHER_CTX_free(s->rx.evp);
    if (s->frame) OPENSSL_cleanse(s->frame, ML_SSR_FRAME_LIMIT);
    free(s->frame);
    free(s->httpHosts);
    free(s->httpHeaders);
    OPENSSL_cleanse(s, sizeof *s);
    free(s);
}

MLSSRUDP *MLSSRUDPOpen(const char *cipher, const char *password, const char *protocol,
                      const char *protocolParam, const vless_dest_t *target) {
    const SSRCipher *method = findCipher(cipher);
    if (!method || !password || !*password || !MLSSRParameters(protocol, protocolParam, "plain", NULL)) {
        errno = EINVAL;
        return NULL;
    }
    MLSSRUDP *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->codec = allocateCodec(method, password, (SSRProtocol)findProtocol(protocol), protocolParam, target);
    if (!s->codec) {
        free(s);
        return NULL;
    }
    return s;
}

static int authenticatedUDP(const MLSSR *s) {
    return s->protocol == SSRAESMD5 || s->protocol == SSRAESSHA1;
}

static int usedIV(const MLSSRUDP *s, const uint8_t *iv) {
    size_t size = s->codec->cipher->ivSize;
    for (unsigned i = 0; i < s->recent; ++i)
        if (CRYPTO_memcmp(iv, s->ivs[i], size) == 0) return 1;
    return 0;
}

static void retainIV(MLSSRUDP *s, const uint8_t *iv) {
    size_t size = s->codec->cipher->ivSize;
    if (!size) return;
    memcpy(s->ivs[s->cursor], iv, size);
    s->cursor = (s->cursor + 1) % SSRRecentIVCount;
    if (s->recent < SSRRecentIVCount) ++s->recent;
}

static int cryptDatagram(const MLSSR *s, const uint8_t *iv, const uint8_t *input, uint8_t *out,
                         size_t size, int encrypt) {
    SSRCipherState state = {0};
    int ok = cipherInit(s, &state, iv, encrypt) && cipherUpdate(s, &state, input, out, size);
    EVP_CIPHER_CTX_free(state.evp);
    OPENSSL_cleanse(&state, sizeof state);
    return ok;
}

ssize_t MLSSRUDPEncode(MLSSRUDP *udp, const uint8_t *data, size_t size,
                      uint8_t *wire, size_t capacity) {
    if (!udp || !data || !wire) { errno = EINVAL; return -1; }
    if (!size || size > ML_SSR_UDP_LIMIT) { errno = EMSGSIZE; return -1; }
    MLSSR *s = udp->codec;
    const size_t ivSize = s->cipher->ivSize;
    const int auth = authenticatedUDP(s);
    size_t length = s->addressSize + size;
    if (capacity < ivSize + length + (auth ? 8 : 0)) { errno = ENOBUFS; return -1; }
    uint8_t plain[SSRAddressSize + ML_SSR_UDP_LIMIT + 8];
    memcpy(plain, s->address, s->addressSize);
    memcpy(plain + s->addressSize, data, size);
    if (auth) {
        memcpy(plain + length, s->userID, sizeof s->userID);
        length += sizeof s->userID;
        if (!mac(s, s->userKey, s->userKeySize, plain, length, plain + length, 4)) goto fail;
        length += 4;
    }
    if (!randomBytes(wire, ivSize) || usedIV(udp, wire) ||
        !cryptDatagram(s, wire, plain, wire + ivSize, length, 1)) goto fail;
    retainIV(udp, wire);
    OPENSSL_cleanse(plain, sizeof plain);
    return (ssize_t)(ivSize + length);
fail:
    OPENSSL_cleanse(plain, sizeof plain);
    errno = EIO;
    return -1;
}

static size_t datagramAddressSize(const uint8_t *packet, size_t length) {
    if (length < 4) return 0;
    size_t head;
    switch (packet[0]) {
        case 1: head = 7; break;
        case 4: head = 19; break;
        case 3: head = packet[1] ? (size_t)packet[1] + 4 : 0; break;
        default: return 0;
    }
    return head && head <= length && read16(packet + head - 2, 0) ? head : 0;
}

static int matchesDatagramTarget(const MLSSR *s, const uint8_t *address, size_t length) {
    if (memcmp(address + length - 2, s->address + s->addressSize - 2, 2)) return 0;
    /* The relay may return a resolved IP when the request used a domain. */
    if (s->address[0] == 3) {
        if (address[0] != 3) return 1;
        return length == s->addressSize &&
               !strncasecmp((const char *)address + 2, (const char *)s->address + 2, address[1]);
    }
    return length == s->addressSize && !memcmp(address, s->address, length);
}

ssize_t MLSSRUDPDecode(MLSSRUDP *udp, const uint8_t *wire, size_t size,
                      uint8_t *data, size_t capacity) {
    if (!udp || !wire || !data) { errno = EINVAL; return -1; }
    const MLSSR *s = udp->codec;
    const size_t ivSize = s->cipher->ivSize;
    size_t tagSize = authenticatedUDP(s) ? 4 : 0;
    uint8_t plain[SSRAddressSize + ML_SSR_UDP_LIMIT + 4];
    if (size < ivSize + tagSize + 5 || size - ivSize > sizeof plain || usedIV(udp, wire)) {
        errno = EPROTO;
        return -1;
    }

    size_t length = size - ivSize - tagSize;
    int error = EIO;
    if (!cryptDatagram(s, wire, wire + ivSize, plain, size - ivSize, 0)) goto fail;
    error = EPROTO;
    if (tagSize && !macMatches(s, s->key, s->cipher->keySize, plain, length, plain + length, tagSize))
        goto fail;
    size_t head = datagramAddressSize(plain, length);
    if (!head || head == length || length - head > ML_SSR_UDP_LIMIT ||
        !matchesDatagramTarget(s, plain, head)) goto fail;
    if (length - head > capacity) { error = ENOBUFS; goto fail; }
    retainIV(udp, wire);
    memcpy(data, plain + head, length - head);
    OPENSSL_cleanse(plain, sizeof plain);
    return (ssize_t)(length - head);
fail:
    OPENSSL_cleanse(plain, sizeof plain);
    errno = error;
    return -1;
}

void MLSSRUDPClose(MLSSRUDP *s) {
    if (!s) return;
    MLSSRClose(s->codec);
    OPENSSL_cleanse(s, sizeof *s);
    free(s);
}
