#include "MLSnell.h"

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SNELL_SALT 16
#define SNELL_TAG 16
#define SNELL_HEADER 7
#define SNELL_LEGACY_MAX 0x3fff
#define SNELL_V6_MAX 0xffff
#define SNELL_SALT_BLOCK_MAX 144
#define SNELL_PSK_MAX 255

static size_t smaller(size_t a, size_t b) { return a < b ? a : b; }

static unsigned get16(const uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }

static void put16(uint8_t *p, size_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void swapBytes(uint8_t *a, uint8_t *b) {
    uint8_t value = *a;
    *a = *b;
    *b = value;
}

#include "MLSnellProfile.h"

typedef enum { SnellOrdinary, SnellProfiled, SnellRaw } SnellMode;
typedef enum { ReceiveSalt, ReceiveHeader, ReceiveBody } ReceivePart;
typedef enum { ReplyCommand, ReplyCode, ReplyLength, ReplyMessage, ReplySuccess } ReplyPart;

typedef struct {
    EVP_CIPHER_CTX *context;
    uint8_t nonce[12];
    uint32_t sequence;
} SnellDirection;

struct MLSnell {
    unsigned version;
    SnellMode mode;
    int datagram, closing, ended, error;
    uint8_t psk[SNELL_PSK_MAX], salt[SNELL_SALT];
    size_t pskLength;
    SnellProfile profile;
    SnellDirection rx, tx;
    ReceivePart rxPart;
    ReplyPart replyPart;
    size_t replyRemaining;
    int saltSent;
    size_t padding, payload, received, needed, plainOffset, plainLength;
    uint8_t header[SNELL_PREFIX_MAX + SNELL_HEADER + SNELL_TAG];
    uint8_t *input, *output;
    size_t inputCap, outputCap, outputLength, outputOffset;
    uint8_t udpHeader[260], udpIP[16];
    size_t udpHeaderLength, udpIPLength;
    uint16_t udpPort;
    unsigned initialPadding;
    size_t chunk;
    time_t lastWrite;
};

static int failure(MLSnell *codec, int error) {
    if (!codec->error) codec->error = error;
    errno = codec->error;
    return -1;
}

static int randomBytes(void *out, size_t length) {
    if (!length || RAND_bytes(out, (int)length) == 1) return 0;
    errno = EIO;
    return -1;
}

static int reserve(uint8_t **buffer, size_t *capacity, size_t length) {
    if (length <= *capacity) return 0;
    size_t rounded = (length + 1023) & ~(size_t)1023;
    uint8_t *next = realloc(*buffer, rounded);
    if (!next) return -1;
    *buffer = next;
    *capacity = rounded;
    return 0;
}

static int setupKey(MLSnell *codec, SnellDirection *direction, uint8_t salt[SNELL_SALT], int encrypt) {
    EVP_KDF *algorithm = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!algorithm) return failure(codec, EIO);
    EVP_KDF_CTX *kdf = EVP_KDF_CTX_new(algorithm);
    EVP_KDF_free(algorithm);
    if (!kdf) return failure(codec, ENOMEM);

    unsigned iterations = 3, memory = 8, lanes = 1, threads = 1, version = 0x13;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, codec->psk, codec->pskLength),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, SNELL_SALT),
        OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations),
        OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory),
        OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
        OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_THREADS, &threads),
        OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_VERSION, &version),
        OSSL_PARAM_construct_end()
    };
    uint8_t key[32];
    int ok = EVP_KDF_derive(kdf, key, sizeof key, params) == 1;
    EVP_KDF_CTX_free(kdf);
    const EVP_CIPHER *cipher = codec->version == 1 ? EVP_chacha20_poly1305() : EVP_aes_128_gcm();
    if (ok) {
        direction->context = EVP_CIPHER_CTX_new();
        ok = direction->context && EVP_CipherInit_ex(direction->context, cipher, NULL, key, NULL, encrypt) == 1;
    }
    OPENSSL_cleanse(key, sizeof key);
    return ok ? 0 : failure(codec, EIO);
}

/* Each record authenticates the header and the body with distinct nonces. */
static int cryptPart(MLSnell *codec, SnellDirection *direction, uint8_t *data,
                     size_t length, const uint8_t *aad, size_t aadLength, int encrypt) {
    EVP_CIPHER_CTX *context = direction->context;
    int count = 0, final = 0;
    if (EVP_CipherInit_ex(context, NULL, NULL, NULL, direction->nonce, encrypt) != 1 ||
        (aadLength && EVP_CipherUpdate(context, NULL, &count, aad, (int)aadLength) != 1) ||
        (!encrypt && EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, SNELL_TAG, data + length) != 1) ||
        EVP_CipherUpdate(context, data, &count, data, (int)length) != 1 ||
        EVP_CipherFinal_ex(context, data + count, &final) != 1 ||
        count + final != (int)length ||
        (encrypt && EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, SNELL_TAG, data + length) != 1))
        return failure(codec, encrypt ? EIO : EPROTO);
    for (size_t i = 0; i < sizeof direction->nonce; i++)
        if (++direction->nonce[i]) return 0;
    return failure(codec, EOVERFLOW);
}

static void swapV4(uint8_t *padding, size_t paddingLength, uint8_t *cipher, size_t cipherLength) {
    size_t limit = smaller(paddingLength, cipherLength);
    for (size_t i = 0; i < limit; i += 2) swapBytes(padding + i, cipher + i);
}

static int v4Padding(uint8_t *padding, size_t length, const uint8_t *cipher, size_t cipherLength) {
    unsigned ones = 0;
    for (size_t i = 0; i < (cipherLength & ~(size_t)3); i++)
        ones += (unsigned)__builtin_popcount(cipher[i]);
    unsigned zeros = (unsigned)(cipherLength * 8) - ones;
    if (!zeros || 2 * ones <= zeros || 5 * ones >= 8 * zeros) return randomBytes(padding, length);

    uint16_t jitter;
    if (randomBytes(&jitter, sizeof jitter) < 0) return -1;
    double ratio = (ones > zeros ? 0.4 : 1.6) + (double)jitter / 655360.0;
    size_t bits = length * 8;
    int target = (int)((double)((length + cipherLength) * 8) * ratio / (1.0 + ratio) - ones);
    if (target < 0 || (size_t)target > bits) return randomBytes(padding, length);

    uint16_t random[64];
    size_t index = sizeof random / sizeof *random;
    memset(padding, 0, length);
    for (size_t i = 0; i < bits && target; i++) {
        unsigned remaining = (unsigned)(bits - i);
        unsigned limit = 65536u - 65536u % remaining;
        unsigned value;
        do {
            if (index == sizeof random / sizeof *random) {
                if (randomBytes(random, sizeof random) < 0) return -1;
                index = 0;
            }
            value = random[index++];
        } while (value >= limit);
        if (value % remaining < (unsigned)target) {
            padding[i / 8] |= (uint8_t)(1u << (i % 8));
            target--;
        }
    }
    return 0;
}

static size_t packetLimit(const MLSnell *codec) {
    return codec->version == 6 ? SNELL_V6_MAX : SNELL_LEGACY_MAX;
}

static size_t streamLimit(MLSnell *codec) {
    if (codec->version == 4) {
        time_t now = time(NULL);
        size_t limit = codec->chunk;
        if (!codec->saltSent) limit = 1460 - 55 - codec->initialPadding;
        else if (!codec->lastWrite || difftime(now, codec->lastWrite) > 30) limit = 1460 - 39;
        codec->lastWrite = now;
        codec->chunk = smaller(limit + 1460 - 39, SNELL_LEGACY_MAX);
        return limit;
    }
    if (codec->mode == SnellProfiled) {
        time_t now = time(NULL);
        if (!codec->chunk || difftime(now, codec->lastWrite) > codec->profile.idle) codec->chunk = codec->profile.initial;
        size_t limit = profiledChunk(&codec->profile, codec->tx.sequence, codec->chunk);
        codec->lastWrite = now;
        codec->chunk = smaller(codec->chunk + codec->profile.step, codec->profile.maxChunk);
        return limit;
    }
    return packetLimit(codec);
}

static size_t headerSize(const MLSnell *codec) {
    return codec->version < 4 ? 2 : SNELL_HEADER;
}

static size_t prefixSize(const MLSnell *codec, const SnellDirection *direction) {
    return codec->mode == SnellProfiled ? profilePrefix(&codec->profile, direction->sequence) : 0;
}

static size_t saltSize(const MLSnell *codec) {
    return codec->mode == SnellProfiled ? codec->profile.saltLength : SNELL_SALT;
}

static void beginHeader(MLSnell *codec) {
    codec->rxPart = ReceiveHeader;
    codec->received = 0;
    codec->needed = prefixSize(codec, &codec->rx) + headerSize(codec) + (codec->mode == SnellRaw ? 0 : SNELL_TAG);
}

static int appendRecord(MLSnell *codec, const void *address, size_t addressLength, const void *data, size_t length) {
    size_t payload = addressLength + length;
    size_t prefix = prefixSize(codec, &codec->tx);
    size_t salt = !codec->saltSent && codec->mode != SnellRaw ? saltSize(codec) : 0;
    size_t pad = 0, tag = codec->mode == SnellRaw ? 0 : SNELL_TAG;
    if (codec->mode == SnellProfiled) pad = profilePadding(&codec->profile, codec->tx.sequence, payload, prefix, salt);
    else if (codec->version == 4 && salt && payload) pad = codec->initialPadding;
    size_t headerLength = headerSize(codec);
    size_t recordLength = salt + prefix + headerLength + tag + pad + payload + (payload ? tag : 0);
    if (reserve(&codec->output, &codec->outputCap, codec->outputLength + recordLength) < 0)
        return failure(codec, ENOMEM);
    uint8_t *record = codec->output + codec->outputLength;
    if (salt) {
        if (codec->mode == SnellProfiled) profilePutSalt(&codec->profile, codec->salt, record);
        else memcpy(record, codec->salt, salt);
    }
    record += salt;
    if (prefix) profileFill(&codec->profile, codec->tx.sequence, record, prefix);

    uint8_t *header = record + prefix;
    if (headerLength == 2) put16(header, payload);
    else {
        header[0] = 4;
        header[1] = header[2] = 0;
        put16(header + 3, pad);
        put16(header + 5, payload);
    }
    if (tag && cryptPart(codec, &codec->tx, header, headerLength, record, prefix, 1) < 0) return -1;
    uint8_t *padding = header + headerLength + tag;
    uint8_t *body = padding + pad;
    if (addressLength) memcpy(body, address, addressLength);
    if (length) memcpy(body + addressLength, data, length);
    if (codec->mode == SnellProfiled && pad) profileFill(&codec->profile, codec->tx.sequence, padding, pad);
    if (tag && payload) {
        size_t paddedAAD = codec->mode == SnellProfiled ? pad : 0;
        if (cryptPart(codec, &codec->tx, body, payload, padding, paddedAAD, 1) < 0) return -1;
        if (codec->mode == SnellProfiled) {
            profileMix(&codec->profile, codec->tx.sequence, padding, pad, body, payload + tag);
        } else if (pad) {
            if (v4Padding(padding, pad, body, payload + tag) < 0) return failure(codec, errno);
            swapV4(padding, pad, body, payload + tag);
        }
    }
    codec->tx.sequence++;
    codec->saltSent = 1;
    codec->outputLength += recordLength;
    return 0;
}

int MLSnellOptions(unsigned version, const char *mode, const char *psk, int udp) {
    size_t length = psk ? strlen(psk) : 0;
    if (!length || length > SNELL_PSK_MAX || version > 6 || (udp && version < 3)) return 0;
    if (version != 6) return !mode || !*mode;
    return length >= 12 && (!mode || !*mode || !strcmp(mode, "default") ||
                            !strcmp(mode, "unshaped") || !strcmp(mode, "unsafe-raw"));
}

static void setUDPAddress(MLSnell *codec, const char *host, size_t length, uint16_t port) {
    static const uint8_t mappedPrefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    uint8_t *address = codec->udpHeader;
    codec->udpPort = port;
    address[0] = 1;
    if (inet_pton(AF_INET, host, codec->udpIP) == 1) codec->udpIPLength = 4;
    else if (inet_pton(AF_INET6, host, codec->udpIP) == 1) {
        if (!memcmp(codec->udpIP, mappedPrefix, sizeof mappedPrefix)) {
            memmove(codec->udpIP, codec->udpIP + sizeof mappedPrefix, 4);
            codec->udpIPLength = 4;
        } else codec->udpIPLength = 16;
    }
    if (codec->udpIPLength) {
        address[1] = 0;
        address[2] = codec->udpIPLength == 4 ? 4 : 6;
        memcpy(address + 3, codec->udpIP, codec->udpIPLength);
        codec->udpHeaderLength = 3 + codec->udpIPLength + 2;
    } else {
        address[1] = (uint8_t)length;
        memcpy(address + 2, host, length);
        codec->udpHeaderLength = 2 + length + 2;
    }
    put16(address + codec->udpHeaderLength - 2, port);
}

MLSnell *MLSnellOpen(unsigned version, const char *mode, const char *psk,
                     const char *host, uint16_t port, int udp) {
    size_t hostLength = host ? strlen(host) : 0;
    if (!hostLength || hostLength > 255 || !port || !MLSnellOptions(version, mode, psk, udp)) {
        errno = EINVAL;
        return NULL;
    }
    MLSnell *codec = calloc(1, sizeof *codec);
    if (!codec) return NULL;
    codec->version = !version ? 1 : version == 5 ? 4 : version;
    codec->datagram = udp;
    if (version == 6) {
        if (mode && !strcmp(mode, "unsafe-raw")) codec->mode = SnellRaw;
        else if (!mode || strcmp(mode, "unshaped")) codec->mode = SnellProfiled;
    }
    if (codec->mode != SnellRaw) {
        codec->pskLength = strlen(psk);
        memcpy(codec->psk, psk, codec->pskLength);
        if (codec->mode == SnellProfiled && !profileInitialize(&codec->profile, codec->psk, codec->pskLength)) {
            errno = EIO;
            goto bad;
        }
        if (randomBytes(codec->salt, sizeof codec->salt) < 0 ||
            setupKey(codec, &codec->tx, codec->salt, 1) < 0) goto bad;
        codec->rxPart = ReceiveSalt;
        codec->needed = saltSize(codec);
    } else beginHeader(codec);
    if (codec->version == 4) {
        uint8_t variation;
        if (randomBytes(&variation, sizeof variation) < 0) goto bad;
        codec->initialPadding = 256 + variation;
    }
    uint8_t request[261] = {1, udp ? 6 : codec->version == 2 ? 5 : 1, 0};
    size_t length = 3;
    if (udp) setUDPAddress(codec, host, hostLength, port);
    else {
        request[3] = (uint8_t)hostLength;
        memcpy(request + 4, host, hostLength);
        put16(request + 4 + hostLength, port);
        length = 6 + hostLength;
    }
    for (size_t offset = 0; offset < length;) {
        size_t take = smaller(length - offset, streamLimit(codec));
        if (appendRecord(codec, NULL, 0, request + offset, take) < 0) goto bad;
        offset += take;
    }
    return codec;

bad: {
        int error = errno;
        MLSnellClose(codec);
        errno = error;
        return NULL;
    }
}

const uint8_t *MLSnellOutput(const MLSnell *codec, size_t *length) {
    *length = codec->outputLength - codec->outputOffset;
    return *length ? codec->output + codec->outputOffset : NULL;
}

void MLSnellConsumeOutput(MLSnell *codec, size_t length) {
    codec->outputOffset += smaller(length, codec->outputLength - codec->outputOffset);
    if (codec->outputOffset == codec->outputLength) codec->outputOffset = codec->outputLength = 0;
}

size_t MLSnellInputSize(const MLSnell *codec) {
    if (codec->ended || codec->error || codec->plainLength) return 0;
    return codec->needed - codec->received;
}

static int receiveSalt(MLSnell *codec) {
    uint8_t salt[SNELL_SALT];
    if (codec->mode == SnellProfiled) profileGetSalt(&codec->profile, codec->header, salt);
    else memcpy(salt, codec->header, sizeof salt);
    if (CRYPTO_memcmp(salt, codec->salt, sizeof salt) == 0) return failure(codec, EPROTO);
    if (setupKey(codec, &codec->rx, salt, 0) < 0) return -1;
    OPENSSL_cleanse(codec->psk, sizeof codec->psk);
    beginHeader(codec);
    return 0;
}

static int receiveEnd(MLSnell *codec) {
    if (codec->replyPart != ReplySuccess) return failure(codec, EPROTO);
    codec->ended = 1;
    return 0;
}

static int receiveHeader(MLSnell *codec) {
    size_t prefix = prefixSize(codec, &codec->rx);
    uint8_t *header = codec->header + prefix;
    size_t tag = codec->mode == SnellRaw ? 0 : SNELL_TAG;
    if (tag && cryptPart(codec, &codec->rx, header, headerSize(codec), codec->header, prefix, 0) < 0)
        return -1;
    codec->padding = 0;
    if (codec->version < 4) codec->payload = get16(header) & SNELL_LEGACY_MAX;
    else {
        int strict = codec->version == 6 && codec->mode != SnellProfiled;
        if (header[0] != 4 || (strict && (header[1] || header[2]))) return failure(codec, EPROTO);
        codec->padding = get16(header + 3);
        codec->payload = get16(header + 5);
        if ((strict && codec->padding) ||
            (codec->version == 4 && (codec->padding > SNELL_LEGACY_MAX || codec->payload > SNELL_LEGACY_MAX ||
                                    (!codec->payload && codec->padding)))) return failure(codec, EPROTO);
    }
    codec->needed = codec->padding + codec->payload + (codec->payload ? tag : 0);
    codec->received = 0;
    if (!codec->needed) return receiveEnd(codec);
    if (reserve(&codec->input, &codec->inputCap, codec->needed) < 0) return failure(codec, ENOMEM);
    codec->rxPart = ReceiveBody;
    return 0;
}

static int readReply(MLSnell *codec, const uint8_t *data, size_t length, size_t *offset) {
    while (*offset < length && codec->replyPart != ReplySuccess) {
        uint8_t value = data[(*offset)++];
        switch (codec->replyPart) {
            case ReplyCommand:
                if (value == 0) codec->replyPart = ReplySuccess;
                else if (value == 2) codec->replyPart = ReplyCode;
                else return failure(codec, EPROTO);
                break;
            case ReplyCode:
                codec->replyPart = ReplyLength;
                break;
            case ReplyLength:
                if (!value) return failure(codec, ECONNREFUSED);
                codec->replyRemaining = value;
                codec->replyPart = ReplyMessage;
                break;
            case ReplyMessage:
                if (!--codec->replyRemaining) return failure(codec, ECONNREFUSED);
                break;
            case ReplySuccess:
                break;
        }
    }
    return 0;
}

static int receiveBody(MLSnell *codec) {
    if (!codec->payload) return receiveEnd(codec);
    uint8_t *body = codec->input + codec->padding;
    if (codec->mode != SnellRaw) {
        size_t size = codec->payload + SNELL_TAG;
        size_t aad = 0;
        if (codec->mode == SnellProfiled) {
            profileMix(&codec->profile, codec->rx.sequence, codec->input, codec->padding, body, size);
            aad = codec->padding;
        } else if (codec->padding) swapV4(codec->input, codec->padding, body, size);
        if (cryptPart(codec, &codec->rx, body, codec->payload, codec->input, aad, 0) < 0)
            return -1;
    }
    codec->rx.sequence++;
    size_t offset = 0;
    if (readReply(codec, body, codec->payload, &offset) < 0) return -1;
    size_t length = codec->payload - offset;
    if (codec->datagram && length) {
        uint8_t kind = body[offset];
        size_t ipLength = kind == 4 ? 4 : kind == 6 ? 16 : 0;
        if (!ipLength || length <= ipLength + 3) return failure(codec, EPROTO);
        const uint8_t *ip = body + offset + 1;
        unsigned port = get16(ip + ipLength);
        if (port != codec->udpPort ||
            (codec->udpIPLength && (codec->udpIPLength != ipLength || memcmp(codec->udpIP, ip, ipLength)))) {
            length = 0; /* Connected UDP only delivers data from the selected peer. */
        } else {
            offset += ipLength + 3;
            length -= ipLength + 3;
        }
    }
    codec->plainOffset = codec->padding + offset;
    codec->plainLength = length;
    beginHeader(codec);
    return 0;
}

int MLSnellFeed(MLSnell *codec, const void *wire, size_t length) {
    if (codec->error) return failure(codec, codec->error);
    if (!length) return 0;
    if (length > MLSnellInputSize(codec) || !wire) { errno = EINVAL; return -1; }
    uint8_t *buffer = codec->rxPart == ReceiveBody ? codec->input : codec->header;
    memcpy(buffer + codec->received, wire, length);
    codec->received += length;
    if (codec->received < codec->needed) return 0;
    if (codec->rxPart == ReceiveSalt) return receiveSalt(codec);
    if (codec->rxPart == ReceiveHeader) return receiveHeader(codec);
    return receiveBody(codec);
}

int MLSnellFinishRead(MLSnell *codec) {
    if (codec->error) return failure(codec, codec->error);
    if (codec->ended) return 0;
    if (codec->rxPart != ReceiveHeader || codec->received) return failure(codec, EPROTO);
    return receiveEnd(codec);
}

int MLSnellPendingRead(const MLSnell *codec) { return codec->plainLength != 0; }

int MLSnellReady(const MLSnell *codec) { return codec->replyPart == ReplySuccess && !codec->error; }

ssize_t MLSnellRead(MLSnell *codec, void *data, size_t length) {
    if (codec->error) return failure(codec, codec->error);
    if (!length) return 0;
    if (!codec->plainLength) {
        if (codec->ended) return 0;
        errno = EAGAIN;
        return -1;
    }
    if (codec->datagram && length < codec->plainLength) {
        codec->plainLength = 0;
        errno = EMSGSIZE;
        return -1;
    }
    size_t take = smaller(length, codec->plainLength);
    memcpy(data, codec->input + codec->plainOffset, take);
    codec->plainOffset += take;
    codec->plainLength -= take;
    return (ssize_t)take;
}

ssize_t MLSnellWrite(MLSnell *codec, const void *data, size_t length) {
    if (codec->error) return failure(codec, codec->error);
    if (codec->closing) { errno = EPIPE; return -1; }
    if (!length) return 0;
    if (codec->outputLength) { errno = EAGAIN; return -1; }
    if (codec->datagram && length > SNELL_LEGACY_MAX - codec->udpHeaderLength) {
        errno = EMSGSIZE;
        return -1;
    }
    size_t limit = streamLimit(codec);
    size_t take = codec->datagram ? length : smaller(length, limit);
    if (appendRecord(codec, codec->udpHeader, codec->udpHeaderLength, data, take) < 0) return -1;
    return (ssize_t)take;
}

int MLSnellShutdown(MLSnell *codec) {
    if (codec->error) return failure(codec, codec->error);
    if (codec->closing) return 0;
    if (codec->outputLength) { errno = EAGAIN; return -1; }
    if (codec->version == 2 && appendRecord(codec, NULL, 0, NULL, 0) < 0) return -1;
    codec->closing = 1;
    return 0;
}

void MLSnellClose(MLSnell *codec) {
    if (!codec) return;
    EVP_CIPHER_CTX_free(codec->rx.context);
    EVP_CIPHER_CTX_free(codec->tx.context);
    if (codec->input) OPENSSL_cleanse(codec->input, codec->inputCap);
    if (codec->output) OPENSSL_cleanse(codec->output, codec->outputCap);
    free(codec->input);
    free(codec->output);
    OPENSSL_cleanse(codec, sizeof *codec);
    free(codec);
}
