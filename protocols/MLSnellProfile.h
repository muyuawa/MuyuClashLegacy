#ifndef ML_SNELL_PROFILE_H
#define ML_SNELL_PROFILE_H

/* Snell v6 profile constants and shaping rules follow Mihomo's
 * transport/snell/v6_profile.go at 0455d0d28c4526937380505153e65a843d8612e8
 * (GPL-3.0), which credits SagerNet/sing-snell's protocol notes. */

#define SNELL_PREFIX_MAX 128
#define PROFILE_PADDING_SPAN 0x2da
#define GOLDEN_GAMMA UINT64_C(0x9e3779b97f4a7c15)
#define DOMAIN_MULTIPLIER UINT64_C(0xd6e8feb86659fd93)
#define COEFFICIENT_A UINT64_C(0xe7037ed1a0b428db)
#define COEFFICIENT_B UINT64_C(0x589965cc75374cc3)
#define ADDEND_A UINT64_C(0x8f3907f7b2b80c35)
#define ADDEND_B UINT64_C(0x33a213ec50ffe2e9)

enum ProfileLabel {
    Padding, BitPercent, Motif, MixOffset, ProfileID = 5, Generator,
    PadMin, PadMax, PadCount, PadInterval, SmallLimit, BitMin, BitMax,
    PrefixMin, PrefixMax, MixMode, MixRounds, MixStride, MixOffsetBase,
    MixBlock, ChunkPolicy, ChunkInitial, ChunkMax, ChunkStep, ChunkJitter,
    ChunkBucket, IdleReset, WritePolicy, WriteFirst, WriteBucket, WriteSeq,
    WriteJitter, RecordPrefix, PayloadPad, WriteTarget, WriteJitterValue,
    WriteNext, ChunkSize, ChunkJitterValue
};

enum ProfileNamespace {
    ProfileValues, PrefixValues, MotifValues, SaltValues, MixValues, ChunkValues, WriteValues, NamespaceCount
};

typedef struct {
    uint64_t namespaces[NamespaceCount];
    unsigned generator, padMin, padMax, padCount, padInterval, smallLimit, bitMin, bitMax;
    unsigned prefixMin, prefixMax, mixMode, mixRounds, mixStride, mixOffset, mixBlock;
    unsigned chunkPolicy, initial, firstCap, maxChunk, step, chunkJitter, idle;
    unsigned writePolicy, writeFirst, writeJitter, writeJitterPercent;
    unsigned chunkBuckets[8], writeBuckets[8], writeSequence[8], generatorOptions[6];
    unsigned saltLength, saltRounds, saltStride;
    uint8_t saltPositions[SNELL_SALT], saltMask[SNELL_SALT];
} SnellProfile;

static uint64_t splitMix(uint64_t value) {
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static uint32_t fold(uint64_t value) {
    uint64_t mixed = splitMix(value);
    return (uint32_t)(mixed ^ (mixed >> 32));
}

static uint32_t profilePRF(const SnellProfile *profile, enum ProfileLabel label, uint32_t a, uint32_t b) {
    enum ProfileNamespace index = ProfileValues;
    switch (label) {
    case Padding: case BitPercent: case PrefixMin: case PrefixMax: case RecordPrefix: case PayloadPad:
        index = PrefixValues; break;
    case Motif:
        index = MotifValues; break;
    case MixOffset: case MixMode: case MixRounds: case MixStride: case MixOffsetBase: case MixBlock:
        index = MixValues; break;
    case ChunkPolicy: case ChunkInitial: case ChunkMax: case ChunkStep: case ChunkJitter:
    case ChunkBucket: case ChunkSize: case ChunkJitterValue:
        index = ChunkValues; break;
    case WritePolicy: case WriteFirst: case WriteBucket: case WriteSeq: case WriteJitter:
    case WriteTarget: case WriteJitterValue: case WriteNext:
        index = WriteValues; break;
    default: break;
    }
    return fold(profile->namespaces[index] ^ (GOLDEN_GAMMA * label) ^
                (COEFFICIENT_A * a + ADDEND_A) ^ (COEFFICIENT_B * b + ADDEND_B));
}

static unsigned pick(uint32_t value, unsigned lower, unsigned upper) {
    return lower + value % (upper - lower + 1);
}

static unsigned staticPick(const SnellProfile *profile, enum ProfileLabel label, unsigned domain,
                           unsigned lower, unsigned upper) {
    return pick(profilePRF(profile, label, 0, domain), lower, upper);
}

static uint64_t little64(const uint8_t *bytes) {
    uint64_t number = 0;
    for (unsigned i = 0; i < 8; i++) number |= (uint64_t)bytes[i] << (8 * i);
    return number;
}

static uint64_t rotate64(uint64_t value, unsigned bits) {
    return value << bits | value >> (64 - bits);
}

static int profileNamespaces(SnellProfile *profile, const uint8_t *psk, size_t length) {
    static const uint8_t seed[] = {
        0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94,
        0x33, 0x18, 0xc0, 0x6e, 0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac
    };
    static const struct { unsigned label; uint64_t seed; } domains[NamespaceCount] = {
        {ProfileID, UINT64_C(0xb46c2e7d9a1538f1)}, {Padding, UINT64_C(0x5d9217c083e64ab9)},
        {Motif, UINT64_C(0xa71f0c54d8396e2b)}, {3, UINT64_C(0x3e8a91b52740f6cd)},
        {MixMode, UINT64_C(0xc9f4260b7d1e835a)}, {ChunkPolicy, UINT64_C(0x62d0b5e19c4a783f)},
        {WritePolicy, UINT64_C(0x917b3c48e6a205d4)}
    };
    uint8_t digest[EVP_MAX_MD_SIZE];
    size_t digestSize = 32;
    unsigned received = 0;
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &digestSize),
        OSSL_PARAM_construct_end()
    };
    EVP_MD *algorithm = EVP_MD_fetch(NULL, "BLAKE2B-512", NULL);
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int ok = algorithm && context && EVP_DigestInit_ex2(context, algorithm, parameters) == 1 &&
        EVP_DigestUpdate(context, seed, sizeof seed) == 1 && EVP_DigestUpdate(context, psk, length) == 1 &&
        EVP_DigestFinal_ex(context, digest, &received) == 1 && received == digestSize;
    EVP_MD_CTX_free(context);
    EVP_MD_free(algorithm);
    if (ok) {
        uint64_t common = little64(digest) ^ (little64(digest + 8) + GOLDEN_GAMMA) ^
                          rotate64(little64(digest + 16), 17) ^ rotate64(little64(digest + 24), 53);
        for (unsigned i = 0; i < NamespaceCount; i++) {
            profile->namespaces[i] = splitMix(common ^ (domains[i].label * DOMAIN_MULTIPLIER) ^
                                              (domains[i].seed + UINT64_C(0xa0761d6478bd642f)));
        }
    }
    OPENSSL_cleanse(digest, sizeof digest);
    return ok;
}

static void profileSaltPositions(SnellProfile *profile) {
    uint8_t permutation[SNELL_SALT_BLOCK_MAX];
    unsigned length = profile->saltLength;
    uint64_t saltNamespace = profile->namespaces[SaltValues];
    for (unsigned i = 0; i < length; i++) permutation[i] = (uint8_t)i;
    for (unsigned round = 0; round < profile->saltRounds; round++) {
        uint64_t domain = (COEFFICIENT_A * (0x51a7 + round) + ADDEND_A) ^
                          saltNamespace ^ UINT64_C(0xdaa66d2c7ddf743f);
        for (unsigned i = 0; i < length; i++) {
            unsigned j = i + fold(domain ^ (COEFFICIENT_B * i + ADDEND_B)) % (length - i);
            swapBytes(permutation + i, permutation + j);
        }
    }
    for (unsigned i = 0; i < SNELL_SALT; i++) {
        profile->saltPositions[i] = permutation[i];
        uint32_t value = fold(saltNamespace ^ (COEFFICIENT_A * 0x51a7 + ADDEND_A) ^
                              (GOLDEN_GAMMA * Motif) ^ (COEFFICIENT_B * i + ADDEND_B));
        profile->saltMask[i] = (uint8_t)((i * profile->saltStride) ^ value);
    }
}

static int profileInitialize(SnellProfile *p, const uint8_t *psk, size_t length) {
    if (!profileNamespaces(p, psk, length)) return 0;

    p->generator = profilePRF(p, Generator, 0, 0) & 3;
    p->padMin = staticPick(p, PadMin, 0, 0x18, 0xa0);
    p->padMax = (unsigned)smaller(p->padMin + staticPick(p, PadMax, 0, 0xa0, 0x3c0), PROFILE_PADDING_SPAN);
    p->padCount = staticPick(p, PadCount, 0, 2, 8);
    p->padInterval = staticPick(p, PadInterval, 0, 2, 11);
    p->smallLimit = staticPick(p, SmallLimit, 0, 0x60, 0x300);
    p->bitMin = staticPick(p, BitMin, 0, 0x18, 0x29);
    p->bitMax = staticPick(p, BitMax, 0, 0x3a, 0x4c);
    p->prefixMin = staticPick(p, PrefixMin, 0, 0x08, 0x50);
    p->prefixMax = (unsigned)smaller(p->prefixMin + staticPick(p, PrefixMax, 0, 0x10, 0xa0), SNELL_PREFIX_MAX);
    p->mixMode = profilePRF(p, MixMode, 0, 0) % 3;
    p->mixRounds = staticPick(p, MixRounds, 0, 1, 3);
    p->mixStride = staticPick(p, MixStride, 0, 2, 13);
    p->mixOffset = staticPick(p, MixOffsetBase, 0, 0, 15);
    p->mixBlock = staticPick(p, MixBlock, 0, 8, 0x40);
    p->chunkPolicy = profilePRF(p, ChunkPolicy, 0, 0) % 3;
    p->initial = staticPick(p, ChunkInitial, 0, 0x200, 0x5b4);
    p->firstCap = (unsigned)smaller(p->initial, staticPick(p, ChunkInitial, 0xf17c, 0x100, 0x300));
    p->maxChunk = staticPick(p, ChunkMax, 0, 0x2000, 0x3fff);
    p->step = (unsigned)smaller(staticPick(p, ChunkStep, 0, 0x400, 0x1000), 0xb68);
    p->chunkJitter = (unsigned)smaller(staticPick(p, ChunkJitter, 0, 0x10, 0xc0), 0xb6);
    p->idle = staticPick(p, IdleReset, 0, 0x0c, 0x5a);
    p->writePolicy = profilePRF(p, WritePolicy, 0, 0) % 3;
    p->writeFirst = staticPick(p, WriteFirst, 0, 4, 8);
    p->writeJitter = staticPick(p, WriteJitter, 0, 8, 0x60);
    p->writeJitterPercent = staticPick(p, WritePolicy, 0x504c, 8, 0x30);
    static const unsigned generatorBounds[6][2] = {{0x18, 0x80}, {0x10, 0x60}, {0x10, 0x60},
                                                   {0, 9}, {1, 8}, {7, 0x17}};
    for (unsigned i = 0; i < 6; i++)
        p->generatorOptions[i] = staticPick(p, Generator, i + 1, generatorBounds[i][0], generatorBounds[i][1]);
    for (unsigned i = 0; i < 8; i++) {
        p->chunkBuckets[i] = staticPick(p, ChunkBucket, i, 0x1000, p->maxChunk);
        p->writeBuckets[i] = staticPick(p, WriteBucket, i, 0x140, 0x5b4);
        p->writeSequence[i] = staticPick(p, WriteSeq, i, 0x168, 0x5b4);
    }

    unsigned saltMin = staticPick(p, PrefixMin, 0x7053, 0x10, 0x60);
    unsigned saltMax = (unsigned)smaller(saltMin + staticPick(p, PrefixMax, 0x7053, 0x10, 0xa0), SNELL_PREFIX_MAX);
    p->saltLength = SNELL_SALT + staticPick(p, RecordPrefix, 0x7053, saltMin, saltMax);
    p->saltRounds = staticPick(p, MixRounds, 0x51a7, 1, 4);
    p->saltStride = staticPick(p, MixStride, 0x51a7, 0x11, 0xfb);
    profileSaltPositions(p);
    return 1;
}

static unsigned profilePrefix(const SnellProfile *p, uint32_t seq) {
    return pick(profilePRF(p, RecordPrefix, seq, 0), p->prefixMin, p->prefixMax);
}

static int signedJitter(uint32_t raw, unsigned span) {
    return (int)(raw % (2 * span + 1)) - (int)span;
}

static unsigned profiledChunk(const SnellProfile *p, uint32_t seq, unsigned chunk) {
    int limit = (int)chunk;
    if (p->chunkPolicy == 1) limit = (int)p->chunkBuckets[profilePRF(p, ChunkSize, seq, chunk) % 8];
    if (p->chunkPolicy == 2) limit += signedJitter(profilePRF(p, ChunkJitterValue, seq, chunk), p->chunkJitter);
    unsigned bounded = (unsigned)smaller(limit < 0x40 ? 0x40 : (unsigned)limit, p->maxChunk);
    return seq ? bounded : (unsigned)smaller(bounded, p->firstCap);
}

static size_t profileTarget(const SnellProfile *p, uint32_t seq, size_t frame) {
    if (frame > 0x5b3) return smaller(frame, SNELL_V6_MAX);
    size_t target = seq < p->writeFirst ? p->writeSequence[seq] :
                   p->writeBuckets[profilePRF(p, WriteTarget, seq, (uint32_t)frame) % 8];
    if (p->writePolicy == 2) {
        int adjusted = (int)target + signedJitter(profilePRF(p, WriteJitterValue, seq, 0), p->writeJitter);
        target = adjusted > 0 ? (size_t)adjusted : 1;
    }
    size_t spread = smaller(PROFILE_PADDING_SPAN, frame * p->writeJitterPercent / 100);
    if (!(profilePRF(p, WriteTarget, seq, (uint32_t)spread) & 1)) target = smaller(target + spread, SNELL_V6_MAX);
    else if (target > spread / 2) target -= spread / 2;
    while (target < frame) {
        size_t next = p->writeBuckets[profilePRF(p, WriteNext, seq, (uint32_t)target) % 8];
        target = next > target ? next : smaller(target + p->padMax, SNELL_V6_MAX);
    }
    return target;
}

static size_t profilePadding(const SnellProfile *p, uint32_t seq, size_t payload, size_t prefix, size_t salt) {
    size_t padding = 0;
    if (seq < p->padCount || (payload && payload <= p->smallLimit) || seq % p->padInterval == 0)
        padding = pick(profilePRF(p, PayloadPad, seq, (uint32_t)payload), p->padMin, p->padMax);
    size_t frame = salt + prefix + SNELL_HEADER + SNELL_TAG + padding + payload + (payload ? SNELL_TAG : 0);
    size_t target = profileTarget(p, seq, frame);
    if (target > frame) padding += smaller(target - frame, PROFILE_PADDING_SPAN);
    if (salt) {
        size_t threshold = ((payload + (payload ? 0x37 : 0x27)) * 25 + 0x4a) / 75;
        if (threshold < 0xc0) threshold = 0xc0;
        size_t overhead = salt - SNELL_SALT + prefix;
        if (overhead + padding < threshold)
            padding = smaller(threshold - overhead, p->padMax + PROFILE_PADDING_SPAN);
    }
    return padding;
}

static void profileBytes(const SnellProfile *p, enum ProfileLabel label, uint32_t seq,
                         uint8_t *out, size_t length) {
    uint64_t domain = p->namespaces[label == Motif ? MotifValues : PrefixValues];
    uint64_t seed = domain ^ (DOMAIN_MULTIPLIER * seq + UINT64_C(0xb57de1f3f82cb33f)) ^
                    (UINT64_C(0xa24baed4963ee407) * label) ^
                    (UINT64_C(0x165667b19e3779f9) * length + UINT64_C(0x0d4cd3e7b14a36d7));
    for (size_t offset = 0; offset < length;) {
        seed += GOLDEN_GAMMA;
        uint64_t value = splitMix(seed);
        for (unsigned i = 0; i < 8 && offset < length; i++, offset++) {
            out[offset] = (uint8_t)value;
            value >>= 8;
        }
    }
}

static uint8_t rotate8(uint8_t value, unsigned shift) {
    return (uint8_t)((unsigned)value << shift | (unsigned)value >> (8 - shift));
}

static void profileFill(const SnellProfile *p, uint32_t seq, uint8_t *out, size_t length) {
    static const uint8_t bitTable[8][16] = {
        {0},
        {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80},
        {0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18, 0x24},
        {0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70, 0xe0},
        {0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78, 0xf0},
        {0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f, 0x1f},
        {0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7, 0xdb},
        {0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f}
    };
    unsigned g1 = p->generatorOptions[0], g2 = p->generatorOptions[1], g3 = p->generatorOptions[2];
    unsigned digits = p->generatorOptions[3], motifScale = p->generatorOptions[4], period = p->generatorOptions[5];
    profileBytes(p, Padding, seq, out, length);
    switch (p->generator) {
    case 0: {
        unsigned bitCount = pick(profilePRF(p, BitPercent, seq, 0), p->bitMin, p->bitMax) * 8;
        unsigned row = bitCount <= 49 ? 1 : bitCount <= 0x2ed ? (bitCount + 50) / 100 : 7;
        for (size_t i = 0; i < length; i++) {
            uint8_t original = out[i], raw = (uint8_t)(original + i);
            out[i] = rotate8(bitTable[row][(raw ^ original) & 15], (raw ^ (original >> 4)) & 7);
        }
        break;
    }
    case 1:
        for (size_t i = 0; i < length; i++) {
            uint8_t original = out[i];
            unsigned bucket = original % (g1 + g2 + g3);
            if (bucket < g1) out[i] = (uint8_t)pick((uint8_t)(original + i), 0x20, 0x7e);
            else if (bucket < g1 + g2) out[i] = (uint8_t)pick((uint8_t)(original ^ i), 0x80, 0xbf);
            else out[i] = (uint8_t)pick((uint8_t)(original + i * 7), 0xc0, 0xff);
        }
        break;
    case 2:
        for (size_t i = 0; i < length; i++)
            out[i] = (uint8_t)(((out[i] + ((i & 3) << 4) + 0x30) & 0xf0) |
                               (((out[i] & 15) + digits + (i & 1)) % 10));
        break;
    case 3: {
        uint8_t motif[32];
        profileBytes(p, Motif, seq, motif, sizeof motif);
        for (size_t i = 0; i < length; i++) {
            unsigned offset = (unsigned)(i % period);
            if (offset < period - 3) out[i] = (uint8_t)((motifScale + 3) * i) ^ motif[i % (motifScale * 4)];
            else if (offset < period - 1) out[i] = (uint8_t)(0x30 | (out[i] % 10));
        }
        break;
    }
    }
}

static void profilePutSalt(const SnellProfile *p, const uint8_t *salt, uint8_t *block) {
    profileFill(p, UINT32_MAX, block, p->saltLength);
    for (unsigned i = 0; i < SNELL_SALT; i++) block[p->saltPositions[i]] = p->saltMask[i] ^ salt[i];
}

static void profileGetSalt(const SnellProfile *p, const uint8_t *block, uint8_t *salt) {
    for (unsigned i = 0; i < SNELL_SALT; i++) salt[i] = p->saltMask[i] ^ block[p->saltPositions[i]];
}

static void profileMix(const SnellProfile *p, uint32_t seq, uint8_t *padding, size_t padLength,
                       uint8_t *payload, size_t cipherLength) {
    size_t limit = smaller(padLength, cipherLength);
    for (unsigned round = 0; round < p->mixRounds; round++) {
        if (p->mixMode == 1) {
            size_t block = p->mixBlock;
            for (size_t offset = (round & 1) * block; offset + block <= limit; offset += 2 * block)
                for (size_t i = offset; i < offset + block; i++) swapBytes(padding + i, payload + i);
        } else {
            unsigned stride = p->mixStride + round % 3;
            uint64_t base = p->mixOffset;
            if (p->mixMode == 2) base += profilePRF(p, MixOffset, seq, round);
            for (size_t i = (size_t)(base % stride); i < limit; i += stride) swapBytes(padding + i, payload + i);
        }
    }
}

#endif
