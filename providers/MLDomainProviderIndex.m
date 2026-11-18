#import "MLDomainProviderFormat.h"
#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

const NSUInteger MLDomainProviderSourceLimit = 8 * 1024 * 1024;
const NSUInteger MLDomainProviderIndexLimit = 16 * 1024 * 1024;
const NSUInteger MLDomainProviderPatternLimit = 250000;

id MLDPError(NSError **error, NSString *reason) {
    if (error) *error = [NSError errorWithDomain:@"E_DOMAIN_PROVIDER" code:1
                                      userInfo:@{NSLocalizedDescriptionKey:reason}];
    return nil;
}

int MLDPCompare(const uint8_t *left, size_t leftLength, const uint8_t *right, size_t rightLength) {
    int order = memcmp(left, right, MIN(leftLength, rightLength));
    if (order) return order;
    return leftLength < rightLength ? -1 : leftLength > rightLength;
}

size_t MLDPNormalize(const uint8_t *bytes, size_t length, BOOL allowWildcard, uint8_t key[MLDP_NAME_LIMIT],
                     uint8_t *anchor, uint8_t *labels) {
    if (!length || length > MLDP_NAME_LIMIT || memchr(bytes, 0, length)) return 0;
    if (bytes[length - 1] == '.') --length;
    if (!length) return 0;
    BOOL nonASCII = NO;
    for (size_t i = 0; i < length && !nonASCII; ++i) nonASCII = bytes[i] >= 128;
    uint8_t unicode[MLDP_NAME_LIMIT + 1];
    if (nonASCII) @autoreleasepool {
        NSString *text = [[NSString alloc] initWithBytes:bytes length:length encoding:NSUTF8StringEncoding];
        if (!text || [text rangeOfCharacterFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].location != NSNotFound ||
            [text rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location != NSNotFound ||
            ![text.lowercaseString getCString:(char *)unicode maxLength:sizeof unicode encoding:NSUTF8StringEncoding]) return 0;
        bytes = unicode;
        length = strlen((char *)unicode);
    }
    *anchor = 0;
    *labels = 1;
    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = bytes[i];
        if (byte >= 'A' && byte <= 'Z') byte += 'a' - 'A';
        if (byte == '.') {
            if (!i || i == length - 1 || bytes[i - 1] == '.') return 0;
            ++*labels;
        } else if (byte == '*' && allowWildcard) {
            *anchor = (uint8_t)(i + 1);
        } else if (byte < 128 && !(byte >= 'a' && byte <= 'z') && !(byte >= '0' && byte <= '9') && byte != '-' && byte != '_') {
            return 0;
        }
        key[i] = byte;
    }
    return length;
}

static BOOL safePath(NSString *path) {
    if (![path isKindOfClass:[NSString class]] || !path.isAbsolutePath || path.length > 4096 ||
        [path.pathComponents containsObject:@".."] ||
        [path rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location != NSNotFound) return NO;
    NSString *current = @"/";
    for (NSString *component in path.stringByDeletingLastPathComponent.pathComponents) {
        if ([component isEqual:@"/"]) continue;
        current = [current stringByAppendingPathComponent:component];
        struct stat status;
        if (lstat(current.fileSystemRepresentation, &status) || !S_ISDIR(status.st_mode)) return NO;
    }
    return YES;
}

static BOOL boundedInteger(id value, uint64_t maximum) {
    if (![value isKindOfClass:[NSNumber class]] || CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID()) return NO;
    double number = [value doubleValue];
    return number >= 0 && number <= maximum && number == [value unsignedLongLongValue];
}

static BOOL validHash(const uint8_t *mapping, NSUInteger size, NSString *expected) {
    const char *text = expected.UTF8String;
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    const char *digits = "0123456789abcdef";
    CC_SHA256(mapping, (CC_LONG)size, digest);
    for (size_t i = 0; i < sizeof digest; ++i)
        if (text[2*i] != digits[digest[i] >> 4] || text[2*i+1] != digits[digest[i] & 15]) return NO;
    return YES;
}

static int compareKeys(const uint8_t *left, const uint8_t *right) {
    int compared = MLDPCompare(left + MLDP_RECORD_SIZE + left[2], left[1] - left[2],
                               right + MLDP_RECORD_SIZE + right[2], right[1] - right[2]);
    if (compared) return compared;
    return MLDPCompare(left + MLDP_RECORD_SIZE, left[1], right + MLDP_RECORD_SIZE, right[1]);
}

static BOOL validateIndex(const uint8_t *bytes, NSUInteger length) {
    if (memcmp(bytes, MLDP_MAGIC, 8)) return NO;
    uint32_t literalCount = MLDPRead32(bytes + 8), wildcardCount = MLDPRead32(bytes + 12), inputCount = MLDPRead32(bytes + 16);
    if (inputCount > MLDomainProviderPatternLimit || literalCount > inputCount || wildcardCount > inputCount - literalCount) return NO;
    uint32_t records = literalCount + wildcardCount;
    size_t offset = MLDP_HEADER_SIZE + 4 * records;
    if (offset > length || (records == 0 && inputCount)) return NO;
    const uint8_t *previous = NULL;
    for (uint32_t i = 0; i < records; i++) {
        if (length - offset < MLDP_RECORD_SIZE || offset != MLDPRead32(bytes + MLDP_HEADER_SIZE + 4 * i)) return NO;
        const uint8_t *record = bytes + offset;
        size_t keyLength = record[1];
        if (!record[0] || record[0] > (MLDP_APEX | MLDP_DESCENDANT) || keyLength > length - offset - MLDP_RECORD_SIZE) return NO;
        uint8_t key[MLDP_NAME_LIMIT], anchor, labels;
        if (MLDPNormalize(record + MLDP_RECORD_SIZE, keyLength, YES, key, &anchor, &labels) != keyLength ||
            !keyLength || anchor != record[2] || labels != record[3] || (anchor != 0) != (i >= literalCount) ||
            memcmp(key, record + MLDP_RECORD_SIZE, keyLength)) return NO;
        if (previous && i != literalCount && compareKeys(previous, record) >= 0) return NO;
        previous = record;
        offset += MLDP_RECORD_SIZE + keyLength;
    }
    return offset == length;
}

static const uint8_t *recordAt(const uint8_t *bytes, uint32_t index) {
    return bytes + MLDPRead32(bytes + MLDP_HEADER_SIZE + 4 * index);
}

static int compareAnchor(const uint8_t *record, const uint8_t *key, size_t length) {
    return MLDPCompare(record + MLDP_RECORD_SIZE + record[2], record[1] - record[2], key, length);
}

static uint32_t lowerBound(const uint8_t *bytes, uint32_t low, uint32_t high, const uint8_t *key, size_t length) {
    while (low < high) {
        uint32_t middle = low + (high - low) / 2;
        if (compareAnchor(recordAt(bytes, middle), key, length) < 0) low = middle + 1;
        else high = middle;
    }
    return low;
}

static BOOL wildcardMatches(const uint8_t *pattern, size_t length, const uint8_t *host, size_t hostLength) {
    const uint8_t *patternEnd = pattern + length, *hostEnd = host + hostLength;
    const uint8_t *star = NULL, *retry = NULL;
    while (host < hostEnd) {
        if (pattern < patternEnd && *pattern == '*') {
            star = pattern++;
            retry = host;
        } else if (pattern < patternEnd && *pattern == *host) {
            if (*host == '.') star = NULL;
            ++pattern;
            ++host;
        } else {
            if (!star || retry == hostEnd || *retry == '.') return NO;
            pattern = star + 1;
            host = ++retry;
        }
    }
    while (pattern < patternEnd && *pattern == '*') ++pattern;
    return pattern == patternEnd;
}

@implementation MLDomainProviderIndex {
    const uint8_t *_mapping;
    NSUInteger _length;
}

- (void)dealloc {
    if (_mapping) munmap((void *)_mapping, _length);
}

+ (instancetype)indexWithDescriptor:(NSDictionary *)descriptor error:(NSError **)error {
    if (error) *error = nil;
    if (![descriptor isKindOfClass:[NSDictionary class]]) return MLDPError(error,@"A domain Provider index descriptor must be a mapping.");
    NSString *path = descriptor[@"path"], *sha = descriptor[@"sha256"];
    NSNumber *owner = descriptor[@"owner"], *size = descriptor[@"size"];
    if (!safePath(path) || ![sha isKindOfClass:[NSString class]] || sha.length != 64 ||
        [sha rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet]].location != NSNotFound ||
        !boundedInteger(owner, UINT32_MAX) || !boundedInteger(size, MLDomainProviderIndexLimit) || size.unsignedLongLongValue < MLDP_HEADER_SIZE)
        return MLDPError(error,@"The domain Provider index descriptor is invalid.");

    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    struct stat status, current;
    BOOL valid = fd >= 0 && fstat(fd, &status) == 0 && S_ISREG(status.st_mode) && status.st_nlink == 1 &&
        status.st_uid == (uid_t)owner.unsignedLongLongValue && (status.st_mode & 07777) == 0444 &&
        status.st_size == (off_t)size.unsignedLongLongValue && lstat(path.fileSystemRepresentation, &current) == 0 &&
        current.st_dev == status.st_dev && current.st_ino == status.st_ino;
    if (!valid) {
        if (fd >= 0) close(fd);
        return MLDPError(error,@"A domain Provider index must be an owned, immutable, bounded regular file.");
    }
    NSUInteger length = (NSUInteger)status.st_size;
    void *mapping = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapping == MAP_FAILED) return MLDPError(error,@"The domain Provider index could not be mapped.");
    if (!validHash(mapping, length, sha) || !validateIndex(mapping, length)) {
        munmap(mapping, length);
        return MLDPError(error,@"The domain Provider index format or digest did not verify.");
    }
    MLDomainProviderIndex *index = [[self alloc] init];
    index->_mapping = mapping;
    index->_length = length;
    return index;
}

- (NSUInteger)count { return _mapping ? MLDPRead32(_mapping + 16) : 0; }

- (BOOL)matchesHost:(NSString *)host {
    if (!_mapping || ![host isKindOfClass:[NSString class]] || host.length > MLDP_NAME_LIMIT) return NO;
    size_t inputLength = [host lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    const uint8_t *input = (const uint8_t *)host.UTF8String;
    uint8_t key[MLDP_NAME_LIMIT], anchor, labels;
    size_t length = input ? MLDPNormalize(input, inputLength, NO, key, &anchor, &labels) : 0;
    if (!length) return NO;
    uint8_t starts[(MLDP_NAME_LIMIT + 1) / 2] = {0};
    for (size_t i = 0, j = 1; i < length; ++i)
        if (key[i] == '.') starts[j++] = (uint8_t)(i + 1);

    uint32_t literalCount = MLDPRead32(_mapping + 8), end = literalCount + MLDPRead32(_mapping + 12);
    for (uint8_t i = 0; i < labels && literalCount; ++i) {
        size_t offset = starts[i];
        uint32_t index = lowerBound(_mapping, 0, literalCount, key + offset, length - offset);
        if (index == literalCount) continue;
        const uint8_t *record = recordAt(_mapping, index);
        if ((record[0] & (i ? MLDP_DESCENDANT : MLDP_APEX)) && !compareAnchor(record, key + offset, length - offset)) return YES;
    }
    for (size_t i = 0; i <= length && literalCount < end; ++i) {
        uint32_t index = lowerBound(_mapping, literalCount, end, key + i, length - i);
        for (; index < end; ++index) {
            const uint8_t *record = recordAt(_mapping, index);
            if (compareAnchor(record, key + i, length - i)) break;
            if (record[3] > labels) continue;
            size_t offset = starts[labels - record[3]];
            if ((record[0] & (offset ? MLDP_DESCENDANT : MLDP_APEX)) &&
                wildcardMatches(record + MLDP_RECORD_SIZE, record[1], key + offset, length - offset)) return YES;
        }
    }
    return NO;
}
@end
