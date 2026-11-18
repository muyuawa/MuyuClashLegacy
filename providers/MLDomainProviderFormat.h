#import "MLDomainProviderIndex.h"
#include <stdint.h>

/* Header: magic, literal count, wildcard count, input count (big-endian u32).
 * Offsets are absolute big-endian u32. Records follow in offset order, with
 * flags, byte length, last-star end, label count, then the pattern bytes. */
#define MLDP_MAGIC "MLDPR1\0\0"
#define MLDP_HEADER_SIZE 20u
#define MLDP_RECORD_SIZE 4u
#define MLDP_NAME_LIMIT 255u
#define MLDP_APEX 1u
#define MLDP_DESCENDANT 2u

static inline uint32_t MLDPRead32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 | (uint32_t)bytes[2] << 8 | bytes[3];
}

static inline void MLDPWrite32(uint8_t *bytes, uint32_t value) {
    bytes[0] = value >> 24;
    bytes[1] = value >> 16;
    bytes[2] = value >> 8;
    bytes[3] = value;
}

id MLDPError(NSError **error, NSString *reason);
int MLDPCompare(const uint8_t *left, size_t leftLength, const uint8_t *right, size_t rightLength);
/* Produces lowercase bytes and returns the normalized length or zero on invalid input. */
size_t MLDPNormalize(const uint8_t *bytes, size_t length, BOOL allowWildcard, uint8_t key[MLDP_NAME_LIMIT],
                     uint8_t *anchor, uint8_t *labels);
