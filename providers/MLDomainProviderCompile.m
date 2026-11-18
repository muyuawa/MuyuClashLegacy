#import "MLDomainProviderFormat.h"
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

typedef struct {
    uint32_t offset;
    uint8_t flags, length, anchor, labels;
} MLDPPattern;

static BOOL appendPattern(NSMutableData *keys, NSMutableData *patterns, const uint8_t *bytes, size_t length) {
    if (patterns.length / sizeof(MLDPPattern) >= MLDomainProviderPatternLimit) return NO;
    MLDPPattern pattern = {.offset = (uint32_t)keys.length, .flags = MLDP_APEX};
    if (length >= 2 && bytes[0] == '+' && bytes[1] == '.') {
        pattern.flags |= MLDP_DESCENDANT;
        bytes += 2;
        length -= 2;
    } else if (length && bytes[0] == '.') {
        pattern.flags = MLDP_DESCENDANT;
        ++bytes;
        --length;
    }
    uint8_t key[MLDP_NAME_LIMIT];
    size_t keyLength = MLDPNormalize(bytes, length, YES, key, &pattern.anchor, &pattern.labels);
    if (!keyLength) return NO;
    pattern.length = (uint8_t)keyLength;
    [keys appendBytes:key length:keyLength];
    [patterns appendBytes:&pattern length:sizeof pattern];
    return YES;
}

static BOOL parseText(NSData *source, NSMutableData *keys, NSMutableData *patterns) {
    if (!source.length) return YES;
    const uint8_t *line = source.bytes, *limit = line + source.length;
    if (source.length >= 3 && !memcmp(line, "\xef\xbb\xbf", 3)) line += 3;
    while (line < limit) {
        const uint8_t *next = line;
        while (next < limit && *next != '\r' && *next != '\n') ++next;
        const uint8_t *end = next;
        while (line < end && (*line == ' ' || *line == '\t')) ++line;
        while (end > line && (end[-1] == ' ' || end[-1] == '\t')) --end;
        if (line < end && *line != '#' && !(end - line >= 2 && !memcmp(line, "//", 2)) &&
            !appendPattern(keys, patterns, line, (size_t)(end - line))) return NO;
        line = next < limit ? next + 1 : next;
    }
    return YES;
}

static BOOL expectEvent(yaml_parser_t *parser, yaml_event_type_t type) {
    yaml_event_t event;
    if (!yaml_parser_parse(parser, &event)) return NO;
    BOOL valid = event.type == type;
    if (valid) switch (type) {
        case YAML_DOCUMENT_START_EVENT:
            valid = event.data.document_start.tag_directives.start == event.data.document_start.tag_directives.end;
            break;
        case YAML_MAPPING_START_EVENT:
            valid = !event.data.mapping_start.anchor && !event.data.mapping_start.tag;
            break;
        case YAML_SEQUENCE_START_EVENT:
            valid = !event.data.sequence_start.anchor && !event.data.sequence_start.tag;
            break;
        case YAML_SCALAR_EVENT:
            valid = !event.data.scalar.anchor && !event.data.scalar.tag && event.data.scalar.length == 7 &&
                !memcmp(event.data.scalar.value, "payload", 7);
            break;
        default: break;
    }
    yaml_event_delete(&event);
    return valid;
}

static BOOL parseSequence(yaml_parser_t *parser, NSMutableData *keys, NSMutableData *patterns) {
    yaml_event_t event;
    while (yaml_parser_parse(parser, &event)) {
        BOOL end = event.type == YAML_SEQUENCE_END_EVENT;
        BOOL valid = end || (event.type == YAML_SCALAR_EVENT && !event.data.scalar.anchor && !event.data.scalar.tag &&
            appendPattern(keys, patterns, event.data.scalar.value, event.data.scalar.length));
        yaml_event_delete(&event);
        if (end || !valid) return valid;
    }
    return NO;
}

static BOOL parseYAML(NSData *source, NSMutableData *keys, NSMutableData *patterns) {
    if (!source.length) return NO;
    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser)) return NO;
    yaml_parser_set_encoding(&parser, YAML_UTF8_ENCODING);
    yaml_parser_set_input_string(&parser, source.bytes, source.length);
    BOOL valid = expectEvent(&parser, YAML_STREAM_START_EVENT) && expectEvent(&parser, YAML_DOCUMENT_START_EVENT) &&
        expectEvent(&parser, YAML_MAPPING_START_EVENT) && expectEvent(&parser, YAML_SCALAR_EVENT) &&
        expectEvent(&parser, YAML_SEQUENCE_START_EVENT) && parseSequence(&parser, keys, patterns) &&
        expectEvent(&parser, YAML_MAPPING_END_EVENT) && expectEvent(&parser, YAML_DOCUMENT_END_EVENT) &&
        expectEvent(&parser, YAML_STREAM_END_EVENT);
    yaml_parser_delete(&parser);
    return valid;
}

static int comparePatterns(void *context, const void *leftEntry, const void *rightEntry) {
    const uint8_t *keys = context;
    const MLDPPattern *left = leftEntry, *right = rightEntry;
    int order = !!left->anchor - !!right->anchor;
    if (order) return order;
    const uint8_t *a = keys + left->offset, *b = keys + right->offset;
    order = MLDPCompare(a + left->anchor, left->length - left->anchor,
                        b + right->anchor, right->length - right->anchor);
    return order ? order : MLDPCompare(a, left->length, b, right->length);
}

NSData *MLDomainProviderCompile(NSData *source, NSString *format, NSUInteger *count, NSError **error) {
    if (count) *count = 0;
    if (error) *error = nil;
    if (![source isKindOfClass:[NSData class]] || source.length > MLDomainProviderSourceLimit ||
        (source.length && memchr(source.bytes, 0, source.length)))
        return MLDPError(error,@"A domain Provider requires bounded UTF-8 text of at most 8 MiB.");
    BOOL yaml = [format isEqual:@"yaml"] || !format;
    if (!yaml && ![format isEqual:@"text"]) return MLDPError(error,@"A domain Provider requires YAML or text format.");

    NSMutableData *keys = [NSMutableData dataWithCapacity:source.length];
    NSMutableData *patterns = [NSMutableData data];
    if (!(yaml ? parseYAML(source, keys, patterns) : parseText(source, keys, patterns)))
        return MLDPError(error,@"The domain Provider contains malformed patterns or exceeds 250,000 entries.");

    uint32_t sourceCount = (uint32_t)(patterns.length / sizeof(MLDPPattern));
    MLDPPattern *entries = patterns.mutableBytes;
    const uint8_t *names = keys.bytes;
    if (sourceCount > 1) qsort_r(entries, sourceCount, sizeof *entries, (void *)names, comparePatterns);
    uint32_t uniqueCount = 0, literalCount = 0;
    size_t recordsLength = 0;
    for (uint32_t i = 0; i < sourceCount; ++i) {
        MLDPPattern entry = entries[i];
        if (uniqueCount && !comparePatterns((void *)names, &entries[uniqueCount - 1], &entry)) {
            entries[uniqueCount - 1].flags |= entry.flags;
            continue;
        }
        entries[uniqueCount++] = entry;
        recordsLength += MLDP_RECORD_SIZE + entry.length;
        literalCount += !entry.anchor;
    }
    size_t offset = MLDP_HEADER_SIZE + 4 * uniqueCount;
    size_t length = offset + recordsLength;
    if (length > MLDomainProviderIndexLimit) return MLDPError(error,@"The compiled domain Provider exceeds 16 MiB.");
    uint8_t *bytes = malloc(length);
    if (!bytes) return MLDPError(error,@"Cannot allocate the compact domain Provider index.");

    memcpy(bytes, MLDP_MAGIC, 8);
    MLDPWrite32(bytes + 8, literalCount);
    MLDPWrite32(bytes + 12, uniqueCount - literalCount);
    MLDPWrite32(bytes + 16, sourceCount);
    for (uint32_t i = 0; i < uniqueCount; ++i) {
        MLDPPattern pattern = entries[i];
        MLDPWrite32(bytes + MLDP_HEADER_SIZE + 4 * i, (uint32_t)offset);
        bytes[offset] = pattern.flags;
        bytes[offset + 1] = pattern.length;
        bytes[offset + 2] = pattern.anchor;
        bytes[offset + 3] = pattern.labels;
        memcpy(bytes + offset + MLDP_RECORD_SIZE, names + pattern.offset, pattern.length);
        offset += MLDP_RECORD_SIZE + pattern.length;
    }
    if (count) *count = sourceCount;
    return [NSData dataWithBytesNoCopy:bytes length:length freeWhenDone:YES];
}
