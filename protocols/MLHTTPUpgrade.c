#include "MLHTTPUpgrade.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ML_HTTP_UPGRADE_PATH_CAP 256
#define ML_HTTP_UPGRADE_AUTHORITY_CAP (ML_HTTP_UPGRADE_HOST_CAP + 8)
#define ML_HTTP_UPGRADE_RESPONSE_CAP 8192

int MLHTTPUpgradePathValid(const char *path) {
    if (!path || *path != '/' || strnlen(path, ML_HTTP_UPGRADE_PATH_CAP) == ML_HTTP_UPGRADE_PATH_CAP) return 0;
    for (const unsigned char *byte = (const unsigned char *)path; *byte; ++byte) {
        if (*byte <= ' ' || *byte >= 127 || *byte == '#') return 0;
    }
    return 1;
}

static int asciiAlnum(unsigned char byte) {
    return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9');
}

int MLHTTPUpgradeHost(const char *authority, char host[ML_HTTP_UPGRADE_HOST_CAP]) {
    if (!authority) return 0;
    size_t length = strnlen(authority, ML_HTTP_UPGRADE_AUTHORITY_CAP);
    if (!length || length == ML_HTTP_UPGRADE_AUTHORITY_CAP) return 0;

    const char *start = authority;
    const char *limit = authority + length;
    const char *end = limit;
    const char *suffix;
    if (*start == '[') {
        ++start;
        end = strchr(start, ']');
        if (!end || end == start || end - start >= INET6_ADDRSTRLEN) return 0;
        char literal[INET6_ADDRSTRLEN];
        memcpy(literal, start, (size_t)(end - start));
        literal[end - start] = '\0';
        struct in6_addr address;
        if (inet_pton(AF_INET6, literal, &address) != 1) return 0;
        suffix = end + 1;
    } else {
        const char *port = strchr(start, ':');
        if (port) end = port;
        if (end == start || end - start >= ML_HTTP_UPGRADE_HOST_CAP || *start == '-' || *start == '.') return 0;
        for (const char *byte = start; byte < end; ++byte) {
            if (!asciiAlnum((unsigned char)*byte) && *byte != '-' && *byte != '.' && *byte != '_') return 0;
        }
        suffix = end;
    }
    if (suffix < limit) {
        if (*suffix++ != ':' || suffix == limit) return 0;
        unsigned port = 0;
        for (; suffix < limit; ++suffix) {
            if (*suffix < '0' || *suffix > '9') return 0;
            port = port * 10 + (unsigned)(*suffix - '0');
            if (port > UINT16_MAX) return 0;
        }
        if (!port) return 0;
    }
    if (host) {
        memcpy(host, start, (size_t)(end - start));
        host[end - start] = '\0';
    }
    return 1;
}

static int equalASCII(const uint8_t *value, const uint8_t *end, const char *lowercase) {
    for (; value < end && *lowercase; ++value, ++lowercase) {
        uint8_t byte = *value;
        if (byte >= 'A' && byte <= 'Z') byte += 'a' - 'A';
        if (byte != (uint8_t)*lowercase) return 0;
    }
    return value == end && !*lowercase;
}

static int fieldNameByte(uint8_t byte) {
    return asciiAlnum(byte) || (byte && strchr("!#$%&'*+-.^_`|~", byte));
}

static int fieldValueValid(const uint8_t *value, const uint8_t *end) {
    for (; value < end; ++value) {
        if ((*value < ' ' && *value != '\t') || *value == 127) return 0;
    }
    return 1;
}

static int isWhitespace(uint8_t byte) { return byte == ' ' || byte == '\t'; }

static int responseValid(const uint8_t *data, size_t length) {
    const uint8_t *limit = data + length;
    const uint8_t *newline = memchr(data, '\n', length);
    if (!newline || newline - data < 13 || newline[-1] != '\r' ||
        memcmp(data, "HTTP/1.", 7) || (data[7] != '0' && data[7] != '1') ||
        memcmp(data + 8, " 101", 4) || (newline - data > 13 && data[12] != ' ') ||
        !fieldValueValid(data + 12, newline - 1)) return 0;

    int haveConnection = 0, haveUpgrade = 0;
    const uint8_t *line = newline + 1;
    while (line < limit) {
        newline = memchr(line, '\n', (size_t)(limit - line));
        if (!newline || newline == line || newline[-1] != '\r') return 0;
        const uint8_t *end = newline - 1;
        if (end == line) return haveConnection && haveUpgrade;

        const uint8_t *colon = line;
        while (colon < end && fieldNameByte(*colon)) ++colon;
        if (colon == line || colon == end || *colon != ':' || !fieldValueValid(colon + 1, end)) return 0;
        const uint8_t *value = colon + 1;
        while (value < end && isWhitespace(*value)) ++value;
        while (end > value && isWhitespace(end[-1])) --end;
        if (equalASCII(line, colon, "connection")) {
            if (haveConnection || !equalASCII(value, end, "upgrade")) return 0;
            haveConnection = 1;
        } else if (equalASCII(line, colon, "upgrade")) {
            if (haveUpgrade || !equalASCII(value, end, "websocket")) return 0;
            haveUpgrade = 1;
        }
        line = newline + 1;
    }
    return 0;
}

int MLHTTPUpgradeHandshake(const char *path, const char *authority, void *context,
                           MLHTTPUpgradeWrite write, MLHTTPUpgradeRead read,
                           uint8_t **tail, size_t *tailLength) {
    if (!tail || !tailLength) { errno = EINVAL; return -1; }
    *tail = NULL;
    *tailLength = 0;
    if (!path) path = "/";
    if (!write || !read || !MLHTTPUpgradePathValid(path) || !MLHTTPUpgradeHost(authority, NULL)) {
        errno = EINVAL;
        return -1;
    }
    char request[1024];
    int count = snprintf(request, sizeof request, "GET %s HTTP/1.1\r\nHost: %s\r\n"
                         "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n", path, authority);
    if (count < 0 || (size_t)count >= sizeof request) { errno = EINVAL; return -1; }
    if (write(context, (const uint8_t *)request, (size_t)count) < 0) return -1;

    uint8_t response[ML_HTTP_UPGRADE_RESPONSE_CAP];
    size_t used = 0, scanned = 0;
    while (used < sizeof response) {
        size_t room = sizeof response - used;
        ssize_t received = read(context, response + used, room);
        if (received < 0) return -1;
        if (!received) { errno = ECONNRESET; return -1; }
        if ((size_t)received > room) break;
        used += (size_t)received;
        for (; scanned + 4 <= used; ++scanned) {
            if (memcmp(response + scanned, "\r\n\r\n", 4)) continue;
            size_t end = scanned + 4;
            if (!responseValid(response, end)) { errno = EPROTO; return -1; }
            if (end < used) {
                uint8_t *retained = malloc(used - end);
                if (!retained) return -1;
                memcpy(retained, response + end, used - end);
                *tail = retained;
                *tailLength = used - end;
            }
            return 0;
        }
    }
    errno = EPROTO;
    return -1;
}
