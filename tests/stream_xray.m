#import <Foundation/Foundation.h>
#include "../protocols/MLStream.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int waitStream(MLStream *s, int read, int write) {
    if (read && MLStreamPendingRead(s)) return MLStreamPump(s) == 0;
    struct pollfd fd = {MLStreamFD(s), MLStreamEvents(s, read, write), 0};
    return poll(&fd, 1, 5000) > 0 && MLStreamPump(s) == 0;
}
int main(int argc, const char **argv) { @autoreleasepool {
    alarm(25);
    if (argc != 4) return 64;
    NSString *node = [NSString stringWithContentsOfFile:[NSString stringWithUTF8String:argv[1]] encoding:NSUTF8StringEncoding error:NULL];
    MLStream *stream = [node hasPrefix:@"["] ? MLStreamOpenChain(node.UTF8String, "127.0.0.1", atoi(argv[2]), 8000)
                                            : MLStreamOpen(node.UTF8String, "127.0.0.1", atoi(argv[2]), 8000);
    if (!strcmp(argv[3], "reject")) {
        if (stream) { MLStreamClose(stream); return 1; }
        printf("rejected_errno=%d\n", errno); return 0;
    }
    if (!strcmp(argv[3], "stream-reject")) {
        if (!stream) { printf("rejected_errno=%d\n", errno); return 0; }
        if (MLStreamWrite(stream, "test", 4) < 0 && errno != EAGAIN) { MLStreamClose(stream); return 0; }
        uint8_t byte;
        for (;;) {
            ssize_t n = MLStreamRead(stream, &byte, 1);
            if (n < 0 && errno == EAGAIN && waitStream(stream, 1, 0)) continue;
            int success = n == -1 && errno != EAGAIN;
            MLStreamClose(stream); return success ? 0 : 9;
        }
    }
    if (!stream) { perror("open"); return 2; }
    if (!strcmp(argv[3], "coalesced") && !MLStreamPendingRead(stream)) {
        MLStreamClose(stream);
        return 12;
    }
    if (!strcmp(argv[3], "tls")) {
        MLStream *secure = MLStreamWrapTLS(stream, "localhost", getenv("MLSTREAM_CA_FILE"), 8000);
        if (!secure) { perror("wrap TLS"); MLStreamClose(stream); return 3; }
        stream = secure;
    }
    uint8_t data[262144], reply[997];
    for (size_t i = 0; i < sizeof data; ++i) data[i] = i % 251;
    size_t sent = 0, got = 0;
    while (got < sizeof data) {
        int progress = 0;
        if (sent < sizeof data) {
            size_t take = sizeof data - sent; if (take > 8192) take = 8192;
            ssize_t n = MLStreamWrite(stream, data + sent, take);
            if (n > 0) { sent += n; progress = 1; }
            else if (n >= 0 || errno != EAGAIN) { perror("write"); return 4; }
        }
        for (unsigned burst = 0; burst < 32 && got < sizeof data; ++burst) {
            ssize_t n = MLStreamRead(stream, reply, sizeof reply);
            if (n < 0 && errno == EAGAIN) break;
            if (n <= 0) { perror("read"); return 5; }
            if ((size_t)n > sizeof data - got || memcmp(reply, data + got, n)) return 6;
            got += n; progress = 1;
        }
        if (!progress && !waitStream(stream, 1, sent < sizeof data)) { perror("poll"); return 10; }
    }
    MLStreamShutdownWrite(stream);
    while (MLStreamWritePending(stream)) if (!waitStream(stream, 0, 1)) return 7;
    if (!strcmp(argv[3], "plain-eof")) {
        for (;;) {
            ssize_t n = MLStreamRead(stream, reply, sizeof reply);
            if (!n) break;
            if (n < 0 && errno == EAGAIN && waitStream(stream, 1, 0)) continue;
            fprintf(stderr, "missing clean HTTP/2 response END_STREAM\n"); return 11;
        }
    }
    int direct = MLStreamVisionDirect(stream);
    if (!strcmp(argv[3], "tls") && [node containsString:@"xtls-rprx-vision"] && direct != 3) { fprintf(stderr, "Vision direct=%d\n", direct); return 8; }
    MLStreamClose(stream);
    printf("roundtrip_bytes=%lu direct=%d\n", (unsigned long)got, direct); return 0;
}}
