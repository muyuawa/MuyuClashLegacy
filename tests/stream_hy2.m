#import <Foundation/Foundation.h>
#include "../protocols/MLStream.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int waitStream(MLStream *stream, int read, int write) {
    struct pollfd fd = {MLStreamFD(stream), MLStreamEvents(stream, read, write), 0};
    return poll(&fd, 1, 5000) > 0 && MLStreamPump(stream) == 0;
}
int main(int argc, const char **argv) { @autoreleasepool {
    alarm(20);
    if (argc != 5) return 64;
    NSString *node = [NSString stringWithContentsOfFile:[NSString stringWithUTF8String:argv[1]] encoding:NSUTF8StringEncoding error:NULL];
    NSMutableDictionary *options = [[NSJSONSerialization JSONObjectWithData:[node dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:NULL] mutableCopy];
    assert(MLStreamValidateNode(options) == nil);
    for (id alpn in @[@"h3", @[], @[@"h2"], @[@"h3", @"h2"], @[@1]]) {
        options[@"alpn"] = alpn;
        assert([MLStreamValidateNode(options) isEqual:@"alpn"]);
    }
    [options removeObjectForKey:@"alpn"];
    assert(MLStreamValidateNode(options) == nil);
    MLStream *stream = MLStreamOpen(node.UTF8String, "127.0.0.1", (uint16_t)atoi(argv[2]), !strcmp(argv[4], "fallback") ? 2400 : 6000);
    if (!strcmp(argv[3], "reject")) {
        if (stream) { MLStreamClose(stream); return 1; }
        printf("rejected_errno=%d\n", errno);
        return 0;
    }
    if (!stream) { perror("MLStreamOpen"); return 1; }
    if (!strcmp(argv[3], "reset")) {
        puts("READY"); fflush(stdout);
        char byte;
        for (;;) {
            ssize_t count = MLStreamRead(stream, &byte, 1);
            if (count < 0 && errno == EAGAIN) { if (!waitStream(stream, 1, 0)) return 2; continue; }
            int success = count == -1 && errno != EAGAIN;
            MLStreamClose(stream);
            return success ? 0 : 3;
        }
    }
    uint8_t data[35000], reply[97];
    for (size_t i = 0; i < sizeof data; ++i) data[i] = (uint8_t)(i % 251);
    size_t sent = 0;
    while (sent < sizeof data) {
        ssize_t count = MLStreamWrite(stream, data + sent, sizeof data - sent);
        if (count > 0) sent += (size_t)count;
        else if (count < 0 && errno == EAGAIN && waitStream(stream, 0, 1)) continue;
        else { perror("write"); return 4; }
    }
    size_t got = 0;
    for (;;) {
        ssize_t count = MLStreamRead(stream, reply, sizeof reply);
        if (count == 0) break;
        if (count < 0) {
            if (errno == EAGAIN && waitStream(stream, 1, 0)) continue;
            perror("read"); return 5;
        }
        for (ssize_t i = 0; i < count; ++i) if (reply[i] != (got + (size_t)i) % 251) return 6;
        got += (size_t)count;
        if (got == sizeof data) MLStreamShutdownWrite(stream);
    }
    MLStreamClose(stream);
    printf("roundtrip_bytes=%lu\n", (unsigned long)got);
    return got == sizeof data ? 0 : 7;
}}
