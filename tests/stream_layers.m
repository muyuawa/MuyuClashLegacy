#import <Foundation/Foundation.h>
#include "../protocols/MLStream.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
static int waitStream(MLStream *s, int reading, int writing) {
    struct pollfd fd = {MLStreamFD(s), MLStreamEvents(s, reading, writing), 0};
    return poll(&fd, 1, 4000) > 0 && MLStreamPump(s) == 0;
}
int main(int argc, const char **argv) { @autoreleasepool {
    alarm(15);
    if (argc != 5) return 64;
    NSString *chain = [NSString stringWithContentsOfFile:[NSString stringWithUTF8String:argv[1]] encoding:NSUTF8StringEncoding error:NULL];
    MLStream *base = MLStreamOpenChain(chain.UTF8String, "127.0.0.1", atoi(argv[2]), 5000);
    if (!base) { perror("chain"); return 1; }
    MLStream *tls = MLStreamWrapTLS(base, argv[3], getenv("MLSTREAM_CA_FILE"), 4000);
    if (!strcmp(argv[4], "reject")) {
        if (tls) { MLStreamClose(tls); return 2; }
        MLStreamClose(base); return 0;
    }
    if (!tls) { perror("https"); MLStreamClose(base); return 3; }
    const char request[] = "GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    size_t sent = 0;
    while (sent < sizeof request - 1) {
        ssize_t n = MLStreamWrite(tls, request + sent, sizeof request - 1 - sent);
        if (n > 0) sent += n;
        else if (errno == EAGAIN && waitStream(tls, 0, 1)) continue;
        else return 4;
    }
    char response[1024] = {0}; size_t got = 0;
    for (;;) {
        ssize_t n = MLStreamRead(tls, response + got, sizeof response - got - 1);
        if (!n) break;
        if (n < 0) {
            if (errno == EAGAIN && (MLStreamPendingRead(tls) || waitStream(tls, 1, 0))) continue;
            perror("read"); return 5;
        }
        got += n;
        if (got == sizeof response - 1) return 6;
    }
    MLStreamClose(tls);
    if (!strstr(response, "through-two-proxies")) return 7;
    puts("PASS ordered proxy chain and nested HTTPS TLS");
    return 0;
}}
