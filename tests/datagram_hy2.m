#import <Foundation/Foundation.h>
#include "../protocols/MLStream.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, const char **argv) { @autoreleasepool {
    alarm(20);
    if (argc != 4 && argc != 5) return 64;
    NSString *source = [NSString stringWithContentsOfFile:[NSString stringWithUTF8String:argv[1]] encoding:NSUTF8StringEncoding error:NULL];
    const char *target = argc == 5 ? argv[4] : "127.0.0.1";
    MLDatagram *session = MLDatagramOpen(source.UTF8String, target, atoi(argv[2]), 6000);
    if (!strcmp(argv[3], "reject")) {
        if (session) { MLDatagramClose(session); return 1; }
        printf("rejected_errno=%d\n", errno); return 0;
    }
    if (!session) { perror("datagram open"); return 2; }
    char address[320]; snprintf(address, sizeof address, strchr(target, ':') ? "[%s]:%d" : "%s:%d", target, atoi(argv[2]));
    unsigned maximum = !strcmp(target,"localhost") ? 4034 : 4096 - 9 - strlen(address);
    unsigned sizes[] = {1, 1400, maximum};
    uint8_t upload[4097], download[4097];
    for (size_t k = 0; k < 3; ++k) {
        size_t length = sizes[k];
        for (size_t i = 0; i < length; ++i) upload[i] = (i + k) % 251;
        if (MLDatagramWrite(session, upload, length) != length) { perror("datagram write"); return 3; }
        struct pollfd fd = {MLDatagramFD(session), POLLIN, 0};
        if (poll(&fd, 1, 5000) <= 0) { fprintf(stderr, "UDP timeout expected=%lu\n", (unsigned long)length); return 4; }
        ssize_t got = MLDatagramRead(session, download, sizeof download);
        if (got != length || memcmp(upload, download, length)) { fprintf(stderr,"UDP mismatch size=%ld expected=%lu\n",(long)got,(unsigned long)length);return 5; }
    }
    if (MLDatagramWrite(session, upload, maximum + 1) != -1 || errno != EMSGSIZE) return 6;
    if (MLDatagramWrite(session, upload, 0) != -1 || errno != EMSGSIZE) return 7;
    if (MLDatagramWrite(session, upload, 20) != 20) return 8;
    struct pollfd fd = {MLDatagramFD(session), POLLIN, 0};
    if (poll(&fd, 1, 5000) <= 0) return 9;
    if (MLDatagramRead(session, download, 19) != -1 || errno != EMSGSIZE) return 10;
    MLDatagramClose(session);
    puts("PASS Hy2 UDP small/fragmented/maximum datagrams and explicit size limits");
    return 0;
}}
