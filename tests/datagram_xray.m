#import <Foundation/Foundation.h>
#include "../protocols/MLStream.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, const char **argv) { @autoreleasepool {
    alarm(25); if (argc != 3) return 64;
    NSString *node = [NSString stringWithContentsOfFile:[NSString stringWithUTF8String:argv[1]] encoding:NSUTF8StringEncoding error:NULL];
    MLDatagram *session = MLDatagramOpen(node.UTF8String, "127.0.0.1", atoi(argv[2]), 8000);
    if (!session) { perror("open UDP"); return 2; }
    uint8_t upload[1501], download[1501]; unsigned sizes[] = {1,1400,1500};
    for (unsigned k = 0; k < 15; ++k) {
        size_t size = sizes[k % 3]; for (size_t i = 0; i < size; ++i) upload[i] = (i + k) % 251;
        if (MLDatagramWrite(session, upload, size) != size) { perror("write UDP"); return 3; }
        struct pollfd fd = {MLDatagramFD(session), POLLIN, 0};
        if (poll(&fd, 1, 5000) <= 0) { fprintf(stderr,"UDP timeout k=%u\n",k);return 4; }
        ssize_t received = MLDatagramRead(session, download, sizeof download);
        if (received < 0) { perror("read UDP"); return 5; }
        if (received != size || memcmp(upload, download, size)) { fprintf(stderr,"UDP mismatch %ld expected=%lu\n",(long)received,(unsigned long)size);return 6; }
    }
    if (MLDatagramWrite(session, upload, sizeof upload) != -1 || errno != EMSGSIZE) return 7;
    if (MLDatagramWrite(session, upload, 0) != -1 || errno != EMSGSIZE) return 8;
    MLDatagramClose(session); puts("PASS 15 UDP datagrams with preserved boundaries/size limits"); return 0;
}}
