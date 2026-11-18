#import "MLRelay.h"
#include <arpa/inet.h>
#include <errno.h>
#include <mach/mach_time.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

uint64_t MLMilliseconds(void) {
    mach_timebase_info_data_t scale;
    mach_timebase_info(&scale);
    return (uint64_t)((double)mach_absolute_time() * scale.numer / scale.denom / 1e6);
}

static BOOL MLRetry(void) {
    return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK;
}

static BOOL MLHandshakeIO(int fd, void *buffer, size_t length, BOOL writing, uint64_t deadline) {
    size_t offset = 0;
    while (offset < length) {
        uint64_t now = MLMilliseconds();
        if (now >= deadline) return NO;
        struct pollfd event = {fd, writing ? POLLOUT : POLLIN, 0};
        int ready = poll(&event, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return NO;
        char *pointer = (char *)buffer + offset;
        ssize_t count = writing ? send(fd, pointer, length - offset, MSG_DONTWAIT)
                                : recv(fd, pointer, length - offset, MSG_DONTWAIT);
        if (count < 0 && MLRetry()) continue;
        if (count <= 0) return NO;
        offset += (size_t)count;
    }
    return YES;
}

static BOOL MLSocksReply(int fd, uint8_t status) {
    uint8_t bytes[] = {5, status, 0, 1, 0, 0, 0, 0, 0, 0};
    return MLHandshakeIO(fd, bytes, sizeof(bytes), YES, MLMilliseconds() + 1000);
}

static NSString *MLSocksDestination(int fd, uint16_t *port, NSString **ip) {
    uint64_t deadline = MLMilliseconds() + 5000;
    uint8_t header[4], methods[255], reply[] = {5, 255};
    if (!MLHandshakeIO(fd, header, 2, NO, deadline) || header[0] != 5 || !header[1] ||
        !MLHandshakeIO(fd, methods, header[1], NO, deadline)) return nil;
    if (memchr(methods, 0, header[1])) reply[1] = 0;
    if (!MLHandshakeIO(fd, reply, 2, YES, deadline) || reply[1] != 0 ||
        !MLHandshakeIO(fd, header, 4, NO, deadline) || header[0] != 5 || header[2] != 0) return nil;
    if (header[1] != 1) { MLSocksReply(fd, 7); return nil; }

    uint8_t bytes[255];
    NSString *host = nil;
    if (header[3] == 3) {
        uint8_t count;
        if (!MLHandshakeIO(fd, &count, 1, NO, deadline) || !count ||
            !MLHandshakeIO(fd, bytes, count, NO, deadline)) return nil;
        for (NSUInteger i = 0; i < count; ++i) {
            unsigned char c = bytes[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) return nil;
        }
        host = [[NSString alloc] initWithBytes:bytes length:count encoding:NSASCIIStringEncoding];
        struct in_addr v4;
        if (inet_pton(AF_INET, host.UTF8String, &v4) == 1) *ip = host;
    } else if (header[3] == 1 || header[3] == 4) {
        int family = header[3] == 1 ? AF_INET : AF_INET6;
        char address[INET6_ADDRSTRLEN];
        if (!MLHandshakeIO(fd, bytes, family == AF_INET ? 4 : 16, NO, deadline) ||
            !inet_ntop(family, bytes, address, sizeof(address))) return nil;
        host = [NSString stringWithUTF8String:address];
        *ip = host;
    } else { MLSocksReply(fd, 8); return nil; }
    uint16_t wirePort;
    if (!MLHandshakeIO(fd, &wirePort, sizeof(wirePort), NO, deadline) || !wirePort) return nil;
    *port = ntohs(wirePort);
    return host;
}

BOOL MLInboundReply(int fd, BOOL http, uint8_t status) {
    if (!http) return MLSocksReply(fd,status);
    const char *reply;
    switch (status) {
        case 0: reply = "HTTP/1.1 200 Connection Established\r\n\r\n"; break;
        case 2: reply = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"; break;
        default: reply = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"; break;
    }
    return MLHandshakeIO(fd,(void *)reply,strlen(reply),YES,MLMilliseconds()+1000);
}

static NSString *MLHTTPDestination(int fd, uint16_t *port, NSString **ip) {
    char buffer[8192];
    size_t used = 0, headerLength = 0;
    uint64_t deadline = MLMilliseconds()+5000;
    // Peek and consume only the HTTP headers. Preserve early TLS bytes sent
    // in the same TCP packet as CONNECT.
    while (used < sizeof(buffer) && !headerLength) {
        uint64_t now = MLMilliseconds();
        if (now >= deadline) return nil;
        struct pollfd event = {fd,POLLIN,0};
        int ready = poll(&event,1,(int)(deadline-now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return nil;
        ssize_t peeked = recv(fd,buffer+used,sizeof(buffer)-used,MSG_PEEK|MSG_DONTWAIT);
        if (peeked < 0 && MLRetry()) continue;
        if (peeked <= 0) return nil;
        for (size_t i = used > 3 ? used-3 : 0; i+3 < used+(size_t)peeked; ++i)
            if (!memcmp(buffer+i,"\r\n\r\n",4)) { headerLength = i+4; break; }
        size_t count = headerLength ? headerLength-used : (size_t)peeked;
        if (!MLHandshakeIO(fd,buffer+used,count,NO,deadline)) return nil;
        used += count;
    }
    if (!headerLength || memchr(buffer,0,headerLength)) return nil;
    NSString *header = [[NSString alloc] initWithBytes:buffer length:headerLength encoding:NSASCIIStringEncoding];
    NSString *line = [[header componentsSeparatedByString:@"\r\n"] firstObject];
    NSArray *parts = [line componentsSeparatedByString:@" "];
    if (parts.count != 3 || ![parts[0] isEqual:@"CONNECT"] ||
        ![@[@"HTTP/1.0",@"HTTP/1.1"] containsObject:parts[2]]) {
        const char *reply = "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        MLHandshakeIO(fd,(void *)reply,strlen(reply),YES,MLMilliseconds()+1000);
        return nil;
    }
    NSString *authority = parts[1];
    NSRange colon = [authority rangeOfString:@":" options:NSBackwardsSearch];
    if (!authority.length || colon.location == NSNotFound) return nil;
    NSString *host = [authority substringToIndex:colon.location];
    NSString *rawPort = [authority substringFromIndex:NSMaxRange(colon)];
    NSCharacterSet *digits = [NSCharacterSet characterSetWithCharactersInString:@"0123456789"];
    if (!rawPort.length || rawPort.length > 5 ||
        [rawPort rangeOfCharacterFromSet:digits.invertedSet].location != NSNotFound ||
        rawPort.integerValue <= 0 || rawPort.integerValue > UINT16_MAX) return nil;
    if ([host hasPrefix:@"["] && [host hasSuffix:@"]"] && host.length > 2) {
        host = [host substringWithRange:NSMakeRange(1,host.length-2)];
        struct in6_addr address;
        if (inet_pton(AF_INET6,host.UTF8String,&address) != 1) return nil;
        *ip = host;
    } else {
        NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"];
        if (!host.length || host.length > 253 ||
            [host rangeOfCharacterFromSet:allowed.invertedSet].location != NSNotFound) return nil;
        struct in_addr address;
        if (inet_pton(AF_INET,host.UTF8String,&address) == 1) *ip = host;
    }
    *port = (uint16_t)rawPort.integerValue;
    return host;
}

NSString *MLInboundDestination(int fd, uint16_t *port, NSString **ip, BOOL *http) {
    struct pollfd event = {fd,POLLIN,0};
    int ready = poll(&event,1,5000);
    if (ready <= 0) return nil;
    unsigned char first;
    if (recv(fd,&first,1,MSG_PEEK|MSG_DONTWAIT) != 1) return nil;
    *http = first != 5;
    return *http ? MLHTTPDestination(fd,port,ip) : MLSocksDestination(fd,port,ip);
}

typedef struct {
    uint8_t bytes[16384];
    size_t offset;
    size_t remaining;
} MLBuffer;

void MLRelay(int client, MLStream *stream, void (^record)(size_t, size_t)) {
    MLBuffer up = {0}, down = {0};
    BOOL localEOF = NO, remoteEOF = NO, localWriteClosed = NO, remoteWriteClosed = NO;
    uint64_t lastActivity = MLMilliseconds();
    while (!localEOF || !remoteEOF || up.remaining || down.remaining || MLStreamWritePending(stream)) {
        size_t sent = 0, received = 0;
        if (!localEOF && !up.remaining) {
            ssize_t count = recv(client, up.bytes, sizeof(up.bytes), MSG_DONTWAIT);
            if (count > 0) { up.offset = 0; up.remaining = count; }
            else if (!count) localEOF = YES;
            else if (!MLRetry()) break;
        }
        if (up.remaining) {
            ssize_t count = MLStreamWrite(stream, up.bytes + up.offset, up.remaining);
            if (count > 0) { up.offset += count; up.remaining -= count; sent = count; }
            else if (!count || !MLRetry()) break;
        }
        if (localEOF && !up.remaining && !remoteWriteClosed) {
            MLStreamShutdownWrite(stream);
            remoteWriteClosed = YES;
        }
        if (!remoteEOF && !down.remaining) {
            ssize_t count = MLStreamRead(stream, down.bytes, sizeof(down.bytes));
            if (count > 0) { down.offset = 0; down.remaining = count; }
            else if (!count) remoteEOF = YES;
            else if (!MLRetry()) break;
        }
        if (down.remaining) {
            ssize_t count = send(client, down.bytes + down.offset, down.remaining, MSG_DONTWAIT);
            if (count > 0) { down.offset += count; down.remaining -= count; received = count; }
            else if (!count || !MLRetry()) break;
        }
        if (remoteEOF && !down.remaining && !localWriteClosed) {
            shutdown(client, SHUT_WR);
            localWriteClosed = YES;
        }
        if (MLStreamPump(stream) < 0) break;
        if (sent || received) {
            lastActivity = MLMilliseconds();
            @autoreleasepool { record(sent, received); }
            continue;
        }
        if (MLMilliseconds() - lastActivity > 300000) break;
        if (localEOF && remoteEOF && !up.remaining && !down.remaining && !MLStreamWritePending(stream)) break;
        if (!remoteEOF && !down.remaining && MLStreamPendingRead(stream)) continue;
        short clientEvents = (short)((!localEOF && !up.remaining ? POLLIN : 0) |
                                     (down.remaining ? POLLOUT : 0));
        short remoteEvents = MLStreamEvents(stream, !remoteEOF && !down.remaining, up.remaining != 0);
        struct pollfd events[] = {{clientEvents ? client : -1,clientEvents,0},
                                  {remoteEvents ? MLStreamFD(stream) : -1,remoteEvents,0}};
        int ready = poll(events, 2, 1000);
        if (ready < 0 && errno != EINTR) break;
    }
}
