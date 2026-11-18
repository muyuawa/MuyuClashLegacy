#include "MLStream.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int listenLoopback(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(fd, (struct sockaddr *)&address, sizeof address) == 0);
    assert(listen(fd, 1) == 0);
    socklen_t size = sizeof address;
    assert(getsockname(fd, (struct sockaddr *)&address, &size) == 0);
    *port = ntohs(address.sin_port);
    return fd;
}

static void readExactly(int fd, char *data, size_t size) {
    while (size) {
        ssize_t length = read(fd, data, size);
        assert(length > 0);
        data += length;
        size -= (size_t)length;
    }
}

static void waitStream(MLStream *stream, int read, int write) {
    struct pollfd fd = {MLStreamFD(stream), MLStreamEvents(stream, read, write), 0};
    assert(poll(&fd, 1, 3000) > 0);
    assert(MLStreamPump(stream) == 0);
}

static void namedDirectDatagram(void) {
    int peer = socket(AF_INET, SOCK_DGRAM, 0); assert(peer >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(peer, (struct sockaddr *)&address, sizeof address) == 0);
    socklen_t addressSize = sizeof address;
    assert(getsockname(peer, (struct sockaddr *)&address, &addressSize) == 0);
    MLDatagram *session = MLDatagramOpen("{\"type\":\"direct\"}", "127.0.0.1", ntohs(address.sin_port), 3000);
    assert(session && MLDatagramWrite(session, "ping", 4) == 4);
    char data[8]; struct sockaddr_in client; socklen_t clientSize = sizeof client;
    assert(recvfrom(peer, data, sizeof data, 0, (struct sockaddr *)&client, &clientSize) == 4 && !memcmp(data,"ping",4));
    assert(sendto(peer,"pong",4,0,(struct sockaddr *)&client,clientSize) == 4);
    struct pollfd fd = {MLDatagramFD(session),POLLIN,0}; assert(poll(&fd,1,3000) == 1);
    assert(MLDatagramRead(session,data,sizeof data) == 4 && !memcmp(data,"pong",4));
    MLDatagramClose(session); close(peer);
}

enum {TestDirect, TestSocks, TestHTTP, TestVLESS};

static void roundTrip(int protocol) {
    uint16_t port;
    int listener = listenLoopback(&port);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        int fd = accept(listener, NULL, NULL);
        assert(fd >= 0);
        char request[256];
        if (protocol == TestSocks) {
            readExactly(fd, request, 3);
            assert(memcmp(request, "\x05\x01\x00", 3) == 0);
            assert(write(fd, "\x05\x00", 2) == 2);
            readExactly(fd, request, 18);
            assert(memcmp(request, "\x05\x01\x00\x03\x0b" "example.com" "\x01\xbb", 18) == 0);
            assert(write(fd, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10) == 10);
        } else if (protocol == TestHTTP) {
            const char connect[] = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
                                   "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
            readExactly(fd, request, sizeof connect - 1);
            assert(memcmp(request, connect, sizeof connect - 1) == 0);
            const char accepted[] = "HTTP/1.1 204 Connection Established\r\n\r\n!";
            assert(write(fd, accepted, sizeof accepted - 1) == sizeof accepted - 1);
        } else if (protocol == TestVLESS) {
            const char header[] = "\0\0\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
                                  "\0\x01\x01\xbb\x02\x0b" "example.com";
            readExactly(fd, request, sizeof header - 1);
            assert(memcmp(request, header, sizeof header - 1) == 0);
        }
        readExactly(fd, request, 4);
        assert(memcmp(request, "ping", 4) == 0);
        assert(read(fd, request, 1) == 0);
        if (protocol == TestVLESS) {
            assert(write(fd, "\0", 1) == 1);
            usleep(5000);
            assert(write(fd, "\x02xy", 3) == 3);
        }
        assert(write(fd, "pong", 4) == 4);
        close(fd);
        _exit(0);
    }
    close(listener);
    const char *type = protocol == TestSocks ? "socks5" : protocol == TestHTTP ? "http" : "vless";
    const char *options = protocol == TestHTTP ? ",\"username\":\"user\",\"password\":\"pass\"" :
        protocol == TestVLESS ? ",\"uuid\":\"00112233-4455-6677-8899-aabbccddeeff\"" : "";
    char node[256];
    snprintf(node, sizeof node, "{\"type\":\"%s\",\"server\":\"127.0.0.1\",\"port\":%u%s}",
             type, port, options);
    MLStream *stream = protocol == TestDirect ? MLStreamOpen(NULL, "127.0.0.1", port, 3000) :
                                               MLStreamOpen(node, "example.com", 443, 3000);
    assert(stream);
    char reply[4];
    if (protocol == TestHTTP) {
        assert(MLStreamRead(stream, reply, 1) == 1 && reply[0] == '!');
    }
    assert(MLStreamRead(stream, reply, sizeof reply) == -1 && errno == EAGAIN);
    assert(MLStreamWrite(stream, "ping", 4) == 4);
    MLStreamShutdownWrite(stream);
    size_t used = 0;
    while (used < sizeof reply) {
        ssize_t length = MLStreamRead(stream, reply + used, sizeof reply - used);
        if (length < 0) {
            assert(errno == EAGAIN);
            waitStream(stream, 1, 0);
        } else {
            assert(length > 0);
            used += (size_t)length;
        }
    }
    assert(memcmp(reply, "pong", 4) == 0);
    MLStreamClose(stream);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static int proxyFixture(const char *type, const char *port, const char *sni, int reject) {
    char node[512];
    if (strcmp(type, "vless-ws") == 0) {
        snprintf(node, sizeof node, "{\"type\":\"vless\",\"server\":\"127.0.0.1\",\"port\":%d,"
                 "\"uuid\":\"00112233-4455-6677-8899-aabbccddeeff\",\"network\":\"ws\","
                 "\"ws-opts\":{\"path\":\"/test?x=1\",\"headers\":{\"Host\":\"proxy.test\"}}}", atoi(port));
    } else {
        const char *ws = strcmp(type, "trojan-wss") == 0 ? ",\"network\":\"ws\"" : "";
        snprintf(node, sizeof node, "{\"type\":\"trojan\",\"server\":\"127.0.0.1\",\"port\":%d,"
                 "\"sni\":\"%s\",\"password\":\"test password\"%s}", atoi(port), sni, ws);
    }
    MLStream *stream = MLStreamOpen(node, "example.com", 443, 3000);
    if (reject) {
        assert(!stream && errno == EACCES);
        return 0;
    }
    assert(stream && MLStreamWrite(stream, "ping", 4) == 4);
    char reply[4];
    size_t got = 0;
    while (got < sizeof reply) {
        ssize_t count = MLStreamRead(stream, reply + got, sizeof reply - got);
        if (count < 0) {
            assert(errno == EAGAIN);
            waitStream(stream, 1, 0);
        } else {
            assert(count > 0);
            got += (size_t)count;
        }
    }
    assert(memcmp(reply, "pong", 4) == 0);
    MLStreamShutdownWrite(stream);
    for (;;) {
        ssize_t count = MLStreamRead(stream, reply, sizeof reply);
        if (!count) break;
        assert(count == -1 && errno == EAGAIN);
        waitStream(stream, 1, 0);
    }
    MLStreamClose(stream);
    return 0;
}

static int encryptedFixture(const char *type, const char *port) {
    const char *credentials = strcmp(type, "ss") == 0 ? "\"password\":\"fixture-password\"" :
        "\"uuid\":\"00112233-4455-6677-8899-aabbccddeeff\"";
    char node[256];
    snprintf(node, sizeof node,
             "{\"type\":\"%s\",\"server\":\"127.0.0.1\",\"port\":%d,\"cipher\":\"aes-128-gcm\",%s}",
             type, atoi(port), credentials);
    MLStream *stream = MLStreamOpen(node, "example.com", 443, 3000);
    assert(stream);

    uint8_t upload[35000];
    for (size_t i = 0; i < sizeof upload; i++) upload[i] = (uint8_t)(i % 91);
    size_t sent = 0;
    while (sent < sizeof upload) {
        ssize_t count = MLStreamWrite(stream, upload + sent, sizeof upload - sent);
        if (count > 0) {
            sent += (size_t)count;
        } else {
            assert(count == -1 && errno == EAGAIN);
            waitStream(stream, 0, 1);
        }
    }
    MLStreamShutdownWrite(stream);

    size_t received = 0;
    for (;;) {
        uint8_t chunk[191];
        ssize_t count = MLStreamRead(stream, chunk, sizeof chunk);
        if (!count) break;
        if (count < 0) {
            assert(errno == EAGAIN);
            if (!MLStreamPendingRead(stream)) waitStream(stream, 1, 0);
            continue;
        }
        for (size_t i = 0; i < (size_t)count; i++) assert(chunk[i] == (received + i) % 97);
        received += (size_t)count;
    }
    assert(received == 60000);
    MLStreamClose(stream);
    return 0;
}

int main(int argc, const char **argv) {
    alarm(10);
    if (argc == 5) return proxyFixture(argv[1], argv[2], argv[3], atoi(argv[4]));
    if (argc == 3 && (!strcmp(argv[1], "ss") || !strcmp(argv[1], "vmess")))
        return encryptedFixture(argv[1], argv[2]);
    assert(argc == 1);
    roundTrip(TestDirect);
    roundTrip(TestSocks);
    roundTrip(TestHTTP);
    roundTrip(TestVLESS);
    namedDirectDatagram();
    assert(MLStreamValidate("{\"type\":\"http\",\"server\":\"localhost\",\"port\":80}") == 0);
    const char *dialer = "{\"type\":\"http\",\"server\":\"localhost\",\"port\":80,\"dialer-proxy\":\"upstream\"}";
    assert(MLStreamValidate(dialer) == 0);
    assert(!MLStreamOpen(dialer, "example.com", 443, 3000) && errno == ENOTSUP);
    assert(!MLDatagramOpen(dialer, "127.0.0.1", 53, 3000) && errno == ENOTSUP);
    assert(MLStreamValidate("{\"type\":\"http\",\"server\":\"localhost\",\"port\":80,\"dialer-proxy\":\"\"}") == -1);
    assert(MLStreamValidate("{\"type\":\"direct\"}") == 0);
    assert(MLStreamValidate("{\"type\":\"reject\"}") == 0);
    assert(!MLStreamOpen("{\"type\":\"reject\"}", "127.0.0.1", 80, 3000) && errno == EACCES);
    assert(!MLDatagramOpen("{\"type\":\"reject\"}", "127.0.0.1", 53, 3000) && errno == EACCES);
    assert(MLStreamValidate("{\"type\":\"trojan\",\"server\":\"localhost\",\"port\":443,\"password\":\"test\",\"skip-cert-verify\":true}") == -1);
    puts("MLStream DIRECT, SOCKS5, HTTP CONNECT and VLESS TCP round trips passed");
    return 0;
}
