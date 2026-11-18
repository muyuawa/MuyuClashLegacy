#include "../protocols/MLHTTPUpgrade.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    int fd;
    size_t firstRead;
} Fixture;

static int writeRequest(void *context, const uint8_t *bytes, size_t length) {
    Fixture *fixture = context;
    return write(fixture->fd, bytes, length) == (ssize_t)length ? 0 : -1;
}

static ssize_t readResponse(void *context, uint8_t *bytes, size_t length) {
    Fixture *fixture = context;
    if (fixture->firstRead && fixture->firstRead < length) length = fixture->firstRead;
    fixture->firstRead = 0;
    return read(fixture->fd, bytes, length);
}

static void testHandshake(void) {
    static const char response[] = "HTTP/1.1 101 Switching Protocols\r\n"
        "uPgRaDe:\t WebSocket \r\nCONNECTION: uPgRaDe\t\r\nX-Test: good\r\n\r\n\0\xffraw";
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(write(sockets[1], response, sizeof response - 1) == sizeof response - 1);
    Fixture fixture = {sockets[0], sizeof response - 8};
    uint8_t *tail = NULL;
    size_t length = 0;
    assert(MLHTTPUpgradeHandshake("/tunnel?a=1%20x", "proxy.test:8443", &fixture,
                                 writeRequest, readResponse, &tail, &length) == 0);
    assert(length == 5 && memcmp(tail, "\0\xffraw", length) == 0);
    free(tail);

    char request[1024];
    ssize_t count = recv(sockets[1], request, sizeof request - 1, MSG_DONTWAIT);
    assert(count > 0);
    request[count] = '\0';
    assert(strcmp(request, "GET /tunnel?a=1%20x HTTP/1.1\r\nHost: proxy.test:8443\r\n"
                           "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n") == 0);
    close(sockets[0]);
    close(sockets[1]);
}

static void expectInvalidResponse(const void *response, size_t responseLength) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    int capacity = 16384;
    assert(setsockopt(sockets[1], SOL_SOCKET, SO_SNDBUF, &capacity, sizeof capacity) == 0);
    assert(write(sockets[1], response, responseLength) == (ssize_t)responseLength);
    assert(shutdown(sockets[1], SHUT_WR) == 0);
    Fixture fixture = {sockets[0], 0};
    uint8_t *tail = NULL;
    size_t length = 0;
    assert(MLHTTPUpgradeHandshake(NULL, "proxy.test", &fixture, writeRequest,
                                 readResponse, &tail, &length) < 0);
    assert(errno == EPROTO && !tail && !length);
    close(sockets[0]);
    close(sockets[1]);
}

static void testInvalidResponses(void) {
    static const char *responses[] = {
        "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 1010 Invalid\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/2.0 101\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgraded\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: keep-alive, upgrade\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade\r\nUpgrade: websockets\r\n\r\n",
        "HTTP/1.1 101\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade\r\nUpgrade: websocket\r\nUpgrade: h2\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade\r\nUpgrade: websocket\r\nBad Header: x\r\n\r\n",
        "HTTP/1.1 101\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade\r\nUpgrade: websocket\r\nX-Test: \x7f\r\n\r\n"
    };
    for (size_t i = 0; i < sizeof responses / sizeof *responses; ++i)
        expectInvalidResponse(responses[i], strlen(responses[i]));
    static const char embeddedNull[] = "HTTP/1.1 101\r\nConnection: upgrade\r\n"
        "Upgrade: websocket\0suffix\r\n\r\n";
    expectInvalidResponse(embeddedNull, sizeof embeddedNull - 1);

    char large[9000];
    static const char prefix[] = "HTTP/1.1 101\r\nConnection: upgrade\r\nUpgrade: websocket\r\nX-Test: ";
    memcpy(large, prefix, sizeof prefix - 1);
    memset(large + sizeof prefix - 1, 'a', sizeof large - (sizeof prefix - 1));
    memcpy(large + sizeof large - 4, "\r\n\r\n", 4);
    expectInvalidResponse(large, sizeof large);
}

static void testInvalidRequests(void) {
    static const char *inputs[][2] = {
        {"/path\r\nInjected: value", "proxy.test"},
        {"/path with spaces", "proxy.test"},
        {"/path#fragment", "proxy.test"},
        {"http://proxy.test/", "proxy.test"},
        {"/", "proxy.test\r\nInjected: value"},
        {"/", "proxy.test@other.test"},
        {"/", "proxy.test:65536"},
        {"/", "[invalid]:443"}
    };
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    Fixture fixture = {sockets[0], 0};
    assert(shutdown(sockets[1], SHUT_WR) == 0);
    for (size_t i = 0; i < sizeof inputs / sizeof *inputs; ++i) {
        uint8_t *tail = NULL;
        size_t length = 0;
        assert(MLHTTPUpgradeHandshake(inputs[i][0], inputs[i][1], &fixture, writeRequest,
                                     readResponse, &tail, &length) < 0);
        assert(errno == EINVAL && !tail && !length);
    }
    char byte;
    assert(recv(sockets[1], &byte, 1, MSG_DONTWAIT) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    close(sockets[0]);
    close(sockets[1]);
}

int main(void) {
    testHandshake();
    testInvalidResponses();
    testInvalidRequests();
    puts("PASS HTTPUpgrade handshake, response bounds, injection rejection and binary tail");
    return 0;
}
