#include "../protocols/MLStream.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(value) do { if (!(value)) { fprintf(stderr, "%s:%d: %s (errno %d)\n", __FILE__, __LINE__, #value, errno); exit(1); } } while (0)

static void buildNode(char *node, size_t size, unsigned port, unsigned version, const char *mode, int udp) {
    int length = snprintf(node, size, "{\"type\":\"snell\",\"server\":\"127.0.0.1\",\"port\":%u,"
                          "\"psk\":\"MuyuClash Snell fixture secret\",\"version\":%u,\"mode\":\"%s\",\"udp\":%s}",
                          port, version, mode, udp ? "true" : "false");
    CHECK(length > 0 && (size_t)length < size);
}

static void waitStream(MLStream *stream, int read, int write) {
    if (!read || !MLStreamPendingRead(stream)) {
        struct pollfd fd = {MLStreamFD(stream), MLStreamEvents(stream, read, write), 0};
        CHECK(poll(&fd, 1, 4000) == 1);
    }
    CHECK(MLStreamPump(stream) == 0);
}

static void checkStream(MLStream *stream, int halfClose) {
    CHECK(stream);
    const size_t length = halfClose ? 49 : 18921;
    uint8_t source[18921], reply[sizeof source];
    for (size_t i = 0; i < length; i++) source[i] = (uint8_t)(i * 97 + i / 57);
    for (size_t sent = 0; sent < length;) {
        ssize_t count = MLStreamWrite(stream, source + sent, length - sent);
        if (count < 0) {
            CHECK(errno == EAGAIN);
            waitStream(stream, 0, 1);
        } else {
            CHECK(count > 0);
            sent += (size_t)count;
        }
    }
    if (halfClose) MLStreamShutdownWrite(stream);
    for (size_t received = 0; received < length;) {
        size_t take = length - received > 503 ? 503 : length - received;
        ssize_t count = MLStreamRead(stream, reply + received, take);
        if (count < 0) {
            CHECK(errno == EAGAIN);
            waitStream(stream, 1, 0);
        } else {
            CHECK(count > 0);
            received += (size_t)count;
        }
    }
    CHECK(!memcmp(source, reply, length));
    if (halfClose) {
        for (;;) {
            ssize_t count = MLStreamRead(stream, reply, sizeof reply);
            if (!count) break;
            CHECK(count < 0 && errno == EAGAIN);
            waitStream(stream, 1, 0);
        }
    }
    MLStreamClose(stream);
}

static void checkDatagram(const char *node, const char *host, uint16_t port) {
    MLDatagram *session = MLDatagramOpen(node, host, port, 4000);
    CHECK(session);
    uint8_t packet[1501], received[1500];
    CHECK(MLDatagramWrite(session, packet, sizeof packet) < 0 && errno == EMSGSIZE);
    CHECK(MLDatagramWrite(session, packet, 0) < 0 && errno == EMSGSIZE);
    for (size_t i = 0; i < sizeof packet; ++i) packet[i] = (uint8_t)(i * 23 + i / 11);
    const size_t sizes[] = {1403, 19, 1500};
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++)
        CHECK(MLDatagramWrite(session, packet + i % 2, sizes[i]) == (ssize_t)sizes[i]);
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        struct pollfd fd = {MLDatagramFD(session), POLLIN, 0};
        CHECK(poll(&fd, 1, 4000) == 1);
        CHECK(MLDatagramRead(session, received, sizeof received) == (ssize_t)sizes[i]);
        CHECK(!memcmp(packet + i % 2, received, sizes[i]));
    }
    MLDatagramClose(session);
}

int main(int argc, char **argv) {
    if (argc == 1) {
        char node[512];
        buildNode(node, sizeof node, 1, 2, "", 1);
        CHECK(MLStreamValidate(node) == -1 && errno == ENOTSUP);
        buildNode(node, sizeof node, 1, 6, "", 0);
        CHECK(!MLStreamValidate(node));
        CHECK(!MLDatagramOpen(node, "127.0.0.1", 9, 100) && errno == ENOTSUP);
        buildNode(node, sizeof node, 1, 4, "unshaped", 0);
        CHECK(MLStreamValidate(node) == -1 && errno == ENOTSUP);
        return 0;
    }
    CHECK(argc == 8 || argc == 9);
    alarm(15);
    unsigned version = (unsigned)atoi(argv[1]), proxyPort = (unsigned)atoi(argv[3]);
    uint16_t destPort = (uint16_t)atoi(argv[4]);
    int udp = !strcmp(argv[6], "udp");
    char node[512];
    buildNode(node, sizeof node, proxyPort, version, argv[2], udp);
    CHECK(!MLStreamValidate(node));
    if (udp) checkDatagram(node, argv[5], destPort);
    else if (argc == 9) {
        char lower[512], chain[1028];
        buildNode(lower, sizeof lower, (unsigned)atoi(argv[8]), 6, "default", 0);
        snprintf(chain, sizeof chain, "[%s,%s]", lower, node);
        checkStream(MLStreamOpenChain(chain, argv[5], destPort, 4000), 0);
    } else checkStream(MLStreamOpen(node, argv[5], destPort, 4000), !strcmp(argv[7], "half-close"));
    return 0;
}
