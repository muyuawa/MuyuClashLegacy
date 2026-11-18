#include "../protocols/MLSnell.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(value) do { if (!(value)) { fprintf(stderr, "%s:%d: %s (errno %d)\n", __FILE__, __LINE__, #value, errno); exit(1); } } while (0)

static const char psk[] = "MuyuClash Snell fixture secret";
static const uint8_t rawRequest[] = {4, 0, 0, 0, 0, 0, 15, 1, 1, 0, 9,
                                     '1', '2', '7', '.', '0', '.', '0', '.', '1', 31, 144};

static void rawFrames(void) {
    MLSnell *codec = MLSnellOpen(6, "unsafe-raw", psk, "127.0.0.1", 8080, 0);
    CHECK(codec);
    size_t size;
    const uint8_t *pending = MLSnellOutput(codec, &size);
    CHECK(size == sizeof rawRequest && !memcmp(pending, rawRequest, size));
    MLSnellConsumeOutput(codec, 4);
    pending = MLSnellOutput(codec, &size);
    CHECK(size == sizeof rawRequest - 4 && !memcmp(pending, rawRequest + 4, size));
    CHECK(MLSnellWrite(codec, "a", 1) == -1 && errno == EAGAIN);
    MLSnellConsumeOutput(codec, size);

    const uint8_t reply[] = {4, 0, 0, 0, 0, 0, 4, 0, 'a', 'b', 'c'};
    for (size_t i = 0; i < sizeof reply; i++) CHECK(!MLSnellFeed(codec, reply + i, 1));
    CHECK(MLSnellPendingRead(codec));
    uint8_t plain[3];
    CHECK(MLSnellRead(codec, plain, 2) == 2 && !memcmp(plain, "ab", 2));
    CHECK(MLSnellRead(codec, plain, sizeof plain) == 1 && plain[0] == 'c');
    CHECK(!MLSnellFinishRead(codec) && MLSnellRead(codec, plain, sizeof plain) == 0);
    MLSnellClose(codec);
}

static void invalidReply(void) {
    const uint8_t refusal[] = {4, 0, 0, 0, 0, 0, 1, 2, 4, 0, 0, 0, 0, 0, 3, 101, 1, 'X'};
    MLSnell *codec = MLSnellOpen(6, "unsafe-raw", psk, "127.0.0.1", 443, 0);
    CHECK(codec);
    for (size_t i = 0; i + 1 < sizeof refusal; i++) CHECK(!MLSnellFeed(codec, refusal + i, 1));
    CHECK(MLSnellFeed(codec, refusal + sizeof refusal - 1, 1) == -1 && errno == ECONNREFUSED);
    uint8_t value;
    CHECK(MLSnellRead(codec, &value, 1) == -1 && errno == ECONNREFUSED);
    MLSnellClose(codec);

    codec = MLSnellOpen(6, "unsafe-raw", psk, "127.0.0.1", 443, 0);
    CHECK(codec && !MLSnellFeed(codec, refusal, 3));
    CHECK(MLSnellFinishRead(codec) == -1 && errno == EPROTO);
    MLSnellClose(codec);
}

static void authenticatedReply(void) {
    /* Independent Argon2id/AES-GCM reply for the fixture PSK and salt 00..0f. */
    static const uint8_t sealed[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x88, 0x28, 0xfc, 0x36, 0x70, 0x06, 0x25, 0x5c,
        0x84, 0x1e, 0x37, 0xc9, 0xa4, 0x69, 0x4e, 0x45, 0x7d, 0xb8, 0x15, 0x0f,
        0x3f, 0xf3, 0x62, 0x16, 0x89, 0x95, 0xfe, 0x57, 0x84, 0x69, 0x32, 0xdc,
        0xac, 0xe5, 0xd6, 0x4b, 0xcf, 0xb2,
    };
    for (unsigned badTag = 0; badTag <= 1; badTag++) {
        MLSnell *codec = MLSnellOpen(3, "", psk, "127.0.0.1", 443, 0);
        CHECK(codec);
        for (size_t i = 0; i + 1 < sizeof sealed; i++) CHECK(!MLSnellFeed(codec, sealed + i, 1));
        CHECK(!MLSnellPendingRead(codec) && !MLSnellReady(codec));
        uint8_t last = sealed[sizeof sealed - 1] ^ badTag;
        int status = MLSnellFeed(codec, &last, 1);
        uint8_t plain[3];
        if (badTag) {
            CHECK(status == -1 && errno == EPROTO);
            CHECK(MLSnellRead(codec, plain, sizeof plain) == -1 && errno == EPROTO);
        } else {
            CHECK(!status && MLSnellReady(codec));
            CHECK(MLSnellRead(codec, plain, sizeof plain) == 3 && !memcmp(plain, "abc", 3));
        }
        MLSnellClose(codec);
    }
}

static int connectPeer(unsigned port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    const struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port),
                                     .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}};
    CHECK(fd >= 0 && !connect(fd, (const struct sockaddr *)&addr, sizeof addr));
    return fd;
}

static void sendPending(int fd, MLSnell *codec) {
    size_t size;
    const uint8_t *wire = MLSnellOutput(codec, &size);
    while (size) {
        ssize_t sent = send(fd, wire, size < 211 ? size : 211, 0);
        CHECK(sent > 0);
        MLSnellConsumeOutput(codec, (size_t)sent);
        wire = MLSnellOutput(codec, &size);
    }
}

static void receiveWire(int fd, MLSnell *codec) {
    size_t need = MLSnellInputSize(codec);
    uint8_t wire[73];
    CHECK(need > 0);
    ssize_t received = recv(fd, wire, need < sizeof wire ? need : sizeof wire, 0);
    CHECK(received >= 0);
    if (received) CHECK(!MLSnellFeed(codec, wire, (size_t)received));
    else CHECK(!MLSnellFinishRead(codec));
}

static ssize_t readPlain(int fd, MLSnell *codec, uint8_t *plain, size_t size) {
    for (;;) {
        ssize_t got = MLSnellRead(codec, plain, size);
        if (got >= 0) return got;
        CHECK(errno == EAGAIN);
        receiveWire(fd, codec);
    }
}

static void testNetwork(unsigned version, const char *mode, unsigned proxyPort, unsigned targetPort,
                        const char *target, int udp, int halfClose) {
    alarm(12);
    int fd = connectPeer(proxyPort);
    MLSnell *codec = MLSnellOpen(version, mode, psk, target, targetPort, udp);
    CHECK(codec);
    sendPending(fd, codec);
    uint8_t source[18921], reply[sizeof source];
    for (size_t i = 0; i < sizeof source; ++i) source[i] = (uint8_t)(i * 97 + i / 57);
    size_t length = udp ? 1403 : halfClose ? 49 : sizeof source;
    size_t sent = 0;
    while (sent < length) {
        ssize_t count = MLSnellWrite(codec, source + sent, length - sent);
        CHECK(count > 0);
        sent += (size_t)count;
        sendPending(fd, codec);
    }
    if (halfClose) {
        CHECK(!MLSnellShutdown(codec));
        sendPending(fd, codec);
        CHECK(!shutdown(fd, SHUT_WR));
    }
    size_t received = 0;
    do {
        ssize_t count = readPlain(fd, codec, reply + received, length - received);
        CHECK(count > 0);
        received += (size_t)count;
    } while (!udp && received < length);
    CHECK(received == length && !memcmp(source, reply, length));
    if (halfClose) CHECK(!readPlain(fd, codec, reply, sizeof reply));
    close(fd);
    MLSnellClose(codec);
}

int main(int argc, char **argv) {
    if (argc == 1) {
        rawFrames();
        invalidReply();
        authenticatedReply();
        CHECK(!MLSnellOpen(7, "", psk, "target", 1, 0) && errno == EINVAL);
        CHECK(!MLSnellOpen(3, "unshaped", psk, "target", 1, 0) && errno == EINVAL);
        CHECK(!MLSnellOpen(6, "", "too-short", "target", 1, 0) && errno == EINVAL);
        CHECK(!MLSnellOpen(2, "", psk, "target", 1, 1) && errno == EINVAL);
        return 0;
    }
    CHECK(argc == 8);
    testNetwork((unsigned)atoi(argv[1]), argv[2], (unsigned)atoi(argv[3]), (unsigned)atoi(argv[4]),
                argv[5], !strcmp(argv[6], "udp"), !strcmp(argv[7], "half-close"));
    return 0;
}
