#include "MLSSR.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void sendWire(const uint8_t *wire, ssize_t length) {
    assert(length > 0 && length <= 8192);
    assert(putchar((int)(length >> 8)) != EOF && putchar((int)(length & 255)) != EOF);
    assert(fwrite(wire, 1, (size_t)length, stdout) == (size_t)length);
}

static void exerciseUDP(char **argv, const vless_dest_t *target) {
    MLSSRUDP *session = MLSSRUDPOpen(argv[1], "ssr-test-password", argv[2], argv[3], target);
    assert(session);
    uint8_t wire[2048], plain[1500];
    for (unsigned i = 0; i < 2; ++i)
        sendWire(wire, MLSSRUDPEncode(session, (const uint8_t *)"client data", 11, wire, sizeof wire));
    assert(fflush(stdout) == 0);
    for (unsigned i = 0; i < 4; ++i) {
        int high = getchar(), low = getchar();
        assert(high >= 0 && low >= 0);
        size_t size = (size_t)(high << 8 | low);
        assert(size < sizeof wire && fread(wire, 1, size, stdin) == size);
        ssize_t got = MLSSRUDPDecode(session, wire, size, plain, sizeof plain);
        if (i == 1 || i == 2) assert(got < 0 && errno == EPROTO);
        else assert(got == 9 && fwrite(plain, 1, (size_t)got, stdout) == (size_t)got);
    }
    MLSSRUDPClose(session);
}

int main(int argc, char **argv) {
    assert(argc == 6);
    vless_dest_t destination = { .atyp = VLESS_ADDR_DOMAIN, .domain = "destination.test", .port = 443 };
    if (!strcmp(argv[5], "udp") || !strcmp(argv[5], "udp-numeric")) {
        if (!strcmp(argv[5], "udp-numeric")) {
            destination.atyp = VLESS_ADDR_IPV4;
            destination.host_addr[0] = 127;
            destination.host_addr[3] = 1;
        }
        exerciseUDP(argv, &destination);
        return 0;
    }
    if (!strcmp(argv[5], "identities")) {
        uint8_t wire[8192];
        for (unsigned i = 0; i < 70; ++i) {
            MLSSR *next = MLSSROpen(argv[1], "ssr-test-password", argv[2], argv[3],
                                   "plain", "", "127.0.0.1", 8443, &destination);
            assert(next);
            sendWire(wire, MLSSRRequest(next, wire, sizeof wire));
            MLSSRClose(next);
        }
        return 0;
    }
    MLSSR *client = MLSSROpen(argv[1], "ssr-test-password", argv[2], argv[3], argv[4],
                              !strcmp(argv[4], "plain") ? "" : "test.example",
                              "127.0.0.1", 8443, &destination);
    assert(client);
    uint8_t wire[8192], plain[16384], payload[4096];
    for (size_t i = 0; i < sizeof payload; ++i) payload[i] = (uint8_t)i;
    sendWire(wire, MLSSRRequest(client, wire, sizeof wire));
    sendWire(wire, MLSSRWrite(client, (const uint8_t *)"client data", 11, wire, sizeof wire));
    sendWire(wire, MLSSRWrite(client, payload, sizeof payload, wire, sizeof wire));
    assert(fflush(stdout) == 0);

    int ch, failed = 0;
    while ((ch = getchar()) != EOF) {
        uint8_t byte = (uint8_t)ch;
        ssize_t length = MLSSRFeed(client, &byte, 1, plain, sizeof plain);
        if (length < 0) {
            assert(errno == EPROTO);
            failed = 1;
            break;
        }
        assert(fwrite(plain, 1, (size_t)length, stdout) == (size_t)length);
    }
    assert(!strcmp(argv[5], "corrupt") ? failed : !failed);
    assert(MLSSRComplete(client) == !strcmp(argv[5], "complete"));
    MLSSRClose(client);
    return 0;
}
