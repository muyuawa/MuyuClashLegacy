#ifndef ML_SNELL_H
#define ML_SNELL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct MLSnell MLSnell;

/* Version 0 uses v1. Version 5 uses v4 framing. Empty or NULL mode selects
 * the default. UDP is supported from v3 and is limited to 0x3fff bytes
 * including the Snell address header, the pinned peer's receive limit. */
int MLSnellOptions(unsigned version, const char *mode, const char *psk, int udp);
MLSnell *MLSnellOpen(unsigned version, const char *mode, const char *psk,
                     const char *host, uint16_t port, int udp);

/* Open queues the connection request. The output pointer remains valid
 * until the next mutation. Consume after each successful lower write. */
const uint8_t *MLSnellOutput(const MLSnell *codec, size_t *length);
void MLSnellConsumeOutput(MLSnell *codec, size_t length);

/* Feed at most InputSize bytes. InputSize is zero while application data
 * is pending or the read side has ended. FinishRead handles lower EOF. */
size_t MLSnellInputSize(const MLSnell *codec);
int MLSnellFeed(MLSnell *codec, const void *wire, size_t length);
int MLSnellFinishRead(MLSnell *codec);
int MLSnellPendingRead(const MLSnell *codec);
int MLSnellReady(const MLSnell *codec);

/* TCP writes may be partial. UDP reads and writes preserve datagrams.
 * A short UDP read buffer returns EMSGSIZE and discards that datagram.
 * Read returns EAGAIN when more wire data is needed, or 0 at EOF. */
ssize_t MLSnellRead(MLSnell *codec, void *data, size_t length);
ssize_t MLSnellWrite(MLSnell *codec, const void *data, size_t length);

/* Call after draining output, then drain the optional v2 end record
 * before shutting down the lower stream's write side. */
int MLSnellShutdown(MLSnell *codec);
void MLSnellClose(MLSnell *codec);

#endif
