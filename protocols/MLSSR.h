#ifndef ML_SSR_H
#define ML_SSR_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "vless.h"

typedef struct MLSSR MLSSR;
typedef struct MLSSRUDP MLSSRUDP;

#define ML_SSR_WRITE_LIMIT 4096
#define ML_SSR_FRAME_LIMIT 8192
#define ML_SSR_UDP_LIMIT 1500

int MLSSRCipher(const char *cipher);
int MLSSRProtocol(const char *protocol);
int MLSSRObfs(const char *obfs);
int MLSSRParameters(const char *protocol, const char *protocolParam,
                    const char *obfs, const char *obfsParam);
MLSSR *MLSSROpen(const char *cipher, const char *password, const char *protocol,
                const char *protocolParam, const char *obfs, const char *obfsParam,
                const char *server, uint16_t port, const vless_dest_t *target);

/* Call Request once, before Write or Feed. Use at least ML_SSR_FRAME_LIMIT
   bytes of wire capacity for Request and Write. Write accepts up to
   ML_SSR_WRITE_LIMIT bytes and encodes the whole input. */
ssize_t MLSSRRequest(MLSSR *session, uint8_t *wire, size_t capacity);
ssize_t MLSSRWrite(MLSSR *session, const uint8_t *data, size_t size,
                  uint8_t *wire, size_t capacity);

/* Feed consumes all input and returns the decoded bytes, or zero while waiting
   for more input. Provide space for the input plus ML_SSR_FRAME_LIMIT bytes
   of previously buffered data. A Feed error terminates the session. */
ssize_t MLSSRFeed(MLSSR *session, const uint8_t *wire, size_t size,
                 uint8_t *data, size_t capacity);
/* Checks whether EOF falls between complete frames and IVs. */
int MLSSRComplete(const MLSSR *session);
void MLSSRClose(MLSSR *session);

/* UDP uses the configured protocol and cipher. TCP obfuscation is ignored. */
MLSSRUDP *MLSSRUDPOpen(const char *cipher, const char *password, const char *protocol,
                      const char *protocolParam, const vless_dest_t *target);
ssize_t MLSSRUDPEncode(MLSSRUDP *session, const uint8_t *data, size_t size,
                      uint8_t *wire, size_t capacity);
ssize_t MLSSRUDPDecode(MLSSRUDP *session, const uint8_t *wire, size_t size,
                      uint8_t *data, size_t capacity);
void MLSSRUDPClose(MLSSRUDP *session);

#endif
