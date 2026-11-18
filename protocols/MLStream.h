#ifndef ML_STREAM_H
#define ML_STREAM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct MLStream MLStream;
typedef struct MLDatagram MLDatagram;
/* Connected UDP association. Hy2 accepts 1..(4096 - address-header) bytes; unsupported
   types/sizes fail explicitly. Calls preserve datagram boundaries. */
MLDatagram *MLDatagramOpen(const char *nodeJSON, const char *dest, uint16_t port, unsigned timeoutMS);
ssize_t MLDatagramRead(MLDatagram *datagram, void *data, size_t length);
ssize_t MLDatagramWrite(MLDatagram *datagram, const void *data, size_t length);
int MLDatagramFD(const MLDatagram *datagram);
void MLDatagramClose(MLDatagram *datagram);

/* NULL selects DIRECT. A named outbound never falls back to DIRECT. */
MLStream *MLStreamOpen(const char *nodeJSON, const char *dest, uint16_t port, unsigned timeoutMS);
int MLStreamValidate(const char *nodeJSON);
/* Ordered TCP proxy stages. Failure closes every stage. Hy2 can be first only. */
MLStream *MLStreamOpenChain(const char *nodesJSONArray, const char *dest, uint16_t port, unsigned timeoutMS);
/* Wrap validated HTTPS TLS around an existing tunnel. On success owns inner;
   on failure the caller still owns inner. NULL roots uses the bundled CA. */
MLStream *MLStreamWrapTLS(MLStream *inner, const char *host, const char *roots, unsigned timeoutMS);

/* Open runs on a dial worker. All operations on an open stream are single-owner. */
ssize_t MLStreamRead(MLStream *stream, void *data, size_t length);
ssize_t MLStreamWrite(MLStream *stream, const void *data, size_t length);
int MLStreamFD(const MLStream *stream);
short MLStreamEvents(const MLStream *stream, int wantRead, int wantWrite);
int MLStreamPendingRead(const MLStream *stream);
int MLStreamWritePending(const MLStream *stream);
/* Vision transition bits: 1 upstream, 2 downstream; searches TLS wrappers. */
int MLStreamVisionDirect(const MLStream *stream);
int MLStreamPump(MLStream *stream);
void MLStreamShutdownWrite(MLStream *stream);
void MLStreamClose(MLStream *stream);

#ifdef __OBJC__
@class NSDictionary, NSString;
/* Returns the offending field, or nil for a supported node. */
NSString *MLStreamValidateNode(NSDictionary *node);
#endif

#endif
