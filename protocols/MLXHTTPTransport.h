#ifndef ML_XHTTP_TRANSPORT_H
#define ML_XHTTP_TRANSPORT_H
#include "MLStream.h"
#include "transport.h"
/* Borrows inner for the handle lifetime; the caller owns/closes it. */
void *MLXHTTPOpen(MLStream *inner, const transport_tls_cfg_t *options, int secure);
int MLXHTTPPendingRead(void *handle);
int MLXHTTPWrite(void *handle, const uint8_t *data, size_t size);
#endif
