/* Preserve the pinned HTTP/2, HPACK and gRPC engine while placing it over
   MuyuClash's verified TLS/Reality or proxy-chain streams. */
#include "MLXHTTPTransport.h"
#include "reality_handshake.h"
#include <errno.h>
#include <poll.h>
#include <pthread.h>
static const transport_vt_t lowerTransport;
#define transport_tcp lowerTransport
#define transport_tls lowerTransport
#define transport_reality lowerTransport
#include "transport_xhttp_muyu.c"
#undef transport_tcp
#undef transport_tls
#undef transport_reality

static pthread_mutex_t openLock = PTHREAD_MUTEX_INITIALIZER;
static MLStream *openingStream;
static void *lowerOpen(int fd, const transport_tls_cfg_t *options) { (void)fd; (void)options; return openingStream; }
static int lowerRead(void *handle, uint8_t *data, size_t size) {
    ssize_t n = MLStreamRead(handle, data, size);
    if (n > 0) return (int)n;
    if (!n) return TRANSPORT_EOF;
    if (errno != EAGAIN) return TRANSPORT_ERR;
    return MLStreamEvents(handle, 1, 0) & POLLOUT ? TRANSPORT_WANT_WRITE : TRANSPORT_WANT_READ;
}
static int lowerWrite(void *handle, const uint8_t *data, size_t size) {
    if (!size) return MLStreamPump(handle) < 0 ? TRANSPORT_ERR : MLStreamWritePending(handle) ? TRANSPORT_WANT_WRITE : 0;
    ssize_t n = MLStreamWrite(handle, data, size);
    if (n >= 0) return (int)n;
    if (errno != EAGAIN) return TRANSPORT_ERR;
    return MLStreamEvents(handle, 0, 1) & POLLIN ? TRANSPORT_WANT_READ : TRANSPORT_WANT_WRITE;
}
static void lowerClose(void *handle) { (void)handle; }
static int lowerPending(void *handle) { return MLStreamWritePending(handle); }
static const transport_vt_t lowerTransport = {lowerOpen, lowerRead, lowerWrite, NULL, lowerClose, lowerPending};

void *MLXHTTPOpen(MLStream *inner, const transport_tls_cfg_t *options, int secure) {
    pthread_mutex_lock(&openLock); openingStream = inner;
    void *result = xh_open_common(MLStreamFD(inner), options, &lowerTransport, secure);
    openingStream = NULL; pthread_mutex_unlock(&openLock); return result;
}
int MLXHTTPPendingRead(void *handle) {
    xh_t *state = handle;
    return state->app_off < state->app_len || MLStreamPendingRead(state->sub_h);
}
int MLXHTTPWrite(void *handle, const uint8_t *data, size_t size) {
    xh_t *state = handle;
    if (state->mode != XH_MODE_PKT || !size) return xh_write(handle, data, size);
    /* A packet body and its HEADERS must fit atomically in the 32 KiB queue.
       Count its DATA against the connection window as stream modes already do. */
    if (size > 8192) size = 8192;
    if (size > state->peer_win) size = state->peer_win;
    if (!size) {
        int result = pump_rx(state);
        if (result < 0 && result != TRANSPORT_WANT_READ && result != TRANSPORT_WANT_WRITE) return result;
        result = flush_tx(state);
        if (result < 0) return result;
        return TRANSPORT_WANT_READ;
    }
    int written = xh_write(handle, data, size);
    if (written > 0) state->peer_win -= (uint32_t)written;
    return written;
}
