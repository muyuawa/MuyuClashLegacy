/* Wrap the pinned QUIC engine without modifying TLS or cryptographic code.
   Socket creation enforces physical-interface binding. Extra QUIC callbacks
   carry Hysteria UDP sessions with bounded fragmentation and reassembly. */
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>
#include "../transport/MLNetworkBinding.h"
#include "MLHy2Engine.h"
static int ml_hy2_socket(int family, int type, int protocol) {
    int fd = socket(family, type, protocol);
    if (fd >= 0 && (family == AF_INET || family == AF_INET6) && MLNetworkBindSocket(fd, family) != 0) {
        int saved = errno; close(fd); errno = saved; return -1;
    }
    return fd;
}
static int ml_hy2_client_new(ngtcp2_conn **, const ngtcp2_cid *, const ngtcp2_cid *, const ngtcp2_path *, uint32_t,
                           const ngtcp2_callbacks *, const ngtcp2_settings *, const ngtcp2_transport_params *, const ngtcp2_mem *, void *);
static int ml_hy2_h3_new(nghttp3_conn **, const nghttp3_callbacks *, const nghttp3_settings *, const nghttp3_mem *, void *);
static ngtcp2_ssize ml_hy2_write_stream(ngtcp2_conn *, ngtcp2_path *, ngtcp2_pkt_info *, uint8_t *, size_t,
                                       ngtcp2_ssize *, uint32_t, int64_t, const ngtcp2_vec *, size_t, ngtcp2_tstamp);
static void ml_hy2_conn_del(ngtcp2_conn *);
#define socket ml_hy2_socket
#undef ngtcp2_conn_client_new
#define ngtcp2_conn_client_new ml_hy2_client_new
#undef nghttp3_conn_client_new
#define nghttp3_conn_client_new ml_hy2_h3_new
#undef ngtcp2_conn_writev_stream
#define ngtcp2_conn_writev_stream ml_hy2_write_stream
#define ngtcp2_conn_del ml_hy2_conn_del
#define hy2_engine_stop ml_hy2_original_stop
#include "transport_hy2_muyu.c"
#undef socket
#undef ngtcp2_conn_client_new
#undef nghttp3_conn_client_new
#undef ngtcp2_conn_writev_stream
#undef ngtcp2_conn_del
#undef hy2_engine_stop

#define ML_HY2_UDP_MAX 4096
#define ML_HY2_FRAME_MAX 1100
#define ML_HY2_SESSIONS_MAX 64
#define ML_HY2_QUEUE_MAX 128

typedef struct MLHy2Frame { struct MLHy2Frame *next; size_t size; uint8_t data[ML_HY2_FRAME_MAX]; } MLHy2Frame;
typedef struct {
    uint16_t id; uint8_t count, seen; uint64_t started;
    uint8_t *parts[8]; uint16_t sizes[8];
} MLHy2Reassembly;
typedef struct MLHy2Context MLHy2Context;
struct MLHy2UDP {
    MLHy2Context *context;
    int pair[2], failed;
    uint32_t id; uint16_t packet;
    size_t maxPayload;
    int domain;
    char address[320];
    MLHy2Reassembly partial[2];
};
struct MLHy2Context {
    MLHy2Context *next;
    hy2_engine_t *engine; ngtcp2_conn *conn; int udpAllowed;
    MLHy2UDP *sessions[ML_HY2_SESSIONS_MAX];
    MLHy2Frame *first, *last; size_t queued;
};
static pthread_mutex_t udpLock = PTHREAD_MUTEX_INITIALIZER;
static MLHy2Context *udpContexts;
static MLHy2Context *contextForEngine(hy2_engine_t *e) {
    for (MLHy2Context *c = udpContexts; c; c = c->next) if (c->engine == e) return c;
    return NULL;
}
static void clearPartial(MLHy2Reassembly *r) {
    for (size_t i = 0; i < 8; ++i) free(r->parts[i]);
    memset(r, 0, sizeof *r);
}
static int replyAddress(const MLHy2UDP *s, const uint8_t *bytes, size_t size) {
    if (strlen(s->address) == size && !memcmp(s->address, bytes, size)) return 1;
    if (!s->domain || size >= sizeof s->address || memchr(bytes, 0, size)) return 0;
    char address[320]; memcpy(address, bytes, size); address[size] = 0;
    char *port = strrchr(address, ':'); const char *expected = strrchr(s->address, ':');
    if (!port || !expected || strcmp(port, expected)) return 0;
    *port = 0; const char *host = address;
    if (address[0] == '[') {
        size_t n = strlen(address); if (n < 3 || address[n - 1] != ']') return 0;
        address[n - 1] = 0; host = address + 1;
    }
    uint8_t numeric[16];
    /* The authenticated proxy resolves domain destinations remotely. Its
       numeric reply is valid only within this association and destination port. */
    return inet_pton(AF_INET, host, numeric) == 1 || inet_pton(AF_INET6, host, numeric) == 1;
}
static int ml_hy2_header(nghttp3_conn *conn, int64_t id, int32_t token, nghttp3_rcbuf *name, nghttp3_rcbuf *value,
                         uint8_t flags, void *user, void *stream_user) {
    nghttp3_vec n = nghttp3_rcbuf_get_buf(name), v = nghttp3_rcbuf_get_buf(value);
    if (n.len == 12 && !memcmp(n.base, "hysteria-udp", 12)) {
        pthread_mutex_lock(&udpLock);
        MLHy2Context *c = contextForEngine(user);
        if (c) c->udpAllowed = v.len == 4 && !memcmp(v.base, "true", 4);
        pthread_mutex_unlock(&udpLock);
    }
    return h3_recv_header(conn, id, token, name, value, flags, user, stream_user);
}
static int ml_hy2_h3_new(nghttp3_conn **out, const nghttp3_callbacks *callbacks, const nghttp3_settings *settings,
                        const nghttp3_mem *mem, void *user) {
    nghttp3_callbacks copy = *callbacks; copy.recv_header = ml_hy2_header;
    return nghttp3_conn_client_new_versioned(out, NGHTTP3_CALLBACKS_VERSION, &copy,
                                             NGHTTP3_SETTINGS_VERSION, settings, mem, user);
}
static int ml_hy2_datagram(ngtcp2_conn *conn, uint32_t flags, const uint8_t *data, size_t size, void *user) {
    (void)conn; (void)flags;
    if (size < 10) return 0;
    uint32_t id; memcpy(&id, data, 4); id = ntohl(id);
    uint16_t packet; memcpy(&packet, data + 4, 2); packet = ntohs(packet);
    uint8_t fragment = data[6], count = data[7];
    uint64_t addressSize = 0; size_t used = hy2_varint_get(data + 8, size - 8, &addressSize);
    if (!used || !addressSize || addressSize >= 320 || size <= 8 + used + addressSize || !count || count > 8 || fragment >= count) return 0;
    const uint8_t *payload = data + 8 + used + addressSize; size_t payloadSize = size - (size_t)(payload - data);
    pthread_mutex_lock(&udpLock);
    MLHy2Context *c = contextForEngine(user); MLHy2UDP *s = NULL;
    if (c) for (size_t i = 0; i < ML_HY2_SESSIONS_MAX; ++i) if (c->sessions[i] && c->sessions[i]->id == id) { s = c->sessions[i]; break; }
    if (!s || s->failed) { pthread_mutex_unlock(&udpLock); return 0; }
    /* A connected association never accepts a reply from another destination. */
    if (!replyAddress(s, data + 8 + used, addressSize)) { pthread_mutex_unlock(&udpLock); return 0; }
    if (count == 1) {
        if (payloadSize <= ML_HY2_UDP_MAX) (void)send(s->pair[1], payload, payloadSize, 0);
    } else {
        MLHy2Reassembly *r = NULL; uint64_t now = (uint64_t)senko_now_ms();
        for (size_t i = 0; i < 2; ++i) {
            if (s->partial[i].count && now - s->partial[i].started > 1500) clearPartial(&s->partial[i]);
            if (s->partial[i].count && s->partial[i].id == packet) r = &s->partial[i];
        }
        if (!r) for (size_t i = 0; i < 2; ++i) if (!s->partial[i].count) { r = &s->partial[i]; break; }
        if (r && payloadSize <= ML_HY2_UDP_MAX) {
            if (!r->count) { r->id = packet; r->count = count; r->started = now; }
            if (r->count == count && !(r->seen & (1u << fragment))) {
                r->parts[fragment] = malloc(payloadSize);
                if (r->parts[fragment]) { memcpy(r->parts[fragment], payload, payloadSize); r->sizes[fragment] = payloadSize; r->seen |= 1u << fragment; }
            }
            if (r->seen == (uint8_t)((1u << count) - 1)) {
                uint8_t assembled[ML_HY2_UDP_MAX]; size_t total = 0;
                for (size_t i = 0; i < count; ++i) {
                    if (r->sizes[i] > sizeof assembled - total) { total = 0; break; }
                    memcpy(assembled + total, r->parts[i], r->sizes[i]); total += r->sizes[i];
                }
                if (total) (void)send(s->pair[1], assembled, total, 0);
                clearPartial(r);
            }
        }
    }
    pthread_mutex_unlock(&udpLock);
    return 0;
}
static int ml_hy2_client_new(ngtcp2_conn **out, const ngtcp2_cid *dcid, const ngtcp2_cid *scid, const ngtcp2_path *path,
                            uint32_t version, const ngtcp2_callbacks *callbacks, const ngtcp2_settings *settings,
                            const ngtcp2_transport_params *params, const ngtcp2_mem *mem, void *user) {
    ngtcp2_callbacks copy = *callbacks; copy.recv_datagram = ml_hy2_datagram;
    ngtcp2_transport_params parameters = *params;
    /* Keep the peer's datagrams within the pinned engine's packet buffer.
       QUIC's DATAGRAM frame limit also makes Hysteria fragment large replies. */
    parameters.max_datagram_frame_size = 1200;
    int result = ngtcp2_conn_client_new_versioned(out, dcid, scid, path, version, NGTCP2_CALLBACKS_VERSION, &copy,
                                                 NGTCP2_SETTINGS_VERSION, settings, NGTCP2_TRANSPORT_PARAMS_VERSION, &parameters, mem, user);
    if (!result) {
        pthread_mutex_lock(&udpLock); MLHy2Context *c = contextForEngine(user);
        if (!c) { c = calloc(1, sizeof *c); if (c) { c->engine = user; c->next = udpContexts; udpContexts = c; } }
        if (c) { c->conn = *out; c->udpAllowed = 0; }
        pthread_mutex_unlock(&udpLock);
        if (!c) { ngtcp2_conn_del(*out); *out = NULL; return NGTCP2_ERR_NOMEM; }
    }
    return result;
}
static void ml_hy2_conn_del(ngtcp2_conn *conn) {
    pthread_mutex_lock(&udpLock);
    for (MLHy2Context *c = udpContexts; c; c = c->next) if (c->conn == conn) {
        c->conn = NULL; c->udpAllowed = 0;
        while (c->first) { MLHy2Frame *f = c->first; c->first = f->next; free(f); } c->last = NULL; c->queued = 0;
        for (size_t i = 0; i < ML_HY2_SESSIONS_MAX; ++i) if (c->sessions[i]) {
            c->sessions[i]->failed = ECONNRESET; (void)send(c->sessions[i]->pair[1], "", 0, 0);
        }
    }
    pthread_mutex_unlock(&udpLock);
    ngtcp2_conn_del(conn);
}
static ngtcp2_ssize ml_hy2_write_stream(ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *info, uint8_t *packet,
                                       size_t capacity, ngtcp2_ssize *written, uint32_t flags, int64_t stream,
                                       const ngtcp2_vec *vec, size_t count, ngtcp2_tstamp time) {
    pthread_mutex_lock(&udpLock);
    MLHy2Context *c = NULL; for (MLHy2Context *it = udpContexts; it; it = it->next) if (it->conn == conn) { c = it; break; }
    if (c && c->udpAllowed && c->engine->auth_done && c->first) {
        MLHy2Frame *f = c->first; ngtcp2_vec datagram = {f->data, f->size}; int accepted = 0;
        ngtcp2_ssize n = ngtcp2_conn_writev_datagram_versioned(conn, path, NGTCP2_PKT_INFO_VERSION, info, packet, capacity,
                                                             &accepted, 0, 0, &datagram, 1, time);
        if (accepted) { c->first = f->next; if (!c->first) c->last = NULL; --c->queued; free(f); }
        if (n > 0) { *written = -1; pthread_mutex_unlock(&udpLock); return n; }
        if (n < 0 && n != NGTCP2_ERR_INVALID_STATE && n != NGTCP2_ERR_INVALID_ARGUMENT) {
            pthread_mutex_unlock(&udpLock); return n;
        }
    }
    pthread_mutex_unlock(&udpLock);
    return ngtcp2_conn_writev_stream_versioned(conn, path, NGTCP2_PKT_INFO_VERSION, info, packet, capacity, written, flags, stream, vec, count, time);
}
int MLHy2WaitReady(hy2_engine_t *e, unsigned timeoutMS) {
    int64_t deadline = senko_now_ms() + timeoutMS;
    pthread_mutex_lock(&e->lock);
    while (!e->stop && e->state != HY2_STATE_READY) {
        if (e->state == HY2_STATE_FAILED || senko_now_ms() >= deadline) {
            int error = e->state == HY2_STATE_FAILED ? EACCES : ETIMEDOUT;
            pthread_mutex_unlock(&e->lock); errno = error; return -1;
        }
        if (e->state == HY2_STATE_IDLE) { e->want_connect = 1; e->state = HY2_STATE_CONNECTING; wake_thread(e); }
        struct timeval now; gettimeofday(&now, NULL);
        struct timespec until = {now.tv_sec, (now.tv_usec + 100000L) * 1000L};
        if (until.tv_nsec >= 1000000000L) { ++until.tv_sec; until.tv_nsec -= 1000000000L; }
        pthread_cond_timedwait(&e->changed, &e->lock, &until);
    }
    int stopped = e->stop; pthread_mutex_unlock(&e->lock);
    if (stopped) { errno = ECANCELED; return -1; } return 0;
}
MLHy2UDP *MLHy2UDPOpen(hy2_engine_t *e, const char *address) {
    if (!e || !address || !*address || strlen(address) >= 320) { errno = EINVAL; return NULL; }
    pthread_mutex_lock(&udpLock); MLHy2Context *c = contextForEngine(e);
    if (!c || !c->conn || !c->udpAllowed) { pthread_mutex_unlock(&udpLock); errno = ENOTSUP; return NULL; }
    size_t slot = ML_HY2_SESSIONS_MAX; for (size_t i = 0; i < ML_HY2_SESSIONS_MAX; ++i) if (!c->sessions[i]) { slot = i; break; }
    if (slot == ML_HY2_SESSIONS_MAX) { pthread_mutex_unlock(&udpLock); errno = EBUSY; return NULL; }
    MLHy2UDP *s = calloc(1, sizeof *s);
    if (!s || socketpair(AF_UNIX, SOCK_DGRAM, 0, s->pair) != 0) { free(s); pthread_mutex_unlock(&udpLock); return NULL; }
    int bufferSize = 65536;
    if (setsockopt(s->pair[1], SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof bufferSize) ||
        setsockopt(s->pair[0], SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof bufferSize)) {
        int saved = errno; close(s->pair[0]); close(s->pair[1]); free(s); pthread_mutex_unlock(&udpLock); errno = saved; return NULL;
    }
    if (set_nonblocking(s->pair[0]) != 0 || set_nonblocking(s->pair[1]) != 0 || RAND_bytes((uint8_t *)&s->id, sizeof s->id) != 1) {
        close(s->pair[0]); close(s->pair[1]); free(s); pthread_mutex_unlock(&udpLock); errno = EIO; return NULL;
    }
    int collision;
    do {
        collision = 0;
        for (size_t i = 0; i < ML_HY2_SESSIONS_MAX; ++i) if (c->sessions[i] && c->sessions[i]->id == s->id) { collision = 1; ++s->id; break; }
    } while (collision);
    /* Hysteria's server serializes the complete response into MaxUDPSize before
       deciding whether to fragment it. Reserve that header on both directions. */
    uint8_t varint[8];
    size_t header = 8 + hy2_varint_put(strlen(address), varint, sizeof varint) + strlen(address);
    char host[320]; strcpy(host, address); char *port = strrchr(host, ':');
    if (!port) { close(s->pair[0]); close(s->pair[1]); free(s); pthread_mutex_unlock(&udpLock); errno = EINVAL; return NULL; }
    *port = 0; uint8_t numeric[16];
    s->domain = host[0] != '[' && inet_pton(AF_INET, host, numeric) != 1;
    /* A resolved domain can return a longer IPv6 source address. */
    if (s->domain && header < 62) header = 62;
    s->maxPayload = ML_HY2_UDP_MAX - header;
    strcpy(s->address, address); s->context = c; c->sessions[slot] = s;
    pthread_mutex_unlock(&udpLock); return s;
}
int MLHy2UDPFD(MLHy2UDP *s) { return s->pair[0]; }
ssize_t MLHy2UDPSend(MLHy2UDP *s, const void *data, size_t size) {
    if (!size || size > s->maxPayload) { errno = EMSGSIZE; return -1; }
    size_t address = strlen(s->address), room = ML_HY2_FRAME_MAX - address - 12;
    size_t fragments = (size + room - 1) / room;
    MLHy2Frame *first = NULL, *last = NULL; size_t offset = 0;
    uint16_t packet = ++s->packet;
    for (size_t i = 0; i < fragments; ++i) {
        MLHy2Frame *f = calloc(1, sizeof *f); if (!f) goto failed;
        uint32_t session = htonl(s->id); uint16_t number = htons(packet);
        memcpy(f->data, &session, 4); memcpy(f->data + 4, &number, 2); f->data[6] = i; f->data[7] = fragments;
        size_t n = hy2_varint_put(address, f->data + 8, sizeof f->data - 8); size_t header = 8 + n + address;
        memcpy(f->data + 8 + n, s->address, address); size_t take = size - offset; if (take > room) take = room;
        memcpy(f->data + header, (const uint8_t *)data + offset, take); f->size = header + take; offset += take;
        if (last) last->next = f; else first = f; last = f;
    }
    pthread_mutex_lock(&udpLock);
    if (s->failed || !s->context->conn || s->context->queued + fragments > ML_HY2_QUEUE_MAX) {
        errno = s->failed ?: EAGAIN; pthread_mutex_unlock(&udpLock); goto failed;
    }
    if (s->context->last) s->context->last->next = first; else s->context->first = first;
    s->context->last = last; s->context->queued += fragments; wake_thread(s->context->engine);
    pthread_mutex_unlock(&udpLock); return size;
failed:
    while (first) { MLHy2Frame *f = first; first = f->next; free(f); } return -1;
}
ssize_t MLHy2UDPReceive(MLHy2UDP *s, void *data, size_t size) {
    pthread_mutex_lock(&udpLock); int failed = s->failed; pthread_mutex_unlock(&udpLock);
    if (failed) { errno = failed; return -1; }
    uint8_t message[ML_HY2_UDP_MAX];
    ssize_t n = recv(s->pair[0], message, sizeof message, 0);
    if (n < 0) { if (errno == EWOULDBLOCK) errno = EAGAIN; return -1; }
    if ((size_t)n > size) { errno = EMSGSIZE; return -1; }
    memcpy(data, message, (size_t)n); return n;
}
void MLHy2UDPClose(MLHy2UDP *s) {
    if (!s) return;
    pthread_mutex_lock(&udpLock);
    for (size_t i = 0; i < ML_HY2_SESSIONS_MAX; ++i) if (s->context->sessions[i] == s) s->context->sessions[i] = NULL;
    MLHy2Frame **p = &s->context->first; s->context->last = NULL;
    while (*p) {
        uint32_t id; memcpy(&id, (*p)->data, 4);
        if (ntohl(id) == s->id) { MLHy2Frame *f = *p; *p = f->next; free(f); --s->context->queued; }
        else { s->context->last = *p; p = &(*p)->next; }
    }
    pthread_mutex_unlock(&udpLock);
    close(s->pair[0]); close(s->pair[1]); for (size_t i = 0; i < 2; ++i) clearPartial(&s->partial[i]); free(s);
}
void hy2_engine_stop(hy2_engine_t *e) {
    ml_hy2_original_stop(e);
    pthread_mutex_lock(&udpLock);
    MLHy2Context **p = &udpContexts;
    while (*p) { if ((*p)->engine == e) { MLHy2Context *c = *p; *p = c->next; free(c); break; } p = &(*p)->next; }
    pthread_mutex_unlock(&udpLock);
}
