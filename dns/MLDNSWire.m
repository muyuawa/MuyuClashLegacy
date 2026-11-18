#import "MLDNSWire.h"
#import "../transport/MLNetworkBinding.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>

static mach_timebase_info_data_t MLWireTimebase;
static void MLWireTimebaseInit(void) { mach_timebase_info(&MLWireTimebase); }
static uint64_t MLWireNow(void) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, MLWireTimebaseInit);
    return (uint64_t)((long double)mach_absolute_time() * MLWireTimebase.numer / MLWireTimebase.denom / 1000000);
}
static BOOL MLWireWait(int fd, short events, uint64_t deadline) {
    for (;;) {
        uint64_t now = MLWireNow();
        if (now >= deadline) { errno = ETIMEDOUT; return NO; }
        struct pollfd descriptor = { fd, events, 0 };
        int status = poll(&descriptor, 1, (int)MIN(deadline - now, (uint64_t)INT_MAX));
        if (status > 0) return !(descriptor.revents & POLLNVAL);
        if (status < 0 && errno != EINTR) return NO;
    }
}
static BOOL MLWireTransfer(int fd, SSL *tls, void *bytes, size_t length, BOOL write, uint64_t deadline) {
    size_t offset = 0;
    while (offset < length) {
        if (MLWireNow() >= deadline) { errno = ETIMEDOUT; return NO; }
        ssize_t used;
        short events = write ? POLLOUT : POLLIN;
        if (tls) {
            used = write ? SSL_write(tls, (char *)bytes + offset, (int)(length - offset))
                         : SSL_read(tls, (char *)bytes + offset, (int)(length - offset));
            if (used <= 0) {
                int error = SSL_get_error(tls, (int)used);
                if (error == SSL_ERROR_WANT_READ) events = POLLIN;
                else if (error == SSL_ERROR_WANT_WRITE) events = POLLOUT;
                else return NO;
            }
        } else {
            used = write ? send(fd, (char *)bytes + offset, length - offset, 0)
                         : recv(fd, (char *)bytes + offset, length - offset, 0);
            if (used == 0) return NO;
            if (used < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return NO;
        }
        if (used > 0) offset += (size_t)used;
        else if (!MLWireWait(fd, events, deadline)) return NO;
    }
    return YES;
}
NSData *MLDNSWireQuery(NSData *query, const struct sockaddr *server, socklen_t serverLength,
                      BOOL tcp, BOOL encrypted, NSString *serverName, NSString *caPath,
                      unsigned timeoutMS) {
    if (query.length < 12 || query.length > 4096 || !server || !timeoutMS ||
        (server->sa_family != AF_INET && server->sa_family != AF_INET6) ||
        (encrypted && (!tcp || !serverName.length || !caPath.length))) return nil;
    struct sockaddr_in6 scoped;
    if (server->sa_family==AF_INET6) {
        if (serverLength<sizeof(scoped)) return nil;
        memcpy(&scoped,server,sizeof(scoped));
        if (IN6_IS_ADDR_LINKLOCAL(&scoped.sin6_addr) && !scoped.sin6_scope_id)
            scoped.sin6_scope_id=MLNetworkInterfaceIndex();
        server=(const struct sockaddr *)&scoped;
    }
    int fd = socket(server->sa_family, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd < 0) return nil;
    uint64_t deadline = MLWireNow() + MIN(timeoutMS, 5000U);
    SSL_CTX *context = NULL;
    SSL *tls = NULL;
    NSData *answer = nil;
    int one = 1;
    if (MLNetworkBindSocket(fd, server->sa_family) || fcntl(fd, F_SETFL, O_NONBLOCK) ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) || setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one))) goto finish;
    if (connect(fd, server, serverLength) < 0) {
        if (errno != EINPROGRESS || !MLWireWait(fd, POLLOUT, deadline)) goto finish;
        int error = 0;
        socklen_t size = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) || error) goto finish;
    }
    if (encrypted) {
        context = SSL_CTX_new(TLS_client_method());
        if (!context || SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) != 1 ||
            SSL_CTX_load_verify_locations(context, caPath.fileSystemRepresentation, NULL) != 1) goto finish;
        SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
        tls = SSL_new(context);
        if (!tls || SSL_set_fd(tls, fd) != 1) goto finish;
        struct in_addr v4;
        struct in6_addr v6;
        BOOL literal = inet_pton(AF_INET, serverName.UTF8String, &v4) == 1 ||
                       inet_pton(AF_INET6, serverName.UTF8String, &v6) == 1;
        X509_VERIFY_PARAM *parameters = SSL_get0_param(tls);
        if (literal) {
            if (X509_VERIFY_PARAM_set1_ip_asc(parameters, serverName.UTF8String) != 1) goto finish;
        } else {
            X509_VERIFY_PARAM_set_hostflags(parameters, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (SSL_set_tlsext_host_name(tls, serverName.UTF8String) != 1 ||
                X509_VERIFY_PARAM_set1_host(parameters, serverName.UTF8String, 0) != 1) goto finish;
        }
        for (;;) {
            int handshake = SSL_connect(tls);
            if (handshake == 1) break;
            int error = SSL_get_error(tls, handshake);
            short events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
            if ((error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) ||
                !MLWireWait(fd, events, deadline)) goto finish;
        }
        if (SSL_get_verify_result(tls) != X509_V_OK) goto finish;
    }
    if (tcp) {
        uint16_t length = htons((uint16_t)query.length);
        if (!MLWireTransfer(fd, tls, &length, 2, YES, deadline) ||
            !MLWireTransfer(fd, tls, (void *)query.bytes, query.length, YES, deadline) ||
            !MLWireTransfer(fd, tls, &length, 2, NO, deadline)) goto finish;
        size_t received = ntohs(length);
        if (received < 12 || received > 4096) goto finish;
        NSMutableData *data = [NSMutableData dataWithLength:received];
        if (MLWireTransfer(fd, tls, data.mutableBytes, received, NO, deadline)) answer = data;
    } else {
        for (;;) {
            ssize_t count = send(fd, query.bytes, query.length, 0);
            if (count == (ssize_t)query.length) break;
            if (count >= 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) ||
                !MLWireWait(fd, POLLOUT, deadline)) goto finish;
        }
        unsigned char bytes[4097];
        for (;;) {
            if (!MLWireWait(fd, POLLIN, deadline)) goto finish;
            ssize_t count = recv(fd, bytes, sizeof(bytes), 0);
            if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            if (count < 12 || count > 4096) goto finish;
            // Connected UDP authenticates the peer. Ignore unrelated transaction IDs.
            if (bytes[0] != ((const unsigned char *)query.bytes)[0] || bytes[1] != ((const unsigned char *)query.bytes)[1]) continue;
            answer = [NSData dataWithBytes:bytes length:(NSUInteger)count];
            break;
        }
    }
finish:
    if (tls) SSL_free(tls);
    if (context) SSL_CTX_free(context);
    close(fd);
    return answer;
}
