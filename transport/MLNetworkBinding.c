#include "MLNetworkBinding.h"
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

static pthread_mutex_t MLInterfaceLock = PTHREAD_MUTEX_INITIALIZER;
static unsigned int MLPhysicalInterface;
static MLNetworkResolver MLResolver;
static void *MLResolverContext;
static MLNetworkResolver MLBootstrapResolver;
static void *MLBootstrapContext;

void MLNetworkSetInterfaceIndex(unsigned int index) {
    pthread_mutex_lock(&MLInterfaceLock);
    MLPhysicalInterface = index;
    pthread_mutex_unlock(&MLInterfaceLock);
}

unsigned int MLNetworkInterfaceIndex(void) {
    pthread_mutex_lock(&MLInterfaceLock);
    unsigned int index = MLPhysicalInterface;
    pthread_mutex_unlock(&MLInterfaceLock);
    return index;
}

int MLNetworkBindSocket(int fd, int family) {
    unsigned int index = MLNetworkInterfaceIndex();
    if (!index) return 0;
    if (family == AF_UNSPEC) {
        struct sockaddr_storage address;
        socklen_t size = sizeof(address);
        if (getsockname(fd, (struct sockaddr *)&address, &size)) return -1;
        family = address.ss_family;
    }
    if (family == AF_INET)
        return setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index));
    if (family == AF_INET6)
        return setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &index, sizeof(index));
    errno = EAFNOSUPPORT;
    return -1;
}

void MLNetworkSetResolver(MLNetworkResolver resolver, void *context) {
    pthread_mutex_lock(&MLInterfaceLock);
    MLResolver = resolver;
    MLResolverContext = context;
    pthread_mutex_unlock(&MLInterfaceLock);
}

void MLNetworkSetBootstrapResolver(MLNetworkResolver resolver, void *context) {
    pthread_mutex_lock(&MLInterfaceLock);
    MLBootstrapResolver = resolver;
    MLBootstrapContext = context;
    pthread_mutex_unlock(&MLInterfaceLock);
}

static int MLResolve(const char *host, const char *service,
                     const struct addrinfo *hints, struct addrinfo **result, int bootstrap) {
    if (!result) return EAI_FAIL;
    *result = NULL;
    struct in_addr v4;
    struct in6_addr v6;
    if (!host || inet_pton(AF_INET, host, &v4) == 1 || inet_pton(AF_INET6, host, &v6) == 1)
        return getaddrinfo(host, service, hints, result);
    pthread_mutex_lock(&MLInterfaceLock);
    unsigned int physical = MLPhysicalInterface;
    MLNetworkResolver resolver = bootstrap ? MLBootstrapResolver : MLResolver;
    void *context = bootstrap ? MLBootstrapContext : MLResolverContext;
    pthread_mutex_unlock(&MLInterfaceLock);
    if (!resolver) return physical ? EAI_FAIL : getaddrinfo(host, service, hints, result);
    char addresses[16][46] = {{0}};
    size_t count = resolver(host, addresses, 16, context);
    if (count > 16) return EAI_FAIL;
    struct addrinfo numeric = hints ? *hints : (struct addrinfo){0};
    numeric.ai_flags |= AI_NUMERICHOST;
    struct addrinfo **tail = result;
    for (size_t i = 0; i < count; i++) {
        if (!memchr(addresses[i], 0, sizeof addresses[i])) continue;
        struct addrinfo *items = NULL;
        if (getaddrinfo(addresses[i], service, &numeric, &items)) continue;
        for (struct addrinfo *item=items;item;item=item->ai_next) if (item->ai_family==AF_INET6) {
            struct sockaddr_in6 *address=(struct sockaddr_in6 *)item->ai_addr;
            if (IN6_IS_ADDR_LINKLOCAL(&address->sin6_addr) && !address->sin6_scope_id) address->sin6_scope_id=physical;
        }
        *tail = items;
        while (*tail) tail = &(*tail)->ai_next;
    }
    return *result ? 0 : EAI_NONAME;
}

int MLNetworkResolveHost(const char *host, const char *service,
                         const struct addrinfo *hints, struct addrinfo **result) {
    return MLResolve(host, service, hints, result, 0);
}

int MLNetworkResolveBootstrapHost(const char *host, const char *service,
                                  const struct addrinfo *hints, struct addrinfo **result) {
    return MLResolve(host, service, hints, result, 1);
}
