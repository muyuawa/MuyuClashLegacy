#ifndef ML_NETWORK_BINDING_H
#define ML_NETWORK_BINDING_H
#include <stddef.h>
#include <netdb.h>

// Set before installing capture routes. Zero is the uncaptured development path.
// Every outbound socket must bind before connect/sendto while capture is active.
void MLNetworkSetInterfaceIndex(unsigned int index);
unsigned int MLNetworkInterfaceIndex(void);
int MLNetworkBindSocket(int fd, int family);

// The owner/context must live for the process lifetime. DNS workers return numeric
// addresses using explicit bootstrap upstreams, avoiding system resolver recursion.
typedef size_t (*MLNetworkResolver)(const char *host, char addresses[][46], size_t capacity, void *context);
void MLNetworkSetResolver(MLNetworkResolver resolver, void *context);
void MLNetworkSetBootstrapResolver(MLNetworkResolver resolver, void *context);
int MLNetworkResolveHost(const char *host, const char *service,
                         const struct addrinfo *hints, struct addrinfo **result);
int MLNetworkResolveBootstrapHost(const char *host, const char *service,
                                  const struct addrinfo *hints, struct addrinfo **result);

#endif
