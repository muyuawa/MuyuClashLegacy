#import <Foundation/Foundation.h>
#include <sys/socket.h>

// One bounded exchange. TCP retries/truncation policy belongs to the resolver.
NSData *MLDNSWireQuery(NSData *query, const struct sockaddr *server, socklen_t serverLength,
                      BOOL tcp, BOOL tls, NSString *serverName, NSString *caPath,
                      unsigned timeoutMS);
