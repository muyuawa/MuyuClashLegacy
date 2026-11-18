#import "MLCaptureCoordinator.h"
#include <netinet/in.h>

// Injection boundary for host transaction tests. The default backend refuses
// every mutating operation on a host build.
@protocol MLCaptureBackend <NSObject>
- (NSDictionary *)openDevice:(NSError **)error;
- (BOOL)closeDevice:(NSError **)error;
- (NSDictionary *)physicalPath:(NSError **)error;
- (unsigned)indexForInterface:(NSString *)name;
- (NSDictionary *)routeForDestination:(NSString *)destination prefix:(unsigned)prefix interfaceIndex:(unsigned)index error:(NSError **)error;
- (BOOL)addRoute:(NSDictionary *)route error:(NSError **)error;
- (BOOL)deleteRoute:(NSDictionary *)route error:(NSError **)error;
- (BOOL)publishDNS:(NSString *)interface nonce:(NSString *)nonce error:(NSError **)error;
- (BOOL)withdrawDNS:(NSString *)nonce error:(NSError **)error;
@optional
- (NSDictionary *)physicalSignature:(NSError **)error;
@end
@interface MLCaptureCoordinator (Testing)
- (id)initWithStateDirectory:(NSString *)directory backend:(id<MLCaptureBackend>)backend error:(NSError **)error;
@end
BOOL MLCaptureRecoverWithBackend(NSString *directory, id<MLCaptureBackend> backend, NSError **error);
id<MLCaptureBackend> MLCaptureSystemBackend(void);
NSString *MLCaptureIPv6SourceNetwork(const struct in6_addr *address, const struct sockaddr_in6 *mask);
// DNS-only configd publication; adding IPv4 service state creates a default
// route on XNU 2050 even without a Router field.
NSDictionary *MLCaptureDNSPublication(NSString *interface, NSString *nonce);
int MLCaptureGuardianRun(NSString *directory, int control, int device, int lifetime,
    int lease, id<MLCaptureBackend> backend);
