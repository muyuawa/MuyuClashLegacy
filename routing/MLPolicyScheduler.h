#import <Foundation/Foundation.h>

// The callback performs an actual request through this node. nil node means
// DIRECT. Return actual {health:"healthy",status:HTTPStatus,delay:milliseconds}
// or a real failure state. The owner interprets its own expected-status range.
// A complete nested/dialer chain is {name:target,_muyu-probe-chain:[nodes]}.
typedef NSDictionary *(^MLPolicyHealthProbe)(NSDictionary *node, NSString *url, NSUInteger timeout);

@interface MLPolicyScheduler : NSObject
- (id)initWithProbe:(MLPolicyHealthProbe)probe;
- (void)replaceDocument:(NSDictionary *)document;
- (void)replaceSelections:(NSDictionary *)selections;
// Safe to call once per second; network work always runs off the caller's queue.
- (void)tick;
- (void)stop;
- (NSDictionary *)measurements;
// Latest actual observation per node, while measurements preserves all URLs.
- (NSDictionary *)nodesMeasurements;
- (NSDictionary *)routeMode:(NSString *)mode selections:(NSDictionary *)selections
                  metadata:(NSDictionary *)metadata resolveIP:(NSString *(^)(void))resolveIP;
- (NSDictionary *)routeTarget:(NSString *)target selections:(NSDictionary *)selections metadata:(NSDictionary *)metadata;
- (NSArray *)groupsWithSelections:(NSDictionary *)selections;
- (NSArray *)proxiesWithSelections:(NSDictionary *)selections group:(NSString *)group;
// Explicit tests bypass the lazy flag but preserve concurrency/resource limits.
- (BOOL)requestProbeNames:(NSArray *)names url:(NSString *)url timeout:(NSUInteger)timeout;
@end
