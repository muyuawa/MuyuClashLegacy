#import <Foundation/Foundation.h>
BOOL MLRoutePrepareProviders(NSDictionary *document);
// Resolve the current complete outbound path without advancing round-robin.
NSArray *MLPolicyChain(NSDictionary *document, NSString *target, NSDictionary *selections, NSDictionary *measurements);

// These entry points take the immutable document from MLConfig. A route reports
// the original rule, target, selected outbound node and outermost group. The
// rule and group are empty strings when absent.
NSDictionary *MLRoute(NSDictionary *document, NSString *mode, NSDictionary *selections,
                      NSString *host, NSString *ip, NSString *source, NSUInteger sourcePort,
                      NSUInteger destPort, NSString *network);

// The callback runs at most once if a destination IP rule needs a hostname
// lookup. Its answer can satisfy subsequent no-resolve rules. A known
// destination IP, including a literal host, is returned as ip.
NSDictionary *MLRouteWithResolver(NSDictionary *document, NSString *mode, NSDictionary *selections,
                                  NSString *host, NSString *ip, NSString *source,
                                  NSUInteger sourcePort, NSUInteger destPort, NSString *network,
                                  NSString *(^resolveIP)(void));

NSArray *MLGroups(NSDictionary *document, NSDictionary *selections);
NSArray *MLProxies(NSDictionary *document, NSDictionary *selections, NSString *group);
BOOL MLCanSelect(NSDictionary *document, NSString *group, NSString *node);

// Runtime measurements are keyed by node name and group URL, as returned by
// MLPolicyScheduler. Metadata contains host/ip/source/sourcePort/destPort/network
// and optional verified processName/processPath/country/asn values.
NSDictionary *MLRouteWithRuntime(NSDictionary *document, NSString *mode, NSDictionary *selections,
                                NSDictionary *measurements, NSMutableDictionary *counters,
                                NSDictionary *metadata, NSString *(^resolveIP)(void));
NSDictionary *MLRouteTargetWithRuntime(NSDictionary *document, NSString *target, NSDictionary *selections,
                                      NSDictionary *measurements, NSMutableDictionary *counters, NSDictionary *metadata);
// Default/MATCH path for status only: no DNS, lazy probes, or round-robin changes.
NSDictionary *MLDefaultRouteWithRuntime(NSDictionary *document, NSString *mode, NSDictionary *selections, NSDictionary *measurements);
NSArray *MLGroupsWithRuntime(NSDictionary *document, NSDictionary *selections, NSDictionary *measurements);
NSArray *MLProxiesWithRuntime(NSDictionary *document, NSDictionary *selections,
                             NSDictionary *measurements, NSString *group);
NSString *MLPolicyMeasurementKey(NSString *name, NSString *url);
