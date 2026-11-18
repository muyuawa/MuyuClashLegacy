#import <Foundation/Foundation.h>
#include <stdint.h>

// The immutable route contains a numeric target and an ordered array of nodes.
// nil/reject is a failed route and never permits a direct fallback.
typedef NSDictionary *(^MLDNSOutboundRoute)(NSString *host, NSString *ip,
    uint16_t port, NSString *network, NSString *explicitGroup);
NSData *MLDNSOutboundQuery(NSString *serverText, NSData *query, double deadline,
    NSString *context, NSString *caPath, BOOL respectRules, MLDNSOutboundRoute route);
