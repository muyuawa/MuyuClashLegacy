#import <Foundation/Foundation.h>
#include <stdint.h>
#include <poll.h>

// All datagram operations after open run on the packet thread. EAGAIN means
// backpressure; a nil receive with no error means no packet is ready.
@protocol MLPacketDatagram <NSObject>
@property(nonatomic,readonly) int fileDescriptor;
- (BOOL)sendData:(NSData *)data error:(NSError **)error;
- (NSData *)receiveData:(NSError **)error;
- (short)eventsForRead:(BOOL)read write:(BOOL)write;
- (void)close;
@end

// Return {host, nodeJSON, chainJSON, metadata} or {reject:true}. chainJSON is an
// ordered node JSON array used by TCP. Both omitted select DIRECT. UDP factory
// must reject unsupported chain combinations. host may restore a Fake-IP to its real hostname. The immutable route
// is retained for the lifetime of its TCP or UDP flow.
typedef NSDictionary *(^MLPacketRouteHandler)(NSString *destination, NSString *source,
    uint16_t sourcePort, uint16_t destinationPort, NSString *network);
typedef id<MLPacketDatagram> (^MLPacketDatagramFactory)(NSDictionary *route, uint16_t port, NSError **error);
typedef NSData *(^MLPacketDNSHandler)(NSData *query);
typedef void (^MLPacketAddressHandler)(NSString *address);

@interface MLPacketBridge : NSObject
// The bridge duplicates fd and owns only that duplicate. root keeps its copy
// alive for strict blocking, and closes it after the core has stopped.
- (id)initWithFileDescriptor:(int)fd interfaceName:(NSString *)name
    route:(MLPacketRouteHandler)route datagram:(MLPacketDatagramFactory)datagram
    dns:(MLPacketDNSHandler)dns retainAddress:(MLPacketAddressHandler)retainAddress
    releaseAddress:(MLPacketAddressHandler)releaseAddress;
- (BOOL)start:(NSError **)error;
- (void)stop;
- (BOOL)running;
- (NSDictionary *)readiness;
- (NSDictionary *)statistics;
- (NSArray *)connections;
// Last successfully opened non-DNS outbound; retained after short flows close.
- (NSDictionary *)lastConnection;
- (BOOL)closeConnection:(NSString *)identifier;
@end
