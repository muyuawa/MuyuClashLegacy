#import <Foundation/Foundation.h>

@interface MLFakeIP : NSObject
// Installed by Core before serving DNS. A new mapping is returned only after ACK.
@property(nonatomic,copy) BOOL (^persistenceHandler)(NSDictionary *snapshot);
- (id)initWithRange:(NSString *)range ipv6Range:(NSString *)range6 capacity:(NSUInteger)capacity;
// v1 snapshots may include a bounded retired address-pair array. Retired
// addresses cannot be reused for 300 monotonic seconds after eviction; all
// persisted pairs restart that full cooldown when restored after a crash.
- (NSDictionary *)snapshot;
- (BOOL)restoreSnapshot:(NSDictionary *)snapshot error:(NSError **)error;
- (NSString *)addressForHost:(NSString *)host ipv6:(BOOL)ipv6;
- (NSString *)hostForAddress:(NSString *)address;
- (BOOL)containsAddress:(NSString *)address;
- (void)retainAddress:(NSString *)address;
- (void)releaseAddress:(NSString *)address;
- (NSDictionary *)statistics;
@end
