#import <Foundation/Foundation.h>
@interface MLService : NSObject
@property(nonatomic,copy) NSString *coreExecutable;
@property(nonatomic) NSUInteger corePort;
@property(nonatomic,copy) NSString *controlSocket;
- (id)initWithDirectory:(NSString *)directory caPath:(NSString *)caPath error:(NSError **)error;
- (NSDictionary *)handleMethod:(NSString *)method params:(NSDictionary *)params error:(NSError **)error;
- (void)tick;
- (void)controlListenerReady;
- (void)shutdown;
@end
