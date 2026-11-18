#import <Foundation/Foundation.h>

@interface MLCoreProcess : NSObject
@property(nonatomic,readonly) pid_t pid;
@property(nonatomic,readonly) NSUInteger port;
- (BOOL)start:(NSString *)executable port:(NSUInteger)port error:(NSError **)error;
- (BOOL)start:(NSString *)executable port:(NSUInteger)port captureFD:(int)captureFD
    lifetimeFD:(int)lifetimeFD outboundInterface:(unsigned)index interfaceName:(NSString *)name error:(NSError **)error;
- (NSDictionary *)request:(NSString *)method params:(NSDictionary *)params error:(NSError **)error;
- (BOOL)running;
- (void)stop;
@end
