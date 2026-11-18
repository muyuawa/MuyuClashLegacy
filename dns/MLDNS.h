#import <Foundation/Foundation.h>
@class MLFakeIP;

NSString *MLDNSUnsupportedField(NSDictionary *options);
NSArray *MLDNSGeoRequests(NSDictionary *options);
NSArray *MLDNSRuleProviderNames(NSDictionary *options);
typedef NSData *(^MLDNSExchangeHandler)(NSString *serverText, NSData *query, double absoluteDeadline, NSString *context);

@interface MLDNS : NSObject
@property(nonatomic,copy) NSString *caPath;
@property(nonatomic,copy) NSArray *bootstrapServers;
@property(nonatomic,copy) NSDictionary *hosts;
@property(nonatomic,strong) MLFakeIP *fakeIP;
@property(nonatomic,copy) MLDNSExchangeHandler exchangeHandler;
- (id)initWithOptions:(NSDictionary *)options ipv6:(BOOL)ipv6;
- (BOOL)installPreparedDocument:(NSDictionary *)document error:(NSError **)error;
- (NSDictionary *)lookup:(NSString *)host;
- (NSDictionary *)lookupProxyServer:(NSString *)host;
- (NSDictionary *)lookupDirect:(NSString *)host;
- (NSDictionary *)lookupBootstrap:(NSString *)host;
- (NSData *)answerQuery:(NSData *)query application:(BOOL)application;
- (NSString *)hostForFakeAddress:(NSString *)address;
- (void)retainFakeAddress:(NSString *)address;
- (void)releaseFakeAddress:(NSString *)address;
- (NSUInteger)flush;
- (NSUInteger)count;
@end
