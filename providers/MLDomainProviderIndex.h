#import <Foundation/Foundation.h>

extern const NSUInteger MLDomainProviderSourceLimit;
extern const NSUInteger MLDomainProviderIndexLimit;
extern const NSUInteger MLDomainProviderPatternLimit;

NSData *MLDomainProviderCompile(NSData *source, NSString *format, NSUInteger *count, NSError **error);

@interface MLDomainProviderIndex : NSObject
@property (nonatomic, readonly) NSUInteger count;
+ (instancetype)indexWithDescriptor:(NSDictionary *)descriptor error:(NSError **)error;
- (BOOL)matchesHost:(NSString *)host;
@end
