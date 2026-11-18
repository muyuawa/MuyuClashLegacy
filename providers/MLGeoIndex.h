#import <Foundation/Foundation.h>
#include <sys/socket.h>
@interface MLGeoIndex : NSObject
+ (id)indexWithDescriptor:(NSDictionary *)descriptor error:(NSError **)error;
- (BOOL)containsKind:(NSString *)kind operand:(NSString *)operand;
- (BOOL)matchKind:(NSString *)kind operand:(NSString *)operand family:(int)family
         address:(const unsigned char *)address domain:(NSString *)domain usable:(BOOL *)usable;
@end
