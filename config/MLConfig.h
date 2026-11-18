#import <Foundation/Foundation.h>

// Immutable validation report. `valid` never means an operational proxy is ready.
@interface MLConfig : NSObject
+ (NSDictionary *)checkYAML:(NSString *)yaml;
// Internal Provider generation only; public YAML cannot inject reserved fields.
+ (NSDictionary *)checkPreparedDocument:(NSDictionary *)document;
@end
