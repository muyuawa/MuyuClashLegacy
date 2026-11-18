#import <Foundation/Foundation.h>

BOOL MLProbeURLIsValid(NSString *url);
NSDictionary *MLProbeStream(NSString *node, NSString *url);
NSDictionary *MLProbeStreamWithTimeout(NSString *node, NSString *url, NSUInteger timeout);
