#import <Foundation/Foundation.h>
FOUNDATION_EXPORT NSString *MLFetchSubscription(NSString *url, NSString *caPath, NSError **error);
FOUNDATION_EXPORT NSData *MLFetchData(NSString *url, NSString *caPath, NSUInteger maxBytes, NSError **error);
FOUNDATION_EXPORT NSData *MLFetchDataWithTimeout(NSString *url, NSString *caPath, NSUInteger maxBytes, NSUInteger timeoutMS, NSError **error);
