#import <Foundation/Foundation.h>
// MRSv1 (zstd) domain/IP rules, with bounded decoding and format validation.
NSArray *MLMRSDecode(NSData *compressed, NSString *behavior, NSError **error);
