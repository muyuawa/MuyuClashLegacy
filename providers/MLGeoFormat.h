#import <Foundation/Foundation.h>
// Compact IP payloads are sorted merged {family,from[16],to[16]} records.
// Site payloads are {type,uint16 UTF8 length,UTF8} records.
NSDictionary *MLGeoDecodeDat(NSData *data, NSString *kind, NSSet *requested, NSError **error);
NSDictionary *MLGeoDecodeMMDB(NSString *path, NSString *kind, NSSet *requested, NSError **error);
NSData *MLGeoEncodeIndex(NSDictionary *sets, NSError **error);
NSString *MLGeoNormalizedKey(NSString *kind, NSString *operand);
