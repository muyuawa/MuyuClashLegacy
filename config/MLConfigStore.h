#import <Foundation/Foundation.h>

@interface MLConfigStore : NSObject
- (id)initWithDirectory:(NSString *)directory error:(NSError **)error;
- (NSDictionary *)importYAML:(NSString *)yaml name:(NSString *)name source:(NSString *)source error:(NSError **)error;
- (NSArray *)list;
- (NSDictionary *)sourceForID:(NSString *)identifier error:(NSError **)error;
- (NSDictionary *)renameID:(NSString *)identifier name:(NSString *)name source:(NSString *)source error:(NSError **)error;
- (BOOL)removeID:(NSString *)identifier error:(NSError **)error;
// prepare receives the immutable parsed configuration. No active marker is changed on NO.
- (BOOL)activateID:(NSString *)identifier prepare:(BOOL (^)(NSDictionary *,NSError **))prepare error:(NSError **)error;
// Downloads/Core preparation happen before this short compare-and-swap.
- (BOOL)activatePreparedID:(NSString *)identifier expectedYAML:(NSString *)yaml ifActiveID:(NSString *)previous error:(NSError **)error;
- (NSString *)activeID;
- (NSDictionary *)selectionsForID:(NSString *)identifier;
- (BOOL)saveSelections:(NSDictionary *)selections forID:(NSString *)identifier error:(NSError **)error;
- (BOOL)restoreActiveID:(NSString *)previous ifCurrent:(NSString *)candidate error:(NSError **)error;
@end
