#import <Foundation/Foundation.h>
// Supervisor-owned private source cache plus public, immutable Core indices.
@interface MLGeoDataManager : NSObject
- (id)initWithDirectory:(NSString *)directory readableDirectory:(NSString *)readableDirectory
                caPath:(NSString *)caPath error:(NSError **)error;
- (id)initWithDirectory:(NSString *)directory readableDirectory:(NSString *)readableDirectory
                caPath:(NSString *)caPath bundledDirectory:(NSString *)bundledDirectory error:(NSError **)error;
// Runs downloads/decoding off the Supervisor state lock. fetch:NO is cache-only.
- (NSDictionary *)prepareDocument:(NSDictionary *)document fetch:(BOOL)fetch refresh:(BOOL)refresh error:(NSError **)error;
- (BOOL)commitPreparedDocument:(NSDictionary *)document error:(NSError **)error;
- (void)discardPreparedDocument;
- (NSArray *)list;
- (BOOL)dueRefresh;
- (id)captureCheckpoint;
- (BOOL)restoreCheckpoint:(id)checkpoint error:(NSError **)error;
@end
