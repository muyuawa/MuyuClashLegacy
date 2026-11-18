#import <Foundation/Foundation.h>

// The directory is a fixed private root. Relative file providers are resolved
// exclusively below directory/local; accepted snapshots live in directory/cache.
@interface MLProviderManager : NSObject
- (id)initWithDirectory:(NSString *)directory caPath:(NSString *)caPath error:(NSError **)error;
- (id)initWithDirectory:(NSString *)directory readableDirectory:(NSString *)readableDirectory caPath:(NSString *)caPath error:(NSError **)error;
// Runs bounded downloads and parsing synchronously, so call on a worker queue
// outside the Supervisor state lock. nil refreshNames updates missing/stale
// sources; a non-nil set forces only the named provider(s), with cached others.
// Only commitPreparedDocument publishes the prepared snapshot pointers.
- (NSDictionary *)prepareDocument:(NSDictionary *)document refreshNames:(NSSet *)refreshNames error:(NSError **)error;
- (BOOL)commitPreparedDocument:(NSDictionary *)document error:(NSError **)error;
- (void)discardPreparedDocument;
- (NSArray *)list;
- (NSSet *)dueProviderNames;
- (NSDictionary *)sourceDocument;
// Internal Coordinator recovery only; opaque snapshots must never enter IPC.
- (id)captureCheckpoint;
- (BOOL)restoreCheckpoint:(id)checkpoint error:(NSError **)error;
// Explicit text import for a relative local provider path, max 512 KiB.
- (BOOL)importLocalText:(NSString *)text path:(NSString *)path error:(NSError **)error;
@end
