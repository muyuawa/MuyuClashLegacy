#import <Foundation/Foundation.h>

// Supervisor-owned schedule/override metadata, in one dedicated private folder.
// Every method validates storage under a private operation/file lock. Call these
// methods outside the Supervisor state lock; downloads and Store work belong to
// the coordinator after claimDueSchedule... returns its immutable job lease.
@interface MLProfileMaintenance : NSObject
- (id)initWithDirectory:(NSString *)directory error:(NSError **)error;
+ (NSArray *)allowedOverrideFields;
- (NSDictionary *)scheduleForID:(NSString *)identifier error:(NSError **)error;
- (BOOL)setScheduleInterval:(NSUInteger)interval forID:(NSString *)identifier error:(NSError **)error;
// At most one claimed job. Returns nil with no error when nothing is due/busy.
- (NSDictionary *)claimDueScheduleAtTime:(NSTimeInterval)time uptime:(NSTimeInterval)uptime error:(NSError **)error;
- (BOOL)isCurrentScheduleClaim:(NSDictionary *)claim error:(NSError **)error;
// A changed/disabled plan only releases the old job. A successful replacement
// moves its unchanged schedule and overrides to the new protected Store ID.
- (BOOL)finishScheduleForID:(NSString *)identifier replacementID:(NSString *)replacementID success:(BOOL)success
                 errorCode:(NSString *)errorCode time:(NSTimeInterval)time uptime:(NSTimeInterval)uptime error:(NSError **)error;
- (NSDictionary *)overridesForID:(NSString *)identifier error:(NSError **)error;
- (BOOL)setOverrides:(NSDictionary *)overrides forID:(NSString *)identifier error:(NSError **)error;
// Dictionary values merge recursively, arrays/scalars replace. The coordinator
// must check the complete merged source with MLConfig before preparing it.
- (NSDictionary *)mergedDocument:(NSDictionary *)document forID:(NSString *)identifier error:(NSError **)error;
@end
