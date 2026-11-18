#import <Foundation/Foundation.h>
#include <stdint.h>
// XNU's __proc_info signature; injection is used only by focused host tests.
typedef int (*MLProcessInformation)(int call,int pid,int flavor,uint64_t argument,void *buffer,int size);
@interface MLProcessOwner : NSObject
- (id)initWithBudgetMilliseconds:(unsigned)milliseconds;
- (id)initWithInformationFunction:(MLProcessInformation)information budgetMilliseconds:(unsigned)milliseconds;
// Root-only lookup of an application socket tuple. No caller-supplied process
// name/path is consumed. A verified result contains pid/processName/processPath;
// failures and ambiguous ownership return verified:false with a controlled reason.
- (NSDictionary *)lookupSource:(NSString *)source sourcePort:(uint16_t)sourcePort
    destination:(NSString *)destination destinationPort:(uint16_t)destinationPort network:(NSString *)network;
- (NSDictionary *)status;
@end
