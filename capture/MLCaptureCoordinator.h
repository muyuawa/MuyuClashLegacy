#import <Foundation/Foundation.h>

// The root supervisor owns the device and network transaction. The unprivileged
// packet core borrows a duplicated descriptor; it never modifies system routes.
@interface MLCaptureCoordinator : NSObject
@property(nonatomic,readonly) int fileDescriptor;
// Duplicate this pipe writer into Core FD 4, then call coreDidStart. It proves
// Core lifetime independently of Supervisor and must remain open until exit.
@property(nonatomic,readonly) int coreLifetimeDescriptor;
@property(nonatomic,readonly) BOOL resumedGuardian;
@property(nonatomic,readonly) unsigned interfaceIndex;
@property(nonatomic,readonly) unsigned outboundInterfaceIndex;
@property(nonatomic,readonly,copy) NSString *interfaceName;
- (id)initWithStateDirectory:(NSString *)directory error:(NSError **)error;
- (BOOL)prepare:(NSError **)error;
- (BOOL)startGuardianWithExecutable:(NSString *)executable strictBlock:(BOOL)strict error:(NSError **)error;
- (void)coreDidStart;
- (BOOL)prepareCoreLifetime:(NSError **)error;
- (BOOL)setStrictBlock:(BOOL)strict error:(NSError **)error;
// Read-only check of physical defaults, interface addresses and DHCP DNS.
- (BOOL)checkPhysicalPathChanged:(BOOL *)changed error:(NSError **)error;
// Call only after the packet core acknowledged all four packet handlers.
- (BOOL)activateWithCoreReady:(NSDictionary *)ready error:(NSError **)error;
- (BOOL)coreFailedWithStrictBlock:(BOOL)strict error:(NSError **)error;
- (BOOL)restore:(NSError **)error;
- (NSDictionary *)status;
@end

// Independent recovery, used before launch and after unloading on uninstall.
BOOL MLCaptureRecover(NSString *directory, NSError **error);
// Explicit emergency recovery can ask an orphaned guardian to release its
// lease. A guardian whose Supervisor is still alive rejects this request.
BOOL MLCaptureEmergencyRecover(NSString *directory, NSError **error);
