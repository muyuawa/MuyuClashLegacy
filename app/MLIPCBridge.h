#import <Foundation/Foundation.h>

#if __has_include("../ipc/MLIPC.h")
#import "../ipc/MLIPC.h"
#else
// The production implementation is supplied by ipc/MLIPC.m.
FOUNDATION_EXPORT NSDictionary *MLIPCRequest(NSString *socketPath, NSString *method,
                                            NSDictionary *params, NSError **error);
#endif
