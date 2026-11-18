#import <Foundation/Foundation.h>

// Bounded version-1 JSON IPC. Always call synchronous requests off the UI thread.
FOUNDATION_EXPORT NSString * const MLControlSocket;
FOUNDATION_EXPORT NSDictionary *MLIPCRequest(NSString *socketPath, NSString *method,
                                             NSDictionary *params, NSError **error);
// A supervised Core receives this expected owner through its private socketpair.
FOUNDATION_EXPORT NSDictionary *MLIPCRequestWithOwner(NSString *socketPath, uid_t owner,
    NSString *method, NSDictionary *params, NSError **error);
FOUNDATION_EXPORT BOOL MLIPCWriteFrame(int fd, NSDictionary *message, NSError **error);
FOUNDATION_EXPORT BOOL MLIPCWriteReply(int fd, NSDictionary *request, NSDictionary *response);
FOUNDATION_EXPORT NSDictionary *MLIPCReadFrame(int fd, NSError **error);
FOUNDATION_EXPORT void MLIPCSetTimeout(int fd, unsigned seconds);
FOUNDATION_EXPORT NSDictionary *MLIPCResponse(NSDictionary *request, NSDictionary *result,
                                              NSString *code, NSString *message);
FOUNDATION_EXPORT BOOL MLIPCValidRequest(NSDictionary *request);
FOUNDATION_EXPORT BOOL MLIPCPeerAllowed(int fd, uid_t owner);
