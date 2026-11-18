#import <Foundation/Foundation.h>
// Shared private storage checks for Supervisor-owned Provider/Geo data.
BOOL MLProviderPrivateDirectory(NSString *path, BOOL create, BOOL private, NSError **error);
NSData *MLProviderPrivateRead(NSString *path, NSUInteger limit, NSError **error);
BOOL MLProviderPrivateWrite(NSString *path, NSData *data, NSError **error);
NSString *MLProviderStorageHash(NSData *data);
BOOL MLProviderStorageIsTemporaryName(NSString *name);
// Owned staging files older than one day may be removed. NSNotFound means removed.
BOOL MLProviderStorageInspectTemporary(NSString *path, NSUInteger limit, BOOL allowReadOnly, NSUInteger *size, NSError **error);
