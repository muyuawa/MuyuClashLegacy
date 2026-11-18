#import "MLConfigStore.h"
#import "MLConfig.h"
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static const NSUInteger MLRecordLimit=4*1024*1024;
static void MLStoreError(NSError **error, NSInteger code, NSString *message) {
    if(error)*error=[NSError errorWithDomain:@"MuyuClash.Config" code:code userInfo:@{NSLocalizedDescriptionKey:message}];
}
static BOOL MLValidID(NSString *identifier) {
    return [identifier isKindOfClass:[NSString class]] && identifier.length==36 &&
      [identifier rangeOfString:@"^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$" options:NSRegularExpressionSearch].location==0;
}
static NSString *MLUUID(void) {
    CFUUIDRef uuid=CFUUIDCreate(kCFAllocatorDefault);
    if(!uuid)return nil;
    CFStringRef text=CFUUIDCreateString(kCFAllocatorDefault,uuid);CFRelease(uuid);
    return CFBridgingRelease(text);
}
static BOOL MLWriteBytes(int fd, NSData *data) {
    const unsigned char *bytes=data.bytes;NSUInteger remaining=data.length;
    while(remaining){ssize_t count=write(fd,bytes,remaining);if(count<0 && errno==EINTR)continue;if(count<=0)return NO;bytes+=count;remaining-=(NSUInteger)count;}
    return YES;
}
static BOOL MLSafeChain(NSString *directory, BOOL create, NSError **error) {
    if(![directory isKindOfClass:[NSString class]] || !directory.isAbsolutePath || [directory isEqual:@"/"] ||
       [directory.pathComponents containsObject:@".."] || [directory rangeOfString:@"\0"].location!=NSNotFound){
        MLStoreError(error,1,@"Configuration storage requires an absolute application-owned directory without traversal.");return NO;
    }
    NSString *path=@"/";
    for(NSString *part in directory.pathComponents){
        if([part isEqual:@"/"] || [part isEqual:@"."])continue;
        path=[path stringByAppendingPathComponent:part];struct stat status;
        if(lstat(path.fileSystemRepresentation,&status)!=0){
            if(errno!=ENOENT || !create || mkdir(path.fileSystemRepresentation,0700)!=0){MLStoreError(error,errno,@"Cannot create or inspect the private configuration directory.");return NO;}
            if(lstat(path.fileSystemRepresentation,&status)!=0){MLStoreError(error,errno,@"Cannot inspect the created configuration directory.");return NO;}
        }
        if(S_ISLNK(status.st_mode) || !S_ISDIR(status.st_mode)){MLStoreError(error,2,@"Symlinks and non-directory storage paths are forbidden.");return NO;}
    }
    return YES;
}

@implementation MLConfigStore {
    NSString *_directory;
    int _directoryFD;
    int _lockFD;
    dev_t _device;
    ino_t _inode;
}
- (id)initWithDirectory:(NSString *)directory error:(NSError **)error {
    if(error)*error=nil;
    if((self=[super init])){
        _directoryFD=-1;_lockFD=-1;
        if(!MLSafeChain(directory,YES,error))return nil;
        _directory=[directory copy];
        _directoryFD=open(_directory.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
        struct stat status;
        if(_directoryFD<0 || fstat(_directoryFD,&status)!=0 || !S_ISDIR(status.st_mode) || status.st_uid!=geteuid()){
            MLStoreError(error,3,@"The configuration directory must belong to this service's user.");return nil;
        }
        if(fchmod(_directoryFD,0700)!=0){MLStoreError(error,errno,@"Cannot make configuration storage private.");return nil;}
        _device=status.st_dev;_inode=status.st_ino;
        NSString *lock=[_directory stringByAppendingPathComponent:@"store.lock"];
        _lockFD=open(lock.fileSystemRepresentation,O_RDWR|O_CREAT|O_NOFOLLOW,0600);
        if(_lockFD<0 || fstat(_lockFD,&status)!=0 || !S_ISREG(status.st_mode) || status.st_nlink!=1 || status.st_uid!=geteuid()){
            MLStoreError(error,4,@"Cannot safely open the private configuration lock.");return nil;
        }
        if(fchmod(_lockFD,0600)!=0){MLStoreError(error,errno,@"Cannot protect the configuration lock.");return nil;}
        (void)fcntl(_directoryFD,F_SETFD,FD_CLOEXEC);(void)fcntl(_lockFD,F_SETFD,FD_CLOEXEC);
    }
    return self;
}
- (void)dealloc {if(_lockFD>=0)close(_lockFD);if(_directoryFD>=0)close(_directoryFD);}
- (BOOL)integrity:(NSError **)error {
    struct stat status;
    if(!MLSafeChain(_directory,NO,error))return NO;
    if(lstat(_directory.fileSystemRepresentation,&status)!=0 || !S_ISDIR(status.st_mode) ||
       status.st_uid!=geteuid() || (status.st_mode&0777)!=0700 || status.st_dev!=_device || status.st_ino!=_inode){
        MLStoreError(error,5,@"The private configuration directory was replaced or its permissions changed.");return NO;
    }
    return YES;
}
- (BOOL)lock:(NSError **)error {
    if(![self integrity:error])return NO;
    int result;do{result=flock(_lockFD,LOCK_EX);}while(result<0 && errno==EINTR);
    if(result<0){MLStoreError(error,errno,@"Cannot lock configuration storage.");return NO;}
    if(![self integrity:error]){flock(_lockFD,LOCK_UN);return NO;}
    return YES;
}
- (NSData *)readFile:(NSString *)name limit:(NSUInteger)limit missingOK:(BOOL)missingOK error:(NSError **)error {
    NSString *path=[_directory stringByAppendingPathComponent:name];
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW);
    if(fd<0){if(!(missingOK && errno==ENOENT))MLStoreError(error,errno,@"Cannot safely read the configuration record.");return nil;}
    struct stat status;
    if(fstat(fd,&status)!=0 || !S_ISREG(status.st_mode) || status.st_nlink!=1 || status.st_uid!=geteuid() ||
       (status.st_mode&0777)!=0600 || status.st_size<0 || (uint64_t)status.st_size>limit){
        close(fd);MLStoreError(error,6,@"Configuration record type, ownership, permissions or size is unsafe.");return nil;
    }
    NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)status.st_size];
    unsigned char *buffer=data.mutableBytes;NSUInteger offset=0;
    while(offset<data.length){ssize_t count=read(fd,buffer+offset,data.length-offset);if(count<0 && errno==EINTR)continue;if(count<=0){close(fd);MLStoreError(error,7,@"The configuration record was truncated while reading.");return nil;}offset+=(NSUInteger)count;}
    unsigned char extra;ssize_t more;do{more=read(fd,&extra,1);}while(more<0&&errno==EINTR);close(fd);
    if(more!=0){MLStoreError(error,8,@"The configuration record changed while reading.");return nil;}
    return [data copy];
}
- (BOOL)atomicWrite:(NSData *)data name:(NSString *)name error:(NSError **)error {
    if(![self integrity:error])return NO;
    NSString *destination=[_directory stringByAppendingPathComponent:name];
    struct stat existing;
    if(lstat(destination.fileSystemRepresentation,&existing)==0 &&
       (!S_ISREG(existing.st_mode) || existing.st_nlink!=1 || existing.st_uid!=geteuid() || (existing.st_mode&0777)!=0600)){
        MLStoreError(error,9,@"Refusing to replace an unsafe configuration record.");return NO;
    }
    if(fsync(_directoryFD)!=0){MLStoreError(error,errno,@"Cannot synchronize configuration storage before the transaction.");return NO;}
    NSString *temporary=[_directory stringByAppendingPathComponent:[@".write-" stringByAppendingString:MLUUID() ?: @"failed"]];
    int fd=open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    if(fd<0){MLStoreError(error,errno,@"Cannot create a private configuration transaction.");return NO;}
    BOOL okay=fchmod(fd,0600)==0 && MLWriteBytes(fd,data) && fsync(fd)==0;
    int saved=errno;if(close(fd)!=0){okay=NO;saved=errno;}
    if(!okay){unlink(temporary.fileSystemRepresentation);MLStoreError(error,saved,@"Cannot write and synchronize the complete configuration transaction.");return NO;}
    if(rename(temporary.fileSystemRepresentation,destination.fileSystemRepresentation)!=0){saved=errno;unlink(temporary.fileSystemRepresentation);MLStoreError(error,saved,@"Cannot atomically commit the configuration transaction.");return NO;}
    // rename is the commit point. A later fsync failure must not report an unchanged active ID.
    if(fsync(_directoryFD)!=0) {
        // The committed record is still authoritative, but power-loss durability is uncertain.
        NSLog(@"MuyuClash: configuration directory synchronization failed after commit (errno %d)",errno);
    }
    return YES;
}
- (NSDictionary *)record:(NSString *)identifier error:(NSError **)error {
    if(!MLValidID(identifier)){MLStoreError(error,10,@"Invalid configuration identifier.");return nil;}
    NSData *data=[self readFile:[identifier stringByAppendingString:@".json"] limit:MLRecordLimit missingOK:NO error:error];if(!data)return nil;
    NSError *jsonError=nil;id record=[NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
    if(![record isKindOfClass:[NSDictionary class]] || ![record[@"id"] isEqual:identifier] ||
       ![record[@"yaml"] isKindOfClass:[NSString class]] || ![record[@"name"] isKindOfClass:[NSString class]] ||
       ![record[@"source"] isKindOfClass:[NSString class]] || ![record[@"updatedAt"] isKindOfClass:[NSNumber class]] ||
       [record[@"yaml"] lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>512*1024 || [record[@"name"] length]>256 || [record[@"source"] length]>4096){
        MLStoreError(error,11,@"The saved configuration record is invalid or exceeds its bounds.");return nil;
    }
    return record;
}
- (NSString *)activeUnlocked {
    NSData *data=[self readFile:@"active" limit:64 missingOK:YES error:NULL];
    NSString *identifier=data?[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]:nil;
    return MLValidID(identifier)?identifier:nil;
}
- (NSDictionary *)metadata:(NSDictionary *)record active:(NSString *)active report:(NSDictionary *)report {
    NSString *status=[report[@"valid"] boolValue]?@"unverified":@"incompatible";
    for(NSDictionary *item in report[@"issues"])if([item[@"category"] isEqual:@"parsing"] && [item[@"severity"] isEqual:@"block"])status=@"invalid";
    id proxies=report[@"document"];
    proxies=[proxies isKindOfClass:[NSDictionary class]]?proxies[@"proxies"]:nil;
    NSUInteger count=[proxies isKindOfClass:[NSArray class]]?[proxies count]:0;
    return @{@"id":record[@"id"],@"name":record[@"name"],@"source":record[@"source"],@"nodeCount":@(count),
             @"updatedAt":record[@"updatedAt"],@"status":status,@"active":@([record[@"id"] isEqual:active])};
}
- (NSDictionary *)importYAML:(NSString *)yaml name:(NSString *)name source:(NSString *)source error:(NSError **)error {
    if(error)*error=nil;
    if(![name isKindOfClass:[NSString class]] || !name.length || name.length>256 ||
       (source && (![source isKindOfClass:[NSString class]] || source.length>4096))){MLStoreError(error,12,@"A configuration name of 1–256 characters and bounded source text are required.");return nil;}
    NSDictionary *report=[MLConfig checkYAML:yaml];
    if(![report[@"syntaxValid"] boolValue]){MLStoreError(error,13,@"YAML parsing failed; the existing configurations remain unchanged.");return nil;}
    NSString *identifier=MLUUID();if(!identifier){MLStoreError(error,14,@"Cannot allocate a configuration identifier.");return nil;}
    NSDictionary *record=@{@"id":identifier,@"name":[name copy],@"source":[source copy]?:@"",@"yaml":[yaml copy],@"updatedAt":@([[NSDate date]timeIntervalSince1970])};
    NSData *data=[NSJSONSerialization dataWithJSONObject:record options:0 error:error];if(!data)return nil;
    @synchronized(self){if(![self lock:error])return nil;
        @try {
            if(![self atomicWrite:data name:[identifier stringByAppendingString:@".json"] error:error])return nil;
            return [self metadata:record active:[self activeUnlocked] report:report];
        }@finally{flock(_lockFD,LOCK_UN);}
    }
}
- (NSArray *)list {
    @synchronized(self){if(![self lock:NULL])return @[];
        @try {
            NSString *active=[self activeUnlocked];NSMutableArray *items=[NSMutableArray array];
            NSArray *files=[[NSFileManager defaultManager]contentsOfDirectoryAtPath:_directory error:NULL];
            for(NSString *file in files){if(![file.pathExtension isEqual:@"json"])continue;NSString *identifier=file.stringByDeletingPathExtension;if(!MLValidID(identifier))continue;
                NSDictionary *record=[self record:identifier error:NULL];
                if(record)[items addObject:[self metadata:record active:active report:[MLConfig checkYAML:record[@"yaml"]]]];
                else [items addObject:@{@"id":identifier,@"name":@"Unreadable configuration",@"source":@"",@"nodeCount":@0,@"updatedAt":@0,@"status":@"unreadable",@"active":@([identifier isEqual:active])}];
            }
            [items sortUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){return [b[@"updatedAt"]compare:a[@"updatedAt"]];}];return [items copy];
        }@finally{flock(_lockFD,LOCK_UN);}
    }
}
- (NSDictionary *)sourceForID:(NSString *)identifier error:(NSError **)error {
    if(error)*error=nil;
    @synchronized(self){if(![self lock:error])return nil;
        @try {NSDictionary *record=[self record:identifier error:error];return record?@{@"yaml":record[@"yaml"],@"name":record[@"name"],@"source":record[@"source"]}:nil;}
        @finally{flock(_lockFD,LOCK_UN);}
    }
}
- (NSString *)activeID {
    @synchronized(self){if(![self lock:NULL])return nil;@try{return [self activeUnlocked];}@finally{flock(_lockFD,LOCK_UN);}}
}
- (NSDictionary *)renameID:(NSString *)identifier name:(NSString *)name source:(NSString *)source error:(NSError **)error {
    if (!name.length || name.length > 256 || source.length > 4096) {
        MLStoreError(error,12,@"A configuration name of 1–256 characters and bounded source text are required.");
        return nil;
    }
    @synchronized(self) {
        if (![self lock:error]) return nil;
        @try {
            NSMutableDictionary *record = [[self record:identifier error:error] mutableCopy];
            if (!record) return nil;
            record[@"name"] = name;
            if (source) record[@"source"] = source;
            NSData *data = [NSJSONSerialization dataWithJSONObject:record options:0 error:error];
            if (!data || ![self atomicWrite:data name:[identifier stringByAppendingString:@".json"] error:error]) return nil;
            return [self metadata:record active:[self activeUnlocked] report:[MLConfig checkYAML:record[@"yaml"]]];
        } @finally { flock(_lockFD,LOCK_UN); }
    }
}
- (NSDictionary *)selectionsForID:(NSString *)identifier {
    if (!MLValidID(identifier)) return @{};
    @synchronized(self) {
        if (![self lock:NULL]) return @{};
        @try {
            NSString *file = [identifier stringByAppendingString:@".selections"];
            NSData *data = [self readFile:file limit:32768 missingOK:YES error:NULL];
            id value = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL] : nil;
            return [value isKindOfClass:[NSDictionary class]] ? value : @{};
        } @finally { flock(_lockFD,LOCK_UN); }
    }
}

- (BOOL)saveSelections:(NSDictionary *)selections forID:(NSString *)identifier error:(NSError **)error {
    @synchronized(self) {
        if (![self lock:error]) return NO;
        @try {
            if (![self record:identifier error:error]) return NO;
            NSData *data = [NSJSONSerialization dataWithJSONObject:selections options:0 error:error];
            if (!data || data.length > 32768) {
                MLStoreError(error,20,@"The selector history exceeds its storage bound.");
                return NO;
            }
            return [self atomicWrite:data name:[identifier stringByAppendingString:@".selections"] error:error];
        } @finally { flock(_lockFD,LOCK_UN); }
    }
}

- (BOOL)restoreActiveID:(NSString *)previous ifCurrent:(NSString *)candidate error:(NSError **)error {
    @synchronized(self) {
        if (![self lock:error]) return NO;
        @try {
            if (!MLValidID(candidate) || ![[self activeUnlocked] isEqual:candidate]) {
                MLStoreError(error,19,@"The active marker changed before recovery.");
                return NO;
            }
            if (previous) {
                if (![self record:previous error:error]) return NO;
                return [self atomicWrite:[previous dataUsingEncoding:NSUTF8StringEncoding] name:@"active" error:error];
            }
            NSString *path = [_directory stringByAppendingPathComponent:@"active"];
            if (unlink(path.fileSystemRepresentation) != 0) {
                MLStoreError(error,errno,@"Cannot restore the empty active marker.");
                return NO;
            }
            if (fsync(_directoryFD) != 0) NSLog(@"MuyuClash: active marker rollback synchronization failed (errno %d)",errno);
            return YES;
        } @finally { flock(_lockFD,LOCK_UN); }
    }
}
- (BOOL)removeID:(NSString *)identifier error:(NSError **)error {
    if(error)*error=nil;
    @synchronized(self){if(![self lock:error])return NO;
        @try {
            if(!MLValidID(identifier)){MLStoreError(error,10,@"Invalid configuration identifier.");return NO;}
            if([[self activeUnlocked]isEqual:identifier]){MLStoreError(error,15,@"The active configuration cannot be removed.");return NO;}
            if(![self record:identifier error:error])return NO;
            NSString *path=[_directory stringByAppendingPathComponent:[identifier stringByAppendingString:@".json"]];
            if(unlink(path.fileSystemRepresentation)!=0){MLStoreError(error,errno,@"Cannot remove the saved configuration.");return NO;}
            NSString *choices = [_directory stringByAppendingPathComponent:[identifier stringByAppendingString:@".selections"]];
            (void)unlink(choices.fileSystemRepresentation);
            (void)fsync(_directoryFD);return YES;
        }@finally{flock(_lockFD,LOCK_UN);}
    }
}
- (BOOL)activatePreparedID:(NSString *)identifier expectedYAML:(NSString *)yaml ifActiveID:(NSString *)previous error:(NSError **)error {
    @synchronized(self) { if(![self lock:error])return NO;
        @try {
            NSDictionary *record=[self record:identifier error:error];if(!record)return NO;
            NSString *active=[self activeUnlocked];
            if(![record[@"yaml"] isEqual:yaml] || ![(active ?: @"") isEqual:(previous ?: @"")]) {
                MLStoreError(error,19,@"Configuration changed during preparation; the active generation is unchanged.");return NO;
            }
            return [self atomicWrite:[identifier dataUsingEncoding:NSUTF8StringEncoding] name:@"active" error:error];
        } @finally { flock(_lockFD,LOCK_UN); }
    }
}
- (BOOL)activateID:(NSString *)identifier prepare:(BOOL (^)(NSDictionary *,NSError **))prepare error:(NSError **)error {
    if(error)*error=nil;
    @synchronized(self){if(![self lock:error])return NO;
        @try {
            NSDictionary *record=[self record:identifier error:error];if(!record)return NO;
            NSDictionary *report=[MLConfig checkYAML:record[@"yaml"]];
            if(![report[@"valid"] boolValue]){MLStoreError(error,16,@"Configuration blockers prevent activation; the active configuration is unchanged.");return NO;}
            if(!prepare){MLStoreError(error,17,@"A successful core preparation acknowledgement is required before activation.");return NO;}
            NSError *prepareError=nil;
            if(!prepare(report[@"document"],&prepareError)){if(error)*error=prepareError ?: [NSError errorWithDomain:@"MuyuClash.Config" code:18 userInfo:@{NSLocalizedDescriptionKey:@"Core preparation failed; the active configuration is unchanged."}];return NO;}
            return [self atomicWrite:[identifier dataUsingEncoding:NSUTF8StringEncoding] name:@"active" error:error];
        }@finally{flock(_lockFD,LOCK_UN);}
    }
}
@end
