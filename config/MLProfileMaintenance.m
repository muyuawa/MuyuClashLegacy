#import "MLProfileMaintenance.h"
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

static const NSUInteger MLPMRecordLimit=768*1024, MLPMOverrideLimit=64*1024, MLPMEntryLimit=128, MLPMNodeLimit=4096;
static id MLPMFail(NSError **error,NSString *code,NSString *reason) {
    if(error)*error=[NSError errorWithDomain:code code:1 userInfo:@{NSLocalizedDescriptionKey:reason}]; return nil;
}
static BOOL MLPMBoolean(id value) { return [value isKindOfClass:[NSNumber class]] && CFGetTypeID((__bridge CFTypeRef)value)==CFBooleanGetTypeID(); }
static BOOL MLPMNumber(id value,double maximum) {
    return [value isKindOfClass:[NSNumber class]] && !MLPMBoolean(value) && isfinite([value doubleValue]) && [value doubleValue]>=0 && [value doubleValue]<=maximum;
}
static BOOL MLPMInterval(NSUInteger value) { return !value || (value>=21600 && value<=604800); }
static NSString *MLPMID(id value) {
    return [value isKindOfClass:[NSString class]] && [value length]==36 && [value rangeOfString:@"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$" options:NSRegularExpressionSearch].location==0 ? [value uppercaseString] : nil;
}
static NSString *MLPMUUID(void) { CFUUIDRef value=CFUUIDCreate(NULL); NSString *text=CFBridgingRelease(CFUUIDCreateString(NULL,value)); CFRelease(value); return text; }
static NSString *MLPMCanonical(id value) {
    if([value isKindOfClass:[NSDictionary class]]) {
        NSMutableArray *parts=[NSMutableArray array]; for(NSString *key in [[value allKeys] sortedArrayUsingSelector:@selector(compare:)]) [parts addObject:[NSString stringWithFormat:@"%@:%@",MLPMCanonical(key),MLPMCanonical(value[key])]];
        return [NSString stringWithFormat:@"{%@}",[parts componentsJoinedByString:@","]];
    }
    if([value isKindOfClass:[NSArray class]]) { NSMutableArray *parts=[NSMutableArray array];for(id item in value)[parts addObject:MLPMCanonical(item)];return [NSString stringWithFormat:@"[%@]",[parts componentsJoinedByString:@","]]; }
    NSString *text=[[NSString alloc]initWithData:[NSJSONSerialization dataWithJSONObject:@[value] options:0 error:NULL] encoding:NSUTF8StringEncoding];return [text substringWithRange:NSMakeRange(1,text.length-2)];
}
static NSString *MLPMHash(id payload) {
    NSData *bytes=[MLPMCanonical(payload) dataUsingEncoding:NSUTF8StringEncoding]; unsigned char digest[32];CC_SHA256(bytes.bytes,(CC_LONG)bytes.length,digest);
    NSMutableString *result=[NSMutableString string];for(NSUInteger i=0;i<32;i++)[result appendFormat:@"%02x",digest[i]];return result;
}
static BOOL MLPMTree(id value,NSUInteger depth,NSUInteger *nodes) {
    if(depth>16 || ++*nodes>MLPMNodeLimit)return NO;
    if([value isKindOfClass:[NSDictionary class]]) {
        for(id key in value) {
            if(![key isKindOfClass:[NSString class]] || ![key length] || [key lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>256 || [key hasPrefix:@"_"] ||
                [key rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location!=NSNotFound || !MLPMTree(value[key],depth+1,nodes))return NO;
        } return YES;
    }
    if([value isKindOfClass:[NSArray class]]) { for(id item in value)if(!MLPMTree(item,depth+1,nodes))return NO;return YES; }
    if([value isKindOfClass:[NSString class]])return [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding]<=MLPMOverrideLimit;
    return [value isKindOfClass:[NSNull class]] || ([value isKindOfClass:[NSNumber class]] && isfinite([value doubleValue]));
}
static BOOL MLPMOverrides(id value) {
    if(![value isKindOfClass:[NSDictionary class]])return NO;
    NSUInteger nodes=0;if(!MLPMTree(value,0,&nodes))return NO;
    for(NSString *key in value) {
        if(![[MLProfileMaintenance allowedOverrideFields] containsObject:key])return NO;
        id item=value[key];
        if([key isEqual:@"mode"] && ![@[@"rule",@"global",@"direct"] containsObject:item])return NO;
        if([key isEqual:@"ipv6"] && !MLPMBoolean(item))return NO;
        if([key isEqual:@"log-level"] && ![@[@"debug",@"info",@"warning",@"error",@"silent"] containsObject:item])return NO;
        if([@[@"dns",@"hosts",@"profile"] containsObject:key] && ![item isKindOfClass:[NSDictionary class]])return NO;
        if([@[@"proxy-groups",@"rules"] containsObject:key] && ![item isKindOfClass:[NSArray class]])return NO;
    }
    NSData *data=[NSJSONSerialization dataWithJSONObject:value options:0 error:NULL];return data && data.length<=MLPMOverrideLimit;
}
static NSDictionary *MLPMMerge(NSDictionary *source,NSDictionary *override) {
    NSMutableDictionary *result=[source mutableCopy];for(NSString *key in override) {
        id old=result[key],value=override[key];result[key]=[old isKindOfClass:[NSDictionary class]] && [value isKindOfClass:[NSDictionary class]] ? MLPMMerge(old,value) : value;
    } return [result copy];
}
static BOOL MLPMState(id state) {
    if(![state isKindOfClass:[NSDictionary class]] || [state count]!=2 || ![state[@"plans"] isKindOfClass:[NSDictionary class]] || ![state[@"overrides"] isKindOfClass:[NSDictionary class]])return NO;
    NSMutableSet *ids=[NSMutableSet setWithArray:[state[@"plans"] allKeys]];[ids addObjectsFromArray:[state[@"overrides"] allKeys]];if(ids.count>MLPMEntryLimit)return NO;
    for(NSString *identifier in ids)if(![MLPMID(identifier) isEqual:identifier])return NO;
    NSSet *fields=[NSSet setWithArray:@[@"interval",@"revision",@"lastSuccessAt",@"lastAttemptAt",@"nextUpdateAt",@"failures",@"lastError"]];
    for(NSDictionary *plan in [state[@"plans"] allValues]) {
        if(![plan isKindOfClass:[NSDictionary class]] || ![[NSSet setWithArray:plan.allKeys] isSubsetOfSet:fields] || !MLPMID(plan[@"revision"]) ||
            !MLPMNumber(plan[@"interval"],604800) || floor([plan[@"interval"] doubleValue])!=[plan[@"interval"] doubleValue] || ![plan[@"interval"] unsignedIntegerValue] || !MLPMInterval([plan[@"interval"] unsignedIntegerValue]) ||
            !MLPMNumber(plan[@"lastSuccessAt"],1e12) || !MLPMNumber(plan[@"lastAttemptAt"],1e12) || !MLPMNumber(plan[@"nextUpdateAt"],1e12) ||
            !MLPMNumber(plan[@"failures"],20) || floor([plan[@"failures"] doubleValue])!=[plan[@"failures"] doubleValue])return NO;
        if(plan[@"lastError"] && (![plan[@"lastError"] isKindOfClass:[NSString class]] || [plan[@"lastError"] length]>64 || [plan[@"lastError"] rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location!=NSNotFound))return NO;
    }
    for(id override in [state[@"overrides"] allValues])if(!MLPMOverrides(override))return NO;
    return YES;
}

@implementation MLProfileMaintenance {
    NSString *_directory,*_path,*_lockPath; int _directoryFD,_lockFD;dev_t _device,_lockDevice;ino_t _inode,_lockInode;
    NSLock *_operation;NSDictionary *_state,*_inflight;NSData *_bytes;NSMutableDictionary *_retryAfter;BOOL _damaged;
}
+ (NSArray *)allowedOverrideFields { return @[@"mode",@"ipv6",@"dns",@"hosts",@"log-level",@"proxy-groups",@"rules",@"profile"]; }
- (BOOL)directory:(BOOL)create error:(NSError **)error {
    if(!_directory.isAbsolutePath || [_directory isEqual:@"/"] || [_directory.pathComponents containsObject:@".."] || [_directory.pathComponents containsObject:@"."] ||
        [_directory rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location!=NSNotFound) { MLPMFail(error,@"E_PROFILE_STORAGE",@"Profile maintenance requires a fixed private directory.");return NO; }
    NSString *path=@"/";for(NSString *part in _directory.pathComponents) {
        if([part isEqual:@"/"])continue;path=[path stringByAppendingPathComponent:part];struct stat status;
        if(lstat(path.fileSystemRepresentation,&status)) {if(!create || errno!=ENOENT || mkdir(path.fileSystemRepresentation,0700) || lstat(path.fileSystemRepresentation,&status)) {MLPMFail(error,@"E_PROFILE_STORAGE",@"Cannot inspect/create profile maintenance storage.");return NO;} }
        if(!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) {MLPMFail(error,@"E_PROFILE_STORAGE",@"Profile storage cannot traverse symbolic links.");return NO;}
    }
    struct stat status;if(lstat(_directory.fileSystemRepresentation,&status) || status.st_uid!=geteuid() || (status.st_mode&0777)!=0700) {MLPMFail(error,@"E_PROFILE_STORAGE",@"Profile storage must be owned by the service and private.");return NO;}return YES;
}
- (BOOL)integrity:(NSError **)error {
    struct stat entry,descriptor,lockEntry,lockDescriptor;
    if(_damaged || ![self directory:NO error:error] || lstat(_directory.fileSystemRepresentation,&entry) || fstat(_directoryFD,&descriptor) || entry.st_dev!=_device || entry.st_ino!=_inode || descriptor.st_dev!=_device || descriptor.st_ino!=_inode ||
        lstat(_lockPath.fileSystemRepresentation,&lockEntry) || fstat(_lockFD,&lockDescriptor) || !S_ISREG(lockEntry.st_mode) || lockEntry.st_uid!=geteuid() || lockEntry.st_nlink!=1 || (lockEntry.st_mode&0777)!=0600 ||
        lockEntry.st_dev!=_lockDevice || lockEntry.st_ino!=_lockInode || lockDescriptor.st_dev!=_lockDevice || lockDescriptor.st_ino!=_lockInode) {MLPMFail(error,@"E_PROFILE_STORAGE",@"Profile maintenance storage was replaced or changed permissions.");return NO;}return YES;
}
- (NSData *)read:(NSError **)error {
    struct stat entry,initial,final; if(lstat(_path.fileSystemRepresentation,&entry)) {if(errno!=ENOENT)MLPMFail(error,@"E_PROFILE_STORAGE",@"Cannot inspect profile maintenance metadata.");return nil;}
    int fd=open(_path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW);
    if(fd<0 || fstat(fd,&initial) || !S_ISREG(initial.st_mode) || initial.st_uid!=geteuid() || initial.st_nlink!=1 || (initial.st_mode&0777)!=0600 || initial.st_size<0 || initial.st_size>MLPMRecordLimit || initial.st_dev!=entry.st_dev || initial.st_ino!=entry.st_ino) {
        if(fd>=0)close(fd);return MLPMFail(error,@"E_PROFILE_STORAGE",@"Profile metadata is not an owned bounded private regular file.");
    }
    NSMutableData *data=[NSMutableData data];unsigned char buffer[8192];BOOL valid=YES;
    for(;;) {ssize_t count=read(fd,buffer,sizeof buffer);if(count<0&&errno==EINTR)continue;if(count<0 || (count>0 && data.length>MLPMRecordLimit-(NSUInteger)count)){valid=NO;break;}if(!count)break;[data appendBytes:buffer length:(NSUInteger)count];}
    valid=valid && !fstat(fd,&final) && final.st_size==(off_t)data.length && final.st_size==initial.st_size && final.st_mtime==initial.st_mtime && final.st_ctime==initial.st_ctime && final.st_uid==geteuid() && final.st_nlink==1 && (final.st_mode&0777)==0600 &&
        !lstat(_path.fileSystemRepresentation,&entry) && entry.st_dev==initial.st_dev && entry.st_ino==initial.st_ino && entry.st_uid==geteuid() && entry.st_nlink==1 && (entry.st_mode&0777)==0600;
    close(fd);if(!valid || ![self integrity:error])return MLPMFail(error,@"E_PROFILE_STORAGE",@"Profile metadata changed during reading.");return [data copy];
}
- (BOOL)lock:(NSError **)error {
    if(error)*error=nil;
    if(![_operation tryLock]) {MLPMFail(error,@"E_BUSY",@"A profile maintenance operation is active.");return NO;}
    if(![self integrity:error] || flock(_lockFD,LOCK_EX|LOCK_NB)) {if(error && !*error)MLPMFail(error,@"E_BUSY",@"Profile maintenance is locked by another process.");[_operation unlock];return NO;}
    NSError *failure=nil;NSData *current=[self read:&failure];
    if(failure || ((current || _bytes) && ![current isEqual:_bytes])) {if(error)*error=failure ?: [NSError errorWithDomain:@"E_PROFILE_STALE" code:1 userInfo:@{NSLocalizedDescriptionKey:@"Another process changed profile maintenance metadata."}];flock(_lockFD,LOCK_UN);[_operation unlock];return NO;}return YES;
}
- (void)unlock {flock(_lockFD,LOCK_UN);[_operation unlock];}
- (BOOL)writeRaw:(NSData *)data error:(NSError **)error {
    if(![self integrity:error] || fsync(_directoryFD)) {MLPMFail(error,@"E_PROFILE_STORAGE",@"Cannot synchronize profile storage before writing.");return NO;}
    NSString *temporary=[_directory stringByAppendingPathComponent:[@".pending-" stringByAppendingString:MLPMUUID()]];
    int fd=open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0){MLPMFail(error,@"E_PROFILE_STORAGE",@"Cannot stage profile metadata.");return NO;}
    NSUInteger used=0;BOOL valid=YES;while(used<data.length){ssize_t n=write(fd,(const unsigned char *)data.bytes+used,data.length-used);if(n<0&&errno==EINTR)continue;if(n<=0){valid=NO;break;}used+=(NSUInteger)n;}
    if(fchmod(fd,0600) || fsync(fd))valid=NO;if(close(fd))valid=NO;
    if(valid && (![self integrity:error] || rename(temporary.fileSystemRepresentation,_path.fileSystemRepresentation)))valid=NO;
    if(!valid){unlink(temporary.fileSystemRepresentation);MLPMFail(error,@"E_PROFILE_STORAGE",@"Cannot install complete profile metadata.");return NO;}
    if(fsync(_directoryFD)){MLPMFail(error,@"E_PROFILE_STORAGE",@"Cannot durably synchronize installed profile metadata.");return NO;}return YES;
}
- (BOOL)persist:(NSDictionary *)state error:(NSError **)error {
    if(!MLPMState(state)){MLPMFail(error,@"E_PROFILE_RESOURCE",@"Profile metadata exceeds its type or 128-profile budget.");return NO;}
    NSDictionary *envelope=@{@"format":@1,@"sha256":MLPMHash(state),@"payload":state};NSData *data=[NSJSONSerialization dataWithJSONObject:envelope options:0 error:NULL];
    if(!data || data.length>MLPMRecordLimit){MLPMFail(error,@"E_PROFILE_RESOURCE",@"Profile metadata exceeds its disk budget.");return NO;}
    NSError *failure=nil;if(![self writeRaw:data error:&failure]) {
        NSError *readError=nil;NSData *current=[self read:&readError];BOOL old=(!current&&!_bytes) || [current isEqual:_bytes];
        if(!old && !readError && [current isEqual:data]) {
            if(_bytes)[self writeRaw:_bytes error:NULL];else if(!unlink(_path.fileSystemRepresentation)) (void)fsync(_directoryFD);
            current=[self read:&readError];old=(!current&&!_bytes) || [current isEqual:_bytes];
        }
        if(readError || !old)_damaged=YES;if(error)*error=failure;return NO;
    }
    _bytes=data;_state=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL][@"payload"];return YES;
}
- (id)initWithDirectory:(NSString *)directory error:(NSError **)error {
    if(error)*error=nil;
    if((self=[super init])) {
        _directoryFD=_lockFD=-1;_directory=[directory copy];_path=[directory stringByAppendingPathComponent:@"maintenance.json"];_lockPath=[directory stringByAppendingPathComponent:@"maintenance.lock"];
        _operation=[NSLock new];_retryAfter=[NSMutableDictionary dictionary];_state=@{@"plans":@{},@"overrides":@{}};
        if(![self directory:YES error:error])return nil;
        _directoryFD=open(directory.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);struct stat status;if(_directoryFD<0 || fstat(_directoryFD,&status)){MLPMFail(error,@"E_PROFILE_STORAGE",@"Cannot open profile storage.");return nil;}_device=status.st_dev;_inode=status.st_ino;
        _lockFD=open(_lockPath.fileSystemRepresentation,O_RDWR|O_CREAT|O_NOFOLLOW,0600);
        if(_lockFD<0 || fstat(_lockFD,&status) || !S_ISREG(status.st_mode) || status.st_uid!=geteuid() || status.st_nlink!=1 || (status.st_mode&0777)!=0600){MLPMFail(error,@"E_PROFILE_STORAGE",@"Cannot open the owned private profile lock.");return nil;}_lockDevice=status.st_dev;_lockInode=status.st_ino;
        fcntl(_directoryFD,F_SETFD,FD_CLOEXEC);fcntl(_lockFD,F_SETFD,FD_CLOEXEC);
        NSError *failure=nil;_bytes=[self read:&failure];if(failure){if(error)*error=failure;return nil;}
        if(_bytes) {
            id envelope=[NSJSONSerialization JSONObjectWithData:_bytes options:0 error:NULL];id payload=[envelope isKindOfClass:[NSDictionary class]] ? envelope[@"payload"] : nil;
            if(![envelope isKindOfClass:[NSDictionary class]] || [envelope count]!=3 || ![envelope[@"format"] isEqual:@1] || !MLPMState(payload) || ![envelope[@"sha256"] isKindOfClass:[NSString class]] || ![envelope[@"sha256"] isEqual:MLPMHash(payload)]) {MLPMFail(error,@"E_PROFILE_STORAGE",@"Profile metadata is malformed or failed its content hash.");return nil;}_state=payload;
        }
    }return self;
}
- (void)dealloc {if(_lockFD>=0)close(_lockFD);if(_directoryFD>=0)close(_directoryFD);}
- (NSDictionary *)scheduleForID:(NSString *)identifier error:(NSError **)error {
    NSString *key=MLPMID(identifier);if(!key)return MLPMFail(error,@"E_PROFILE_ID",@"A protected configuration UUID is required.");if(![self lock:error])return nil;
    @try {NSMutableDictionary *row=[_state[@"plans"][key] mutableCopy] ?: [NSMutableDictionary dictionaryWithObject:@0 forKey:@"interval"];row[@"id"]=key;return [row copy];}@finally{[self unlock];}
}
- (BOOL)setScheduleInterval:(NSUInteger)interval forID:(NSString *)identifier error:(NSError **)error {
    NSString *key=MLPMID(identifier);if(!key || !MLPMInterval(interval)){MLPMFail(error,@"E_PROFILE_SCHEDULE",@"Schedules require a configuration UUID and zero or 21600–604800 seconds.");return NO;}if(![self lock:error])return NO;
    @try {NSMutableDictionary *plans=[_state[@"plans"] mutableCopy];double now=[NSDate date].timeIntervalSince1970;
        if(interval)plans[key]=@{@"interval":@(interval),@"revision":MLPMUUID(),@"lastSuccessAt":@(now),@"lastAttemptAt":@(now),@"nextUpdateAt":@(now+interval),@"failures":@0};else[plans removeObjectForKey:key];
        BOOL result=[self persist:@{@"plans":plans,@"overrides":_state[@"overrides"]} error:error];if(result)[_retryAfter removeObjectForKey:key];return result;
    }@finally{[self unlock];}
}
- (NSDictionary *)claimDueScheduleAtTime:(NSTimeInterval)time uptime:(NSTimeInterval)uptime error:(NSError **)error {
    if(!isfinite(time)||time<0||time>1e12||!isfinite(uptime)||uptime<0)return MLPMFail(error,@"E_PROFILE_CLOCK",@"Finite schedule clocks are required.");if(![self lock:error])return nil;
    @try {if(_inflight)return nil;NSArray *ids=[[_state[@"plans"] allKeys] sortedArrayUsingSelector:@selector(compare:)];NSString *chosen=nil;double earliest=INFINITY;
        for(NSString *key in ids){NSDictionary *plan=_state[@"plans"][key];double next=[plan[@"nextUpdateAt"] doubleValue];BOOL due=time>=next || time<[plan[@"lastAttemptAt"] doubleValue];
            if(due && uptime>=[_retryAfter[key] doubleValue] && next<earliest){chosen=key;earliest=next;}}
        if(!chosen)return nil;NSDictionary *plan=_state[@"plans"][chosen];_inflight=@{@"id":chosen,@"interval":plan[@"interval"],@"revision":plan[@"revision"],@"lease":MLPMUUID()};return _inflight;
    }@finally{[self unlock];}
}
- (BOOL)isCurrentScheduleClaim:(NSDictionary *)claim error:(NSError **)error {
    if(![self lock:error])return NO;@try {BOOL current=[claim isKindOfClass:[NSDictionary class]] && [claim isEqual:_inflight] && [_state[@"plans"][claim[@"id"]][@"revision"] isEqual:claim[@"revision"]];if(!current)MLPMFail(error,@"E_PROFILE_STALE",@"This automatic update lease was changed or disabled.");return current;}@finally{[self unlock];}
}
- (BOOL)finishScheduleForID:(NSString *)identifier replacementID:(NSString *)replacementID success:(BOOL)success errorCode:(NSString *)errorCode time:(NSTimeInterval)time uptime:(NSTimeInterval)uptime error:(NSError **)error {
    NSString *key=MLPMID(identifier),*replacement=replacementID ? MLPMID(replacementID) : nil;
    if(!key || (replacementID&&!replacement) || !isfinite(time)||time<0||time>1e12||!isfinite(uptime)||uptime<0 || (errorCode&&(![errorCode isKindOfClass:[NSString class]] || errorCode.length>64 || [errorCode rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location!=NSNotFound))) {MLPMFail(error,@"E_PROFILE_SCHEDULE",@"Invalid schedule completion metadata.");return NO;}if(![self lock:error])return NO;
    @try {if(![_inflight[@"id"] isEqual:key]){MLPMFail(error,@"E_PROFILE_STALE",@"This completion does not own the automatic update slot.");return NO;}
        NSDictionary *old=_state[@"plans"][key];if(![old[@"revision"] isEqual:_inflight[@"revision"]]){_inflight=nil;return YES;}
        NSMutableDictionary *plans=[_state[@"plans"] mutableCopy],*overrides=[_state[@"overrides"] mutableCopy],*plan=[old mutableCopy];plan[@"lastAttemptAt"]=@(time);
        NSUInteger failures=success?0:MIN(20,[old[@"failures"] unsignedIntegerValue]+1);double retry=MIN(21600.0,60.0*pow(2.0,(double)MIN(failures?failures-1:0,9)));
        plan[@"failures"]=@(failures);plan[@"nextUpdateAt"]=@(time+(success?[old[@"interval"] doubleValue]:retry));
        if(success){plan[@"lastSuccessAt"]=@(time);[plan removeObjectForKey:@"lastError"];if(replacement&&![replacement isEqual:key]) {
                if(plans[replacement] || overrides[replacement]){MLPMFail(error,@"E_PROFILE_STALE",@"The replacement already has independent maintenance settings.");_inflight=nil;return NO;}
                [plans removeObjectForKey:key];if(overrides[key]){overrides[replacement]=overrides[key];[overrides removeObjectForKey:key];}key=replacement;
            }}else plan[@"lastError"]=errorCode ?: @"E_CONFIG_UPDATE";
        plans[key]=plan;BOOL result=[self persist:@{@"plans":plans,@"overrides":overrides} error:error];_inflight=nil;
        if(result){if(success)[_retryAfter removeObjectForKey:identifier.uppercaseString];else _retryAfter[key]=@(uptime+retry);}else _retryAfter[key]=@(uptime+60);return result;
    }@finally{[self unlock];}
}
- (NSDictionary *)overridesForID:(NSString *)identifier error:(NSError **)error {
    NSString *key=MLPMID(identifier);if(!key)return MLPMFail(error,@"E_PROFILE_ID",@"A protected configuration UUID is required.");if(![self lock:error])return nil;@try{return _state[@"overrides"][key] ?: @{};}@finally{[self unlock];}
}
- (BOOL)setOverrides:(NSDictionary *)overrides forID:(NSString *)identifier error:(NSError **)error {
    NSString *key=MLPMID(identifier);if(!key || !MLPMOverrides(overrides)){MLPMFail(error,@"E_PROFILE_OVERRIDE",@"Overrides must use supported fields, JSON values and bounded nonreserved keys.");return NO;}if(![self lock:error])return NO;
    @try {NSMutableDictionary *values=[_state[@"overrides"] mutableCopy];if(overrides.count)values[key]=overrides;else[values removeObjectForKey:key];return [self persist:@{@"plans":_state[@"plans"],@"overrides":values} error:error];}@finally{[self unlock];}
}
- (NSDictionary *)mergedDocument:(NSDictionary *)document forID:(NSString *)identifier error:(NSError **)error {
    if(![document isKindOfClass:[NSDictionary class]] || ![NSJSONSerialization isValidJSONObject:document])return MLPMFail(error,@"E_PROFILE_OVERRIDE",@"A source configuration mapping is required.");
    NSDictionary *overrides=[self overridesForID:identifier error:error];if(!overrides)return nil;
    NSDictionary *merged=MLPMMerge(document,overrides);NSData *data=[NSJSONSerialization dataWithJSONObject:merged options:0 error:NULL];
    if(!data||data.length>512*1024)return MLPMFail(error,@"E_PROFILE_RESOURCE",@"The merged configuration exceeds its source budget.");return [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
}
@end
