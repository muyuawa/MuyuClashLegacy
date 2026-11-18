#import "MLGeoDataManager.h"
#import "MLGeoFormat.h"
#import "MLGeoIndex.h"
#import "MLProviderStorage.h"
#import "../config/MLFetch.h"
#import "../dns/MLDNS.h"
#import "../routing/MLRoutingInternal.h"
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <CommonCrypto/CommonDigest.h>
#include <TargetConditionals.h>

static id MLGMFail(NSError **error, NSString *code, NSString *reason) {
    if (error) *error=[NSError errorWithDomain:code code:1 userInfo:@{NSLocalizedDescriptionKey:reason}]; return nil;
}
static NSArray *MLGMArray(id value) { return [value isKindOfClass:[NSArray class]] ? value : @[]; }
static BOOL MLGMHash(id value) { return [value isKindOfClass:[NSString class]] && [value length]==64 && [value rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet]].location==NSNotFound; }
static BOOL MLGMSameData(NSData *a, NSData *b) {
    return (!a && !b) || (a && b && [a isEqual:b] && [MLProviderStorageHash(a) isEqual:MLProviderStorageHash(b)]);
}
// Package resources are readable by mobile but may only be changed by their owner.
static NSData *MLGMBundleRead(NSString *directory, NSString *name, NSUInteger limit) {
    struct stat parent, initial, final;
    if (!directory || lstat(directory.fileSystemRepresentation,&parent) || !S_ISDIR(parent.st_mode) || parent.st_uid!=geteuid() || (parent.st_mode&0022)) return nil;
    NSString *path=[directory stringByAppendingPathComponent:name];
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW);
    if (fd<0) return nil;
    BOOL valid=!fstat(fd,&initial) && S_ISREG(initial.st_mode) && initial.st_nlink==1 && initial.st_uid==geteuid() && !(initial.st_mode&0022) && initial.st_size>0 && (uint64_t)initial.st_size<=limit;
    NSMutableData *data=valid ? [NSMutableData dataWithLength:(NSUInteger)initial.st_size] : nil; NSUInteger total=0;
    while (valid && total<data.length) {
        ssize_t count=read(fd,(unsigned char *)data.mutableBytes+total,data.length-total);
        if (count<0 && errno==EINTR) continue;
        if (count<=0) { valid=NO; break; } total+=(NSUInteger)count;
    }
    valid=valid && !fstat(fd,&final) && initial.st_size==final.st_size && initial.st_mtime==final.st_mtime && initial.st_ctime==final.st_ctime;
    close(fd); return valid ? data : nil;
}
static NSString *MLGMRawHash(NSString *path, NSError **error) {
    if (!MLProviderPrivateDirectory(path.stringByDeletingLastPathComponent,NO,YES,error)) return nil;
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW); struct stat initial,final,entry;
    if (fd<0 || fstat(fd,&initial)!=0 || !S_ISREG(initial.st_mode) || initial.st_uid!=geteuid() || initial.st_nlink!=1 || (initial.st_mode&0777)!=0600 || initial.st_size<0 || initial.st_size>32*1024*1024 ||
        lstat(path.fileSystemRepresentation,&entry)!=0 || entry.st_dev!=initial.st_dev || entry.st_ino!=initial.st_ino) {
        if (fd>=0) close(fd); return MLGMFail(error,@"E_GEO_STORAGE",@"A raw Geo snapshot is not an owned bounded private file.");
    }
    CC_SHA256_CTX context; CC_SHA256_Init(&context); unsigned char buffer[8192],digest[CC_SHA256_DIGEST_LENGTH]; NSUInteger total=0; BOOL valid=YES;
    for (;;) {
        ssize_t count=read(fd,buffer,sizeof buffer); if (count<0 && errno==EINTR) continue;
        if (count<0 || (count>0 && total>32*1024*1024-(NSUInteger)count)) { valid=NO; break; }
        if (!count) break; total+=(NSUInteger)count; CC_SHA256_Update(&context,buffer,(CC_LONG)count);
    }
    valid=valid && fstat(fd,&final)==0 && final.st_size==(off_t)total && final.st_size==initial.st_size && final.st_mtime==initial.st_mtime && final.st_ctime==initial.st_ctime &&
        lstat(path.fileSystemRepresentation,&entry)==0 && entry.st_dev==initial.st_dev && entry.st_ino==initial.st_ino;
    close(fd);
    if (!valid || !MLProviderPrivateDirectory(path.stringByDeletingLastPathComponent,NO,YES,error)) return MLGMFail(error,@"E_GEO_STORAGE",@"A raw Geo snapshot changed during validation.");
    CC_SHA256_Final(digest,&context); NSMutableString *hash=[NSMutableString string]; for (NSUInteger i=0;i<sizeof digest;++i) [hash appendFormat:@"%02x",digest[i]]; return hash;
}
static void MLGMCollect(NSString *line, NSMutableDictionary *requests, NSUInteger depth) {
    if (![line isKindOfClass:[NSString class]] || depth>32) return;
    if ([line hasPrefix:@"("] && [line hasSuffix:@")"]) line=[line substringWithRange:NSMakeRange(1,line.length-2)];
    NSArray *parts=MLRouteRuleFields(line); if (parts.count<2) return;
    NSString *type=parts[0], *operand=parts[1];
    NSString *kind=[type isEqual:@"GEOIP"] ? @"geoip" : ([type isEqual:@"GEOSITE"] ? @"geosite" : ([type isEqual:@"IP-ASN"] ? @"asn" : nil));
    if (kind && !([kind isEqual:@"geoip"] && [operand caseInsensitiveCompare:@"LAN"]==NSOrderedSame)) [requests[kind] addObject:operand];
    else if ([@[@"AND",@"OR",@"NOT"] containsObject:type]) for (NSString *child in MLRouteConditionChildren(type,operand)) MLGMCollect(child,requests,depth+1);
    else if ([type isEqual:@"SUB-RULE"]) MLGMCollect(operand,requests,depth+1);
}
static BOOL MLGMPrune(NSString *directory, NSString *extension, NSUInteger budget, NSSet *preserve, NSUInteger reserve, NSError **error) {
    NSArray *names=[[NSFileManager defaultManager] contentsOfDirectoryAtPath:directory error:error];
    if (!names || names.count>1024 || reserve>budget) { MLGMFail(error,@"E_GEO_STORAGE",@"The Geo cache exceeds its storage budget."); return NO; }
    uint64_t total=reserve; NSUInteger count=0; NSMutableArray *discardable=[NSMutableArray array];
    for (NSString *name in names) {
        if ([extension isEqual:@".index"] && [name isEqual:@"providers"]) {
            NSString *path=[directory stringByAppendingPathComponent:name]; struct stat status;
            if (!lstat(path.fileSystemRepresentation,&status) && S_ISDIR(status.st_mode) && status.st_uid==geteuid() && (status.st_mode&0777)==0755) continue;
            MLGMFail(error,@"E_GEO_STORAGE",@"The Provider index directory is unsafe."); return NO;
        }
        if (MLProviderStorageIsTemporaryName(name)) {
            NSUInteger size=0;
            if (!MLProviderStorageInspectTemporary([directory stringByAppendingPathComponent:name],32*1024*1024,[extension isEqual:@".index"],&size,error)) return NO;
            if (size!=NSNotFound) { total+=size; ++count; } continue;
        }
        if (![name hasSuffix:extension] || !MLGMHash([name substringToIndex:name.length-extension.length])) { MLGMFail(error,@"E_GEO_STORAGE",@"The controlled Geo cache contains an unexpected entry."); return NO; }
        NSString *path=[directory stringByAppendingPathComponent:name]; struct stat status;
        if (lstat(path.fileSystemRepresentation,&status)!=0 || !S_ISREG(status.st_mode) || status.st_uid!=geteuid() || status.st_nlink!=1 || status.st_size<0 || status.st_size>32*1024*1024) { MLGMFail(error,@"E_GEO_STORAGE",@"A Geo cache entry is not an owned bounded regular file."); return NO; }
        total+=(NSUInteger)status.st_size; ++count;
        if (![preserve containsObject:[name substringToIndex:64]]) [discardable addObject:@{@"path":path,@"size":@((uint64_t)status.st_size),@"mtime":@((double)status.st_mtime)}];
    }
    [discardable sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) { NSComparisonResult order=[a[@"mtime"] compare:b[@"mtime"]]; return order==NSOrderedSame ? [a[@"path"] compare:b[@"path"]] : order; }];
    for (NSDictionary *entry in discardable) {
        if (total<=budget && count<64) break;
        if (unlink([entry[@"path"] fileSystemRepresentation])!=0) { MLGMFail(error,@"E_GEO_STORAGE",@"Cannot prune obsolete Geo snapshots."); return NO; }
        total-=[entry[@"size"] unsignedIntegerValue]; --count;
    }
    if (total>budget || count>=64) { MLGMFail(error,@"E_GEO_STORAGE",@"Active Geo snapshots exceed the bounded disk budget."); return NO; }
    return YES;
}
@implementation MLGeoDataManager {
    NSString *_directory, *_readableDirectory, *_caPath, *_bundledDirectory;
    dev_t _device, _readableDevice; ino_t _inode, _readableInode;
    NSLock *_operation;
    NSDictionary *_current, *_prepared, *_preparedManifest;
    NSData *_manifestData, *_pointerAttemptData;
    double _lastAttempt;
}
- (id)initWithDirectory:(NSString *)directory readableDirectory:(NSString *)readableDirectory caPath:(NSString *)caPath error:(NSError **)error {
#if TARGET_OS_IPHONE
    NSString *bundle=@"/usr/share/muyuclash/geodata";
#else
    NSString *bundle=nil;
#endif
    return [self initWithDirectory:directory readableDirectory:readableDirectory caPath:caPath bundledDirectory:bundle error:error];
}
- (id)initWithDirectory:(NSString *)directory readableDirectory:(NSString *)readableDirectory caPath:(NSString *)caPath bundledDirectory:(NSString *)bundle error:(NSError **)error {
    if (error) *error=nil;
    if ((self=[super init])) {
        if (!MLProviderPrivateDirectory(directory,YES,YES,error) || !MLProviderPrivateDirectory(readableDirectory,YES,NO,error)) return nil;
        struct stat privateStatus, readableStatus;
        if (lstat(directory.fileSystemRepresentation,&privateStatus)!=0 || lstat(readableDirectory.fileSystemRepresentation,&readableStatus)!=0 || readableStatus.st_uid!=geteuid() || (readableStatus.st_mode&0022) || chmod(readableDirectory.fileSystemRepresentation,0755)!=0) return MLGMFail(error,@"E_GEO_STORAGE",@"The Geo index directory must be service-owned and searchable by the Core.");
        _directory=[directory copy]; _readableDirectory=[readableDirectory copy]; _caPath=[caPath copy]; _bundledDirectory=[bundle copy];
        _device=privateStatus.st_dev; _inode=privateStatus.st_ino; _readableDevice=readableStatus.st_dev; _readableInode=readableStatus.st_ino;
        for (NSString *child in @[@"local",@"cache"]) if (!MLProviderPrivateDirectory([directory stringByAppendingPathComponent:child],YES,YES,error)) return nil;
        _operation=[[NSLock alloc] init]; _current=@{@"format":@1,@"sources":@{},@"updatedAt":@0};
        NSString *path=[directory stringByAppendingPathComponent:@"geo-current.json"]; struct stat status;
        if (lstat(path.fileSystemRepresentation,&status)==0) {
            _manifestData=MLProviderPrivateRead(path,32768,error);
            NSDictionary *manifest=_manifestData ? [NSJSONSerialization JSONObjectWithData:_manifestData options:0 error:NULL] : nil;
            if (![manifest isKindOfClass:[NSDictionary class]] || ![manifest[@"format"] isEqual:@1] || ![manifest[@"sources"] isKindOfClass:[NSDictionary class]] || [manifest[@"sources"] count]>3) return MLGMFail(error,@"E_GEO_STORAGE",@"The private Geo manifest is malformed.");
            for (id source in [manifest[@"sources"] allValues]) if (![source isKindOfClass:[NSDictionary class]] || !MLGMHash(source[@"hash"]) || !MLGMHash(source[@"sourceHash"]) || ![source[@"updatedAt"] isKindOfClass:[NSNumber class]]) return MLGMFail(error,@"E_GEO_STORAGE",@"The Geo manifest contains invalid source identities.");
            _current=manifest;
        } else if (errno!=ENOENT) return MLGMFail(error,@"E_GEO_STORAGE",@"Cannot inspect the Geo manifest.");
    }
    return self;
}
- (BOOL)integrity:(NSError **)error {
    struct stat privateStatus,publicStatus;
    if (!MLProviderPrivateDirectory(_directory,NO,YES,error) || !MLProviderPrivateDirectory(_readableDirectory,NO,NO,error) || lstat(_directory.fileSystemRepresentation,&privateStatus)!=0 || lstat(_readableDirectory.fileSystemRepresentation,&publicStatus)!=0 ||
        privateStatus.st_dev!=_device || privateStatus.st_ino!=_inode || publicStatus.st_dev!=_readableDevice || publicStatus.st_ino!=_readableInode || publicStatus.st_uid!=geteuid() || (publicStatus.st_mode&0777)!=0755) {
        MLGMFail(error,@"E_GEO_STORAGE",@"A controlled Geo directory was replaced or changed permissions."); return NO;
    }
    return YES;
}
- (NSSet *)privatePreserve:(NSDictionary *)additional {
    NSMutableSet *hashes=[NSMutableSet set];
    for (NSDictionary *manifest in @[_current,_preparedManifest ?: @{},additional ?: @{}]) for (NSDictionary *source in [manifest[@"sources"] allValues]) if (MLGMHash(source[@"hash"])) [hashes addObject:source[@"hash"]];
    return hashes;
}
- (BOOL)stagePublic:(NSData *)data hash:(NSString *)hash descriptor:(NSDictionary **)descriptor error:(NSError **)error {
    NSString *path=[_readableDirectory stringByAppendingPathComponent:[hash stringByAppendingString:@".index"]];
    NSDictionary *description=@{@"path":path,@"sha256":hash,@"owner":@(geteuid()),@"size":@(data.length)}; struct stat existing;
    if (lstat(path.fileSystemRepresentation,&existing)==0) {
        if (![MLGeoIndex indexWithDescriptor:description error:error]) return NO; *descriptor=description; return YES;
    }
    if (errno!=ENOENT) { MLGMFail(error,@"E_GEO_STORAGE",@"Cannot inspect a staged Geo index."); return NO; }
    NSMutableSet *preserve=[NSMutableSet setWithObject:hash];
    for (NSDictionary *manifest in @[_current,_preparedManifest ?: @{}]) if (MLGMHash(manifest[@"index"][@"sha256"])) [preserve addObject:manifest[@"index"][@"sha256"]];
    if (!MLGMPrune(_readableDirectory,@".index",96*1024*1024,preserve,data.length,error)) return NO;
    NSString *temporary=[_readableDirectory stringByAppendingPathComponent:[@".pending-" stringByAppendingString:[[NSUUID UUID] UUIDString]]];
    int fd=open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    if (fd<0) { MLGMFail(error,@"E_GEO_STORAGE",@"Cannot stage an immutable Geo index."); return NO; }
    NSUInteger written=0; BOOL valid=YES;
    while (written<data.length) { ssize_t n=write(fd,(const unsigned char *)data.bytes+written,data.length-written); if (n<0 && errno==EINTR) continue; if (n<=0) { valid=NO; break; } written+=(NSUInteger)n; }
    if (valid && (fchmod(fd,0444)!=0 || fsync(fd)!=0)) valid=NO;
    if (close(fd)!=0) valid=NO;
    if (valid && (![self integrity:error] || rename(temporary.fileSystemRepresentation,path.fileSystemRepresentation)!=0)) valid=NO;
    if (!valid) { unlink(temporary.fileSystemRepresentation); MLGMFail(error,@"E_GEO_STORAGE",@"Cannot install the immutable Geo index."); return NO; }
    int parent=open(_readableDirectory.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW); BOOL durable=parent>=0;
    if (parent>=0) { if (fsync(parent)!=0) durable=NO; if (close(parent)!=0) durable=NO; }
    if (!durable) { MLGMFail(error,@"E_GEO_STORAGE",@"Cannot durably sync the installed immutable Geo index."); return NO; }
    if (![MLGeoIndex indexWithDescriptor:description error:error]) return NO; *descriptor=description; return YES;
}
- (NSString *)stageRaw:(NSData *)raw sources:(NSDictionary *)sources error:(NSError **)error {
    NSString *hash=MLProviderStorageHash(raw), *directory=[_directory stringByAppendingPathComponent:@"cache"], *path=[directory stringByAppendingPathComponent:[hash stringByAppendingString:@".raw"]];
    struct stat status;
    if (lstat(path.fileSystemRepresentation,&status)==0) {
        NSString *existing=MLGMRawHash(path,error); if (!existing) return nil;
        if ([existing isEqual:hash]) return path;
        // Repair only a safely owned regular file, using atomic replacement.
    } else if (errno!=ENOENT) return MLGMFail(error,@"E_GEO_STORAGE",@"Cannot inspect a raw Geo snapshot.");
    NSMutableSet *preserve=[[self privatePreserve:@{@"sources":sources}] mutableCopy]; [preserve addObject:hash];
    if (!MLGMPrune(directory,@".raw",128*1024*1024,preserve,raw.length,error) || !MLProviderPrivateWrite(path,raw,error)) return nil;
    NSString *stored=MLGMRawHash(path,error);
    if (!stored || ![stored isEqual:hash]) return MLGMFail(error,@"E_GEO_STORAGE",@"The staged raw Geo snapshot failed integrity validation.");
    return path;
}
- (NSDictionary *)prepareDocument:(NSDictionary *)document fetch:(BOOL)fetch refresh:(BOOL)refresh error:(NSError **)error {
    if (error) *error=nil;
    if (![_operation tryLock]) return MLGMFail(error,@"E_BUSY",@"A Geo generation is already being prepared.");
    @try {
        if (![self integrity:error] || ![document isKindOfClass:[NSDictionary class]]) return nil;
        NSMutableDictionary *requests=[@{@"geoip":[NSMutableSet set],@"geosite":[NSMutableSet set],@"asn":[NSMutableSet set]} mutableCopy];
        for (NSString *line in MLGMArray(document[@"rules"])) MLGMCollect(line,requests,0);
        if ([document[@"sub-rules"] isKindOfClass:[NSDictionary class]]) for (NSArray *lines in [document[@"sub-rules"] allValues]) for (NSString *line in MLGMArray(lines)) MLGMCollect(line,requests,0);
        if ([document[@"_rule-provider-payloads"] isKindOfClass:[NSDictionary class]]) for (NSDictionary *provider in [document[@"_rule-provider-payloads"] allValues]) if ([provider[@"behavior"] isEqual:@"classical"]) for (NSString *line in MLGMArray(provider[@"payload"])) MLGMCollect(line,requests,0);
        for (NSDictionary *request in MLDNSGeoRequests([document[@"dns"] isKindOfClass:[NSDictionary class]] ? document[@"dns"] : @{})) [requests[request[@"kind"]] addObject:request[@"operand"]];
        NSMutableDictionary *sets=[NSMutableDictionary dictionary], *sources=[NSMutableDictionary dictionary];
        NSDictionary *urls=[document[@"geox-url"] isKindOfClass:[NSDictionary class]] ? document[@"geox-url"] : @{};
        BOOL dat=[document[@"geodata-mode"] boolValue]; double now=[[NSDate date] timeIntervalSince1970];
        NSDictionary *defaults=@{@"geoip":@"https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",@"geosite":@"https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",@"mmdb":@"https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",@"asn":@"https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"};
        NSMutableArray *requestIdentity=[NSMutableArray array]; BOOL localReload=NO;
        for (NSString *kind in @[@"geoip",@"geosite",@"asn"]) {
            if (![requests[kind] count]) continue;
            NSString *key=[kind isEqual:@"geoip"] && !dat ? @"mmdb" : kind;
            NSString *name=[key isEqual:@"mmdb"] ? @"Country.mmdb" : ([key isEqual:@"asn"] ? @"ASN.mmdb" : ([key isEqual:@"geoip"] ? @"GeoIP.dat" : @"GeoSite.dat"));
            struct stat st; BOOL file=!urls[key] && !lstat([[[_directory stringByAppendingPathComponent:@"local"] stringByAppendingPathComponent:name] fileSystemRepresentation],&st);
            if (file && fetch) localReload=YES;
            [requestIdentity addObject:@[key,file ? [@"file:" stringByAppendingString:name] : (urls[key] ?: defaults[key]),[[requests[kind] allObjects] sortedArrayUsingSelector:@selector(compare:)]]];
        }
        NSString *requestHash=MLProviderStorageHash([NSJSONSerialization dataWithJSONObject:requestIdentity options:0 error:NULL]);
        // Reopen the validated native index rather than walking a full MMDB on every restart/apply.
        if (!refresh && !localReload && [_current[@"requestHash"] isEqual:requestHash] && [_current[@"index"] count] && [MLGeoIndex indexWithDescriptor:_current[@"index"] error:NULL]) {
            NSMutableDictionary *expanded=[document mutableCopy]; expanded[@"_geo-index"]=_current[@"index"];
            NSData *encoded=[NSJSONSerialization dataWithJSONObject:expanded options:0 error:NULL];
            if (!encoded || encoded.length>768*1024) return MLGMFail(error,@"E_GEO_RESOURCE",@"The generation descriptor exceeds its 768 KiB IPC budget.");
            NSMutableDictionary *manifest=[_current mutableCopy]; BOOL remote=NO;
            for (NSDictionary *source in [_current[@"sources"] allValues]) if (! [source[@"type"] isEqual:@"file"]) remote=YES;
            manifest[@"autoUpdate"]=@([document[@"geo-auto-update"] boolValue] && remote); manifest[@"interval"]=document[@"geo-update-interval"] ?: @24;
            @synchronized(self) { _prepared=[NSJSONSerialization JSONObjectWithData:encoded options:0 error:NULL]; _preparedManifest=[manifest copy]; }
            return _prepared;
        }
        for (NSString *kind in @[@"geoip",@"geosite",@"asn"]) {
            if (![requests[kind] count]) continue;
            NSError *failure=nil; NSDictionary *decoded=nil, *source=nil;
            @autoreleasepool {
                NSString *key=[kind isEqual:@"geoip"] && !dat ? @"mmdb" : kind;
                NSString *localName=[key isEqual:@"mmdb"] ? @"Country.mmdb" : ([key isEqual:@"asn"] ? @"ASN.mmdb" : ([key isEqual:@"geoip"] ? @"GeoIP.dat" : @"GeoSite.dat"));
                NSString *local=[[_directory stringByAppendingPathComponent:@"local"] stringByAppendingPathComponent:localName]; struct stat localStatus;
                BOOL file=!urls[key] && lstat(local.fileSystemRepresentation,&localStatus)==0;
                NSString *url=urls[key] ?: defaults[key];
                NSString *identity=MLProviderStorageHash([[NSString stringWithFormat:@"%@:%@",key,file ? [@"file:" stringByAppendingString:localName] : url] dataUsingEncoding:NSUTF8StringEncoding]);
                NSDictionary *old=_current[@"sources"][key]; NSString *oldHash=[old[@"sourceHash"] isEqual:identity] ? old[@"hash"] : nil;
                NSData *cached=oldHash ? MLProviderPrivateRead([[_directory stringByAppendingPathComponent:@"cache"] stringByAppendingPathComponent:[oldHash stringByAppendingString:@".raw"]],32*1024*1024,NULL) : nil;
                if (cached && ![MLProviderStorageHash(cached) isEqual:oldHash]) cached=nil;
                NSData *bundled=nil;
                if (!file && !urls[key] && !cached && _bundledDirectory) {
                    NSData *manifestData=MLGMBundleRead(_bundledDirectory,@"manifest.json",32768);
                    NSDictionary *manifest=manifestData ? [NSJSONSerialization JSONObjectWithData:manifestData options:0 error:NULL] : nil;
                    NSDictionary *entry=[manifest isKindOfClass:[NSDictionary class]] ? manifest[@"files"][localName] : nil;
                    NSData *candidate=MLGMBundleRead(_bundledDirectory,localName,32*1024*1024);
                    if ([entry isKindOfClass:[NSDictionary class]] && candidate && [MLProviderStorageHash(candidate) isEqual:entry[@"sha256"]]) bundled=candidate;
                }
                NSData *raw=cached ?: bundled; BOOL downloaded=NO, localLoaded=file && (fetch || refresh || !cached);
                if (localLoaded) raw=MLProviderPrivateRead(local,32*1024*1024,&failure);
                else if (fetch && !file && (refresh || !raw)) { _lastAttempt=[NSProcessInfo processInfo].systemUptime; raw=MLFetchDataWithTimeout(url,_caPath,32*1024*1024,120000,&failure); downloaded=raw!=nil; }
                if (!raw && bundled) raw=bundled;
                if (raw) {
                    NSString *hash=MLProviderStorageHash(raw);
                    if ([kind isEqual:@"geosite"] || ([kind isEqual:@"geoip"] && dat)) decoded=MLGeoDecodeDat(raw,kind,requests[kind],&failure);
                    else {
                        NSString *path=[self stageRaw:raw sources:sources error:&failure];
                        if (path) decoded=MLGeoDecodeMMDB(path,kind,requests[kind],&failure);
                    }
                    if (decoded) {
                        if (![self stageRaw:raw sources:sources error:&failure]) decoded=nil;
                        if (decoded) source=@{@"name":key,@"type":file ? @"file" : (bundled && raw==bundled ? @"builtin" : (cached && !downloaded ? old[@"type"] : @"http")),@"hash":hash,@"sourceHash":identity,@"updatedAt":@((downloaded || localLoaded || !cached) ? now : [old[@"updatedAt"] doubleValue]),@"status":@"ready"};
                    }
                }
                if (!decoded && cached && (downloaded || failure)) {
                    NSError *cacheError=nil;
                    if ([kind isEqual:@"geosite"] || ([kind isEqual:@"geoip"] && dat)) decoded=MLGeoDecodeDat(cached,kind,requests[kind],&cacheError);
                    else decoded=MLGeoDecodeMMDB([[_directory stringByAppendingPathComponent:@"cache"] stringByAppendingPathComponent:[oldHash stringByAppendingString:@".raw"]],kind,requests[kind],&cacheError);
                    if (decoded) { NSMutableDictionary *state=[old mutableCopy]; state[@"status"]=@"cached"; state[@"lastError"]=failure.domain ?: @"E_GEO_UPDATE"; source=[state copy]; }
                }
            }
            if (!decoded) { if (failure && error) *error=failure; else MLGMFail(error,@"E_GEO_DATABASE_UNAVAILABLE",@"A referenced Geo database has no validated local/cache snapshot."); return nil; }
            [sets addEntriesFromDictionary:decoded]; sources[source[@"name"]]=source;
        }
        NSData *index=MLGeoEncodeIndex(sets,error); if (!index) return nil;
        NSDictionary *descriptor=nil;
        if (sets.count && ![self stagePublic:index hash:MLProviderStorageHash(index) descriptor:&descriptor error:error]) return nil;
        NSMutableDictionary *expanded=[document mutableCopy]; [expanded removeObjectForKey:@"_geo-index"]; if (descriptor) expanded[@"_geo-index"]=descriptor;
        NSData *encoded=[NSJSONSerialization dataWithJSONObject:expanded options:0 error:NULL]; if (!encoded || encoded.length>768*1024) return MLGMFail(error,@"E_GEO_RESOURCE",@"The generation descriptor exceeds its 768 KiB IPC budget.");
        double updated=now; BOOL remote=NO;
        for (NSDictionary *source in sources.allValues) if (![source[@"type"] isEqual:@"file"]) { remote=YES; updated=MIN(updated,[source[@"updatedAt"] doubleValue]); }
        NSDictionary *manifest=@{@"format":@1,@"requestHash":requestHash,@"sources":sources,@"index":descriptor ?: @{},@"updatedAt":@(updated),@"autoUpdate":@([document[@"geo-auto-update"] boolValue] && remote),@"interval":document[@"geo-update-interval"] ?: @24};
        @synchronized(self) { _prepared=[NSJSONSerialization JSONObjectWithData:encoded options:0 error:NULL]; _preparedManifest=manifest; }
        return _prepared;
    } @finally { [_operation unlock]; }
}
- (BOOL)commitPreparedDocument:(NSDictionary *)document error:(NSError **)error {
    if (![_operation tryLock]) { MLGMFail(error,@"E_BUSY",@"A Geo generation is being prepared."); return NO; }
    int lock=-1;
    @try {
        if (![self integrity:error]) return NO;
        lock=open([[_directory stringByAppendingPathComponent:@"geo.lock"] fileSystemRepresentation],O_RDWR|O_CREAT|O_NOFOLLOW,0600); struct stat status;
        if (lock<0 || fstat(lock,&status)!=0 || !S_ISREG(status.st_mode) || status.st_uid!=geteuid() || status.st_nlink!=1 || (status.st_mode&0077) || flock(lock,LOCK_EX|LOCK_NB)!=0) { MLGMFail(error,@"E_BUSY",@"The private Geo commit lock is unavailable."); return NO; }
        @synchronized(self) {
            if (!_prepared || document!=_prepared) { MLGMFail(error,@"E_GEO_GENERATION",@"This Geo generation is stale or was not prepared by this manager."); return NO; }
            NSString *path=[_directory stringByAppendingPathComponent:@"geo-current.json"]; NSData *current=nil; struct stat st;
            if (lstat(path.fileSystemRepresentation,&st)==0) { current=MLProviderPrivateRead(path,32768,error); if (!current) return NO; }
            else if (errno!=ENOENT) { MLGMFail(error,@"E_GEO_STORAGE",@"Cannot inspect the Geo manifest."); return NO; }
            if ((current || _manifestData) && ![current isEqual:_manifestData]) { MLGMFail(error,@"E_GEO_GENERATION",@"Another service changed the Geo manifest."); return NO; }
            NSData *data=[NSJSONSerialization dataWithJSONObject:_preparedManifest options:0 error:NULL];
            if (!data || data.length>32768) return NO;
            // Keep the exact attempted pointer until recovery: a durable-write
            // failure may occur after rename already made these bytes visible.
            _pointerAttemptData=data;
            if (!MLProviderPrivateWrite(path,data,error)) return NO;
            _current=_preparedManifest; _manifestData=data; _pointerAttemptData=nil; _prepared=nil; _preparedManifest=nil; return YES;
        }
    } @finally { if (lock>=0) { (void)flock(lock,LOCK_UN); close(lock); } [_operation unlock]; }
}
- (void)discardPreparedDocument { @synchronized(self) { _prepared=nil; _preparedManifest=nil; } }
- (NSArray *)list { @synchronized(self) { NSMutableArray *items=[NSMutableArray array]; for (NSString *key in [_current[@"sources"] allKeys]) [items addObject:_current[@"sources"][key]]; return [items copy]; } }
- (BOOL)dueRefresh {
    @synchronized(self) {
        if (![_current[@"autoUpdate"] boolValue] || [_current[@"sources"] count]==0 || [NSProcessInfo processInfo].systemUptime-_lastAttempt<60) return NO;
        double interval=[_current[@"interval"] doubleValue]*3600, updated=[_current[@"updatedAt"] doubleValue], now=[[NSDate date] timeIntervalSince1970]; return now<updated || now-updated>=MAX(3600,interval);
    }
}
- (id)captureCheckpoint { @synchronized(self) { return @{@"owner":self,@"manifest":_current,@"data":_manifestData ?: [NSNull null]}; } }
- (BOOL)restoreCheckpoint:(id)checkpoint error:(NSError **)error {
    if (![checkpoint isKindOfClass:[NSDictionary class]] || checkpoint[@"owner"]!=self) { MLGMFail(error,@"E_GEO_RECOVERY",@"The Geo checkpoint belongs to another manager."); return NO; }
    if (![_operation tryLock]) { MLGMFail(error,@"E_BUSY",@"A Geo operation is active during recovery."); return NO; }
    int lock=-1;
    @try {
        if (![self integrity:error]) return NO;
        lock=open([[_directory stringByAppendingPathComponent:@"geo.lock"] fileSystemRepresentation],O_RDWR|O_CREAT|O_NOFOLLOW,0600); struct stat status;
        if (lock<0 || fstat(lock,&status)!=0 || !S_ISREG(status.st_mode) || status.st_uid!=geteuid() || status.st_nlink!=1 || (status.st_mode&0077) || flock(lock,LOCK_EX|LOCK_NB)!=0) { MLGMFail(error,@"E_BUSY",@"Cannot acquire the Geo recovery lock."); return NO; }
        @synchronized(self) {
            NSString *path=[_directory stringByAppendingPathComponent:@"geo-current.json"]; NSData *current=nil; struct stat existing;
            if (lstat(path.fileSystemRepresentation,&existing)==0) { current=MLProviderPrivateRead(path,32768,error); if (!current) return NO; }
            else if (errno!=ENOENT) { MLGMFail(error,@"E_GEO_RECOVERY",@"Cannot inspect the Geo pointer during recovery."); return NO; }
            NSData *old=[checkpoint[@"data"] isKindOfClass:[NSData class]] ? checkpoint[@"data"] : nil;
            // This comparison uses the validated owned/private disk file, not
            // the in-memory pointer. An unchanged pointer needs no directory
            // write, even when a failed commit left the directory read-only.
            if (!MLGMSameData(current,old)) {
                if (!MLGMSameData(current,_manifestData) && !(_pointerAttemptData && MLGMSameData(current,_pointerAttemptData))) { MLGMFail(error,@"E_GEO_RECOVERY",@"Another service changed the Geo pointer; recovery cannot overwrite it."); return NO; }
                if (old) { _pointerAttemptData=old; if (!MLProviderPrivateWrite(path,old,error)) return NO; }
                else if (current && unlink(path.fileSystemRepresentation)!=0) { MLGMFail(error,@"E_GEO_RECOVERY",@"Cannot restore the initial Geo pointer."); return NO; }
            }
            _current=checkpoint[@"manifest"]; _manifestData=old; _pointerAttemptData=nil; _prepared=nil; _preparedManifest=nil; return YES;
        }
    } @finally { if (lock>=0) { (void)flock(lock,LOCK_UN); close(lock); } [_operation unlock]; }
}
@end
