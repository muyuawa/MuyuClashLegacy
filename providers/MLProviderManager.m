#import "MLProviderManager.h"
#import "MLMRS.h"
#import "MLDomainProviderIndex.h"
#import "MLProviderStorage.h"
#import "../config/MLConfig.h"
#import "../config/MLFetch.h"
#import "../routing/MLRoutingInternal.h"
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static const NSUInteger MLProviderTextLimit=512*1024, MLProviderBinaryLimit=8*1024*1024, MLProviderCacheLimit=1024*1024, MLProviderGenerationLimit=768*1024;
static NSArray *MLPArray(id v) { return [v isKindOfClass:[NSArray class]] ? v : @[]; }
static NSDictionary *MLPDictionary(id v) { return [v isKindOfClass:[NSDictionary class]] ? v : @{}; }
static NSString *MLPString(id v) { return [v isKindOfClass:[NSString class]] ? v : nil; }
static id MLPFail(NSError **error, NSString *code, NSString *message) {
    if (error) *error=[NSError errorWithDomain:code code:1 userInfo:@{NSLocalizedDescriptionKey:message}];
    return nil;
}
static NSString *MLPPath(NSString *path) {
    if (!MLPString(path) || !path.length || path.isAbsolutePath || [path lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>256 ||
        [path rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound) return nil;
    // Clash Providers commonly spell their private relative cache/file path
    // with one leading './'. Resolve only that prefix before constructing IO.
    if ([path hasPrefix:@"./"]) path=[path substringFromIndex:2];
    if (!path.length || path.isAbsolutePath) return nil;
    NSArray *parts=[path componentsSeparatedByString:@"/"];
    if (parts.count>16) return nil;
    for (NSString *part in parts) if (!part.length || [part isEqual:@"."] || [part isEqual:@".."] || [part isEqual:@"~"]) return nil;
    return [parts componentsJoinedByString:@"/"];
}
static BOOL MLPDirectory(NSString *path, BOOL create, BOOL private, NSError **error) {
    if (!path.isAbsolutePath || [path.pathComponents containsObject:@".."] || [path rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound) {
        MLPFail(error,@"E_PROVIDER_PATH",@"Provider storage requires a fixed absolute private directory."); return NO;
    }
    NSString *current=@"/";
    for (NSString *part in path.pathComponents) {
        if ([part isEqual:@"/"]) continue;
        current=[current stringByAppendingPathComponent:part]; struct stat status;
        if (lstat(current.fileSystemRepresentation,&status)!=0) {
            if (!create || errno!=ENOENT || mkdir(current.fileSystemRepresentation,0700)!=0 || lstat(current.fileSystemRepresentation,&status)!=0) {
                MLPFail(error,@"E_PROVIDER_STORAGE",@"Cannot prepare the private Provider directory."); return NO;
            }
        }
        if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) { MLPFail(error,@"E_PROVIDER_PATH",@"Provider paths cannot traverse symbolic links."); return NO; }
    }
    if (private) {
        struct stat status;
        if (lstat(path.fileSystemRepresentation,&status)!=0 || status.st_uid!=geteuid() || (status.st_mode&0077)) {
            MLPFail(error,@"E_PROVIDER_STORAGE",@"Provider directories must belong to the service user and be private."); return NO;
        }
    }
    return YES;
}
static NSData *MLPRead(NSString *path, NSUInteger limit, NSError **error) {
    if (!MLPDirectory(path.stringByDeletingLastPathComponent,NO,YES,error)) return nil;
    struct stat before, status;
    if (lstat(path.fileSystemRepresentation,&before)!=0) { MLPFail(error,@"E_PROVIDER_FILE",@"The local Provider file is unavailable."); return nil; }
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW);
    if (fd<0 || fstat(fd,&status)!=0 || !S_ISREG(status.st_mode) || status.st_nlink!=1 || status.st_uid!=geteuid() ||
        (status.st_mode&0077) || status.st_size<0 || (uint64_t)status.st_size>limit || status.st_dev!=before.st_dev || status.st_ino!=before.st_ino) {
        if (fd>=0) close(fd); MLPFail(error,@"E_PROVIDER_FILE",@"The Provider file is not a private bounded regular file."); return nil;
    }
    NSMutableData *data=[NSMutableData data]; unsigned char buffer[8192];
    for (;;) {
        ssize_t n=read(fd,buffer,sizeof buffer);
        if (n<0 && errno==EINTR) continue;
        if (n<0 || (n>0 && data.length>limit-(NSUInteger)n)) { close(fd); MLPFail(error,@"E_PROVIDER_FILE",@"The Provider file changed or exceeded its size limit."); return nil; }
        if (!n) break;
        [data appendBytes:buffer length:(NSUInteger)n];
    }
    struct stat after;
    BOOL same=fstat(fd,&after)==0 && after.st_dev==status.st_dev && after.st_ino==status.st_ino && after.st_size==(off_t)data.length &&
        after.st_size==status.st_size && after.st_mtime==status.st_mtime && after.st_ctime==status.st_ctime &&
        after.st_uid==geteuid() && after.st_nlink==1 && (after.st_mode&0077)==0 &&
        lstat(path.fileSystemRepresentation,&before)==0 && before.st_dev==status.st_dev && before.st_ino==status.st_ino &&
        before.st_uid==geteuid() && before.st_nlink==1 && (before.st_mode&0077)==0;
    close(fd);
    if (!same || !MLPDirectory(path.stringByDeletingLastPathComponent,NO,YES,error)) return MLPFail(error,@"E_PROVIDER_FILE",@"The Provider file was replaced during reading.");
    return data;
}
static NSString *MLPCanonical(id value) {
    if ([value isKindOfClass:[NSDictionary class]]) {
        NSMutableArray *parts=[NSMutableArray array];
        for (NSString *key in [[value allKeys] sortedArrayUsingSelector:@selector(compare:)])
            [parts addObject:[NSString stringWithFormat:@"%@:%@",MLPCanonical(key),MLPCanonical(value[key])]];
        return [NSString stringWithFormat:@"{%@}",[parts componentsJoinedByString:@","]];
    }
    if ([value isKindOfClass:[NSArray class]]) {
        NSMutableArray *parts=[NSMutableArray array]; for (id item in value) [parts addObject:MLPCanonical(item)];
        return [NSString stringWithFormat:@"[%@]",[parts componentsJoinedByString:@","]];
    }
    NSData *data=[NSJSONSerialization dataWithJSONObject:@[value ?: [NSNull null]] options:0 error:NULL];
    NSString *text=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return text.length>=2 ? [text substringWithRange:NSMakeRange(1,text.length-2)] : @"null";
}
static NSString *MLPHash(NSString *text) {
    NSData *data=[text dataUsingEncoding:NSUTF8StringEncoding]; unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes,(CC_LONG)data.length,digest); NSMutableString *result=[NSMutableString string];
    for (NSUInteger i=0;i<sizeof digest;++i) [result appendFormat:@"%02x",digest[i]];
    return result;
}
static BOOL MLPHashValid(id value) {
    return MLPString(value).length==64 && [value rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet]].location==NSNotFound;
}
static BOOL MLPSameData(NSData *a, NSData *b) {
    return (!a && !b) || (a && b && [a isEqual:b] && [MLProviderStorageHash(a) isEqual:MLProviderStorageHash(b)]);
}
static BOOL MLPWriteMode(NSString *path, NSData *data, mode_t mode, NSError **error) {
    NSString *directory=path.stringByDeletingLastPathComponent;
    BOOL privateFile = mode == 0600;
    if (!MLPDirectory(directory,privateFile,privateFile,error)) return NO;
    CFUUIDRef uuid=CFUUIDCreate(NULL); NSString *identifier=CFBridgingRelease(CFUUIDCreateString(NULL,uuid)); CFRelease(uuid);
    NSString *temporary=[directory stringByAppendingPathComponent:[@".pending-" stringByAppendingString:identifier]];
    int fd=open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    if (fd<0) { MLPFail(error,@"E_PROVIDER_STORAGE",@"Cannot stage a private Provider snapshot."); return NO; }
    const unsigned char *bytes=data.bytes; NSUInteger written=0; BOOL good=YES;
    while (written<data.length) { ssize_t n=write(fd,bytes+written,data.length-written); if (n<0 && errno==EINTR) continue; if (n<=0) { good=NO; break; } written+=(NSUInteger)n; }
    if (good && (fchmod(fd,mode)!=0 || fsync(fd)!=0)) good=NO;
    if (close(fd)!=0) good=NO;
    struct stat old;
    if (lstat(path.fileSystemRepresentation,&old)==0 && (!S_ISREG(old.st_mode) || old.st_uid!=geteuid() || old.st_nlink!=1 || (old.st_mode&0777)!=mode)) good=NO;
    if (good && !MLPDirectory(directory,NO,privateFile,error)) good=NO;
    if (good && rename(temporary.fileSystemRepresentation,path.fileSystemRepresentation)!=0) good=NO;
    if (!good) { unlink(temporary.fileSystemRepresentation); MLPFail(error,@"E_PROVIDER_STORAGE",@"Cannot atomically install the Provider snapshot."); return NO; }
    int parent=open(directory.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    BOOL durable=parent>=0;
    if (parent>=0) { if (fsync(parent)!=0) durable=NO; if (close(parent)!=0) durable=NO; }
    if (!durable) { MLPFail(error,@"E_PROVIDER_STORAGE",@"Cannot durably sync the installed private Provider snapshot."); return NO; }
    return YES;
}
static BOOL MLPWrite(NSString *path, NSData *data, NSError **error) { return MLPWriteMode(path,data,0600,error); }

static BOOL MLPPruneCache(NSString *directory, NSSet *preserved, NSArray *writes, BOOL indexed, NSError **error) {
    if (!MLPDirectory(directory,NO,!indexed,error)) return NO;
    NSString *extension = indexed ? @".index" : @".json";
    NSUInteger fileLimit = indexed ? MLDomainProviderIndexLimit : MLProviderCacheLimit;
    mode_t mode = indexed ? 0444 : 0600;
    NSArray *names=[[NSFileManager defaultManager] contentsOfDirectoryAtPath:directory error:error];
    if (!names || names.count>4096) { MLPFail(error,@"E_PROVIDER_STORAGE",@"The Provider cache directory exceeds its entry budget."); return NO; }
    NSMutableSet *incoming=[NSMutableSet set]; NSUInteger bytes=0, count=0;
    for (NSDictionary *write in writes) { [incoming addObject:write[@"hash"]]; bytes+=[write[@"data"] length]; ++count; }
    NSMutableArray *discardable=[NSMutableArray array]; NSCharacterSet *hex=[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet];
    for (NSString *name in names) {
        if (MLProviderStorageIsTemporaryName(name)) {
            NSUInteger size=0;
            if (!MLProviderStorageInspectTemporary([directory stringByAppendingPathComponent:name],fileLimit,indexed,&size,error)) return NO;
            if (size!=NSNotFound) { bytes+=size; ++count; } continue;
        }
        if (name.length!=64+extension.length || ![name hasSuffix:extension] || [[name substringToIndex:64] rangeOfCharacterFromSet:hex].location!=NSNotFound) {
            MLPFail(error,@"E_PROVIDER_STORAGE",@"The Provider cache contains an unexpected entry."); return NO;
        }
        NSString *hash=[name substringToIndex:64], *path=[directory stringByAppendingPathComponent:name]; struct stat status;
        if (lstat(path.fileSystemRepresentation,&status)!=0 || !S_ISREG(status.st_mode) || status.st_nlink!=1 || status.st_uid!=geteuid() || (status.st_mode&0777)!=mode || status.st_size<0 || (uint64_t)status.st_size>fileLimit) {
            MLPFail(error,@"E_PROVIDER_STORAGE",@"The Provider cache contains an invalid file."); return NO;
        }
        if ([incoming containsObject:hash]) continue;
        if ((uint64_t)status.st_size>NSUIntegerMax-bytes) { MLPFail(error,@"E_PROVIDER_STORAGE",@"The Provider cache exceeds its size budget."); return NO; }
        bytes+=(NSUInteger)status.st_size; ++count;
        if (![preserved containsObject:hash]) [discardable addObject:@{@"path":path,@"size":@((uint64_t)status.st_size),@"mtime":@((double)status.st_mtime)}];
    }
    [discardable sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSComparisonResult order=[a[@"mtime"] compare:b[@"mtime"]]; return order==NSOrderedSame ? [a[@"path"] compare:b[@"path"]] : order;
    }];
    for (NSDictionary *entry in discardable) {
        if (bytes<=64*1024*1024 && count<=256) break;
        if (unlink([entry[@"path"] fileSystemRepresentation])!=0) { MLPFail(error,@"E_PROVIDER_STORAGE",@"Cannot prune obsolete Provider snapshots."); return NO; }
        bytes-=[entry[@"size"] unsignedIntegerValue]; --count;
    }
    if (bytes>64*1024*1024 || count>256) { MLPFail(error,@"E_PROVIDER_STORAGE",@"Active Provider snapshots exceed the 64 MiB cache budget."); return NO; }
    return YES;
}
BOOL MLProviderPrivateDirectory(NSString *path, BOOL create, BOOL private, NSError **error) { return MLPDirectory(path,create,private,error); }
NSData *MLProviderPrivateRead(NSString *path, NSUInteger limit, NSError **error) { return MLPRead(path,limit,error); }
BOOL MLProviderPrivateWrite(NSString *path, NSData *data, NSError **error) { return MLPWrite(path,data,error); }
NSString *MLProviderStorageHash(NSData *data) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(data.bytes,(CC_LONG)data.length,digest); NSMutableString *result=[NSMutableString string];
    for (NSUInteger i=0;i<sizeof digest;++i) [result appendFormat:@"%02x",digest[i]]; return result;
}
static NSArray *MLPPatterns(NSString *text, NSError **error) {
    if (!MLPString(text) || !text.length) return @[];
    if (text.length>4096) return MLPFail(error,@"E_PROVIDER_FILTER",@"The Provider filter exceeds its size limit.");
    NSMutableArray *patterns=[NSMutableArray array];
    for (NSString *part in [text componentsSeparatedByString:@"`"]) {
        if (patterns.count>=16 || !part.length) return MLPFail(error,@"E_PROVIDER_FILTER",@"A filter requires at most sixteen nonempty expressions.");
        NSRegularExpression *pattern=[NSRegularExpression regularExpressionWithPattern:part options:0 error:NULL];
        if (!pattern) return MLPFail(error,@"E_PROVIDER_FILTER",@"This regular expression cannot be compiled on the legacy platform.");
        [patterns addObject:pattern];
    }
    return patterns;
}
static BOOL MLPMatch(NSRegularExpression *regex, NSString *name, NSTimeInterval deadline, BOOL *valid) {
    NSTimeInterval now=[NSProcessInfo processInfo].systemUptime;
    if (!*valid || now>=deadline) { *valid=NO; return NO; }
    NSTimeInterval end=MIN(deadline,now+0.05); __block BOOL match=NO;
    [regex enumerateMatchesInString:name options:NSMatchingReportProgress|NSMatchingReportCompletion range:NSMakeRange(0,name.length)
        usingBlock:^(NSTextCheckingResult *result, NSMatchingFlags flags, BOOL *stop) {
            if (flags&NSMatchingInternalError || [NSProcessInfo processInfo].systemUptime>end) { *valid=NO; *stop=YES; }
            else if (result) { match=YES; *stop=YES; }
        }];
    return match;
}
static NSArray *MLPFilterBefore(NSArray *nodes, NSDictionary *options, NSTimeInterval deadline, NSError **error) {
    NSArray *include=MLPPatterns(options[@"filter"],error), *exclude=MLPPatterns(options[@"exclude-filter"],error);
    if (!include || !exclude) return nil;
    NSArray *types=[MLPString(options[@"exclude-type"]).lowercaseString componentsSeparatedByString:@"|"] ?: @[];
    NSMutableOrderedSet *chosen=[NSMutableOrderedSet orderedSet]; BOOL valid=YES;
    if (!include.count) [chosen addObjectsFromArray:nodes];
    else for (NSRegularExpression *pattern in include) for (NSDictionary *node in nodes) {
        if (MLPMatch(pattern,node[@"name"],deadline,&valid)) [chosen addObject:node];
        if (!valid) return MLPFail(error,@"E_PROVIDER_FILTER",@"The Provider filter exceeded its matching budget.");
    }
    NSMutableArray *result=[NSMutableArray array];
    for (NSDictionary *node in chosen) {
        BOOL removed=[types containsObject:[node[@"type"] lowercaseString]];
        for (NSRegularExpression *pattern in exclude) if (MLPMatch(pattern,node[@"name"],deadline,&valid)) { removed=YES; break; }
        if (!valid || [NSProcessInfo processInfo].systemUptime>=deadline) return MLPFail(error,@"E_PROVIDER_FILTER",@"The Provider filter exceeded its matching budget.");
        if (!removed) [result addObject:node];
    }
    if (!valid) return MLPFail(error,@"E_PROVIDER_FILTER",@"The Provider filter exceeded its matching budget.");
    return result;
}
BOOL MLProviderStorageIsTemporaryName(NSString *name) {
    if ([name hasPrefix:@".pending-"] && name.length==45) return [[NSUUID alloc] initWithUUIDString:[name substringFromIndex:9]]!=nil;
    return name.length==72 && [name hasSuffix:@".pending"] && MLPHashValid([name substringToIndex:64]);
}
BOOL MLProviderStorageInspectTemporary(NSString *path, NSUInteger limit, BOOL allowReadOnly, NSUInteger *size, NSError **error) {
    struct stat status;
    if (lstat(path.fileSystemRepresentation,&status)!=0 || !S_ISREG(status.st_mode) || status.st_uid!=geteuid() || status.st_nlink!=1 || status.st_size<0 || (uint64_t)status.st_size>limit ||
        ((status.st_mode&0777)!=0600 && !(allowReadOnly && (status.st_mode&0777)==0444))) {
        MLPFail(error,@"E_PROVIDER_STORAGE",@"A staging entry is not an owned, bounded temporary file."); return NO;
    }
    if ([[NSDate date] timeIntervalSince1970]-(double)status.st_mtime>=86400) {
        if (unlink(path.fileSystemRepresentation)!=0) { MLPFail(error,@"E_PROVIDER_STORAGE",@"Cannot remove an obsolete staging file."); return NO; }
        *size=NSNotFound;
    } else *size=(NSUInteger)status.st_size;
    return YES;
}
static NSArray *MLPFilter(NSArray *nodes, NSDictionary *options, NSError **error) {
    return MLPFilterBefore(nodes,options,[NSProcessInfo processInfo].systemUptime+2,error);
}
static NSString *MLPReplace(NSRegularExpression *pattern, NSString *name, NSString *target, NSTimeInterval deadline, NSError **error) {
    NSTimeInterval now=[NSProcessInfo processInfo].systemUptime;
    if (now>=deadline) return MLPFail(error,@"E_PROVIDER_FILTER",@"Proxy-name replacement exceeded its matching budget.");
    NSTimeInterval end=MIN(deadline,now+0.05); __block BOOL valid=YES;
    NSMutableArray *matches=[NSMutableArray array];
    [pattern enumerateMatchesInString:name options:NSMatchingReportProgress|NSMatchingReportCompletion range:NSMakeRange(0,name.length)
        usingBlock:^(NSTextCheckingResult *match, NSMatchingFlags flags, BOOL *stop) {
            if (flags&NSMatchingInternalError || [NSProcessInfo processInfo].systemUptime>end || matches.count>256) { valid=NO; *stop=YES; }
            else if (match) [matches addObject:match];
        }];
    if (!valid) return MLPFail(error,@"E_PROVIDER_FILTER",@"Proxy-name replacement exceeded its matching budget.");
    NSMutableString *result=[NSMutableString string]; NSUInteger cursor=0;
    @try {
        for (NSTextCheckingResult *match in matches) {
            [result appendString:[name substringWithRange:NSMakeRange(cursor,match.range.location-cursor)]];
            [result appendString:[pattern replacementStringForResult:match inString:name offset:0 template:target]];
            cursor=NSMaxRange(match.range);
            if (result.length>256) return MLPFail(error,@"E_PROVIDER_NAME",@"A transformed Provider name exceeds 256 characters.");
        }
        [result appendString:[name substringFromIndex:cursor]];
    } @catch (NSException *exception) { return MLPFail(error,@"E_PROVIDER_OVERRIDE",@"The proxy-name replacement template is invalid."); }
    if (result.length>256) return MLPFail(error,@"E_PROVIDER_NAME",@"A transformed Provider name exceeds 256 characters.");
    return result;
}
static NSArray *MLPOverride(NSArray *nodes, NSDictionary *options, NSError **error) {
    NSTimeInterval deadline=[NSProcessInfo processInfo].systemUptime+2;
    NSDictionary *override=MLPDictionary(options[@"override"]);
    NSSet *allowed=[NSSet setWithArray:@[@"tfo",@"mptcp",@"udp",@"udp-over-tcp",@"up",@"down",@"dialer-proxy",@"skip-cert-verify",@"name-cert-verify",@"interface-name",@"routing-mark",@"ip-version",@"additional-prefix",@"additional-suffix",@"proxy-name"]];
    for (NSString *key in override) if (![allowed containsObject:key]) return MLPFail(error,@"E_PROVIDER_OVERRIDE",@"The Provider override contains an unimplemented field.");
    NSMutableArray *result=[NSMutableArray array];
    for (NSDictionary *original in nodes) {
        if (![original isKindOfClass:[NSDictionary class]] || !MLPString(original[@"name"]).length || [original[@"name"] length]>256 || !MLPString(original[@"type"]).length) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"Every Provider node requires a bounded name and type.");
        NSMutableDictionary *node=[original mutableCopy];
        for (NSString *key in override) if (![@[@"additional-prefix",@"additional-suffix",@"proxy-name"] containsObject:key]) node[key]=override[key];
        NSString *name=node[@"name"];
        for (NSDictionary *entry in MLPArray(override[@"proxy-name"])) {
            if (!MLPString(entry[@"pattern"]) || !MLPString(entry[@"target"])) return MLPFail(error,@"E_PROVIDER_OVERRIDE",@"Proxy-name replacement requires pattern and target strings.");
            NSRegularExpression *pattern=[NSRegularExpression regularExpressionWithPattern:entry[@"pattern"] options:0 error:NULL];
            if (!pattern || [entry[@"pattern"] length]>1024 || [entry[@"target"] length]>256) return MLPFail(error,@"E_PROVIDER_OVERRIDE",@"The proxy-name expression is invalid or too large.");
            name=MLPReplace(pattern,name,entry[@"target"],deadline,error); if (!name) return nil;
        }
        name=[NSString stringWithFormat:@"%@%@%@",MLPString(override[@"additional-prefix"]) ?: @"",name,MLPString(override[@"additional-suffix"]) ?: @""];
        if (!name.length || name.length>256 || [name rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound) return MLPFail(error,@"E_PROVIDER_NAME",@"A transformed Provider node name must contain 1–256 ordinary characters.");
        node[@"name"]=name; [result addObject:[node copy]];
    }
    return MLPFilterBefore(result,options,deadline,error);
}
static NSArray *MLPValidateNodes(NSArray *nodes, NSError **error) {
    if (!nodes.count || nodes.count>1024) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"A proxy Provider requires 1–1024 nodes.");
    NSMutableArray *schemaNodes=[NSMutableArray array];
    for (NSDictionary *node in nodes) {
        if (![node isKindOfClass:[NSDictionary class]]) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"A proxy Provider node must be a mapping.");
        // References to outer configuration groups are checked after expansion.
        NSMutableDictionary *schema=[node mutableCopy]; [schema removeObjectForKey:@"dialer-proxy"]; [schemaNodes addObject:schema];
    }
    NSData *data=[NSJSONSerialization dataWithJSONObject:@{@"proxies":schemaNodes,@"rules":@[@"MATCH,DIRECT"]} options:0 error:NULL];
    if (!data || data.length>MLProviderTextLimit) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"The proxy Provider exceeds its parsed size limit.");
    NSDictionary *report=[MLConfig checkYAML:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]];
    if (![report[@"valid"] boolValue]) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"The proxy Provider contains invalid or unavailable node options.");
    return nodes;
}
static NSArray *MLPValidateRules(NSArray *rules, NSString *behavior, NSError **error) {
    if (rules.count>10000 || ![@[@"domain",@"ipcidr",@"classical"] containsObject:behavior]) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"The rule Provider has an invalid behavior or too many entries.");
    for (NSString *rule in rules) {
        if (!MLPString(rule) || !rule.length || rule.length>4096) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"A rule Provider contains an invalid entry.");
        if ([behavior isEqual:@"domain"]) {
            if (rule.length>255 || [rule rangeOfCharacterFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].location!=NSNotFound || [rule rangeOfString:@","].location!=NSNotFound) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"The domain Provider contains a malformed domain pattern.");
        } else if ([behavior isEqual:@"ipcidr"]) {
            if (MLRouteRuleOperandIssue(@"IP-CIDR",rule)) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"The IP Provider contains an invalid prefix.");
        } else {
            NSArray *fields=MLRouteRuleFields(rule);
            if (fields.count<2 || [fields[0] isEqual:@"RULE-SET"] || [fields[0] isEqual:@"SUB-RULE"] || MLRouteRuleOperandIssue(fields[0],fields[1])) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"The classical Provider contains an invalid or recursive rule.");
        }
    }
    return rules;
}

@implementation MLProviderManager {
    NSString *_directory, *_indexDirectory, *_caPath;
    dev_t _device, _indexDevice; ino_t _inode, _indexInode;
    NSLock *_operation;
    NSDictionary *_source, *_prepared, *_preparedSource, *_preparedStates, *_states, *_cacheIndex;
    NSData *_cacheIndexData, *_pointerAttemptData;
    NSArray *_writes;
    NSMutableDictionary *_attempts;
}
- (id)initWithDirectory:(NSString *)directory caPath:(NSString *)caPath error:(NSError **)error {
    return [self initWithDirectory:directory readableDirectory:[directory stringByAppendingPathComponent:@"domain-indexes"] caPath:caPath error:error];
}
- (id)initWithDirectory:(NSString *)directory readableDirectory:(NSString *)readableDirectory caPath:(NSString *)caPath error:(NSError **)error {
    if (error) *error=nil;
    if ((self=[super init])) {
        if (!MLPDirectory(directory,YES,YES,error) || !MLPDirectory(readableDirectory,YES,NO,error)) return nil;
        _directory=[directory copy]; _indexDirectory=[readableDirectory copy]; _caPath=[caPath copy];
        struct stat status; if (lstat(directory.fileSystemRepresentation,&status)!=0) return nil;
        _device=status.st_dev; _inode=status.st_ino;
        if (lstat(readableDirectory.fileSystemRepresentation,&status)!=0 || status.st_uid!=geteuid() || (status.st_mode&0022) || chmod(readableDirectory.fileSystemRepresentation,0755)!=0)
            return MLPFail(error,@"E_PROVIDER_STORAGE",@"The Provider index directory must be service-owned and searchable by the Core.");
        _indexDevice=status.st_dev; _indexInode=status.st_ino;
        for (NSString *child in @[@"local",@"cache"]) if (!MLPDirectory([directory stringByAppendingPathComponent:child],YES,YES,error)) return nil;
        _operation=[[NSLock alloc] init]; _states=@{}; _attempts=[NSMutableDictionary dictionary];
        NSString *indexPath=[directory stringByAppendingPathComponent:@"cache-index.json"]; struct stat indexStatus;
        _cacheIndex=@{};
        if (lstat(indexPath.fileSystemRepresentation,&indexStatus)==0) {
            NSData *indexData=MLPRead(indexPath,32768,error);
            NSDictionary *index=indexData ? MLPDictionary([NSJSONSerialization JSONObjectWithData:indexData options:0 error:NULL]) : nil;
            if (![index[@"format"] isEqual:@1] || ![index[@"snapshots"] isKindOfClass:[NSDictionary class]] || [index[@"snapshots"] count]>64) return MLPFail(error,@"E_PROVIDER_STORAGE",@"The Provider cache index is malformed.");
            for (NSString *hash in index[@"snapshots"]) if (!MLPHashValid(hash) || !MLPHashValid(index[@"snapshots"][hash])) return MLPFail(error,@"E_PROVIDER_STORAGE",@"The Provider cache index contains an invalid identity.");
            if (index[@"domains"] && ![index[@"domains"] isKindOfClass:[NSDictionary class]]) return MLPFail(error,@"E_PROVIDER_STORAGE",@"The domain snapshot index is malformed.");
            for (NSString *hash in index[@"domains"]) if (!index[@"snapshots"][hash] || !MLPHashValid(index[@"domains"][hash])) return MLPFail(error,@"E_PROVIDER_STORAGE",@"The domain snapshot index contains an invalid identity.");
            _cacheIndex=index[@"snapshots"];
            _cacheIndexData=indexData;
        } else if (errno!=ENOENT) return MLPFail(error,@"E_PROVIDER_STORAGE",@"Cannot inspect the Provider cache index.");
    }
    return self;
}
- (BOOL)integrity:(NSError **)error {
    struct stat status, indexStatus;
    if (!MLPDirectory(_directory,NO,YES,error) || lstat(_directory.fileSystemRepresentation,&status)!=0 || status.st_dev!=_device || status.st_ino!=_inode) {
        MLPFail(error,@"E_PROVIDER_STORAGE",@"The private Provider root was replaced."); return NO;
    }
    if (!MLPDirectory(_indexDirectory,NO,NO,error) || lstat(_indexDirectory.fileSystemRepresentation,&indexStatus)!=0 || indexStatus.st_dev!=_indexDevice || indexStatus.st_ino!=_indexInode || indexStatus.st_uid!=geteuid() || (indexStatus.st_mode&0777)!=0755) {
        MLPFail(error,@"E_PROVIDER_STORAGE",@"The Provider index directory was replaced or changed permissions."); return NO;
    }
    return YES;
}
- (NSDictionary *)cache:(NSString *)hash {
    NSString *snapshot=_cacheIndex[hash] ?: hash;
    NSString *path=[[_directory stringByAppendingPathComponent:@"cache"] stringByAppendingPathComponent:[snapshot stringByAppendingString:@".json"]];
    NSData *data=MLPRead(path,MLProviderCacheLimit,NULL);
    if (_cacheIndex[hash] && data && ![MLProviderStorageHash(data) isEqual:snapshot]) return nil;
    NSDictionary *cache=data ? MLPDictionary([NSJSONSerialization JSONObjectWithData:data options:0 error:NULL]) : nil;
    return [cache[@"format"] isEqual:@1] && [cache[@"sourceHash"] isEqual:hash] && ([cache[@"payload"] isKindOfClass:[NSArray class]] || [cache[@"domainIndex"] isKindOfClass:[NSDictionary class]]) &&
        [cache[@"updatedAt"] isKindOfClass:[NSNumber class]] ? cache : nil;
}
- (NSDictionary *)storedDomainHashes {
    if (!_cacheIndexData) return @{};
    NSDictionary *cached = [NSJSONSerialization JSONObjectWithData:_cacheIndexData options:0 error:NULL];
    return cached[@"domains"] ?: @{};
}
- (NSDictionary *)domainDescriptor:(NSDictionary *)metadata error:(NSError **)error {
    NSString *hash = metadata[@"sha256"];
    if (!MLPHashValid(hash) || ![metadata[@"size"] isKindOfClass:[NSNumber class]] || ![metadata[@"count"] isKindOfClass:[NSNumber class]])
        return MLPFail(error,@"E_PROVIDER_STORAGE",@"The stored domain snapshot metadata is invalid.");
    return @{@"path":[_indexDirectory stringByAppendingPathComponent:[hash stringByAppendingString:@".index"]],
             @"sha256":hash,@"size":metadata[@"size"],@"owner":@(geteuid())};
}
- (NSDictionary *)stageDomainData:(NSData *)data count:(NSUInteger)count preserve:(NSMutableSet *)preserve error:(NSError **)error {
    NSString *hash = MLProviderStorageHash(data);
    NSDictionary *metadata = @{@"sha256":hash,@"size":@(data.length),@"count":@(count)};
    NSDictionary *descriptor = [self domainDescriptor:metadata error:error];
    NSString *path = descriptor[@"path"];
    struct stat status;
    if (lstat(path.fileSystemRepresentation,&status)!=0) {
        if (errno!=ENOENT) return MLPFail(error,@"E_PROVIDER_STORAGE",@"Cannot inspect an immutable domain snapshot.");
        if (!MLPPruneCache(_indexDirectory,preserve,@[@{@"hash":hash,@"data":data}],YES,error) || ![self integrity:error] || !MLPWriteMode(path,data,0444,error)) return nil;
    }
    MLDomainProviderIndex *index = [MLDomainProviderIndex indexWithDescriptor:descriptor error:error];
    if (!index) return nil;
    if (index.count!=count) return MLPFail(error,@"E_PROVIDER_STORAGE",@"The staged domain snapshot entry count changed.");
    [preserve addObject:hash];
    return metadata;
}
- (NSArray *)payloadText:(NSString *)text kind:(NSString *)kind spec:(NSDictionary *)spec error:(NSError **)error {
    if (!MLPString(text) || [text lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>MLProviderTextLimit) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"Provider content must be bounded UTF-8 text.");
    NSString *format=spec[@"format"] ?: @"yaml";
    if ([kind isEqual:@"rule"] && [format isEqual:@"text"]) {
        NSMutableArray *rules=[NSMutableArray array];
        for (NSString *line in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
            NSString *entry=[line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (!entry.length || [entry hasPrefix:@"#"] || [entry hasPrefix:@"//"]) continue;
            [rules addObject:entry]; if (rules.count>10000) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"The rule Provider exceeds its entry limit.");
        }
        return MLPValidateRules(rules,spec[@"behavior"],error);
    }
    if (![format isEqual:@"yaml"]) return MLPFail(error,@"E_PROVIDER_FORMAT",@"This Provider format has no installed native decoder.");
    NSDictionary *report=[MLConfig checkYAML:text];
    if (![report[@"syntaxValid"] boolValue]) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"Provider YAML parsing failed.");
    id value=report[@"document"][[kind isEqual:@"proxy"] ? @"proxies" : @"payload"];
    if (![value isKindOfClass:[NSArray class]]) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"The Provider YAML does not contain the required payload array.");
    return [kind isEqual:@"proxy"] ? MLPValidateNodes(value,error) : MLPValidateRules(value,spec[@"behavior"],error);
}
- (NSDictionary *)source:(NSString *)name kind:(NSString *)kind spec:(NSDictionary *)spec force:(BOOL)force fetch:(BOOL)fetch preserve:(NSMutableSet *)preserve error:(NSError **)error {
    NSString *type=spec[@"type"] ?: @"http";
    if (![@[@"http",@"file",@"inline"] containsObject:type]) return MLPFail(error,@"E_PROVIDER_TYPE",@"A Provider must use http, file or inline storage.");
    if (spec[@"path"] && !MLPPath(spec[@"path"])) return MLPFail(error,@"E_PROVIDER_PATH",@"A Provider path must remain relative to its private storage root.");
    BOOL binary=[spec[@"format"] isEqual:@"mrs"];
    BOOL canIndex=[kind isEqual:@"rule"] && [spec[@"behavior"] isEqual:@"domain"] && !binary && ![type isEqual:@"inline"];
    if (binary && (![kind isEqual:@"rule"] || [type isEqual:@"inline"])) return MLPFail(error,@"E_PROVIDER_FORMAT",@"MRS requires a domain or IP rule Provider using HTTP or private file storage.");
    NSString *hash=MLPHash([NSString stringWithFormat:@"%@:%@:%@",kind,name,MLPCanonical(spec)]);
    NSDictionary *cache=[self cache:hash], *domainMetadata=cache[@"domainIndex"], *domainDescriptor=nil;
    if (domainMetadata) {
        domainDescriptor=canIndex ? [self domainDescriptor:domainMetadata error:NULL] : nil;
        MLDomainProviderIndex *index=domainDescriptor ? [MLDomainProviderIndex indexWithDescriptor:domainDescriptor error:NULL] : nil;
        if (!index || index.count!=[domainMetadata[@"count"] unsignedIntegerValue]) cache=domainMetadata=domainDescriptor=nil;
        else [preserve addObject:domainMetadata[@"sha256"]];
    }
    NSArray *payload=cache[@"payload"];
    NSError *failure=nil; BOOL changed=NO; double updated=[cache[@"updatedAt"] doubleValue];
    double now=[[NSDate date] timeIntervalSince1970]; double interval=[spec[@"interval"] doubleValue];
    if (interval<0 || interval>31*86400) return MLPFail(error,@"E_PROVIDER_INTERVAL",@"Provider update intervals must be between zero and 31 days.");
    BOOL due=force || !cache || (interval>0 && (now<updated || now-updated>=interval));
    if ([type isEqual:@"inline"]) {
        id inlinePayload=spec[@"payload"];
        if (![inlinePayload isKindOfClass:[NSArray class]]) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"An inline Provider requires a payload array.");
        payload=[kind isEqual:@"proxy"] ? MLPValidateNodes(inlinePayload,error) : MLPValidateRules(inlinePayload,spec[@"behavior"],error);
        if (!payload) return nil; updated=now;
    } else if (due && fetch) {
        @synchronized(self) { _attempts[[kind stringByAppendingFormat:@":%@",name]]=@([NSProcessInfo processInfo].systemUptime); }
        NSData *data=nil;
        NSUInteger limit=binary ? MLProviderBinaryLimit : (canIndex ? MLDomainProviderSourceLimit : MLProviderTextLimit);
        if ([type isEqual:@"http"]) data=MLFetchDataWithTimeout(spec[@"url"],_caPath,limit,canIndex ? 120000 : 30000,&failure);
        else {
            NSString *path=MLPPath(spec[@"path"]);
            if (!path) return MLPFail(error,@"E_PROVIDER_PATH",@"File Providers require a relative path inside the private local Provider root.");
            data=MLPRead([[_directory stringByAppendingPathComponent:@"local"] stringByAppendingPathComponent:path],limit,&failure);
        }
        NSArray *fresh=nil;
        NSDictionary *freshDomain=nil;
        if (data && binary) fresh=MLMRSDecode(data,spec[@"behavior"],&failure);
        else if (canIndex && data.length>64*1024) {
            NSUInteger count=0;
            NSData *compiled=MLDomainProviderCompile(data,spec[@"format"] ?: @"yaml",&count,&failure);
            if (compiled) freshDomain=[self stageDomainData:compiled count:count preserve:preserve error:&failure];
        }
        else if (data) {
            NSString *text=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (!text) MLPFail(&failure,@"E_PROVIDER_PAYLOAD",@"The Provider is not UTF-8.");
            else fresh=[self payloadText:text kind:kind spec:spec error:&failure];
        }
        if (fresh && binary) fresh=MLPValidateRules(fresh,spec[@"behavior"],&failure);
        if (fresh || freshDomain) {
            payload=fresh; domainMetadata=freshDomain;
            domainDescriptor=freshDomain ? [self domainDescriptor:freshDomain error:NULL] : nil;
            updated=now; changed=YES;
        }
    }
    if (!payload && !domainDescriptor) { if (failure && error) *error=failure; else MLPFail(error,@"E_PROVIDER_PENDING",@"This Provider has no validated snapshot yet."); return nil; }
    if ([kind isEqual:@"proxy"] && !MLPValidateNodes(payload,error)) return nil;
    if ([kind isEqual:@"rule"] && !domainDescriptor && !MLPValidateRules(payload,spec[@"behavior"],error)) return nil;
    NSArray *effective=[kind isEqual:@"proxy"] ? MLPOverride(payload,spec,error) : payload;
    if (!effective && !domainDescriptor) return nil;
    if ([kind isEqual:@"proxy"] && !MLPValidateNodes(effective,error)) return nil;
    NSMutableDictionary *state=[@{@"name":name,@"kind":kind,@"type":type,@"sourceHash":hash,@"count":domainMetadata[@"count"] ?: @(effective.count),@"updatedAt":@(updated),
                                 @"interval":@(interval),@"status":failure ? @"cached" : @"ready"} mutableCopy];
    if (failure) state[@"lastError"]=[NSString stringWithFormat:@"%@ (%ld)",failure.domain,(long)failure.code];
    if (domainDescriptor) state[@"_domainHash"]=domainMetadata[@"sha256"];
    NSMutableDictionary *result=[@{@"state":[state copy]} mutableCopy];
    if (domainDescriptor) result[@"index"]=domainDescriptor;
    else result[@"payload"]=effective;
    if (changed) {
        NSMutableDictionary *stored=[@{@"format":@1,@"sourceHash":hash,@"updatedAt":@(updated)} mutableCopy];
        if (domainMetadata) stored[@"domainIndex"]=domainMetadata;
        else stored[@"payload"]=payload;
        NSData *data=[NSJSONSerialization dataWithJSONObject:stored options:0 error:NULL];
        if (!data || data.length>MLProviderCacheLimit) return MLPFail(error,@"E_PROVIDER_PAYLOAD",@"The parsed Provider snapshot exceeds its cache limit.");
        result[@"write"]=@{@"hash":hash,@"data":data};
    }
    return result;
}
- (NSDictionary *)prepareDocument:(NSDictionary *)document refreshNames:(NSSet *)refreshNames error:(NSError **)error {
    if (error) *error=nil;
    if (![_operation tryLock]) return MLPFail(error,@"E_BUSY",@"A Provider generation is already being prepared.");
    @try {
        if (![self integrity:error] || ![document isKindOfClass:[NSDictionary class]]) return nil;
        NSDictionary *proxySpecs=MLPDictionary(document[@"proxy-providers"]), *ruleSpecs=MLPDictionary(document[@"rule-providers"]);
        if (proxySpecs.count+ruleSpecs.count>32) return MLPFail(error,@"E_PROVIDER_LIMIT",@"At most 32 Providers may be active in a configuration.");
        NSMutableDictionary *states=[NSMutableDictionary dictionary], *proxyPayloads=[NSMutableDictionary dictionary], *rulePayloads=[NSMutableDictionary dictionary];
        NSMutableArray *writes=[NSMutableArray array], *nodes=[MLPArray(document[@"proxies"]) mutableCopy], *checks=[NSMutableArray array];
        NSUInteger ruleCount=0;
        NSMutableSet *names=[NSMutableSet setWithArray:@[@"DIRECT",@"REJECT",@"GLOBAL"]];
        for (NSDictionary *node in nodes) if (MLPString(node[@"name"])) [names addObject:node[@"name"]];
        NSMutableSet *preservedIndexes=[NSMutableSet setWithArray:[self storedDomainHashes].allValues];
        for (NSString *kind in @[@"proxy",@"rule"]) {
            NSDictionary *specs=[kind isEqual:@"proxy"] ? proxySpecs : ruleSpecs;
            for (NSString *name in [specs.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
                if (!MLPString(name).length || name.length>256 || ![specs[name] isKindOfClass:[NSDictionary class]]) return MLPFail(error,@"E_PROVIDER_NAME",@"Providers require bounded names and mapping definitions.");
                BOOL force=[refreshNames containsObject:name] || [refreshNames containsObject:[kind stringByAppendingFormat:@":%@",name]];
                NSError *failure=nil;
                NSDictionary *snapshot;
                @autoreleasepool {
                    snapshot=[self source:name kind:kind spec:specs[name] force:force fetch:(refreshNames==nil || force) preserve:preservedIndexes error:&failure];
                }
                if (!snapshot) {
                    if (error) *error=[NSError errorWithDomain:failure.domain ?: @"E_PROVIDER_PENDING" code:failure.code
                        userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"规则与节点来源 %@：%@",name,failure.localizedDescription ?: @"来源准备失败"]}];
                    return nil;
                }
                states[[kind stringByAppendingFormat:@":%@",name]]=snapshot[@"state"];
                if (snapshot[@"write"]) [writes addObject:snapshot[@"write"]];
                if ([kind isEqual:@"proxy"]) {
                    proxyPayloads[name]=snapshot[@"payload"];
                    for (NSDictionary *node in snapshot[@"payload"]) {
                        if ([names containsObject:node[@"name"]]) return MLPFail(error,@"E_PROVIDER_NAME_COLLISION",@"Provider node names collide; use an explicit additional-prefix or name replacement.");
                        [names addObject:node[@"name"]]; [nodes addObject:node];
                        if (nodes.count>1024) return MLPFail(error,@"E_PROVIDER_LIMIT",@"The merged generation exceeds 1024 proxy nodes.");
                    }
                    NSDictionary *health=MLPDictionary(specs[name][@"health-check"]);
                    if ([health[@"enable"] boolValue]) {
                        NSMutableArray *members=[NSMutableArray array]; for (NSDictionary *node in snapshot[@"payload"]) [members addObject:node[@"name"]];
                        [checks addObject:@{@"name":[@"provider:" stringByAppendingString:name],@"nodes":members,@"url":health[@"url"] ?: @"http://www.gstatic.com/generate_204",
                                           @"interval":health[@"interval"] ?: @300,@"timeout":health[@"timeout"] ?: @5000,@"lazy":health[@"lazy"] ?: @YES,
                                           @"expected-status":health[@"expected-status"] ?: @"*"}];
                    }
                } else {
                    if (snapshot[@"index"]) rulePayloads[name]=@{@"behavior":@"domain",@"index":snapshot[@"index"]};
                    else {
                        ruleCount += [snapshot[@"payload"] count];
                        if (ruleCount>10000) return MLPFail(error,@"E_PROVIDER_LIMIT",@"The merged generation exceeds 10000 inline Provider rules.");
                        rulePayloads[name]=@{@"behavior":specs[name][@"behavior"],@"payload":snapshot[@"payload"]};
                    }
                }
            }
        }
        NSMutableArray *groups=[NSMutableArray array];
        for (NSDictionary *original in MLPArray(document[@"proxy-groups"])) {
            NSMutableDictionary *group=[original mutableCopy]; NSMutableOrderedSet *members=[NSMutableOrderedSet orderedSetWithArray:MLPArray(group[@"proxies"])];
            NSMutableArray *providerNodes=[NSMutableArray array];
            NSArray *used=([group[@"include-all"] boolValue] || [group[@"include-all-providers"] boolValue]) ? [proxyPayloads.allKeys sortedArrayUsingSelector:@selector(compare:)] : MLPArray(group[@"use"]);
            for (NSString *provider in used) {
                if (!proxyPayloads[provider]) return MLPFail(error,@"E_PROVIDER_REFERENCE",@"A policy group references a missing proxy Provider.");
                [providerNodes addObjectsFromArray:proxyPayloads[provider]];
            }
            NSArray *filtered=MLPFilter(providerNodes,group,error); if (!filtered) return nil;
            for (NSDictionary *node in filtered) [members addObject:node[@"name"]];
            if ([group[@"include-all"] boolValue] || [group[@"include-all-proxies"] boolValue]) {
                NSArray *inlineNodes=MLPFilter(MLPArray(document[@"proxies"]),group,error); if (!inlineNodes) return nil;
                for (NSDictionary *node in inlineNodes) [members addObject:node[@"name"]];
            }
            // Exclusion filters apply to inline selectors too; inclusion filters
            // are limited to provider membership, matching the fixed baseline.
            NSMutableArray *final=[NSMutableArray array]; NSArray *exclude=MLPPatterns(group[@"exclude-filter"],error); if (!exclude) return nil;
            NSArray *excludedTypes=[MLPString(group[@"exclude-type"]).lowercaseString componentsSeparatedByString:@"|"] ?: @[];
            NSTimeInterval deadline=[NSProcessInfo processInfo].systemUptime+2;
            for (NSString *member in members) {
                BOOL omit=NO, valid=YES;
                for (NSRegularExpression *pattern in exclude) if (MLPMatch(pattern,member,deadline,&valid)) { omit=YES; break; }
                if (!valid) return MLPFail(error,@"E_PROVIDER_FILTER",@"The policy exclusion filter exceeded its matching budget.");
                for (NSDictionary *node in nodes) if ([node[@"name"] isEqual:member] && [excludedTypes containsObject:[node[@"type"] lowercaseString]]) { omit=YES; break; }
                if (!omit) [final addObject:member];
            }
            if (!final.count) {
                NSString *fallback=MLPString(group[@"empty-fallback"]);
                if (!fallback) return MLPFail(error,@"E_PROVIDER_EMPTY_GROUP",@"Provider filtering left a policy group without members.");
                [final addObject:fallback];
            }
            group[@"proxies"]=final; [groups addObject:[group copy]];
        }
        NSMutableDictionary *expanded=[document mutableCopy]; expanded[@"proxies"]=nodes; expanded[@"proxy-groups"]=groups;
        expanded[@"_rule-provider-payloads"]=rulePayloads; expanded[@"_provider-health-checks"]=checks;
        CFUUIDRef uuid=CFUUIDCreate(NULL); expanded[@"_provider-generation"]=CFBridgingRelease(CFUUIDCreateString(NULL,uuid)); CFRelease(uuid);
        NSData *encoded=[NSJSONSerialization dataWithJSONObject:expanded options:0 error:NULL];
        if (!encoded || encoded.length>MLProviderGenerationLimit) return MLPFail(error,@"E_PROVIDER_GENERATION_SIZE",@"The expanded Provider generation exceeds the 768 KiB IPC limit.");
        @synchronized(self) { _prepared=[NSJSONSerialization JSONObjectWithData:encoded options:0 error:NULL]; _preparedSource=[document copy]; _preparedStates=[states copy]; _writes=[writes copy]; }
        return _prepared;
    } @finally { [_operation unlock]; }
}
- (BOOL)commitPreparedDocument:(NSDictionary *)document error:(NSError **)error {
    if (![_operation tryLock]) { MLPFail(error,@"E_BUSY",@"A Provider generation is being prepared."); return NO; }
    int lock=-1;
    @try {
        if (![self integrity:error]) return NO;
        NSString *lockPath=[_directory stringByAppendingPathComponent:@"providers.lock"];
        lock=open(lockPath.fileSystemRepresentation,O_RDWR|O_CREAT|O_NOFOLLOW,0600); struct stat lockStatus;
        if (lock<0 || fstat(lock,&lockStatus)!=0 || !S_ISREG(lockStatus.st_mode) || lockStatus.st_uid!=geteuid() || lockStatus.st_nlink!=1 || (lockStatus.st_mode&0077)) { MLPFail(error,@"E_PROVIDER_STORAGE",@"Cannot acquire the private Provider commit lock."); return NO; }
        if (flock(lock,LOCK_EX|LOCK_NB)!=0) { MLPFail(error,@"E_BUSY",@"Another service is committing a Provider generation."); return NO; }
        @synchronized(self) {
            if (!_prepared || document!=_prepared) { MLPFail(error,@"E_PROVIDER_GENERATION",@"This Provider candidate is stale or was not prepared by this manager."); return NO; }
            NSString *indexPath=[_directory stringByAppendingPathComponent:@"cache-index.json"]; struct stat indexStatus;
            NSData *current=nil;
            if (lstat(indexPath.fileSystemRepresentation,&indexStatus)==0) { current=MLPRead(indexPath,32768,error); if (!current) return NO; }
            else if (errno!=ENOENT) { MLPFail(error,@"E_PROVIDER_STORAGE",@"Cannot inspect the Provider cache index."); return NO; }
            if ((current || _cacheIndexData) && ![current isEqual:_cacheIndexData]) { MLPFail(error,@"E_PROVIDER_GENERATION",@"Another service changed the Provider cache index; this candidate is stale."); return NO; }
            NSMutableSet *preserved=[NSMutableSet set]; NSMutableDictionary *index=[NSMutableDictionary dictionary], *domains=[NSMutableDictionary dictionary]; NSMutableArray *writes=[NSMutableArray array];
            for (NSDictionary *states in @[_states,_preparedStates]) for (NSDictionary *state in states.allValues) {
                NSString *hash=state[@"sourceHash"]; if ([state[@"type"] isEqual:@"inline"]) continue;
                index[hash]=_cacheIndex[hash] ?: hash; [preserved addObject:index[hash]];
                // iOS 6 rejects nil in the keyed-subscript setter. IP and
                // classical providers have no domain index to preserve.
                NSString *domainHash=state[@"_domainHash"];
                if (domainHash) domains[hash]=domainHash;
                else [domains removeObjectForKey:hash];
            }
            for (NSDictionary *write in _writes) {
                NSString *snapshot=MLPHash([[NSString alloc] initWithData:write[@"data"] encoding:NSUTF8StringEncoding]);
                index[write[@"hash"]]=snapshot; [preserved addObject:snapshot]; [writes addObject:@{@"hash":snapshot,@"data":write[@"data"]}];
            }
            NSData *indexData=[NSJSONSerialization dataWithJSONObject:@{@"format":@1,@"snapshots":index,@"domains":domains} options:0 error:NULL];
            if (!indexData || indexData.length>32768) { MLPFail(error,@"E_PROVIDER_STORAGE",@"The Provider cache index exceeds its budget."); return NO; }
            if (!MLPPruneCache([_directory stringByAppendingPathComponent:@"cache"],preserved,writes,NO,error)) return NO;
            for (NSDictionary *write in writes) {
                NSString *path=[[_directory stringByAppendingPathComponent:@"cache"] stringByAppendingPathComponent:[write[@"hash"] stringByAppendingString:@".json"]];
                if (!MLPWrite(path,write[@"data"],error)) return NO;
            }
            // Only this atomic pointer makes the staged, immutable snapshots
            // visible after restart. Earlier failures leave the old index live.
            // Preserve the exact attempted pointer if a write reports failure
            // after rename; recovery still owns this known candidate on disk.
            _pointerAttemptData=indexData;
            if (!MLPWrite([_directory stringByAppendingPathComponent:@"cache-index.json"],indexData,error)) return NO;
            _cacheIndex=[index copy];
            _cacheIndexData=indexData;
            _pointerAttemptData=nil;
            _source=_preparedSource; _states=_preparedStates; _prepared=nil; _preparedSource=nil; _preparedStates=nil; _writes=nil;
        }
        return YES;
    } @finally { if (lock>=0) { (void)flock(lock,LOCK_UN); close(lock); } [_operation unlock]; }
}
- (void)discardPreparedDocument { @synchronized(self) { _prepared=nil; _preparedSource=nil; _preparedStates=nil; _writes=nil; } }
- (NSArray *)list {
    @synchronized(self) {
        NSMutableArray *items=[NSMutableArray array];
        for (NSString *key in [_states.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
            NSMutableDictionary *item=[_states[key] mutableCopy];
            [item removeObjectForKey:@"_domainHash"];
            [items addObject:[item copy]];
        }
        return [items copy];
    }
}
- (NSDictionary *)sourceDocument { @synchronized(self) { return _source; } }
- (id)captureCheckpoint {
    @synchronized(self) { return @{@"owner":self,@"indexData":_cacheIndexData ?: [NSNull null],@"index":_cacheIndex,@"states":_states,@"source":_source ?: [NSNull null]}; }
}
- (BOOL)restoreCheckpoint:(id)checkpoint error:(NSError **)error {
    if (![checkpoint isKindOfClass:[NSDictionary class]] || checkpoint[@"owner"]!=self) { MLPFail(error,@"E_PROVIDER_RECOVERY",@"The Provider recovery checkpoint belongs to another manager."); return NO; }
    if (![_operation tryLock]) { MLPFail(error,@"E_BUSY",@"A Provider operation is active during recovery."); return NO; }
    int lock=-1;
    @try {
        if (![self integrity:error]) return NO;
        lock=open([[_directory stringByAppendingPathComponent:@"providers.lock"] fileSystemRepresentation],O_RDWR|O_CREAT|O_NOFOLLOW,0600); struct stat status;
        if (lock<0 || fstat(lock,&status)!=0 || !S_ISREG(status.st_mode) || status.st_uid!=geteuid() || status.st_nlink!=1 || (status.st_mode&0077) || flock(lock,LOCK_EX|LOCK_NB)!=0) { MLPFail(error,@"E_BUSY",@"Cannot acquire the Provider recovery lock."); return NO; }
        @synchronized(self) {
            NSString *path=[_directory stringByAppendingPathComponent:@"cache-index.json"]; NSData *current=nil; struct stat existing;
            if (lstat(path.fileSystemRepresentation,&existing)==0) { current=MLPRead(path,32768,error); if (!current) return NO; }
            else if (errno!=ENOENT) { MLPFail(error,@"E_PROVIDER_RECOVERY",@"Cannot inspect the Provider pointer during recovery."); return NO; }
            NSData *old=[checkpoint[@"indexData"] isKindOfClass:[NSData class]] ? checkpoint[@"indexData"] : nil;
            // MLPRead validated the actual owned/private pointer. Reusing
            // checkpoint bytes avoids an unnecessary write in a read-only
            // directory while still restoring the old in-memory generation.
            if (!MLPSameData(current,old)) {
                if (!MLPSameData(current,_cacheIndexData) && !(_pointerAttemptData && MLPSameData(current,_pointerAttemptData))) { MLPFail(error,@"E_PROVIDER_RECOVERY",@"Another service changed the Provider pointer; recovery cannot overwrite it."); return NO; }
                if (old) { _pointerAttemptData=old; if (!MLPWrite(path,old,error)) return NO; }
                else if (current && unlink(path.fileSystemRepresentation)!=0) { MLPFail(error,@"E_PROVIDER_RECOVERY",@"Cannot restore the initial Provider pointer."); return NO; }
            }
            _cacheIndexData=old; _pointerAttemptData=nil; _cacheIndex=checkpoint[@"index"]; _states=checkpoint[@"states"]; _source=checkpoint[@"source"]==[NSNull null] ? nil : checkpoint[@"source"];
            _prepared=nil; _preparedSource=nil; _preparedStates=nil; _writes=nil; return YES;
        }
    } @finally { if (lock>=0) { (void)flock(lock,LOCK_UN); close(lock); } [_operation unlock]; }
}
- (NSSet *)dueProviderNames {
    @synchronized(self) {
        NSMutableSet *due=[NSMutableSet set]; double now=[[NSDate date] timeIntervalSince1970], monotonic=[NSProcessInfo processInfo].systemUptime;
        for (NSString *key in _states) {
            NSDictionary *state=_states[key]; double interval=[state[@"interval"] doubleValue], last=[state[@"updatedAt"] doubleValue];
            if ([state[@"type"] isEqual:@"inline"] || interval<=0 || monotonic-[_attempts[key] doubleValue]<60) continue;
            if (now<last || now-last>=interval) [due addObject:key];
        }
        return [due copy];
    }
}
- (BOOL)importLocalText:(NSString *)text path:(NSString *)path error:(NSError **)error {
    NSData *data=MLPString(text) ? [text dataUsingEncoding:NSUTF8StringEncoding] : nil;
    path=MLPPath(path);
    if (!path || !data || data.length>MLProviderTextLimit) { MLPFail(error,@"E_PROVIDER_PATH",@"Local Provider import requires bounded UTF-8 text and a relative private path."); return NO; }
    if (![_operation tryLock]) { MLPFail(error,@"E_BUSY",@"A Provider operation is in progress."); return NO; }
    @try { return [self integrity:error] && MLPWrite([[_directory stringByAppendingPathComponent:@"local"] stringByAppendingPathComponent:path],data,error); }
    @finally { [_operation unlock]; }
}
@end
