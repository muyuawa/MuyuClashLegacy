#import "MLGeoIndex.h"
#import "MLGeoFormat.h"
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

static id MLGIndexError(NSError **error, NSString *reason) {
    if (error) *error=[NSError errorWithDomain:@"E_GEO_INDEX" code:1 userInfo:@{NSLocalizedDescriptionKey:reason}]; return nil;
}
static BOOL MLGIndexInteger(const unsigned char *bytes, NSUInteger length, NSUInteger *cursor, unsigned count, uint32_t *out) {
    if (*cursor>length || count>length-*cursor) return NO;
    uint32_t value=0; for (unsigned i=0;i<count;++i) value=(value<<8)|bytes[(*cursor)++]; *out=value; return YES;
}
static BOOL MLGIndexPath(NSString *path) {
    if (![path isKindOfClass:[NSString class]] || !path.isAbsolutePath || path.length>4096 || [path.pathComponents containsObject:@".."] || [path rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound) return NO;
    NSString *current=@"/";
    for (NSString *part in path.stringByDeletingLastPathComponent.pathComponents) {
        if ([part isEqual:@"/"]) continue;
        current=[current stringByAppendingPathComponent:part]; struct stat status;
        if (lstat(current.fileSystemRepresentation,&status)!=0 || !S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) return NO;
    }
    return YES;
}
static BOOL MLGIndexHostMatch(const char *host, size_t hostLength, const unsigned char *value, size_t length, unsigned type) {
    if (length>hostLength) return NO;
    if (type==0) { for (size_t i=0;i<=hostLength-length;++i) if (!memcmp(host+i,value,length)) return YES; return NO; }
    if (hostLength==length) return !memcmp(host,value,length);
    return type==2 && host[hostLength-length-1]=='.' && !memcmp(host+hostLength-length,value,length);
}
@implementation MLGeoIndex {
    void *_mapping; NSUInteger _length;
    NSDictionary *_sets, *_regexes;
}
- (void)dealloc { if (_mapping && _length) munmap(_mapping,_length); }
+ (id)indexWithDescriptor:(NSDictionary *)descriptor error:(NSError **)error {
    if (error) *error=nil;
    if (![descriptor isKindOfClass:[NSDictionary class]]) return MLGIndexError(error,@"The Geo index descriptor must be a mapping.");
    NSString *path=descriptor[@"path"], *sha=descriptor[@"sha256"];
    if (![descriptor isKindOfClass:[NSDictionary class]] || !MLGIndexPath(path) || ![sha isKindOfClass:[NSString class]] || sha.length!=64 || ![descriptor[@"owner"] isKindOfClass:[NSNumber class]] || ![descriptor[@"size"] isKindOfClass:[NSNumber class]]) return MLGIndexError(error,@"The Geo index descriptor is invalid.");
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW); struct stat status, current;
    BOOL valid=fd>=0 && fstat(fd,&status)==0 && S_ISREG(status.st_mode) && status.st_nlink==1 && status.st_uid==(uid_t)[descriptor[@"owner"] unsignedIntValue] && (status.st_mode&0777)==0444 && status.st_size>=12 && status.st_size<=32*1024*1024 &&
        (uint64_t)status.st_size==[descriptor[@"size"] unsignedLongLongValue] && lstat(path.fileSystemRepresentation,&current)==0 && current.st_dev==status.st_dev && current.st_ino==status.st_ino;
    if (!valid) { if (fd>=0) close(fd); return MLGIndexError(error,@"The Geo index must be an owned, immutable, bounded regular file."); }
    void *mapping=mmap(NULL,(size_t)status.st_size,PROT_READ,MAP_PRIVATE,fd,0); close(fd);
    if (mapping==MAP_FAILED) return MLGIndexError(error,@"Cannot map the bounded Geo index.");
    MLGeoIndex *index=[[self alloc] init]; index->_mapping=mapping; index->_length=(NSUInteger)status.st_size;
    unsigned char hash[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(mapping,(CC_LONG)index->_length,hash); NSMutableString *actual=[NSMutableString string];
    for (NSUInteger i=0;i<sizeof hash;++i) [actual appendFormat:@"%02x",hash[i]];
    if (![actual isEqual:sha]) return MLGIndexError(error,@"The Geo index hash does not match the prepared generation.");
    const unsigned char *bytes=mapping; NSUInteger cursor=8; uint32_t count;
    if (memcmp(bytes,"MLGEO1\0\0",8) || !MLGIndexInteger(bytes,index->_length,&cursor,4,&count) || count>256) return MLGIndexError(error,@"The Geo index header is invalid.");
    NSMutableDictionary *sets=[NSMutableDictionary dictionary], *regexes=[NSMutableDictionary dictionary];
    for (uint32_t i=0;i<count;++i) {
        uint32_t kind,inverse,keyLength,entries,payloadLength;
        if (!MLGIndexInteger(bytes,index->_length,&cursor,1,&kind) || kind>2 || !MLGIndexInteger(bytes,index->_length,&cursor,1,&inverse) || inverse>1 || !MLGIndexInteger(bytes,index->_length,&cursor,2,&keyLength) || !keyLength || keyLength>256 ||
            !MLGIndexInteger(bytes,index->_length,&cursor,4,&entries) || !MLGIndexInteger(bytes,index->_length,&cursor,4,&payloadLength) || keyLength>index->_length-cursor || payloadLength>index->_length-cursor-keyLength) return MLGIndexError(error,@"The Geo index category table is malformed.");
        NSString *key=[[NSString alloc] initWithBytes:bytes+cursor length:keyLength encoding:NSUTF8StringEncoding]; cursor+=keyLength;
        NSString *kindName=kind==0 ? @"geoip" : (kind==1 ? @"asn" : @"geosite"); NSString *name=[kindName stringByAppendingFormat:@":%@",key]; NSUInteger offset=cursor, end=cursor+payloadLength;
        if (!key || sets[name]) return MLGIndexError(error,@"Geo categories must have unique UTF-8 identifiers.");
        if (kind<2) {
            if (entries>32*1024*1024/33 || payloadLength!=(NSUInteger)entries*33) return MLGIndexError(error,@"A Geo IP table exceeds its interval budget.");
            const unsigned char *previous=NULL;
            for (uint32_t record=0;record<entries;++record) {
                const unsigned char *range=bytes+cursor+33*record;
                if ((range[0]!=4 && range[0]!=6) || memcmp(range+1,range+17,16)>0 || (previous && (range[0]<previous[0] || (range[0]==previous[0] && memcmp(range+1,previous+17,16)<=0)))) return MLGIndexError(error,@"Geo IP intervals are malformed or overlapping.");
                if (range[0]==4) { static const unsigned char zero[12]={0}; if (memcmp(range+5,zero,12) || memcmp(range+21,zero,12)) return MLGIndexError(error,@"An IPv4 Geo interval contains invalid padding."); }
                previous=range;
            }
            cursor=end;
        } else {
            for (uint32_t record=0;record<entries;++record) {
                NSUInteger recordOffset=cursor; uint32_t type,length;
                if (!MLGIndexInteger(bytes,end,&cursor,1,&type) || type>3 || !MLGIndexInteger(bytes,end,&cursor,2,&length) || !length || length>1024 || length>end-cursor) return MLGIndexError(error,@"A GeoSite domain table is malformed.");
                NSString *value=[[NSString alloc] initWithBytes:bytes+cursor length:length encoding:NSUTF8StringEncoding];
                if (!value || [value rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound) return MLGIndexError(error,@"A GeoSite value must be bounded UTF-8 text.");
                NSString *pattern=nil;
                if (type==1) pattern=value;
                else if (type>=2 && [value rangeOfString:@"*"].location!=NSNotFound) {
                    pattern=[[NSRegularExpression escapedPatternForString:value] stringByReplacingOccurrencesOfString:@"\\*" withString:@"[^.]+"];
                    if (type==2) pattern=[@"(?:[^.]+\\.)*" stringByAppendingString:pattern]; pattern=[NSString stringWithFormat:@"^%@$",pattern];
                }
                if (pattern) {
                    NSRegularExpression *regex=[NSRegularExpression regularExpressionWithPattern:pattern options:0 error:NULL];
                    if (!regex || regexes.count>=4096) return MLGIndexError(error,@"GeoSite regexes are invalid or exceed the 4096-expression memory budget.");
                    regexes[@(recordOffset)]=regex;
                }
                cursor+=length;
            }
            if (cursor!=end) return MLGIndexError(error,@"Unexpected data follows a GeoSite category.");
        }
        sets[name]=@{@"offset":@(offset),@"end":@(end),@"count":@(entries),@"inverse":@(inverse)};
    }
    if (cursor!=index->_length) return MLGIndexError(error,@"Unexpected data follows the Geo index.");
    index->_sets=[sets copy]; index->_regexes=[regexes copy]; return index;
}
- (BOOL)containsKind:(NSString *)kind operand:(NSString *)operand { return _sets[[kind stringByAppendingFormat:@":%@",MLGeoNormalizedKey(kind,operand)]]!=nil; }
- (BOOL)matchKind:(NSString *)kind operand:(NSString *)operand family:(int)family address:(const unsigned char *)address domain:(NSString *)domain usable:(BOOL *)usable {
    NSDictionary *set=_sets[[kind stringByAppendingFormat:@":%@",MLGeoNormalizedKey(kind,operand)]];
    if (!set) { *usable=NO; return NO; }
    BOOL match=NO; const unsigned char *bytes=_mapping; NSUInteger offset=[set[@"offset"] unsignedIntegerValue], count=[set[@"count"] unsignedIntegerValue];
    if (![kind isEqual:@"geosite"]) {
        if ((family!=AF_INET && family!=AF_INET6) || !address) return NO;
        unsigned char target[17]={0}; target[0]=family==AF_INET ? 4 : 6; memcpy(target+1,address,family==AF_INET ? 4 : 16);
        NSUInteger low=0,high=count;
        while (low<high) { NSUInteger middle=low+(high-low)/2; if (memcmp(bytes+offset+33*middle,target,17)<=0) low=middle+1; else high=middle; }
        if (low) { const unsigned char *range=bytes+offset+33*(low-1); match=range[0]==target[0] && memcmp(target+1,range+17,16)<=0; }
    } else {
        if (!domain.length) return NO;
        const char *host=domain.UTF8String; size_t hostLength=strlen(host);
        NSUInteger cursor=offset, end=[set[@"end"] unsignedIntegerValue]; NSTimeInterval deadline=[NSProcessInfo processInfo].systemUptime+0.05;
        for (NSUInteger i=0;i<count && !match;++i) {
            NSUInteger record=cursor; uint32_t type,length; MLGIndexInteger(bytes,end,&cursor,1,&type); MLGIndexInteger(bytes,end,&cursor,2,&length);
            NSRegularExpression *regex=_regexes[@(record)];
            if (regex) {
                __block BOOL found=NO;
                [regex enumerateMatchesInString:domain options:NSMatchingReportProgress|NSMatchingReportCompletion range:NSMakeRange(0,domain.length) usingBlock:^(NSTextCheckingResult *result, NSMatchingFlags flags, BOOL *stop) {
                    if (flags&NSMatchingInternalError || [NSProcessInfo processInfo].systemUptime>deadline) { *usable=NO; *stop=YES; }
                    else if (result) { found=YES; *stop=YES; }
                }];
                if (!*usable) return NO;
                match=found;
            } else {
                match=MLGIndexHostMatch(host,hostLength,bytes+cursor,length,type);
            }
            cursor+=length;
            if (!(i%256) && [NSProcessInfo processInfo].systemUptime>deadline) { *usable=NO; return NO; }
        }
    }
    return [set[@"inverse"] boolValue] ? !match : match;
}
@end
