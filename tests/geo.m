#import <Foundation/Foundation.h>
#import "../providers/MLGeoFormat.h"
#import "../providers/MLGeoIndex.h"
#import "../providers/MLGeoDataManager.h"
#import "../providers/MLProviderStorage.h"
#import "../routing/MLRouting.h"
#include <assert.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <CommonCrypto/CommonDigest.h>
static BOOL match(MLGeoIndex *index, NSString *kind, NSString *operand, NSString *ip, NSString *domain) {
    unsigned char address[16]={0}; int family=ip && inet_pton(AF_INET,ip.UTF8String,address)==1 ? AF_INET : AF_INET6;
    if (ip && family==AF_INET6) assert(inet_pton(AF_INET6,ip.UTF8String,address)==1);
    BOOL usable=YES; BOOL result=[index matchKind:kind operand:operand family:ip ? family : 0 address:ip ? address : NULL domain:domain usable:&usable]; assert(usable); return result;
}
int main(int argc, char **argv) { @autoreleasepool {
    if (argc==3 && !strcmp(argv[1],"--bundled")) {
        char temp[]="/private/tmp/muyu-builtin-geo.XXXXXX"; assert(mkdtemp(temp));
        NSString *root=[NSString stringWithUTF8String:temp], *bundle=[NSString stringWithUTF8String:argv[2]];
        NSError *failure=nil;
        for (NSNumber *dat in @[@NO,@YES]) { @autoreleasepool {
            NSString *private=[root stringByAppendingPathComponent:dat.boolValue ? @"dat" : @"mmdb"];
            MLGeoDataManager *manager=[[MLGeoDataManager alloc] initWithDirectory:private readableDirectory:[private stringByAppendingString:@"-index"] caPath:nil bundledDirectory:bundle error:&failure]; assert(manager && !failure);
            NSDictionary *doc=@{@"geodata-mode":dat,@"rules":@[@"GEOIP,CN,REJECT,no-resolve",@"GEOIP,US,DIRECT,no-resolve",@"MATCH,REJECT"]};
            double start=[NSProcessInfo processInfo].systemUptime;
            NSDictionary *ready=[manager prepareDocument:doc fetch:NO refresh:NO error:&failure];
            if (!ready) fprintf(stderr,"Bundled GeoIP failed: %s\n",failure.localizedDescription.UTF8String);
            assert(ready && !failure); assert([manager commitPreparedDocument:ready error:&failure]);
            assert([MLRoute(ready,@"Rule",nil,@"test.invalid",@"114.114.114.114",nil,0,443,@"TCP")[@"node"] isEqual:@"REJECT"]);
            assert([MLRoute(ready,@"Rule",nil,@"test.invalid",@"8.8.8.8",nil,0,443,@"TCP")[@"node"] isEqual:@"DIRECT"]);
            double first=[NSProcessInfo processInfo].systemUptime-start; start=[NSProcessInfo processInfo].systemUptime;
            ready=[manager prepareDocument:doc fetch:NO refresh:NO error:&failure]; assert(ready && !failure);
            printf("PASS bundled %s offline: initial %.3fs, native index reuse %.3fs\n",dat.boolValue ? "DAT" : "MMDB",first,[NSProcessInfo processInfo].systemUptime-start);
        }}
        [[NSFileManager defaultManager] removeItemAtPath:root error:NULL]; return 0;
    }
    assert(argc>=2); NSString *fixtures=[NSString stringWithUTF8String:argv[1]]; NSError *error=nil;
    NSArray *cases=[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"cases.json"]] options:0 error:NULL]; assert(cases.count);
    NSMutableDictionary *sets=[NSMutableDictionary dictionary];
    for (NSString *kind in @[@"geoip",@"asn"]) {
        NSMutableSet *requested=[NSMutableSet set]; for (NSDictionary *item in cases) if ([item[@"kind"] isEqual:kind]) [requested addObject:item[@"key"]];
        NSString *name=[kind isEqual:@"asn"] ? @"GeoLite2-ASN-Test.mmdb" : @"GeoIP2-Country-Test.mmdb";
        NSDictionary *decoded=MLGeoDecodeMMDB([fixtures stringByAppendingPathComponent:name],kind,requested,&error); assert(decoded && !error); [sets addEntriesFromDictionary:decoded];
    }
    NSDictionary *sites=MLGeoDecodeDat([NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"GeoSite.dat"]],@"geosite",[NSSet setWithArray:@[@"test",@"test@ads",@"!test@ads"]],&error); assert(sites && !error); [sets addEntriesFromDictionary:sites];
    NSData *encoded=MLGeoEncodeIndex(sets,&error); assert(encoded && !error);
    char temporary[]="/private/tmp/muyu-geo-tests.XXXXXX"; char *created=mkdtemp(temporary); assert(created); NSString *directory=[NSString stringWithUTF8String:created];
    NSString *path=[directory stringByAppendingPathComponent:@"fixture.index"]; assert([encoded writeToFile:path atomically:NO]); assert(chmod(path.fileSystemRepresentation,0444)==0);
    unsigned char hash[32]; CC_SHA256(encoded.bytes,(CC_LONG)encoded.length,hash); NSMutableString *sha=[NSMutableString string]; for (NSUInteger i=0;i<32;++i) [sha appendFormat:@"%02x",hash[i]];
    NSDictionary *descriptor=@{@"path":path,@"owner":@(geteuid()),@"size":@(encoded.length),@"sha256":sha}; MLGeoIndex *index=[MLGeoIndex indexWithDescriptor:descriptor error:&error]; assert(index && !error);
    for (NSDictionary *item in cases) { assert(match(index,item[@"kind"],item[@"key"],item[@"ip"],nil)); assert(!match(index,item[@"kind"],item[@"wrongKey"],item[@"ip"],nil)); }
    assert(match(index,@"geosite",@"test",nil,@"x.root.test")); assert(match(index,@"geosite",@"test",nil,@"exact.test"));
    assert(!match(index,@"geosite",@"test",nil,@"x.exact.test")); assert(match(index,@"geosite",@"test",nil,@"a.rx.test"));
    assert(match(index,@"geosite",@"test@ads",nil,@"x.root.test")); assert(!match(index,@"geosite",@"test@ads",nil,@"exact.test"));
    assert(match(index,@"geosite",@"!test@ads",nil,@"unrelated.test")); assert(!match(index,@"geosite",@"!test@ads",nil,@""));
    NSDictionary *ips=MLGeoDecodeDat([NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"GeoIP.dat"]],@"geoip",[NSSet setWithArray:@[@"CN",@"!CN"]],&error); assert(ips && !error);
    assert(!MLGeoDecodeDat([NSData dataWithBytes:"\12\377" length:2],@"geoip",[NSSet setWithObject:@"CN"],&error)); error=nil;
    assert(!MLGeoDecodeDat([NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"GeoIP.dat"]],@"geoip",[NSSet setWithObject:@"absent"],&error)); error=nil;
    NSString *private=[directory stringByAppendingPathComponent:@"private"], *public=[directory stringByAppendingPathComponent:@"public"];
    NSString *ca=argc>2 ? [NSString stringWithUTF8String:argv[2]] : nil;
    MLGeoDataManager *manager=[[MLGeoDataManager alloc] initWithDirectory:private readableDirectory:public caPath:ca error:&error]; assert(manager && !error);
    for (NSString *name in @[@"GeoIP.dat",@"GeoSite.dat"]) {
        NSString *local=[[private stringByAppendingPathComponent:@"local"] stringByAppendingPathComponent:name]; assert([[NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:name]] writeToFile:local atomically:NO]); assert(chmod(local.fileSystemRepresentation,0600)==0);
    }
    NSMutableDictionary *document=[@{@"geodata-mode":@YES,@"rules":@[@"GEOSITE,test@ads,REJECT",@"GEOIP,!CN,REJECT",@"MATCH,DIRECT"]} mutableCopy];
    if (argc>3) { NSString *base=[NSString stringWithUTF8String:argv[3]]; document[@"geox-url"]=@{@"geoip":[base stringByAppendingString:@"/GeoIP.dat"],@"geosite":[base stringByAppendingString:@"/GeoSite.dat"]}; }
    NSDictionary *prepared=[manager prepareDocument:document fetch:argc>3 refresh:NO error:&error];
    if (argc>4) { assert(!prepared && error); [[NSFileManager defaultManager] removeItemAtPath:directory error:NULL]; puts("PASS Geo HTTPS hostname rejection"); return 0; }
    assert(prepared && !error); assert([manager commitPreparedDocument:prepared error:&error]);
    id checkpoint=[manager captureCheckpoint];
    NSString *pointer=[private stringByAppendingPathComponent:@"geo-current.json"];
    NSData *checkpointBytes=[NSData dataWithContentsOfFile:pointer]; assert(checkpointBytes);
    assert([MLRoute(prepared,@"Rule",nil,@"unrelated.test",@"203.0.113.1",nil,0,443,@"TCP")[@"node"] isEqual:@"REJECT"]);
    assert([MLRoute(prepared,@"Rule",nil,@"unrelated.test",@"192.0.2.1",nil,0,443,@"TCP")[@"node"] isEqual:@"DIRECT"]);
    assert([MLRoute(prepared,@"Rule",nil,@"unrelated.test",@"2001:db8::1",nil,0,443,@"TCP")[@"node"] isEqual:@"DIRECT"]);
    NSString *bad=[private stringByAppendingPathComponent:@"local/GeoIP.dat"]; assert([[NSData dataWithBytes:"bad" length:3] writeToFile:bad atomically:NO]);
    prepared=[manager prepareDocument:document fetch:argc>3 refresh:YES error:&error]; assert(prepared && !error); assert([manager commitPreparedDocument:prepared error:&error]);
    assert(MLProviderPrivateWrite(pointer,checkpointBytes,&error));
    struct stat pointerBefore,pointerAfter; assert(lstat(pointer.fileSystemRepresentation,&pointerBefore)==0);
    assert(chmod(private.fileSystemRepresentation,0500)==0); assert([manager restoreCheckpoint:checkpoint error:&error]);
    assert(chmod(private.fileSystemRepresentation,0700)==0);
    assert(lstat(pointer.fileSystemRepresentation,&pointerAfter)==0 && pointerBefore.st_ino==pointerAfter.st_ino);
    for (NSDictionary *state in [manager list]) assert([state[@"status"] isEqual:@"ready"]);
    NSData *foreign=[@"{}" dataUsingEncoding:NSUTF8StringEncoding]; assert(MLProviderPrivateWrite(pointer,foreign,&error));
    assert(![manager restoreCheckpoint:checkpoint error:&error] && [error.domain isEqual:@"E_GEO_RECOVERY"]); error=nil;
    assert([[NSData dataWithContentsOfFile:pointer] isEqual:foreign]); assert(MLProviderPrivateWrite(pointer,checkpointBytes,&error));
    assert(chmod(pointer.fileSystemRepresentation,0644)==0); assert(![manager restoreCheckpoint:checkpoint error:&error] && error); error=nil;
    assert(chmod(pointer.fileSystemRepresentation,0600)==0); assert([manager restoreCheckpoint:checkpoint error:&error]);
    MLGeoDataManager *restart=[[MLGeoDataManager alloc] initWithDirectory:private readableDirectory:public caPath:ca error:&error]; assert(restart && !error);
    prepared=[restart prepareDocument:document fetch:NO refresh:NO error:&error]; assert(prepared && !error);
    // A separate local MMDB generation verifies reuse, corruption repair and crash staging cleanup.
    NSString *repairPrivate=[directory stringByAppendingPathComponent:@"repair-private"], *repairPublic=[directory stringByAppendingPathComponent:@"repair-public"];
    MLGeoDataManager *repair=[[MLGeoDataManager alloc] initWithDirectory:repairPrivate readableDirectory:repairPublic caPath:nil error:&error]; assert(repair && !error);
    NSData *mmdb=[NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"GeoIP2-Country-Test.mmdb"]];
    NSString *mmdbLocal=[repairPrivate stringByAppendingPathComponent:@"local/Country.mmdb"]; assert([mmdb writeToFile:mmdbLocal atomically:NO]); assert(chmod(mmdbLocal.fileSystemRepresentation,0600)==0);
    NSDictionary *mmdbDocument=@{@"rules":@[@"GEOIP,US,REJECT",@"MATCH,DIRECT"]};
    prepared=[repair prepareDocument:mmdbDocument fetch:NO refresh:NO error:&error]; assert(prepared && !error); assert([repair commitPreparedDocument:prepared error:&error]);
    NSString *mmdbCache=[[repairPrivate stringByAppendingPathComponent:@"cache"] stringByAppendingPathComponent:[[MLProviderStorageHash(mmdb) description] stringByAppendingString:@".raw"]];
    struct stat before,after; assert(lstat(mmdbCache.fileSystemRepresentation,&before)==0);
    prepared=[repair prepareDocument:mmdbDocument fetch:NO refresh:YES error:&error]; assert(prepared && !error); assert(lstat(mmdbCache.fileSystemRepresentation,&after)==0); assert(before.st_ino==after.st_ino); [repair discardPreparedDocument];
    assert([[NSData dataWithBytes:"bad" length:3] writeToFile:mmdbCache atomically:NO]);
    NSString *pendingPrivate=[repairPrivate stringByAppendingPathComponent:@"cache/.pending-12345678-1234-1234-1234-123456789abc"];
    NSString *pendingPublic=[repairPublic stringByAppendingPathComponent:[[@"0" stringByPaddingToLength:64 withString:@"0" startingAtIndex:0] stringByAppendingString:@".pending"]];
    struct timeval stale[2]={{1,0},{1,0}};
    for (NSString *pending in @[pendingPrivate,pendingPublic]) { assert([[NSData dataWithBytes:"staged" length:6] writeToFile:pending atomically:NO]); assert(chmod(pending.fileSystemRepresentation,0600)==0); assert(utimes(pending.fileSystemRepresentation,stale)==0); }
    prepared=[repair prepareDocument:@{@"rules":@[@"GEOIP,CN,REJECT",@"MATCH,DIRECT"]} fetch:NO refresh:YES error:&error]; assert(prepared && !error);
    assert([[NSData dataWithContentsOfFile:mmdbCache] isEqual:mmdb]); assert(access(pendingPrivate.fileSystemRepresentation,F_OK)!=0); assert(access(pendingPublic.fileSystemRepresentation,F_OK)!=0);
    // Fresh installs prepare GeoIP offline, while explicit URLs retain their own identity.
    NSString *bundle=[directory stringByAppendingPathComponent:@"bundle"];
    assert([[NSFileManager defaultManager] createDirectoryAtPath:bundle withIntermediateDirectories:NO attributes:@{NSFilePosixPermissions:@0755} error:&error]);
    NSMutableDictionary *files=[NSMutableDictionary dictionary];
    for (NSString *name in @[@"Country.mmdb",@"GeoIP.dat"]) {
        NSData *data=[name isEqual:@"Country.mmdb"] ? mmdb : [NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:name]];
        NSString *target=[bundle stringByAppendingPathComponent:name]; assert([data writeToFile:target atomically:NO]); assert(chmod(target.fileSystemRepresentation,0644)==0);
        files[name]=@{@"sha256":MLProviderStorageHash(data)};
    }
    NSString *manifest=[bundle stringByAppendingPathComponent:@"manifest.json"]; assert([[NSJSONSerialization dataWithJSONObject:@{@"files":files} options:0 error:NULL] writeToFile:manifest atomically:NO]);
    NSString *builtinPrivate=[directory stringByAppendingPathComponent:@"builtin-private"], *builtinPublic=[directory stringByAppendingPathComponent:@"builtin-public"];
    MLGeoDataManager *builtin=[[MLGeoDataManager alloc] initWithDirectory:builtinPrivate readableDirectory:builtinPublic caPath:nil bundledDirectory:bundle error:&error]; assert(builtin && !error);
    prepared=[builtin prepareDocument:mmdbDocument fetch:NO refresh:NO error:&error]; assert(prepared && !error); assert([builtin commitPreparedDocument:prepared error:&error]);
    assert([[[builtin list] firstObject][@"type"] isEqual:@"builtin"]);
    NSString *builtinCache=[builtinPrivate stringByAppendingPathComponent:[@"cache/" stringByAppendingFormat:@"%@.raw",MLProviderStorageHash(mmdb)]];
    assert([[NSData dataWithBytes:"bad" length:3] writeToFile:builtinCache atomically:NO]);
    builtin=[[MLGeoDataManager alloc] initWithDirectory:builtinPrivate readableDirectory:builtinPublic caPath:nil bundledDirectory:bundle error:&error]; assert(builtin && !error);
    prepared=[builtin prepareDocument:mmdbDocument fetch:NO refresh:NO error:&error]; assert(prepared && !error);
    assert([MLRoute(prepared,@"Rule",nil,@"test.invalid",@"216.160.83.56",nil,0,443,@"TCP")[@"node"] isEqual:@"REJECT"]);
    [builtin discardPreparedDocument];
    NSDictionary *custom=@{@"geox-url":@{@"mmdb":@"https://custom.invalid/Country.mmdb"},@"rules":mmdbDocument[@"rules"]};
    assert(![builtin prepareDocument:custom fetch:NO refresh:NO error:&error] && error); error=nil;
    prepared=[builtin prepareDocument:@{@"geodata-mode":@YES,@"rules":@[@"GEOIP,!CN,REJECT",@"MATCH,DIRECT"]} fetch:NO refresh:NO error:&error]; assert(prepared && !error);
    assert([builtin commitPreparedDocument:prepared error:&error]);
    assert([[[builtin list] firstObject][@"type"] isEqual:@"builtin"]);
    [[NSFileManager defaultManager] removeItemAtPath:directory error:NULL];
    puts("PASS actual Country/ASN MMDB IPv4/IPv6, GeoSite attributes/negative, GeoIP negative, immutable cache, checkpoint/tamper recovery and restart");
} return 0; }
