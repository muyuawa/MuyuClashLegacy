#import <Foundation/Foundation.h>
#import "../providers/MLProviderManager.h"
#import "../providers/MLProviderStorage.h"
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>

static NSDictionary *source(NSString *type, NSString *location) {
    NSMutableDictionary *spec=[@{@"type":type,@"interval":@1,@"override":@{@"additional-prefix":@"P "}} mutableCopy];
    spec[[type isEqual:@"http"] ? @"url" : @"path"]=location;
    if ([type isEqual:@"http"]) spec[@"path"]=@"./ruleset/remote.yaml";
    return @{@"proxy-providers":@{@"Remote":spec},@"proxy-groups":@[@{@"name":@"Select",@"type":@"select",@"use":@[@"Remote"]}],@"rules":@[@"MATCH,Select"]};
}
static NSString *valid(void) { return @"proxies:\n - {name: Original, type: http, server: 127.0.0.1, port: 19090}\n"; }
int main(int argc, char **argv) { @autoreleasepool {
    char pattern[]="/private/tmp/muyu-provider-tests.XXXXXX";
    char *created=mkdtemp(pattern); assert(created);
    NSString *directory=[NSString stringWithUTF8String:created]; NSError *error=nil;
    NSString *ca=argc>1 ? [NSString stringWithUTF8String:argv[1]] : nil;
    MLProviderManager *manager=[[MLProviderManager alloc] initWithDirectory:directory caPath:ca error:&error]; assert(manager && !error);
    if (argc>2) {
        NSString *url=[NSString stringWithUTF8String:argv[2]]; NSDictionary *document=source(@"http",url);
        NSDictionary *prepared=[manager prepareDocument:document refreshNames:nil error:&error];
        if (argc>3 && !strcmp(argv[3],"reject")) { assert(!prepared); assert(error); puts("PASS Provider TLS rejection"); }
        else {
            assert(prepared && !error); assert([manager commitPreparedDocument:prepared error:&error]);
            assert([prepared[@"proxy-providers"][@"Remote"][@"path"] isEqual:@"./ruleset/remote.yaml"]);
            assert(access([directory stringByAppendingPathComponent:@"local/ruleset/remote.yaml"].fileSystemRepresentation,F_OK)!=0);
            NSDictionary *updated=[manager prepareDocument:document refreshNames:[NSSet setWithObject:@"Remote"] error:&error]; assert(updated && !error);
            assert([updated[@"proxies"][0][@"name"] isEqual:@"P Original"]);
            assert([manager commitPreparedDocument:updated error:&error]);
            assert([[manager list][0][@"status"] isEqual:@"cached"]);
            puts("PASS HTTPS Provider, invalid update cache preservation and atomic generation");
        }
    } else {
        assert([manager importLocalText:valid() path:@"nodes.yaml" error:&error]);
        NSDictionary *document=source(@"file",@"nodes.yaml"); NSDictionary *prepared=[manager prepareDocument:document refreshNames:nil error:&error];
        assert(prepared && !error); assert([prepared[@"proxies"][0][@"name"] isEqual:@"P Original"]);
        assert([prepared[@"proxy-groups"][0][@"proxies"][0] isEqual:@"P Original"]);
        assert([manager commitPreparedDocument:prepared error:&error]);
        id checkpoint=[manager captureCheckpoint];
        NSString *index=[directory stringByAppendingPathComponent:@"cache-index.json"];
        NSData *checkpointBytes=[NSData dataWithContentsOfFile:index]; assert(checkpointBytes);
        assert([manager importLocalText:@"proxies: [broken]" path:@"nodes.yaml" error:&error]);
        prepared=[manager prepareDocument:document refreshNames:[NSSet setWithObject:@"Remote"] error:&error];
        assert(prepared && !error); assert([manager commitPreparedDocument:prepared error:&error]);
        assert([[manager list][0][@"status"] isEqual:@"cached"]);
        // A verified on-disk checkpoint needs no write, but must still restore
        // the earlier ready memory state after a cached candidate was active.
        assert(MLProviderPrivateWrite(index,checkpointBytes,&error));
        struct stat pointerBefore,pointerAfter; assert(lstat(index.fileSystemRepresentation,&pointerBefore)==0);
        assert(chmod(directory.fileSystemRepresentation,0500)==0);
        assert([manager restoreCheckpoint:checkpoint error:&error]);
        assert(chmod(directory.fileSystemRepresentation,0700)==0);
        assert(lstat(index.fileSystemRepresentation,&pointerAfter)==0 && pointerBefore.st_ino==pointerAfter.st_ino);
        assert([[manager list][0][@"status"] isEqual:@"ready"]);
        NSData *foreign=[@"{}" dataUsingEncoding:NSUTF8StringEncoding]; assert(MLProviderPrivateWrite(index,foreign,&error));
        assert(![manager restoreCheckpoint:checkpoint error:&error] && [error.domain isEqual:@"E_PROVIDER_RECOVERY"]); error=nil;
        assert([[NSData dataWithContentsOfFile:index] isEqual:foreign]); assert(MLProviderPrivateWrite(index,checkpointBytes,&error));
        assert(chmod(index.fileSystemRepresentation,0644)==0);
        assert(![manager restoreCheckpoint:checkpoint error:&error] && error); error=nil;
        assert(chmod(index.fileSystemRepresentation,0600)==0); assert([manager restoreCheckpoint:checkpoint error:&error]);
        // Failed pointer commit preserves the old cache even after restart.
        assert([manager importLocalText:@"proxies:\n - {name: New, type: http, server: 127.0.0.1, port: 19090}\n" path:@"nodes.yaml" error:&error]);
        NSDictionary *candidate=[manager prepareDocument:document refreshNames:[NSSet setWithObject:@"Remote"] error:&error]; assert(candidate && !error);
        assert(chmod(index.fileSystemRepresentation,0644)==0);
        assert(![manager commitPreparedDocument:candidate error:&error]); assert(error); error=nil;
        assert(chmod(index.fileSystemRepresentation,0600)==0);
        MLProviderManager *rollback=[[MLProviderManager alloc] initWithDirectory:directory caPath:nil error:&error]; assert(rollback && !error);
        NSDictionary *old=[rollback prepareDocument:document refreshNames:[NSSet set] error:&error]; assert(old && !error);
        assert([old[@"proxies"][0][@"name"] isEqual:@"P Original"]); [manager discardPreparedDocument];
        MLProviderManager *second=[[MLProviderManager alloc] initWithDirectory:directory caPath:nil error:&error];
        prepared=[second prepareDocument:document refreshNames:[NSSet set] error:&error]; assert(prepared && !error);
        assert([prepared[@"proxies"][0][@"name"] isEqual:@"P Original"]);
        NSDictionary *cacheIndex=[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:index] options:0 error:NULL];
        NSString *snapshot=cacheIndex[@"snapshots"][[manager list][0][@"sourceHash"]]; assert(snapshot);
        NSString *snapshotPath=[[directory stringByAppendingPathComponent:@"cache"] stringByAppendingPathComponent:[snapshot stringByAppendingString:@".json"]];
        NSData *originalSnapshot=[NSData dataWithContentsOfFile:snapshotPath];
        NSMutableDictionary *changedSnapshot=[[NSJSONSerialization JSONObjectWithData:originalSnapshot options:NSJSONReadingMutableContainers error:NULL] mutableCopy];
        changedSnapshot[@"payload"][0][@"name"]=@"Altered";
        assert([[NSJSONSerialization dataWithJSONObject:changedSnapshot options:0 error:NULL] writeToFile:snapshotPath atomically:NO]);
        assert(![second prepareDocument:document refreshNames:[NSSet set] error:&error]); assert(error); error=nil;
        assert([originalSnapshot writeToFile:snapshotPath atomically:NO]);
        assert([manager importLocalText:valid() path:@"./ruleset/nodes.yaml" error:&error]);
        NSString *normalized=[directory stringByAppendingPathComponent:@"local/ruleset/nodes.yaml"];
        struct stat normalizedStatus; assert(lstat(normalized.fileSystemRepresentation,&normalizedStatus)==0 && S_ISREG(normalizedStatus.st_mode) && normalizedStatus.st_uid==geteuid());
        prepared=[manager prepareDocument:source(@"file",@"./ruleset/nodes.yaml") refreshNames:nil error:&error]; assert(prepared && !error);
        assert([prepared[@"proxies"][0][@"name"] isEqual:@"P Original"]); [manager discardPreparedDocument];
        for (NSString *unsafe in @[@"./../outside.yaml",@"./",@".//outside.yaml",@"././nodes.yaml",@"ruleset/./nodes.yaml",@"ruleset/../nodes.yaml",@"/tmp/outside.yaml"]) {
            assert(![manager importLocalText:valid() path:unsafe error:&error] && error); error=nil;
            assert(![manager prepareDocument:source(@"file",unsafe) refreshNames:nil error:&error] && error); error=nil;
        }
        NSString *prefixedLink=[directory stringByAppendingPathComponent:@"local/ruleset/link.yaml"]; assert(symlink(normalized.fileSystemRepresentation,prefixedLink.fileSystemRepresentation)==0);
        assert(![manager importLocalText:valid() path:@"./ruleset/link.yaml" error:&error] && error); error=nil;
        assert(![manager prepareDocument:source(@"file",@"./ruleset/link.yaml") refreshNames:nil error:&error] && error); error=nil;
        assert(![manager importLocalText:valid() path:@"../outside.yaml" error:&error]);
        error=nil;
        NSString *target=[directory stringByAppendingPathComponent:@"local/link.yaml"];
        assert(symlink("/etc/passwd",target.fileSystemRepresentation)==0);
        assert(![manager prepareDocument:source(@"file",@"link.yaml") refreshNames:nil error:&error]); assert(error); error=nil;
        assert(![manager importLocalText:valid() path:@"link.yaml" error:&error]); error=nil;
        NSDictionary *rules=@{@"rule-providers":@{@"Domains":@{@"type":@"inline",@"behavior":@"domain",@"payload":@[@"+.example.test"]}},@"rules":@[@"RULE-SET,Domains,REJECT",@"MATCH,DIRECT"]};
        prepared=[manager prepareDocument:rules refreshNames:nil error:&error]; assert(prepared && !error);
        assert([prepared[@"_rule-provider-payloads"][@"Domains"][@"payload"][0] isEqual:@"+.example.test"]);
        assert([manager commitPreparedDocument:prepared error:&error]);
        NSString *cache=[directory stringByAppendingPathComponent:@"cache"];
        NSString *temporary=[cache stringByAppendingPathComponent:@".pending-12345678-1234-1234-1234-123456789abc"];
        assert([[@"staged" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:temporary atomically:NO]); assert(chmod(temporary.fileSystemRepresentation,0600)==0);
        struct timeval stale[2]={{1,0},{1,0}}; assert(utimes(temporary.fileSystemRepresentation,stale)==0);
        for (NSUInteger i=0;i<260;++i) {
            NSString *name=[NSString stringWithFormat:@"%064lx.json",(unsigned long)i]; NSString *path=[cache stringByAppendingPathComponent:name];
            assert([[@"{}" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:path atomically:NO]); assert(chmod(path.fileSystemRepresentation,0600)==0);
        }
        prepared=[manager prepareDocument:rules refreshNames:nil error:&error]; assert(prepared && !error); assert([manager commitPreparedDocument:prepared error:&error]);
        assert([[[NSFileManager defaultManager] contentsOfDirectoryAtPath:cache error:NULL] count]<=256);
        assert(access(temporary.fileSystemRepresentation,F_OK)!=0);
        NSDictionary *renamed=@{@"proxy-providers":@{@"Names":@{@"type":@"inline",@"payload":@[@{@"name":@"aa bb aa",@"type":@"http",@"server":@"127.0.0.1",@"port":@19090}],@"override":@{@"proxy-name":@[@{@"pattern":@"(aa)",@"target":@"$1!"},@{@"pattern":@"$",@"target":@" end"}]}}},@"proxy-groups":@[@{@"name":@"Select",@"type":@"select",@"use":@[@"Names"]}],@"rules":@[@"MATCH,Select"]};
        prepared=[manager prepareDocument:renamed refreshNames:nil error:&error]; assert(prepared && !error);
        assert([prepared[@"proxies"][0][@"name"] isEqual:@"aa! bb aa! end"]); [manager discardPreparedDocument];
        puts("PASS Providers: sources, naming, membership, cached updates, restart, unchanged checkpoint memory recovery, pointer tamper and private paths");
    }
    [[NSFileManager defaultManager] removeItemAtPath:directory error:NULL];
} return 0; }
