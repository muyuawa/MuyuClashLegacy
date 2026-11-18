#import <Foundation/Foundation.h>
#import "../providers/MLMRS.h"
#import "../providers/MLProviderManager.h"
#import "../routing/MLRouting.h"
#include <assert.h>
#include <sys/stat.h>

static NSArray *load(NSString *directory, NSString *name, NSString *behavior) {
    NSError *error=nil; NSArray *rules=MLMRSDecode([NSData dataWithContentsOfFile:[directory stringByAppendingPathComponent:name]],behavior,&error);
    assert(rules && !error); return rules;
}
static NSDictionary *source(NSString *location, BOOL remote) {
    NSMutableDictionary *spec=[@{@"type":remote ? @"http" : @"file",@"behavior":@"domain",@"format":@"mrs"} mutableCopy];
    spec[remote ? @"url" : @"path"]=location;
    return @{@"rule-providers":@{@"Domains":spec},@"rules":@[@"RULE-SET,Domains,REJECT",@"MATCH,DIRECT"]};
}
int main(int argc, char **argv) { @autoreleasepool {
    assert(argc>=2); NSString *fixtures=[NSString stringWithUTF8String:argv[1]];
    NSArray *domains=load(fixtures,@"domain.mrs",@"domain");
    assert(([domains isEqual:@[@"+.example.test",@".suffix.test",@"exact.test",@"x.*.wild.test",@"食狮.中国"]]));
    NSArray *ip=load(fixtures,@"ip.mrs",@"ipcidr");
    assert(([ip isEqual:@[@"192.0.2.1/32",@"192.0.2.2/31",@"192.0.2.4/31",@"192.0.2.6/32",@"::/128",@"2001:db8::/126"]]));
    for (NSString *name in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:fixtures error:NULL]) if ([name hasPrefix:@"bad-"]) {
        NSError *failure=nil; NSArray *invalid=MLMRSDecode([NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:name]],[name hasPrefix:@"bad-ip"] ? @"ipcidr" : @"domain",&failure);
        assert(!invalid && failure && [failure.domain isEqual:@"E_PROVIDER_MRS"]);
    }
    NSError *error=nil;
    assert(!MLMRSDecode([NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"domain.mrs"]],@"ipcidr",&error)); error=nil;
    assert(!MLMRSDecode([NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"domain.mrs"]],@"classical",&error)); error=nil;
    char pattern[]="/private/tmp/muyu-mrs-tests.XXXXXX"; char *created=mkdtemp(pattern); assert(created);
    NSString *directory=[NSString stringWithUTF8String:created];
    NSString *ca=argc>2 ? [NSString stringWithUTF8String:argv[2]] : nil;
    MLProviderManager *manager=[[MLProviderManager alloc] initWithDirectory:directory caPath:ca error:&error]; assert(manager && !error);
    NSString *path=[directory stringByAppendingPathComponent:@"local/rules.mrs"];
    NSData *valid=[NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"domain.mrs"]];
    assert([valid writeToFile:path atomically:NO]); assert(chmod(path.fileSystemRepresentation,0600)==0);
    NSDictionary *document=source(argc>3 ? [NSString stringWithUTF8String:argv[3]] : @"rules.mrs",argc>3);
    NSDictionary *prepared=[manager prepareDocument:document refreshNames:nil error:&error]; assert(prepared && !error);
    assert([prepared[@"_rule-provider-payloads"][@"Domains"][@"payload"] isEqual:domains]);
    assert([MLRoute(prepared,@"Rule",nil,@"www.example.test",nil,nil,0,443,@"TCP")[@"node"] isEqual:@"REJECT"]);
    assert([MLRoute(prepared,@"Rule",nil,@"suffix.test",nil,nil,0,443,@"TCP")[@"node"] isEqual:@"DIRECT"]);
    assert([MLRoute(prepared,@"Rule",nil,@"x.suffix.test",nil,nil,0,443,@"TCP")[@"node"] isEqual:@"REJECT"]);
    assert([manager commitPreparedDocument:prepared error:&error]);
    assert([[NSData dataWithBytes:"broken" length:6] writeToFile:path atomically:NO]);
    prepared=[manager prepareDocument:document refreshNames:[NSSet setWithObject:@"Domains"] error:&error]; assert(prepared && !error);
    assert([manager commitPreparedDocument:prepared error:&error]); assert([[manager list][0][@"status"] isEqual:@"cached"]);
    MLProviderManager *restart=[[MLProviderManager alloc] initWithDirectory:directory caPath:ca error:&error]; assert(restart && !error);
    prepared=[restart prepareDocument:document refreshNames:[NSSet set] error:&error]; assert(prepared && !error);
    assert([prepared[@"_rule-provider-payloads"][@"Domains"][@"payload"] isEqual:domains]);
    [[NSFileManager defaultManager] removeItemAtPath:directory error:NULL];
    puts("PASS MRS domain/IP decoding, malformed frames, Provider cache retention and restart");
} return 0; }
