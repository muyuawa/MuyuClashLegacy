#import <Foundation/Foundation.h>
#import "MLConfig.h"
#import "MLConfigStore.h"
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>

static NSDictionary *issue(NSDictionary *report, NSString *identifier) {
    for (NSDictionary *item in report[@"issues"])
        if ([item[@"id"] isEqual:identifier]) return item;
    return nil;
}

int main(void) { @autoreleasepool {
    // Catch permissive parsing, lost source locations and silently ignored fields.
    NSDictionary *report = [MLConfig checkYAML:@"mode: rule\nrules:\n  - MATCH,DIRECT\n"];
    assert([report[@"valid"] boolValue] && [report[@"document"] isKindOfClass:[NSDictionary class]]);
    assert(issue(report, @"RUNTIME_UNVERIFIED"));
    report = [MLConfig checkYAML:@"mode: rule\nmode: global\n"];
    assert(![report[@"valid"] boolValue]);

    // Catch malformed semantic values reaching string/number-only selectors.
    for (NSString *yaml in @[@"proxies: [{name: x, type: socks5, server: example.com, port: 1, skip-cert-verify: []}]\n",
                             @"proxy-groups: [{name: g, type: select, proxies: [], use: 1}]\n"])
        assert(![[MLConfig checkYAML:yaml][@"valid"] boolValue]);
    assert(issue([MLConfig checkYAML:@"rules: ['IP-CIDR,::1/129,DIRECT']\n"],@"RULE_CIDR"));
    assert(issue([MLConfig checkYAML:@"rules: ['DST-PORT,70000,DIRECT']\n"],@"RULE_PORT"));
    assert([issue(report,@"YAML_DUPLICATE_KEY")[@"line"] integerValue] == 2);
    assert([report[@"unchecked"] boolValue]);
    for (NSString *yaml in @[@"x: &x [*x]\n", @"a: !!str value\n", @"? [a,b]\n: c\n", @"1: value\n", @"{}\n---\n{}\n", @"rules: [\n"])
        assert(![[MLConfig checkYAML:yaml][@"valid"] boolValue]);
    assert(issue([MLConfig checkYAML:@"surprise: true\n"],@"UNKNOWN_FIELD"));
    NSMutableString *deep=[NSMutableString stringWithString:@"x: "];
    for(int i=0;i<40;i++)[deep appendString:@"["];
    [deep appendString:@"0"];
    for(int i=0;i<40;i++)[deep appendString:@"]"];
    assert(issue([MLConfig checkYAML:deep],@"YAML_DEPTH_LIMIT"));
    NSMutableString *large=[NSMutableString stringWithCapacity:524289];
    for(int i=0;i<524289;i++)[large appendString:@"a"];
    assert(issue([MLConfig checkYAML:large],@"YAML_SIZE_LIMIT"));
    NSMutableString *many=[NSMutableString stringWithString:@"x: ["];
    for(int i=0;i<20001;i++)[many appendString:@"0,"];
    [many appendString:@"]"];
    assert(issue([MLConfig checkYAML:many],@"YAML_NODE_LIMIT"));

    // Catch source-location path amplification from a long mapping key reused
    // for every descendant. Keep the repro small enough to run on old devices.
    NSMutableString *longKey=[NSMutableString string];
    for(int i=0;i<4096;i++)[longKey appendString:@"x"];
    NSString *amplified=[NSString stringWithFormat:@"? '%@'\n: [0,0,0,0,0,0,0,0]\n",longKey];
    assert(issue([MLConfig checkYAML:amplified],@"YAML_KEY_LIMIT"));
    NSMutableString *longPath=[NSMutableString string];
    NSMutableString *key=[NSMutableString string];
    for(int i=0;i<240;i++)[key appendString:@"k"];
    for(int depth=0;depth<6;depth++)[longPath appendFormat:@"%@%@: ",depth?@"{":@"",key];
    [longPath appendString:@"0}}}}}\n"];
    assert(issue([MLConfig checkYAML:longPath],@"YAML_FIELD_PATH_LIMIT"));

    // Catch dangling references, cycles, malformed ports and unsupported protocol claims.
    assert(issue([MLConfig checkYAML:@"rules: [MATCH,missing]\n"],@"FIELD_TYPE"));
    assert(issue([MLConfig checkYAML:@"rules: ['MATCH,missing']\n"],@"REFERENCE_MISSING"));
    assert(issue([MLConfig checkYAML:@"proxy-groups:\n - name: a\n   type: select\n   proxies: [b]\n - name: b\n   type: select\n   proxies: [a]\n"],@"GROUP_CYCLE"));
    report=[MLConfig checkYAML:@"proxy-groups:\n - {name: GLOBAL, type: select, proxies: [choice, DIRECT]}\n - {name: choice, type: select, proxies: [DIRECT, REJECT], default-selected: REJECT}\nrules: ['IP-CIDR,2001:db8::/32,GLOBAL,no-resolve', 'domain-regex,^x{2,3}\\.test$,REJECT']\n"];
    assert([report[@"valid"] boolValue]);
    assert(issue([MLConfig checkYAML:@"proxy-groups: [{name: Picker, type: select, proxies: [DIRECT], default-selected: REJECT}]"],@"GROUP_DEFAULT_SELECTION"));
    assert([[MLConfig checkYAML:@"proxy-groups: [{name: Picker, type: url-test, proxies: [DIRECT]}]"][@"valid"] boolValue]);
    assert(issue([MLConfig checkYAML:@"proxy-groups: [{name: Picker, type: url-test, proxies: [DIRECT], timeout: 0}]"],@"FIELD_RANGE"));
    assert(issue([MLConfig checkYAML:@"proxy-groups: [{name: Picker, type: select, proxies: [DIRECT], interval: 60}]"],@"GROUP_OPTION_UNAVAILABLE"));
    assert(issue([MLConfig checkYAML:@"proxy-groups: [{name: Picker, type: select, proxies: [GLOBAL]}]"],@"GROUP_CYCLE"));
    assert([[MLConfig checkYAML:@"rules: ['NETWORK,UDP,DIRECT']"][@"valid"] boolValue]);
    assert(issue([MLConfig checkYAML:@"rules: ['MATCH,PASS']"],@"TARGET_UNAVAILABLE"));
    report=[MLConfig checkYAML:@"dns: {enable: true, ipv6: true, enhanced-mode: redir-host, nameserver: ['127.0.0.1:5353', 'tcp://[::1]:53']}\n"];
    assert([report[@"valid"] boolValue]);
    assert([[MLConfig checkYAML:@"dns: {enable: true, enhanced-mode: fake-ip, nameserver: [127.0.0.1]}"][@"valid"] boolValue]);
    assert([[MLConfig checkYAML:@"dns: {enable: true, nameserver: [tls://dns.example.test:853]}"][@"valid"] boolValue]);
    assert(![[MLConfig checkYAML:@"dns: {enable: true, nameserver: [tls://dns.example.test:0]}"][@"valid"] boolValue]);
    report=[MLConfig checkYAML:@"proxies:\n - name: node\n   type: socks5\n   server: example.com\n   port: 0\n"];
    assert(issue(report,@"PORT_RANGE"));
    report=[MLConfig checkYAML:@"proxies:\n - name: missing\n   type: socks5\n   port: 1080\n"];
    assert([issue(report,@"REQUIRED_FIELD")[@"line"] integerValue]==2);
    report=[MLConfig checkYAML:@"proxies:\n - name: node\n   type: made-up-protocol\n   server: example.com\n   port: 1080\n   mystery: true\n"];
    assert(issue(report,@"PROTOCOL_UNAVAILABLE") && issue(report,@"UNKNOWN_FIELD"));
    assert(![report[@"valid"] boolValue]);

    // Catch replacement of active configuration before a failed core preparation.
    char temp[]="/private/tmp/muyu-config-XXXXXX";assert(mkdtemp(temp));
    NSString *directory=[NSString stringWithUTF8String:temp];
    NSError *error=nil;
    MLConfigStore *store=[[MLConfigStore alloc] initWithDirectory:directory error:&error];
    assert(store && !error);
    NSDictionary *first=[store importYAML:@"rules: ['MATCH,DIRECT']\n" name:@"First" source:@"" error:&error];
    assert(first && !error && ![first[@"active"] boolValue]);
    assert([store activateID:first[@"id"] prepare:^BOOL(NSDictionary *configuration,NSError **failure){
        (void)failure;
        assert([configuration[@"rules"][0] isEqual:@"MATCH,DIRECT"]);return YES;
    } error:&error]);
    NSDictionary *second=[store importYAML:@"rules: ['MATCH,REJECT']\n" name:@"Second" source:@"https://example.com/config" error:&error];
    assert(second);
    assert(![store activateID:second[@"id"] prepare:^BOOL(NSDictionary *configuration,NSError **failure){
        (void)configuration;
        *failure=[NSError errorWithDomain:@"test" code:42 userInfo:nil];return NO;
    } error:&error]);
    assert([store.activeID isEqual:first[@"id"]]);
    MLConfigStore *reopened=[[MLConfigStore alloc] initWithDirectory:directory error:NULL];
    assert([reopened.activeID isEqual:first[@"id"]] && reopened.list.count==2);
    assert([[reopened sourceForID:first[@"id"] error:NULL][@"yaml"] isEqual:@"rules: ['MATCH,DIRECT']\n"]);
    NSDictionary *candidate=[store importYAML:@"proxies: [{name: n, type: made-up-protocol, server: example.com, port: 1080}]\n" name:@"Candidate" source:@"" error:NULL];
    assert(candidate && [candidate[@"status"] isEqual:@"incompatible"]);
    __block BOOL prepared=NO;
    assert(![store activateID:candidate[@"id"] prepare:^BOOL(NSDictionary *configuration,NSError **failure){(void)configuration;(void)failure;prepared=YES;return YES;} error:NULL]);
    assert(!prepared && [store.activeID isEqual:first[@"id"]]);
    assert(![store removeID:first[@"id"] error:NULL]);
    assert([store removeID:second[@"id"] error:NULL]);
    assert(![store sourceForID:@"../outside" error:NULL]);
    struct stat st;assert(lstat(temp,&st)==0 && (st.st_mode&0777)==0700);
    NSString *record=[directory stringByAppendingPathComponent:[first[@"id"] stringByAppendingString:@".json"]];
    assert(lstat(record.fileSystemRepresentation,&st)==0 && (st.st_mode&0777)==0600);
    NSString *link=[directory stringByAppendingString:@"-link"];
    assert(symlink(temp,link.fileSystemRepresentation)==0);
    assert(![[MLConfigStore alloc] initWithDirectory:link error:NULL]);
    unlink(link.fileSystemRepresentation);
    NSString *candidatePath=[directory stringByAppendingPathComponent:[candidate[@"id"] stringByAppendingString:@".json"]];
    assert(unlink(candidatePath.fileSystemRepresentation)==0);
    assert(symlink(record.fileSystemRepresentation,candidatePath.fileSystemRepresentation)==0);
    assert(![store sourceForID:candidate[@"id"] error:NULL]);
    assert(![store importYAML:@"a: [\n" name:@"Broken" source:@"" error:NULL]);
    [[NSFileManager defaultManager] removeItemAtPath:directory error:NULL];
    puts("PASS config: bounded YAML, locations, schema, references/cycles, capability blockers, transactional private storage");
}return 0;}
