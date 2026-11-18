#import <Foundation/Foundation.h>
#import "../config/MLConfig.h"
#include <assert.h>
static NSDictionary *check(NSDictionary *document, BOOL prepared) {
    if (prepared) return [MLConfig checkPreparedDocument:document];
    NSData *data=[NSJSONSerialization dataWithJSONObject:document options:0 error:NULL];
    return [MLConfig checkYAML:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]];
}
static BOOL issue(NSDictionary *report, NSString *name) { for (NSDictionary *item in report[@"issues"]) if ([item[@"id"] isEqual:name]) return YES; return NO; }
static NSDictionary *node(NSString *name) { return @{@"name":name,@"type":@"http",@"server":@"127.0.0.1",@"port":@19090}; }
int main(void) { @autoreleasepool {
    NSDictionary *source=@{@"proxies":@[node(@"A")],@"proxy-providers":@{@"Remote":@{@"type":@"file",@"path":@"nodes.yaml"}},
        @"rule-providers":@{@"Rules":@{@"type":@"http",@"url":@"https://example.test/rules.mrs",@"behavior":@"domain",@"format":@"mrs"}},
        @"proxy-groups":@[@{@"name":@"Fast",@"type":@"url-test",@"proxies":@[@"A"],@"use":@[@"Remote"],@"url":@"https://health.test/",@"expected-status":@"204/200-299",@"interval":@300,@"timeout":@5000,@"lazy":@YES,@"tolerance":@50}],
        @"rules":@[@"AND,((DOMAIN,a.test),(NOT,(DST-PORT,80))),Fast",@"RULE-SET,Rules,Fast,no-resolve",@"SUB-RULE,(NETWORK,TCP),Nested",@"MATCH,DIRECT"],@"sub-rules":@{@"Nested":@[@"PROCESS-NAME,Example,Fast"]}};
    assert([check(source,NO)[@"valid"] boolValue]);
    NSDictionary *wg=[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:@"tests/fixtures/wg-peers-ipv6-only.json"] options:0 error:NULL];
    assert(wg&&[check(@{@"proxies":@[wg],@"rules":@[@"MATCH,DIRECT"]},NO)[@"valid"] boolValue]);
    NSMutableDictionary *prepared=[source mutableCopy]; prepared[@"_rule-provider-payloads"]=@{@"Rules":@{@"behavior":@"domain",@"payload":@[@"+.blocked.test"]}};
    assert([check(prepared,YES)[@"valid"] boolValue]);
    assert(![check(prepared,NO)[@"valid"] boolValue]); assert(issue(check(prepared,NO),@"RESERVED_FIELD"));
    NSDictionary *cycle=@{@"proxies":@[@{@"name":@"A",@"type":@"http",@"server":@"127.0.0.1",@"port":@19090,@"dialer-proxy":@"G"}],@"proxy-groups":@[@{@"name":@"G",@"type":@"select",@"proxies":@[@"A"]}],@"rules":@[@"MATCH,G"]};
    assert(issue(check(cycle,NO),@"GROUP_CYCLE"));
    NSDictionary *hy2=@{@"name":@"H",@"type":@"hy2",@"server":@"127.0.0.1",@"port":@443,@"password":@"test"};
    assert(issue(check(@{@"proxies":@[node(@"A"),hy2],@"proxy-groups":@[@{@"name":@"G",@"type":@"relay",@"proxies":@[@"A",@"H"]}],@"rules":@[@"MATCH,G"]},NO),@"CHAIN_PROTOCOL_UNAVAILABLE"));
    NSDictionary *physical=@{@"name":@"TLS",@"type":@"anytls",@"server":@"127.0.0.1",@"port":@443,@"password":@"test"};
    assert(issue(check(@{@"proxies":@[node(@"A"),physical],@"proxy-groups":@[@{@"name":@"G",@"type":@"relay",@"proxies":@[@"A",@"TLS"]}],@"rules":@[@"MATCH,G"]},NO),@"CHAIN_PROTOCOL_UNAVAILABLE"));
    assert(issue(check(@{@"rules":@[@"SUB-RULE,(NETWORK,TCP),A"],@"sub-rules":@{@"A":@[@"SUB-RULE,(NETWORK,TCP),B"],@"B":@[@"SUB-RULE,(NETWORK,TCP),A"]}},NO),@"SUB_RULE_CYCLE"));
    NSMutableDictionary *subrules=[NSMutableDictionary dictionary];
    for (NSUInteger i=0;i<34;++i) {
        NSString *name=[NSString stringWithFormat:@"S%02lu",(unsigned long)i];
        subrules[name]=i==33 ? @[@"MATCH,DIRECT"] : @[[NSString stringWithFormat:@"SUB-RULE,(NETWORK,TCP),S%02lu",(unsigned long)i+1]];
    }
    assert(issue(check(@{@"rules":@[@"SUB-RULE,(NETWORK,TCP),S00"],@"sub-rules":subrules},NO),@"SUB_RULE_CYCLE"));
    [subrules removeObjectForKey:@"S00"]; subrules[@"S01"]=@[@"MATCH,DIRECT"];
    assert([check(@{@"rules":@[@"SUB-RULE,(NETWORK,TCP),S01"],@"sub-rules":subrules},NO)[@"valid"] boolValue]);
    assert(issue(check(@{@"rules":@[@"GEOIP,CN,DIRECT"]},NO),@"RULE_DATABASE_PENDING"));
    assert([check(@{@"rules":@[@"IP-ASN,AS4294967295,DIRECT"]},NO)[@"valid"] boolValue]);
    assert(![check(@{@"rules":@[@"IP-ASN,4294967296,DIRECT"]},NO)[@"valid"] boolValue]);
    assert(issue(check(@{@"rules":@[@"GEOIP,CN,DIRECT"]},YES),@"RULE_DATABASE_UNAVAILABLE"));
    assert([check(@{@"rules":@[@"GEOIP,CN,DIRECT"],@"_geoip":@{@"CN":@[@"192.0.2.0/24"]}},YES)[@"valid"] boolValue]);
    assert(![check(@{@"proxy-providers":@{@"R":@{@"type":@"http",@"url":@"https://example.test/",@"headers":@{@"X-Key":@"x"}}}},NO)[@"valid"] boolValue]);
    assert([check(@{@"rule-providers":@{@"R":@{@"type":@"http",@"url":@"https://example.test/rules.yaml",@"path":@"./ruleset/rules.yaml",@"behavior":@"domain"}}},NO)[@"valid"] boolValue]);
    for(NSString *path in @[@"./../rules.yaml",@"./ruleset//rules.yaml",@"./ruleset/./rules.yaml",@"/rules.yaml"])
        assert(issue(check(@{@"rule-providers":@{@"R":@{@"type":@"file",@"path":path,@"behavior":@"domain"}}},NO),@"PROVIDER_PATH"));
    for (id value in @[[NSNull null],@[],@{},@1,@"invalid"]) {
        check(@{@"proxy-groups":@[@{@"name":@"G",@"type":@"url-test",@"proxies":@[@"DIRECT"],@"include-all":value,@"url":value,@"expected-status":value}]},NO);
        check(@{@"proxy-providers":@{@"R":@{@"type":value,@"url":value,@"health-check":value,@"override":value}}},NO);
        check(@{@"rules":@[value],@"sub-rules":value},NO);
    }
    puts("PASS policy/Provider validation, reserved fields, chain cycles and malformed types");
} return 0; }
