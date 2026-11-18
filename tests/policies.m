#import <Foundation/Foundation.h>
#import "../routing/MLRouting.h"
#import "../routing/MLPolicyScheduler.h"
#import "../routing/MLPublicSuffix.h"
#include <assert.h>
#include <dispatch/dispatch.h>
#include <unistd.h>

static NSDictionary *node(NSString *name) { return @{@"name":name,@"type":@"http",@"server":@"127.0.0.1",@"port":@19090}; }
static NSDictionary *group(NSString *name, NSString *type, NSArray *members, NSDictionary *extra) {
    NSMutableDictionary *g=[@{@"name":name,@"type":type,@"proxies":members,@"url":@"http://health.test/"} mutableCopy];
    [g addEntriesFromDictionary:extra ?: @{}]; return [g copy];
}
static NSDictionary *metadata(NSString *host) { return @{@"host":host,@"destPort":@443,@"network":@"TCP",@"source":@"192.0.2.1",@"sourcePort":@1234}; }
static NSDictionary *route(NSDictionary *document, NSString *name, NSDictionary *measurements, NSMutableDictionary *counters) {
    NSMutableDictionary *d=[document mutableCopy]; d[@"rules"]=@[[NSString stringWithFormat:@"MATCH,%@",name]];
    return MLRouteWithRuntime(d,@"Rule",nil,measurements,counters,metadata(@"www.example.co.uk"),nil);
}
int main(void) { @autoreleasepool {
    NSArray *nodes=@[node(@"A"),node(@"B"),node(@"C")];
    NSDictionary *document=@{@"proxies":nodes,@"proxy-groups":@[
        group(@"Fast",@"url-test",@[@"A",@"B",@"C"],@{@"tolerance":@50}),
        group(@"Ordered",@"fallback",@[@"A",@"B",@"C"],nil),
        group(@"Round",@"load-balance",@[@"A",@"B",@"C"],@{@"strategy":@"round-robin"}),
        group(@"Hash",@"load-balance",@[@"A",@"B",@"C"],nil),
        group(@"Relay",@"relay",@[@"A",@"B"],nil)]};
    NSMutableDictionary *measurements=[NSMutableDictionary dictionary];
    measurements[MLPolicyMeasurementKey(@"A",@"http://health.test/")]=@{@"health":@"healthy",@"delay":@40};
    measurements[MLPolicyMeasurementKey(@"B",@"http://health.test/")]=@{@"health":@"healthy",@"delay":@10};
    measurements[MLPolicyMeasurementKey(@"C",@"http://health.test/")]=@{@"health":@"timeout"};
    NSMutableDictionary *counters=[NSMutableDictionary dictionary];
    assert([route(document,@"Fast",measurements,counters)[@"node"] isEqual:@"B"]);
    counters[@"@choice.Fast"]=@"A";
    assert([route(document,@"Fast",measurements,counters)[@"node"] isEqual:@"A"]);
    assert([route(document,@"Ordered",measurements,counters)[@"node"] isEqual:@"A"]);
    assert([route(document,@"Round",measurements,counters)[@"node"] isEqual:@"A"]);
    assert([route(document,@"Round",measurements,counters)[@"node"] isEqual:@"B"]);
    assert([route(document,@"Round",measurements,counters)[@"node"] isEqual:@"A"]);
    measurements[MLPolicyMeasurementKey(@"A",@"http://health.test/")]=@{@"health":@"failed"};
    assert([route(document,@"Ordered",measurements,counters)[@"node"] isEqual:@"B"]);
    NSDictionary *relay=route(document,@"Relay",measurements,counters);
    assert(([relay[@"chain"] isEqual:@[@"A",@"B"]]));
    assert([MLEffectiveDomain(@"www.example.co.uk") isEqual:@"example.co.uk"]);
    assert([MLEffectiveDomain(@"www.city.kawasaki.jp") isEqual:@"city.kawasaki.jp"]);
    assert([MLEffectiveDomain(@"foo.blogspot.com") isEqual:@"foo.blogspot.com"]);
    assert([MLEffectiveDomain(@"www.xn--85x722f.xn--55qx5d.cn") isEqual:@"xn--85x722f.xn--55qx5d.cn"]);
    NSDictionary *directRelay=@{@"proxies":nodes,@"proxy-groups":@[group(@"TailDirect",@"relay",@[@"A",@"DIRECT"],nil)]};
    assert([MLGroupsWithRuntime(directRelay,nil,nil)[0][@"actual"] isEqual:@"A"]);
    NSMutableArray *hops=[NSMutableArray array]; for (NSUInteger i=0;i<16;++i) [hops addObject:@"A"];
    NSDictionary *longRelay=@{@"proxies":nodes,@"proxy-groups":@[group(@"Long",@"relay",hops,nil)]};
    assert([route(longRelay,@"Long",nil,nil)[@"chain"] count]==16);
    [hops addObject:@"A"]; longRelay=@{@"proxies":nodes,@"proxy-groups":@[group(@"Long",@"relay",[hops copy],nil)]};
    assert([route(longRelay,@"Long",nil,nil)[@"node"] isEqual:@"REJECT"]);
    NSDictionary *statusGroups=@{@"proxies":nodes,@"proxy-groups":@[group(@"AnyStatus",@"url-test",@[@"A",@"B"],nil),group(@"StrictStatus",@"url-test",@[@"A",@"B"],@{@"expected-status":@"200-299/404"})]};
    NSDictionary *statusMeasurements=@{MLPolicyMeasurementKey(@"A",@"http://health.test/"):@{@"health":@"healthy",@"status":@503,@"delay":@3},MLPolicyMeasurementKey(@"B",@"http://health.test/"):@{@"health":@"healthy",@"status":@204,@"delay":@9}};
    assert([route(statusGroups,@"AnyStatus",statusMeasurements,nil)[@"node"] isEqual:@"A"]);
    assert([route(statusGroups,@"StrictStatus",statusMeasurements,nil)[@"node"] isEqual:@"B"]);
    NSMutableDictionary *hash=[document mutableCopy]; hash[@"rules"]=@[@"MATCH,Hash"];
    NSString *first=MLRouteWithRuntime(hash,@"Rule",nil,measurements,counters,metadata(@"www.example.co.uk"),nil)[@"node"];
    NSString *second=MLRouteWithRuntime(hash,@"Rule",nil,measurements,counters,metadata(@"api.example.co.uk"),nil)[@"node"];
    assert([first isEqual:second]);

    NSDictionary *rules=@{@"rules":@[@"AND,((DOMAIN,a.test),(NOT,(DST-PORT,80))),REJECT",@"RULE-SET,Domains,REJECT",@"SUB-RULE,(NETWORK,TCP),Nested",@"MATCH,DIRECT"],
        @"_rule-provider-payloads":@{@"Domains":@{@"behavior":@"domain",@"payload":@[@"+.blocked.test"]}},
        @"sub-rules":@{@"Nested":@[@"PROCESS-NAME,Example,REJECT",@"DOMAIN,inside.test,REJECT"]}};
    assert([MLRouteWithRuntime(rules,@"Rule",nil,nil,nil,metadata(@"a.test"),nil)[@"node"] isEqual:@"REJECT"]);
    assert([MLRouteWithRuntime(rules,@"Rule",nil,nil,nil,metadata(@"x.blocked.test"),nil)[@"rule"] isEqual:@"RULE-SET,Domains,REJECT"]);
    assert([MLRouteWithRuntime(rules,@"Rule",nil,nil,nil,metadata(@"inside.test"),nil)[@"rule"] isEqual:@"DOMAIN,inside.test,REJECT"]);
    assert([MLRouteWithRuntime(rules,@"Rule",nil,nil,nil,metadata(@"unknown.test"),nil)[@"node"] isEqual:@"DIRECT"]);
    NSMutableDictionary *process=[metadata(@"unknown.test") mutableCopy]; process[@"processName"]=@"Example";
    assert([MLRouteWithRuntime(rules,@"Rule",nil,nil,nil,process,nil)[@"node"] isEqual:@"REJECT"]);
    __block NSUInteger lookups=0;
    NSDictionary *noResolve=@{@"rules":@[@"RULE-SET,IPs,REJECT,no-resolve",@"GEOIP,LAN,REJECT,no-resolve",@"IP-ASN,64500,REJECT,no-resolve",@"AND,((IP-CIDR,192.0.2.0/24),(NETWORK,TCP)),REJECT,no-resolve",@"SUB-RULE,(NETWORK,TCP),Nested,no-resolve",@"MATCH,DIRECT"],
        @"_rule-provider-payloads":@{@"IPs":@{@"behavior":@"ipcidr",@"payload":@[@"192.0.2.0/24"]}},@"_ip-asn":@{@"64500":@[@"192.0.2.0/24"]},@"sub-rules":@{@"Nested":@[@"IP-CIDR,192.0.2.0/24,REJECT"]}};
    assert([MLRouteWithRuntime(noResolve,@"Rule",nil,nil,nil,metadata(@"no-lookup.test"),^NSString *{ ++lookups; return @"192.0.2.1"; })[@"node"] isEqual:@"DIRECT"]);
    assert(lookups==0);
    NSMutableDictionary *asn=[metadata(@"asn.test") mutableCopy]; asn[@"asn"]=@4294967295u;
    assert([MLRouteWithRuntime(@{@"rules":@[@"IP-ASN,AS4294967295,REJECT",@"MATCH,DIRECT"]},@"Rule",nil,nil,nil,asn,nil)[@"node"] isEqual:@"REJECT"]);

    dispatch_semaphore_t gate=dispatch_semaphore_create(0);
    __block NSUInteger running=0, maximum=0, completed=0;
    NSObject *lock=[[NSObject alloc] init];
    MLPolicyScheduler *scheduler=[[MLPolicyScheduler alloc] initWithProbe:^NSDictionary *(NSDictionary *node, NSString *url, NSUInteger timeout) {
        (void)node; (void)url; (void)timeout;
        @synchronized(lock) { ++running; maximum=MAX(maximum,running); }
        dispatch_semaphore_wait(gate,dispatch_time(DISPATCH_TIME_NOW,3*NSEC_PER_SEC));
        @synchronized(lock) { --running; ++completed; }
        return @{@"health":@"healthy",@"delay":@7};
    }];
    [scheduler replaceDocument:@{@"proxies":nodes,@"proxy-groups":@[group(@"Test",@"url-test",@[@"A",@"B",@"C"],@{@"lazy":@NO})]}];
    for (NSUInteger i=0;i<100;++i) { usleep(10000); @synchronized(lock) { if (running==3) break; } }
    @synchronized(lock) { assert(running==3); }
    assert([[[scheduler nodesMeasurements][@"A"] objectForKey:@"health"] isEqual:@"testing"]);
    assert([[[scheduler measurements][MLPolicyMeasurementKey(@"A",@"http://health.test/")] objectForKey:@"health"] isEqual:@"unknown"]);
    [scheduler replaceDocument:@{@"proxies":nodes}];
    for (NSUInteger i=0;i<3;++i) dispatch_semaphore_signal(gate);
    for (NSUInteger i=0;i<100;++i) { usleep(10000); @synchronized(lock) { if (completed==3) break; } }
    assert([scheduler measurements].count==1); // Only the empty choice map; no stale result.
    [scheduler requestProbeNames:@[@"A",@"B",@"C"] url:@"http://health.test/" timeout:5000];
    for (NSUInteger i=0;i<3;++i) dispatch_semaphore_signal(gate);
    for (NSUInteger i=0;i<100;++i) { [scheduler tick]; usleep(10000); @synchronized(lock) { if (completed==6) break; } }
    @synchronized(lock) { assert(maximum<=3 && completed==6); }
    assert([[scheduler measurements][MLPolicyMeasurementKey(@"A",@"http://health.test/")][@"health"] isEqual:@"healthy"]);
    assert([[scheduler nodesMeasurements][@"A"][@"health"] isEqual:@"healthy"]);
    NSMutableArray *manyNodes=[NSMutableArray array], *manyNames=[NSMutableArray array];
    for (NSUInteger i=0;i<8;++i) { NSString *name=[NSString stringWithFormat:@"N%lu",(unsigned long)i]; [manyNames addObject:name]; [manyNodes addObject:node(name)]; }
    [scheduler replaceDocument:@{@"proxies":manyNodes}];
    assert([scheduler requestProbeNames:manyNames url:@"http://health.test/" timeout:5000]);
    for (NSUInteger i=0;i<8;++i) dispatch_semaphore_signal(gate);
    for (NSUInteger i=0;i<200;++i) { [scheduler tick]; usleep(10000); @synchronized(lock) { if (completed==14) break; } }
    @synchronized(lock) { assert(maximum<=3 && completed==14); }
    assert([scheduler nodesMeasurements].count==8);
    [scheduler stop];
    assert([scheduler nodesMeasurements].count==0);
    __block NSArray *observedChain=nil;
    MLPolicyScheduler *chained=[[MLPolicyScheduler alloc] initWithProbe:^NSDictionary *(NSDictionary *target, NSString *url, NSUInteger timeout) {
        (void)url; (void)timeout; @synchronized(lock) { observedChain=target[@"_muyu-probe-chain"]; }
        return @{@"health":@"healthy",@"status":@204,@"delay":@8};
    }];
    [chained replaceDocument:@{@"proxies":nodes,@"proxy-groups":@[group(@"Relay",@"relay",@[@"A",@"B"],nil),group(@"Outer",@"url-test",@[@"Relay"],@{@"lazy":@NO})]}];
    for (NSUInteger i=0;i<100;++i) { usleep(10000); if ([chained measurements][MLPolicyMeasurementKey(@"Relay",@"http://health.test/")][@"status"]) break; }
    @synchronized(lock) { assert(observedChain.count==2); assert([observedChain[0][@"name"] isEqual:@"A"]); assert([observedChain[1][@"name"] isEqual:@"B"]); }
    assert(([[chained measurements][MLPolicyMeasurementKey(@"Relay",@"http://health.test/")][@"chain"] isEqual:@[@"A",@"B"]]));
    [chained stop];
    MLPolicyScheduler *explicit=[[MLPolicyScheduler alloc] initWithProbe:nil]; [explicit replaceDocument:document];
    assert([[explicit routeTarget:@"Round" selections:nil metadata:metadata(@"dns.test")][@"node"] isEqual:@"A"]);
    assert([[explicit routeTarget:@"Round" selections:nil metadata:metadata(@"dns.test")][@"node"] isEqual:@"B"]);
    assert([[explicit routeTarget:@"Relay" selections:nil metadata:metadata(@"dns.test")][@"chain"] count]==2);
    assert([[explicit routeTarget:@"Missing" selections:nil metadata:metadata(@"dns.test")][@"node"] isEqual:@"REJECT"]); [explicit stop];
    puts("PASS policies: distinct algorithms, tolerance, chain order, ordered logical/rule-set matching, bounded probes and generation isolation");
} return 0; }
