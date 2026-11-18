// Focused status regression; no sockets or real network probes are opened.
#define main MLCoreProgramMain
#import "../core/main.m"
#undef main
#include <assert.h>

@interface MLHomeStatusScheduler : MLPolicyScheduler
@property(nonatomic,strong) NSDictionary *observations;
@property(nonatomic) NSUInteger probeCount;
@end
@implementation MLHomeStatusScheduler
- (NSDictionary *)nodesMeasurements { return self.observations ?: @{}; }
- (BOOL)requestProbeNames:(NSArray *)names url:(NSString *)url timeout:(NSUInteger)timeout {
    assert(names.count==1);self.probeCount++;return YES;
}
@end
@interface MLHomeStatusBridge : NSObject
@property(nonatomic,strong) NSDictionary *lastConnection;
@end
@implementation MLHomeStatusBridge
- (NSDictionary *)statistics { return @{}; }
- (NSArray *)connections { return @[]; }
@end
static NSDictionary *Summary(MLCore *core) { return [core command:@"statistics" params:@{}][@"outbound"]; }
int main(void) { @autoreleasepool {
    NSDictionary *document=@{@"proxies":@[@{@"name":@"A",@"type":@"socks5"},@{@"name":@"B",@"type":@"http"}],
        @"proxy-groups":@[@{@"name":@"Outer",@"type":@"select",@"proxies":@[@"Inner"]},@{@"name":@"Inner",@"type":@"select",@"proxies":@[@"A",@"B"]}],
        @"rules":@[@"DOMAIN,special.test,DIRECT",@"MATCH,Outer"]};
    MLHomeStatusScheduler *scheduler=[[MLHomeStatusScheduler alloc]initWithProbe:nil];
    [scheduler replaceDocument:document];
    MLCore *core=[MLCore new];core.configuration=document;core.nodes=@{@"A":@{@"type":@"socks5"},@"B":@{@"type":@"http"}};
    core.scheduler=scheduler;core.selections=[NSMutableDictionary dictionary];core.flows=[NSMutableDictionary dictionary];
    core.mode=@"Rule";core.routingToken=@"first";core.started=core.sampleAt=MLMilliseconds();
    NSDictionary *summary=Summary(core);
    assert([summary[@"group"] isEqual:@"Outer"] && [summary[@"actual"] isEqual:@"A"]);
    assert([summary[@"protocol"] isEqual:@"socks5"] && [summary[@"source"] isEqual:@"default"]);
    assert(!summary[@"latency"] && [summary[@"latencyState"] isEqual:@"testing"]);
    Summary(core);assert(scheduler.probeCount==1); // Polling must not repeat the probe.
    scheduler.observations=@{@"Outer":@{@"health":@"healthy",@"delay":@37,@"checkedAt":@([[NSDate date]timeIntervalSince1970]),@"chain":@[@"A"]}};
    assert([Summary(core)[@"latency"] isEqual:@37]);
    MLHomeStatusBridge *bridge=[MLHomeStatusBridge new];core.bridge=(id)bridge;
    bridge.lastConnection=@{@"routingToken":@"first",@"actual":@"B",@"group":@"Outer",@"protocol":@"http",@"startedAt":@1};
    summary=Summary(core);assert([summary[@"actual"] isEqual:@"B"] && [summary[@"source"] isEqual:@"recent"]);
    assert(!summary[@"latency"]); // A's sample must never be attached to B.
    assert(!core.flows.count && !bridge.connections.count); // Short connection already closed.
    assert(([core command:@"select" params:@{@"group":@"Inner",@"proxy":@"B"}]));
    summary=Summary(core);assert([summary[@"source"] isEqual:@"default"] && [summary[@"actual"] isEqual:@"B"]);
    assert([summary[@"protocol"] isEqual:@"http"]);
    [core command:@"mode" params:@{@"mode":@"Direct"}];
    summary=Summary(core);assert([summary[@"actual"] isEqual:@"DIRECT"] && [summary[@"latencyState"] isEqual:@"not-applicable"]);
    assert(!summary[@"latency"]);
    NSMutableDictionary *round=[document mutableCopy];round[@"proxy-groups"]=@[@{@"name":@"Round",@"type":@"load-balance",@"strategy":@"round-robin",@"proxies":@[@"A",@"B"]}];round[@"rules"]=@[@"MATCH,Round"];
    NSDictionary *first=MLDefaultRouteWithRuntime(round,@"Rule",nil,nil);
    assert([first isEqual:MLDefaultRouteWithRuntime(round,@"Rule",nil,nil)]);
    assert([MLDefaultRouteWithRuntime(round,@"Direct",nil,nil)[@"node"] isEqual:@"DIRECT"]);
    [scheduler stop];puts("PASS home status: idle/nested path, retained short flow, selection/mode invalidation, true latency, bounded probes");
}return 0;}
