#import "MLPolicyScheduler.h"
#import "MLRouting.h"
#include <dispatch/dispatch.h>
#include <math.h>

static NSArray *MLPolicyArray(id value) { return [value isKindOfClass:[NSArray class]] ? value : @[]; }
static BOOL MLPolicyURL(NSString *text) {
    if (![text isKindOfClass:[NSString class]] || text.length > 1024 ||
        [text rangeOfCharacterFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].location != NSNotFound ||
        [text rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location != NSNotFound) return NO;
    NSURL *url = [NSURL URLWithString:text];
    return [@[@"http",@"https"] containsObject:url.scheme.lowercaseString] && url.host.length &&
        !url.user && !url.password && !url.fragment && (!url.port || (url.port.integerValue > 0 && url.port.integerValue <= 65535));
}
static double MLPolicyNow(void) { return [NSProcessInfo processInfo].systemUptime; }

@implementation MLPolicyScheduler {
    MLPolicyHealthProbe _probe;
    NSDictionary *_document, *_nodes, *_groups, *_jobs, *_selections;
    NSMutableDictionary *_measurements, *_lastRun, *_used, *_counters;
    NSMutableSet *_pending;
    NSMutableArray *_manualQueue;
    NSUInteger _generation, _inFlight;
}
- (id)initWithProbe:(MLPolicyHealthProbe)probe {
    if ((self = [super init])) {
        _probe = [probe copy];
        _measurements = [NSMutableDictionary dictionary];
        _lastRun = [NSMutableDictionary dictionary];
        _used = [NSMutableDictionary dictionary];
        _counters = [NSMutableDictionary dictionary];
        _pending = [NSMutableSet set];
        _manualQueue = [NSMutableArray array];
        _selections=@{};
    }
    return self;
}
- (void)collect:(NSString *)target groups:(NSDictionary *)groups nodes:(NSDictionary *)nodes
         names:(NSMutableOrderedSet *)names depth:(NSUInteger)depth {
    if (depth > 32 || names.count >= 1024 || [target isEqual:@"REJECT"]) return;
    if (nodes[target] || [target isEqual:@"DIRECT"]) { [names addObject:target]; return; }
    if (groups[target]) [names addObject:target];
}
- (void)replaceDocument:(NSDictionary *)document {
    @synchronized(self) {
        ++_generation;
        _document = [document copy];
        NSMutableDictionary *nodes = [NSMutableDictionary dictionary], *groups = [NSMutableDictionary dictionary];
        for (NSDictionary *node in MLPolicyArray(document[@"proxies"])) if ([node isKindOfClass:[NSDictionary class]] && node[@"name"]) nodes[node[@"name"]] = node;
        for (NSDictionary *group in MLPolicyArray(document[@"proxy-groups"])) if ([group isKindOfClass:[NSDictionary class]] && group[@"name"]) groups[group[@"name"]] = group;
        _nodes = [nodes copy];
        _groups=[groups copy]; _selections=@{};
        NSMutableDictionary *jobs = [NSMutableDictionary dictionary];
        NSMutableArray *checks = [NSMutableArray array];
        for (NSDictionary *group in groups.allValues) {
            if (![@[@"url-test",@"fallback",@"load-balance"] containsObject:group[@"type"]]) continue;
            NSMutableOrderedSet *names = [NSMutableOrderedSet orderedSet];
            for (NSString *member in MLPolicyArray(group[@"proxies"])) [self collect:member groups:groups nodes:nodes names:names depth:0];
            [checks addObject:@{@"name":group[@"name"],@"nodes":names.array,
                               @"url":group[@"url"] ?: @"http://www.gstatic.com/generate_204",
                               @"interval":group[@"interval"] ?: @300,@"timeout":group[@"timeout"] ?: @5000,
                               @"lazy":group[@"lazy"] ?: @YES}];
        }
        [checks addObjectsFromArray:MLPolicyArray(document[@"_provider-health-checks"])];
        for (NSDictionary *check in checks) {
            NSString *url = check[@"url"], *owner = check[@"name"];
            if (!MLPolicyURL(url) || ![owner isKindOfClass:[NSString class]]) continue;
            double interval = MAX(1,MIN(86400,[check[@"interval"] doubleValue] ?: 300));
            NSUInteger timeout = MAX(100,MIN(30000,[check[@"timeout"] unsignedIntegerValue] ?: 5000));
            for (NSString *name in MLPolicyArray(check[@"nodes"])) {
                if (!nodes[name] && !groups[name] && ![name isEqual:@"DIRECT"]) continue;
                NSString *key = MLPolicyMeasurementKey(name,url);
                NSMutableDictionary *job = jobs[key];
                if (!job) {
                    job = [@{@"name":name,@"url":url,@"interval":@(interval),@"timeout":@(timeout),@"owners":[NSMutableDictionary dictionary]} mutableCopy];
                    jobs[key] = job;
                }
                job[@"interval"] = @(MIN(interval,[job[@"interval"] doubleValue]));
                job[@"timeout"] = @(MIN(timeout,[job[@"timeout"] unsignedIntegerValue]));
                job[@"owners"][owner] = check[@"lazy"] ?: @YES;
            }
        }
        _jobs = [jobs copy];
        [_lastRun removeAllObjects]; [_measurements removeAllObjects]; [_used removeAllObjects];
        [_pending removeAllObjects]; [_manualQueue removeAllObjects]; _counters = [NSMutableDictionary dictionary];
    }
    [self tick];
}
- (void)replaceSelections:(NSDictionary *)selections {
    @synchronized(self) {
        NSDictionary *next=[selections isKindOfClass:[NSDictionary class]] ? [selections copy] : @{};
        if ([_selections isEqual:next]) return;
        _selections=next; ++_generation; [_pending removeAllObjects]; [_manualQueue removeAllObjects]; [_lastRun removeAllObjects];
        for (NSString *key in [_measurements.allKeys copy]) {
            NSString *name=_measurements[key][@"name"];
            if (_groups[name] || _nodes[name][@"dialer-proxy"]) [_measurements removeObjectForKey:key];
        }
    }
}
- (void)enqueue:(NSDictionary *)job key:(NSString *)key {
    if (!_probe || _inFlight >= 3 || [_pending containsObject:key]) return;
    NSArray *chain=MLPolicyChain(_document,job[@"name"],_selections,[self snapshot]);
    NSDictionary *node = _nodes[job[@"name"]];
    if (chain.count>1 || _groups[job[@"name"]]) {
        NSMutableArray *stages=[NSMutableArray array];
        for (NSString *name in chain) [stages addObject:_nodes[name] ?: @{@"name":name,@"type":[name lowercaseString]}];
        node=@{@"name":job[@"name"],@"_muyu-probe-chain":[stages copy]};
    }
    NSUInteger generation = _generation;
    MLPolicyHealthProbe probe = _probe;
    _lastRun[key] = @(MLPolicyNow());
    [_pending addObject:key]; ++_inFlight;
    NSMutableDictionary *retained = [_measurements[key] mutableCopy] ?: [NSMutableDictionary dictionary];
    if (!retained[@"health"]) retained[@"health"] = @"unknown";
    retained[@"testing"] = @YES; retained[@"name"] = job[@"name"]; retained[@"url"] = job[@"url"];
    retained[@"testingStartedAt"]=@(MLPolicyNow());
    _measurements[key] = [retained copy];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW,0),^{ @autoreleasepool {
        NSDictionary *answer = [chain containsObject:@"REJECT"] ? @{@"health":@"failed"} : probe(node,job[@"url"],[job[@"timeout"] unsignedIntegerValue]);
        NSString *health = [answer[@"health"] isKindOfClass:[NSString class]] ? answer[@"health"] : @"failed";
        if (![@[@"healthy",@"failed",@"timeout",@"invalid"] containsObject:health]) health = @"failed";
        NSMutableDictionary *result = [@{@"health":health,@"name":job[@"name"],@"url":job[@"url"],@"chain":chain,@"checkedAt":@([[NSDate date] timeIntervalSince1970])} mutableCopy];
        double delay = [answer[@"delay"] isKindOfClass:[NSNumber class]] ? [answer[@"delay"] doubleValue] : NAN;
        NSUInteger status = [answer[@"status"] isKindOfClass:[NSNumber class]] ? [answer[@"status"] unsignedIntegerValue] : 0;
        if (status >= 100 && status <= 599) result[@"status"] = @(status);
        if (([health isEqual:@"healthy"] || result[@"status"]) && isfinite(delay) && delay >= 0 && delay <= 30000) result[@"delay"] = @(delay);
        else if ([health isEqual:@"healthy"]) result[@"health"] = @"failed";
        @synchronized(self) {
            --self->_inFlight;
            if (generation == self->_generation && [chain isEqual:MLPolicyChain(self->_document,job[@"name"],self->_selections,[self snapshot])]) {
                [self->_pending removeObject:key];
                self->_measurements[key] = [result copy];
            } else if (generation==self->_generation) {
                [self->_pending removeObject:key]; [self->_lastRun removeObjectForKey:key];
            }
        }
    }});
}
- (void)tick {
    @synchronized(self) {
        double now = MLPolicyNow();
        while (_manualQueue.count && _inFlight < 3) {
            NSDictionary *job = _manualQueue[0]; [_manualQueue removeObjectAtIndex:0];
            [self enqueue:job key:MLPolicyMeasurementKey(job[@"name"],job[@"url"])];
        }
        // Stable order prevents a large provider from starving the first groups.
        NSArray *keys = [_jobs.allKeys sortedArrayUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
            double left = [self->_lastRun[a] doubleValue], right = [self->_lastRun[b] doubleValue];
            return left < right ? NSOrderedAscending : (left > right ? NSOrderedDescending : [a compare:b]);
        }];
        for (NSString *key in keys) {
            if (_inFlight >= 3) break;
            NSDictionary *job = _jobs[key]; double previous = [_lastRun[key] doubleValue];
            if (previous && now - previous < [job[@"interval"] doubleValue]) continue;
            BOOL demand = NO;
            for (NSString *owner in job[@"owners"]) {
                if (![job[@"owners"][owner] boolValue] || [_used[owner] doubleValue] > previous) { demand = YES; break; }
            }
            if (demand) [self enqueue:job key:key];
        }
    }
}
- (void)stop {
    @synchronized(self) {
        ++_generation; _document = nil; _jobs = nil; _nodes = nil; _groups=nil; _selections=@{};
        [_pending removeAllObjects]; [_manualQueue removeAllObjects];
        [_measurements removeAllObjects]; [_lastRun removeAllObjects]; [_used removeAllObjects];
        _counters=[NSMutableDictionary dictionary];
    }
}
- (NSDictionary *)snapshot {
    NSMutableDictionary *snapshot = [_measurements mutableCopy], *choices = [NSMutableDictionary dictionary];
    @synchronized(_counters) {
        for (NSString *key in _counters) if ([key hasPrefix:@"@choice."]) choices[[key substringFromIndex:8]] = _counters[key];
    }
    snapshot[@"_choices"] = [choices copy];
    return [snapshot copy];
}
- (NSDictionary *)measurements { @synchronized(self) { return [self snapshot]; } }
- (NSDictionary *)nodesMeasurements {
    @synchronized(self) {
        NSMutableDictionary *latest=[NSMutableDictionary dictionary];
        for (NSString *key in [_measurements.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
            NSDictionary *value=_measurements[key]; NSString *name=value[@"name"];
            if (!name) continue;
            BOOL testing=[value[@"testing"] boolValue], previousTesting=[latest[name][@"testing"] boolValue];
            BOOL newer=testing ? (!previousTesting || [value[@"testingStartedAt"] doubleValue]>=[latest[name][@"testingStartedAt"] doubleValue]) : (!previousTesting && [value[@"checkedAt"] doubleValue]>=[latest[name][@"checkedAt"] doubleValue]);
            if (name && (!latest[name] || newer)) {
                NSMutableDictionary *observed=[value mutableCopy];
                if (testing) { observed[@"previousHealth"]=value[@"health"] ?: @"unknown"; observed[@"health"]=@"testing"; }
                latest[name]=[observed copy];
            }
        }
        return [latest copy];
    }
}
- (NSDictionary *)routeMode:(NSString *)mode selections:(NSDictionary *)selections metadata:(NSDictionary *)metadata resolveIP:(NSString *(^)(void))resolveIP {
    [self replaceSelections:selections];
    NSDictionary *document, *measurements;
    NSMutableDictionary *counters;
    @synchronized(self) { document = _document; measurements = [self snapshot]; counters = _counters; }
    NSDictionary *route = MLRouteWithRuntime(document,mode,selections,measurements,counters,metadata,resolveIP);
    @synchronized(self) {
        if (_document == document) {
            NSNumber *now=@(MLPolicyNow());
            for (NSString *name in MLPolicyArray(route[@"groups"])) _used[name] = now;
            for (NSDictionary *job in _jobs.allValues) if ([MLPolicyArray(route[@"chain"]) containsObject:job[@"name"]])
                for (NSString *owner in job[@"owners"]) if ([owner hasPrefix:@"provider:"]) _used[owner]=now;
        }
    }
    [self tick];
    return route;
}
- (NSArray *)groupsWithSelections:(NSDictionary *)selections {
    @synchronized(self) { return MLGroupsWithRuntime(_document,selections,[self snapshot]); }
}
- (NSDictionary *)routeTarget:(NSString *)target selections:(NSDictionary *)selections metadata:(NSDictionary *)metadata {
    [self replaceSelections:selections]; NSDictionary *document, *measurements; NSMutableDictionary *counters;
    @synchronized(self) { document=_document; measurements=[self snapshot]; counters=_counters; }
    NSDictionary *route=MLRouteTargetWithRuntime(document,target,selections,measurements,counters,metadata);
    @synchronized(self) { if (_document==document) {
        NSNumber *now=@(MLPolicyNow()); for (NSString *name in MLPolicyArray(route[@"groups"])) _used[name]=now;
        for (NSDictionary *job in _jobs.allValues) if ([MLPolicyArray(route[@"chain"]) containsObject:job[@"name"]]) for (NSString *owner in job[@"owners"]) if ([owner hasPrefix:@"provider:"]) _used[owner]=now;
    } }
    [self tick]; return route;
}
- (NSArray *)proxiesWithSelections:(NSDictionary *)selections group:(NSString *)group {
    @synchronized(self) { return MLProxiesWithRuntime(_document,selections,[self snapshot],group); }
}
- (BOOL)requestProbeNames:(NSArray *)names url:(NSString *)url timeout:(NSUInteger)timeout {
    if (!MLPolicyURL(url) || names.count == 0 || names.count > 24 || timeout < 100 || timeout > 30000) return NO;
    @synchronized(self) {
        for (NSString *name in names) if (!_nodes[name] && !_groups[name] && ![name isEqual:@"DIRECT"]) return NO;
        if (_manualQueue.count) return NO;
        NSOrderedSet *unique=[NSOrderedSet orderedSetWithArray:names]; NSMutableSet *requested=[NSMutableSet set];
        for (NSString *name in unique) [requested addObject:MLPolicyMeasurementKey(name,url)];
        NSUInteger added=0; for (NSString *key in requested) if (!_measurements[key]) ++added;
        NSArray *oldest=[_measurements.allKeys sortedArrayUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
            double left=[self->_measurements[a][@"checkedAt"] doubleValue], right=[self->_measurements[b][@"checkedAt"] doubleValue];
            return left<right ? NSOrderedAscending : (left>right ? NSOrderedDescending : [a compare:b]);
        }];
        for (NSString *key in oldest) {
            if (_measurements.count+added<=4096) break;
            if (!_jobs[key] && ![_pending containsObject:key] && ![requested containsObject:key]) [_measurements removeObjectForKey:key];
        }
        if (_measurements.count+added>4096) return NO;
        for (NSString *name in unique) {
            NSString *key = MLPolicyMeasurementKey(name,url);
            if (![_pending containsObject:key]) [_manualQueue addObject:@{@"name":name,@"url":url,@"timeout":@(timeout)}];
        }
    }
    [self tick]; return YES;
}
@end
