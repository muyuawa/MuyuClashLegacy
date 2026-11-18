#import <Foundation/Foundation.h>
#import "MLIPC.h"
#import "MLRelay.h"
#import "MLRouting.h"
#import "MLDNS.h"
#import "MLProbe.h"
#import "MLPolicyScheduler.h"
#import "MLPacketBridge.h"
#import "MLCoreDatagram.h"
#import "MLFakeIP.h"
#import "MLDNSOutbound.h"
#import "../transport/MLNetworkBinding.h"
#include <arpa/inet.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

enum { MLMaxFlows = 24 };

@interface MLCore : NSObject
@property(nonatomic,strong) NSDictionary *configuration;
@property(nonatomic,strong) NSDictionary *nodes;
@property(nonatomic,strong) MLDNS *dns;
@property(nonatomic,strong) NSDictionary *prepared;
@property(nonatomic,strong) NSDictionary *preparedNodes;
@property(nonatomic,strong) NSMutableDictionary *selections;
@property(nonatomic,strong) NSMutableDictionary *flows;
@property(nonatomic,strong) NSMutableDictionary *measurements;
@property(nonatomic,strong) MLPolicyScheduler *scheduler;
@property(nonatomic,strong) MLDNS *preparedDNS;
@property(nonatomic,strong) MLFakeIP *fakeIP;
@property(nonatomic,strong) NSMutableArray *fakePools;
@property(nonatomic,strong) MLFakeIP *preparedFakeIP;
@property(nonatomic) BOOL preparedNewFakePool;
@property(nonatomic,copy) NSArray *fakeRanges;
@property(nonatomic,strong) MLPacketBridge *bridge;
@property(nonatomic) int captureFD;
@property(nonatomic,copy) NSString *captureName;
@property(nonatomic,copy) NSString *ownerSocket;
@property(nonatomic,copy) NSString *preparedOwnerSocket;
@property(nonatomic) uid_t ownerUID;
@property(nonatomic) uid_t preparedOwnerUID;
@property(nonatomic) uint16_t listenerPort;
@property(nonatomic) BOOL requiresOwner;
@property(nonatomic,copy) NSString *activeID;
@property(nonatomic,copy) NSString *mode;
@property(nonatomic,copy) NSString *routingToken;
@property(nonatomic,strong) NSDictionary *lastConnection;
@property(nonatomic,strong) NSMutableDictionary *homeProbeTimes;
@property(nonatomic) uint64_t started;
@property(nonatomic) uint64_t upload;
@property(nonatomic) uint64_t download;
@property(nonatomic) uint64_t sampleAt;
@property(nonatomic) uint64_t sampleUpload;
@property(nonatomic) uint64_t sampleDownload;
- (void)serve:(int)client address:(NSString *)source port:(uint16_t)sourcePort;
- (NSDictionary *)command:(NSString *)method params:(NSDictionary *)params;
- (NSDictionary *)packetRoute:(NSString *)destination source:(NSString *)source sourcePort:(uint16_t)sourcePort port:(uint16_t)port network:(NSString *)network;
- (MLDNS *)resolver;
- (NSDictionary *)dnsRouteHost:(NSString *)host ip:(NSString *)ip port:(uint16_t)port network:(NSString *)network group:(NSString *)group;
@end

@implementation MLCore
- (MLDNS *)resolver { @synchronized(self) { return self.dns; } }
- (NSDictionary *)dnsRouteHost:(NSString *)host ip:(NSString *)ip port:(uint16_t)port network:(NSString *)network group:(NSString *)group {
    NSDictionary *document,*nodes,*selections;NSString *mode;MLPolicyScheduler *scheduler;
    @synchronized(self){document=self.configuration;nodes=self.nodes;selections=[self.selections copy];mode=self.mode;scheduler=self.scheduler;}
    if(!document)return nil;
    NSArray *names;
    if(group)names=[scheduler routeTarget:group selections:selections metadata:@{@"host":host,@"ip":ip,@"destPort":@(port),@"network":network}][@"chain"];
    else names=[scheduler routeMode:mode selections:selections metadata:@{@"host":host,@"ip":ip,@"destPort":@(port),@"network":network} resolveIP:nil][@"chain"];
    if(!names.count||[names containsObject:@"REJECT"])return @{@"reject":@YES};
    NSMutableArray *chain=[NSMutableArray array];
    for(NSString *name in names) {
        if([name isEqual:@"DIRECT"]){if(chain.count)[chain addObject:@{@"type":@"direct"}];continue;}
        NSMutableDictionary *node=[nodes[name][@"node"] mutableCopy];if(!node)return nil;
        [node removeObjectForKey:@"dialer-proxy"];[chain addObject:node];
    }
    return @{@"target":ip,@"chain":chain};
}
- (NSDictionary *)processForSource:(NSString *)source port:(uint16_t)sourcePort destination:(NSString *)destination port:(uint16_t)destinationPort network:(NSString *)network {
    NSString *path;BOOL enabled;uint16_t listener;uid_t ownerUID;
    @synchronized(self){path=self.ownerSocket;enabled=self.requiresOwner;listener=self.listenerPort;ownerUID=self.ownerUID;}
    if(!enabled||!path.length)return @{};
    if([source isEqual:@"127.0.0.1"]) {destination=@"127.0.0.1";destinationPort=listener;}
    struct in_addr v4;struct in6_addr v6;
    if(inet_pton(AF_INET,destination.UTF8String,&v4)!=1&&inet_pton(AF_INET6,destination.UTF8String,&v6)!=1)return @{};
    NSDictionary *owner=MLIPCRequestWithOwner(path,ownerUID,@"system.flow-owner",@{@"source":source,@"sourcePort":@(sourcePort),@"destination":destination,@"destinationPort":@(destinationPort),@"network":network},NULL);
    if(![owner[@"verified"] boolValue])return @{@"processOwner":@"unknown"};
    return @{@"processName":owner[@"processName"] ?: @"",@"processPath":owner[@"processPath"] ?: @"",@"processPID":owner[@"pid"] ?: @0,@"processOwner":@"kernel-proc-info"};
}
- (NSDictionary *)packetRoute:(NSString *)destination source:(NSString *)source sourcePort:(uint16_t)sourcePort port:(uint16_t)port network:(NSString *)network {
    NSDictionary *nodes,*selections; BOOL ipv6; NSString *mode,*configID,*routingToken; MLDNS *dns; MLPolicyScheduler *scheduler;
    @synchronized(self) { ipv6=[self.configuration[@"ipv6"] boolValue];nodes=self.nodes;selections=[self.selections copy];mode=self.mode;configID=self.activeID;routingToken=self.routingToken;dns=self.dns;scheduler=self.scheduler; }
    if(!nodes||!dns) return @{@"reject":@YES};
    // The reserved resolver endpoint belongs to the local DNS handler, even
    // when it lies inside the Fake-IP pool and has no hostname mapping.
    if(port==53)return @{@"host":destination,@"metadata":@{@"host":destination,@"source":source ?: @"",@"sourcePort":@(sourcePort),@"destPort":@(port),@"network":network,@"actual":@"DNS",@"group":@"",@"protocol":@"dns",@"rule":@"DNS-HIJACK",@"configID":configID ?: @""}};
    NSString *fake=nil;BOOL fakeRange=NO;NSArray *pools;
    @synchronized(self){pools=[self.fakePools copy];}
    for(MLFakeIP *pool in pools) {if([pool containsAddress:destination])fakeRange=YES;NSString *mapped=[pool hostForAddress:destination];if(mapped){fake=mapped;break;}}
    if(!fake&&fakeRange) return @{@"reject":@YES};
    NSString *host=fake ?: destination;
    struct in_addr v4;struct in6_addr v6;
    BOOL numeric=!fake&&(inet_pton(AF_INET,destination.UTF8String,&v4)==1||inet_pton(AF_INET6,destination.UTF8String,&v6)==1);
    if(!ipv6 && inet_pton(AF_INET6,destination.UTF8String,&v6)==1)return @{@"reject":@YES};
    NSMutableDictionary *metadata=[@{@"host":host,@"source":source ?: @"",@"sourcePort":@(sourcePort),@"destPort":@(port),@"network":network} mutableCopy];
    if(numeric)metadata[@"ip"]=destination;
    [metadata addEntriesFromDictionary:[self processForSource:source port:sourcePort destination:destination port:port network:network]];
    NSDictionary *decision=[scheduler routeMode:mode selections:selections metadata:metadata resolveIP:^NSString *{ return [[dns lookup:host][@"addresses"] firstObject]; }];
    NSString *leaf=decision[@"node"];
    if(!leaf||[leaf isEqual:@"REJECT"])return @{@"reject":@YES};
    NSMutableArray *chain=[NSMutableArray array];
    for(NSString *name in decision[@"chain"]) {
        if([name isEqual:@"DIRECT"]) { if(!chain.count)continue; [chain addObject:@{@"type":@"direct",@"name":@"DIRECT"}]; }
        else { NSMutableDictionary *node=[nodes[name][@"node"] mutableCopy]; if(!node)return @{@"reject":@YES};[node removeObjectForKey:@"dialer-proxy"]; [chain addObject:node]; }
    }
    NSString *target=numeric?destination:host;
    // Direct and packet stream adapters need an actual IP. Fake-IP never leaves the device.
    if([leaf isEqual:@"DIRECT"]||([network isEqual:@"UDP"]&&![nodes[leaf][@"type"] isEqual:@"hysteria2"])) {
        target=decision[@"ip"] ?: (numeric?destination:[[dns lookupDirect:host][@"addresses"] firstObject]);
        if(!target)return @{@"reject":@YES};
    }
    NSMutableDictionary *route=[@{@"host":target} mutableCopy];
    if(chain.count>1) {
        NSData *data=[NSJSONSerialization dataWithJSONObject:chain options:0 error:NULL];
        route[@"chainJSON"]=[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
    } else if(chain.count==1) route[@"nodeJSON"]=nodes[leaf][@"json"];
    [metadata addEntriesFromDictionary:decision];
    metadata[@"actual"]=leaf; metadata[@"configID"]=configID ?: @"";metadata[@"protocol"]=nodes[leaf][@"type"] ?: @"direct";
    metadata[@"routingToken"]=routingToken ?: @"";
    route[@"metadata"]=metadata;
    return route;
}
- (void)serve:(int)client address:(NSString *)source port:(uint16_t)sourcePort {
    MLIPCSetTimeout(client, 5);
    uint16_t targetPort;
    NSString *ip = nil;
    BOOL http = NO;
    NSString *host = MLInboundDestination(client, &targetPort, &ip, &http);
    if (!host) return;
    NSDictionary *route=[self packetRoute:host source:source sourcePort:sourcePort port:targetPort network:@"TCP"];
    NSDictionary *decision=route[@"metadata"];
    NSString *leaf=decision[@"actual"];
    NSString *json=route[@"nodeJSON"], *chain=route[@"chainJSON"];
    if (!route || [route[@"reject"] boolValue]) { MLInboundReply(client,http,2); return; }
    NSString *destination=route[@"host"];
    MLStream *stream=chain?MLStreamOpenChain(chain.UTF8String,destination.UTF8String,targetPort,8000)
                          :MLStreamOpen(json.UTF8String,destination.UTF8String,targetPort,8000);
    NSString *configID=decision[@"configID"];
    if (!stream) { MLInboundReply(client,http, 4); return; }
    if (!MLInboundReply(client,http, 0)) { MLStreamClose(stream); return; }

    NSString *identifier = [[NSProcessInfo processInfo] globallyUniqueString];
    NSMutableDictionary *flow = [@{
        @"id":identifier, @"fd":@(client), @"remoteFD":@(MLStreamFD(stream)), @"source":source, @"sourcePort":@(sourcePort),
        @"target":host, @"host":host, @"targetPort":@(targetPort),
        @"destination":[NSString stringWithFormat:@"%@:%u",host,(unsigned)targetPort], @"actual":leaf,
        @"network":@"TCP", @"rule":decision[@"rule"] ?: @"", @"node":leaf, @"proxy":leaf,
        @"group":decision[@"group"] ?: @"", @"configID":configID ?: @"",
        @"protocol":decision[@"protocol"] ?: @"direct",
        @"routingToken":decision[@"routingToken"] ?: @"",
        @"uploadBytes":@0, @"downloadBytes":@0, @"startedAt":@([[NSDate date] timeIntervalSince1970])
    } mutableCopy];
    @synchronized (self) {
        self.flows[identifier] = flow;
        if ([flow[@"startedAt"] doubleValue]>=[self.lastConnection[@"startedAt"] doubleValue])
            self.lastConnection=[flow dictionaryWithValuesForKeys:@[@"actual",@"group",@"protocol",@"configID",@"routingToken",@"startedAt"]];
    }
    __block uint64_t sent = 0, received = 0;
    MLRelay(client, stream, ^(size_t up, size_t down) {
        @synchronized (self) {
            self.upload += up; self.download += down;
            sent += up; received += down;
            flow[@"uploadBytes"] = @(sent); flow[@"downloadBytes"] = @(received);
        }
    });
    @synchronized (self) { [self.flows removeObjectForKey:identifier]; }
    MLStreamClose(stream);
}

- (NSDictionary *)command:(NSString *)method params:(NSDictionary *)params {
    @synchronized (self) {
        if([method isEqual:@"fake.restore"]) {
            NSArray *states=params[@"pools"];
            if(self.configuration||![states isKindOfClass:[NSArray class]]||states.count>2)return nil;
            NSMutableArray *pools=[NSMutableArray array];
            for(NSDictionary *snapshot in states) {
                id v6=snapshot[@"ipv6Range"];
                MLFakeIP *pool=[[MLFakeIP alloc]initWithRange:snapshot[@"range"] ipv6Range:[v6 isKindOfClass:[NSString class]]?v6:nil capacity:512];
                if(!pool||![pool restoreSnapshot:snapshot error:NULL])return nil;
                for(MLFakeIP *existing in pools)for(NSString *key in @[@"range",@"ipv6Range"]) {
                    id left=existing.snapshot[key],right=snapshot[key];
                    NSString *a=[left isKindOfClass:[NSString class]]?[left componentsSeparatedByString:@"/"][0]:nil;
                    NSString *b=[right isKindOfClass:[NSString class]]?[right componentsSeparatedByString:@"/"][0]:nil;
                    if((a&&[pool containsAddress:a])||(b&&[existing containsAddress:b]))return nil;
                }
                [pools addObject:pool];
            }
            self.fakePools=pools;return @{};
        }
        if ([method isEqual:@"prepare"]) {
            NSDictionary *document = params[@"document"];
            if (![document isKindOfClass:[NSDictionary class]]) return nil;
            if (!MLRoutePrepareProviders(document)) return nil;
            NSMutableDictionary *nodes = [NSMutableDictionary dictionary];
            for (NSDictionary *node in document[@"proxies"]) {
                NSMutableDictionary *adapter=[node mutableCopy];[adapter removeObjectForKey:@"dialer-proxy"];
                NSData *data = [NSJSONSerialization dataWithJSONObject:adapter options:0 error:NULL];
                NSString *json = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
                if (!json || MLStreamValidate(json.UTF8String) != 0) return nil;
                nodes[node[@"name"]] = @{@"json":json,@"type":node[@"type"],@"node":node};
            }
            NSDictionary *runtime=params[@"runtime"] ?: @{};
            NSMutableDictionary *dnsOptions=[document[@"dns"] mutableCopy] ?: [NSMutableDictionary dictionary];
            NSString *dnsMode=runtime[@"dnsMode"];
            if([@[@"fake-ip",@"redir-host"] containsObject:dnsMode ?: @""])dnsOptions[@"enhanced-mode"]=dnsMode;
            MLDNS *dns=[[MLDNS alloc]initWithOptions:dnsOptions ipv6:[document[@"ipv6"] boolValue]];
            if(![dns installPreparedDocument:document error:NULL])return nil;
            if([runtime[@"caPath"] isKindOfClass:[NSString class]]) dns.caPath=runtime[@"caPath"];
            if([runtime[@"bootstrapServers"] isKindOfClass:[NSArray class]]) dns.bootstrapServers=runtime[@"bootstrapServers"];
            NSMutableDictionary *hosts=[dns.hosts mutableCopy] ?: [NSMutableDictionary dictionary];
            if([document[@"hosts"] isKindOfClass:[NSDictionary class]]) for(NSString *name in document[@"hosts"]) {
                NSString *key=name.lowercaseString;if([key hasSuffix:@"."])key=[key substringToIndex:key.length-1];hosts[key]=document[@"hosts"][name];
            }
            dns.hosts=hosts;
            __weak MLCore *weakCore=self;NSString *dnsCA=dns.caPath;BOOL respectRules=[document[@"dns"][@"respect-rules"] boolValue];
            dns.exchangeHandler=^NSData *(NSString *server,NSData *wire,double deadline,NSString *context) {
                return MLDNSOutboundQuery(server,wire,deadline,context,dnsCA,respectRules,^NSDictionary *(NSString *host,NSString *ip,uint16_t port,NSString *network,NSString *group) {
                    return [weakCore dnsRouteHost:host ip:ip port:port network:network group:group];
                });
            };
            BOOL fake=[dnsOptions[@"enhanced-mode"] isEqual:@"fake-ip"];
            NSArray *ranges=@[dnsOptions[@"fake-ip-range"] ?: @"198.18.0.0/16",
                              dnsOptions[@"fake-ip-range6"] ?: @"fd00:5e4b:1::/112"];
            self.preparedFakeIP=nil;self.preparedNewFakePool=NO;
            if(fake) {
                NSString *socket=runtime[@"ownerSocket"],*token=runtime[@"fakeToken"];
                NSNumber *owner=runtime[@"ownerUID"];
                if(self.captureFD<0||!socket.length||!token.length||![owner isKindOfClass:[NSNumber class]]||owner.doubleValue!=owner.unsignedIntValue)return nil;
                uid_t expectedOwner=owner.unsignedIntValue;
                MLFakeIP *pool=nil;
                MLFakeIP *candidate=[[MLFakeIP alloc]initWithRange:ranges[0] ipv6Range:ranges[1] capacity:512];
                if(!candidate)return nil;
                NSDictionary *identity=candidate.snapshot;
                for(MLFakeIP *existing in self.fakePools) {
                    NSDictionary *saved=existing.snapshot;
                    if([saved[@"range"] isEqual:identity[@"range"]]&&[saved[@"ipv6Range"] isEqual:identity[@"ipv6Range"]]){pool=existing;break;}
                }
                if(!pool) {
                    if(self.fakePools.count>=2)return nil;
                    // Retained ranges may not assign different hosts to the same cached address.
                    for(MLFakeIP *existing in self.fakePools)for(NSString *key in @[@"range",@"ipv6Range"]) {
                        id left=existing.snapshot[key],right=identity[key];
                        NSString *old=[left isKindOfClass:[NSString class]]?[left componentsSeparatedByString:@"/"][0]:nil;
                        NSString *new=[right isKindOfClass:[NSString class]]?[right componentsSeparatedByString:@"/"][0]:nil;
                        if((new&&[existing containsAddress:new])||(old&&[candidate containsAddress:old]))return nil;
                    }
                    pool=candidate;self.preparedNewFakePool=YES;
                }
                pool.persistenceHandler=^BOOL(NSDictionary *snapshot) {
                    return [MLIPCRequestWithOwner(socket,expectedOwner,@"network.fake.persist",@{@"token":token,@"snapshot":snapshot},NULL)[@"saved"] boolValue];
                };
                self.preparedFakeIP=pool;dns.fakeIP=pool;
            }
            self.prepared = document;
            self.preparedNodes = nodes;
            self.preparedDNS=dns;self.preparedOwnerSocket=runtime[@"ownerSocket"];self.preparedOwnerUID=[runtime[@"ownerUID"] unsignedIntValue];
            return @{};
        }
        if ([method isEqual:@"discard"]) {
            self.prepared=nil;self.preparedNodes=nil;self.preparedDNS=nil;return @{};
        }
        if ([method isEqual:@"commit"]) {
            if (!self.prepared) return nil;
            // Start handlers before acknowledging a generation. Routes are still owned by root.
            if(self.captureFD>=0 && !self.bridge) {
                __weak MLCore *weakSelf=self;
                MLPacketBridge *bridge=[[MLPacketBridge alloc]initWithFileDescriptor:self.captureFD interfaceName:self.captureName
                    route:^NSDictionary *(NSString *destination,NSString *source,uint16_t sourcePort,uint16_t port,NSString *network) {
                        return [weakSelf packetRoute:destination source:source sourcePort:sourcePort port:port network:network];
                    } datagram:^id<MLPacketDatagram>(NSDictionary *route,uint16_t port,NSError **error) {
                        return MLCoreOpenDatagram(route,port,error);
                    } dns:^NSData *(NSData *query) { return [[weakSelf resolver] answerQuery:query application:YES]; }
                    retainAddress:^(NSString *address) { MLCore *core=weakSelf;NSArray *pools;@synchronized(core){pools=[core.fakePools copy];}for(MLFakeIP *pool in pools)[pool retainAddress:address]; }
                    releaseAddress:^(NSString *address) { MLCore *core=weakSelf;NSArray *pools;@synchronized(core){pools=[core.fakePools copy];}for(MLFakeIP *pool in pools)[pool releaseAddress:address]; }];
                if(![bridge start:NULL]) return nil;
                self.bridge=bridge;
            }
            if(self.preparedNewFakePool) {if(!self.fakePools)self.fakePools=[NSMutableArray array];[self.fakePools addObject:self.preparedFakeIP];}
            self.configuration = self.prepared;
            self.nodes = self.preparedNodes;
            self.dns = self.preparedDNS;self.fakeIP=self.preparedFakeIP;self.ownerSocket=self.preparedOwnerSocket;self.ownerUID=self.preparedOwnerUID;
            self.requiresOwner=![self.configuration[@"find-process-mode"] isEqual:@"off"]&&
                ([self.configuration[@"rules"] description].uppercaseString &&
                 ([[self.configuration[@"rules"] description].uppercaseString rangeOfString:@"PROCESS-"].location!=NSNotFound||
                  [([self.configuration[@"sub-rules"] description].uppercaseString ?: @"") rangeOfString:@"PROCESS-"].location!=NSNotFound||
                  [([self.configuration[@"_rule-provider-payloads"] description].uppercaseString ?: @"") rangeOfString:@"PROCESS-"].location!=NSNotFound));
            [self.scheduler replaceDocument:self.configuration];
            self.prepared = nil; self.preparedNodes = nil; self.preparedDNS=nil;
            self.activeID = params[@"id"];
            self.mode = params[@"mode"];
            self.routingToken=[[NSProcessInfo processInfo] globallyUniqueString];
            self.lastConnection=nil;self.homeProbeTimes=[NSMutableDictionary dictionary];
            self.selections = [params[@"selections"] mutableCopy] ?: [NSMutableDictionary dictionary];
            [self.scheduler replaceSelections:self.selections];
            return @{@"capture":self.bridge.readiness ?: @{@"ready":@NO}};
        }
        if ([method isEqual:@"group.list"]) return @{@"items":[self.scheduler groupsWithSelections:self.selections]};
        if ([method isEqual:@"proxy.list"]) {
            NSString *name=[params[@"group"] isKindOfClass:[NSString class]]?params[@"group"]:@"GLOBAL";
            if(!name.length)name=@"GLOBAL";
            NSMutableDictionary *result=[@{@"items":[self.scheduler proxiesWithSelections:self.selections group:name]} mutableCopy];
            for(NSDictionary *group in [self.scheduler groupsWithSelections:self.selections])if([group[@"name"] isEqual:name]) {
                NSMutableDictionary *parent=[group mutableCopy];
                parent[@"manualSelectable"]=@([@[@"select",@"url-test",@"fallback"] containsObject:group[@"type"]]);
                result[@"group"]=parent;result[@"selected"]=group[@"selected"] ?: @"";break;
            }
            return result;
        }
        if ([method isEqual:@"dns.query"]) return [self.dns lookup:params[@"name"]];
        if ([method isEqual:@"network.status"]) {
            NSMutableDictionary *result=[self.bridge.readiness mutableCopy] ?: [@{@"ready":@NO} mutableCopy];
            result[@"statistics"]=self.bridge.statistics ?: @{};return result;
        }
        if ([method isEqual:@"mode"]) {
            self.mode = params[@"mode"]; self.routingToken=[[NSProcessInfo processInfo] globallyUniqueString];
            self.lastConnection=nil;return @{};
        }
        if ([method isEqual:@"select"]) {
            NSString *group = params[@"group"], *proxy = params[@"proxy"];
            if (!MLCanSelect(self.configuration, group, proxy)) return nil;
            self.selections[group] = proxy;[self.scheduler replaceSelections:self.selections];
            self.routingToken=[[NSProcessInfo processInfo] globallyUniqueString];self.lastConnection=nil;
            return @{};
        }
        if ([method isEqual:@"connections.list"]) {
            NSMutableArray *items = [NSMutableArray array];
            for (NSDictionary *flow in self.flows.allValues) {
                NSMutableDictionary *row = [flow mutableCopy];
                [row removeObjectsForKeys:@[@"fd",@"remoteFD"]];
                row[@"duration"] = @(fmax(0, [[NSDate date] timeIntervalSince1970] - [row[@"startedAt"] doubleValue]));
                [items addObject:row];
            }
            [items addObjectsFromArray:self.bridge.connections ?: @[]];
            return @{@"items":items};
        }
        if ([method isEqual:@"connections.close"]) {
            NSDictionary *flow = self.flows[params[@"id"]];
            if (!flow) return [self.bridge closeConnection:params[@"id"]]?@{}:nil;
            shutdown([flow[@"fd"] intValue], SHUT_RDWR);
            shutdown([flow[@"remoteFD"] intValue], SHUT_RDWR);
            return @{};
        }
        if ([method isEqual:@"proxy.measurements"]) return [self.scheduler nodesMeasurements];
        if ([method isEqual:@"proxy.probe"]) {
            NSString *url=params[@"url"]; NSArray *targets=params[@"targets"];
            if(![self.scheduler requestProbeNames:targets url:url timeout:3500]) return nil;
            return @{@"queued":@(targets.count),@"url":url};
        }
        if ([method isEqual:@"dns.cache"]) return @{@"entries":@([self.dns count]),@"capacity":@128};
        if ([method isEqual:@"dns.flush"]) return @{@"cleared":@([self.dns flush])};
        if ([method isEqual:@"statistics"]) {
            NSDictionary *packets=self.bridge.statistics;
            uint64_t totalUpload=self.upload+[packets[@"uploadBytes"] unsignedLongLongValue];
            uint64_t totalDownload=self.download+[packets[@"downloadBytes"] unsignedLongLongValue];
            uint64_t now = MLMilliseconds();
            double elapsed = (now - self.sampleAt) / 1000.0;
            NSMutableDictionary *result = [@{
                @"uploadBytes":@(totalUpload), @"downloadBytes":@(totalDownload),
                @"uploadRate":@(elapsed > 0 ? (totalUpload - self.sampleUpload)/elapsed : 0),
                @"downloadRate":@(elapsed > 0 ? (totalDownload - self.sampleDownload)/elapsed : 0),
                @"duration":@((now-self.started)/1000),@"captureStatistics":packets ?: @{}, @"connections":@(self.flows.count+self.bridge.connections.count)
            } mutableCopy];
            // A status poll must not depend on catching a short flow while it is open.
            NSDictionary *last=nil;
            for (NSDictionary *flow in @[self.lastConnection ?: @{},self.bridge.lastConnection ?: @{}])
                if ([flow[@"routingToken"] isEqual:self.routingToken] && (!last || [flow[@"startedAt"] doubleValue]>[last[@"startedAt"] doubleValue])) last=flow;
            NSDictionary *fallback=MLDefaultRouteWithRuntime(self.configuration,self.mode,self.selections,self.scheduler.measurements);
            NSString *actual=last ? last[@"actual"] : fallback[@"node"];
            NSString *group=last ? last[@"group"] : fallback[@"group"];
            NSString *protocol=last ? last[@"protocol"] : (self.nodes[actual][@"type"] ?: [actual lowercaseString]);
            NSMutableDictionary *outbound=[@{@"actual":actual ?: @"",@"group":group ?: @"",@"protocol":protocol ?: @"",@"source":last ? @"recent" : @"default"} mutableCopy];
            NSString *target=group.length ? group : actual;
            NSDictionary *measurements=self.scheduler.nodesMeasurements;
            NSDictionary *measurement=measurements[target];
            if (measurement[@"chain"] && ![[measurement[@"chain"] lastObject] isEqual:actual]) measurement=nil;
            NSDictionary *path=last ? MLRouteTargetWithRuntime(self.configuration,target,self.selections,self.scheduler.measurements,nil,@{}) : fallback;
            if (!measurement && [path[@"chain"] count]==1 && [[path[@"chain"] lastObject] isEqual:actual]) {
                NSDictionary *nodeMeasurement=measurements[actual];
                if ([nodeMeasurement[@"chain"] isEqual:path[@"chain"]]) measurement=nodeMeasurement;
            }
            if (measurement[@"delay"]) outbound[@"latency"]=measurement[@"delay"];
            outbound[@"latencyState"]=measurement[@"health"] ?: @"unknown";
            if ([@[@"DIRECT",@"REJECT"] containsObject:actual]) outbound[@"latencyState"]=@"not-applicable";
            else if (target.length) {
                // One current-path sample, at most once per five minutes; never a full-list test.
                NSString *key=[NSString stringWithFormat:@"%@/%@",target,actual];
                double timestamp=[[NSDate date] timeIntervalSince1970];
                if (!self.homeProbeTimes) self.homeProbeTimes=[NSMutableDictionary dictionary];
                if (!measurement[@"testing"] && timestamp-[measurement[@"checkedAt"] doubleValue]>300 && timestamp-[self.homeProbeTimes[key] doubleValue]>300) {
                    self.homeProbeTimes[key]=@(timestamp);
                    if (self.homeProbeTimes.count>128) { [self.homeProbeTimes removeAllObjects];self.homeProbeTimes[key]=@(timestamp); }
                    if ([self.scheduler requestProbeNames:@[target] url:@"http://www.gstatic.com/generate_204" timeout:3500]) outbound[@"latencyState"]=@"testing";
                }
            }
            result[@"outbound"]=outbound;
            for (NSString *key in @[@"actual",@"group",@"protocol",@"latency"]) if(outbound[key]) result[key]=outbound[key];
            self.sampleAt = now; self.sampleUpload = totalUpload; self.sampleDownload = totalDownload;
            return result;
        }
        return nil;
    }
}
@end

static int MLOpenListener(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) || listen(fd, MLMaxFlows)) {
        close(fd); return -1;
    }
    return fd;
}

static size_t MLCoreResolveCommon(const char *host,char addresses[][46],size_t capacity,void *context,BOOL bootstrap) {
    @autoreleasepool {
        MLCore *core=(__bridge MLCore *)context;MLDNS *dns=[core resolver];
        NSString *name=[NSString stringWithUTF8String:host];
        NSArray *results=(bootstrap?[dns lookupBootstrap:name]:[dns lookupProxyServer:name])[@"addresses"];
        size_t count=0;for(NSString *address in results) { if(count>=capacity)break; if(address.length>=46)continue;strlcpy(addresses[count++],address.UTF8String,46); }
        return count;
    }
}
static size_t MLCoreResolve(const char *host,char addresses[][46],size_t capacity,void *context) { return MLCoreResolveCommon(host,addresses,capacity,context,NO); }
static size_t MLCoreBootstrap(const char *host,char addresses[][46],size_t capacity,void *context) { return MLCoreResolveCommon(host,addresses,capacity,context,YES); }

int main(int argc, const char *argv[]) { @autoreleasepool {
    if (argc < 3 || strcmp(argv[1],"--supervised") || (argc-3)%2) return 64;
    int captureFD=-1,lifetimeFD=-1;unsigned outbound=0;NSString *captureName=nil;
    for(int i=3;i+1<argc;i+=2) {
        if(!strcmp(argv[i],"--capture-name")) { captureName=[NSString stringWithUTF8String:argv[i+1]];continue; }
        char *last=NULL;unsigned long value=strtoul(argv[i+1],&last,10);
        if(!last||*last||value>UINT32_MAX)return 64;
        if(!strcmp(argv[i],"--capture-fd"))captureFD=(int)value;
        else if(!strcmp(argv[i],"--capture-lifetime-fd"))lifetimeFD=(int)value;
        else if(!strcmp(argv[i],"--outbound-if"))outbound=(unsigned)value;
        else return 64;
    }
    if(argc>3&&(captureFD!=3||lifetimeFD!=4||!outbound||!captureName.length))return 64;
    int control = STDIN_FILENO;
    int type; socklen_t size = sizeof(type);
    if (getsockopt(control,SOL_SOCKET,SO_TYPE,&type,&size) || type != SOCK_STREAM) return 64;
    // The supervisor uses close-on-exec. Clear any descriptor accepted during
    // the interval between accept() and setting that flag before dropping UID.
    int openLimit = getdtablesize();
    for (int fd = STDERR_FILENO + 1; fd < openLimit; ++fd) if(fd!=captureFD&&fd!=lifetimeFD) close(fd);
    if (geteuid() == 0) {
        struct passwd *mobile = getpwnam("mobile");
        if (!mobile || !mobile->pw_uid || initgroups("mobile",mobile->pw_gid) != 0 ||
            setgid(mobile->pw_gid) != 0 || setuid(mobile->pw_uid) != 0 || geteuid() == 0) return 77;
    }
    signal(SIGPIPE,SIG_IGN);
    MLIPCSetTimeout(control,5);
    char *end;
    unsigned long port = strtoul(argv[2],&end,10);
    if (end == argv[2] || *end || port > UINT16_MAX) return 64;
    int listener = MLOpenListener((uint16_t)port);
    if (listener < 0) {
        MLIPCWriteFrame(control,@{@"error":@"无法绑定本机 SOCKS 端口"},NULL);
        return 69;
    }
    struct sockaddr_in address;
    socklen_t addressSize = sizeof(address);
    if (getsockname(listener,(struct sockaddr *)&address,&addressSize) != 0) return 69;
    MLCore *core = [MLCore new];
    core.captureFD=captureFD;core.captureName=captureName;core.listenerPort=ntohs(address.sin_port);
    core.scheduler=[[MLPolicyScheduler alloc]initWithProbe:^NSDictionary *(NSDictionary *node,NSString *url,NSUInteger timeout) {
        id payload=node;
        if(node[@"_muyu-probe-chain"]) {
            NSMutableArray *chain=[NSMutableArray array];
            for(NSDictionary *entry in node[@"_muyu-probe-chain"]) { NSMutableDictionary *adapter=[entry mutableCopy];[adapter removeObjectForKey:@"dialer-proxy"];[chain addObject:adapter]; }
            payload=chain;
        } else if(node) { NSMutableDictionary *adapter=[node mutableCopy];[adapter removeObjectForKey:@"dialer-proxy"];payload=adapter; }
        NSData *data=payload?[NSJSONSerialization dataWithJSONObject:payload options:0 error:NULL]:nil;
        NSString *json=data?[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]:nil;
        return MLProbeStreamWithTimeout(json,url,(unsigned)timeout);
    }];
    MLNetworkSetInterfaceIndex(outbound);
    MLNetworkSetResolver(MLCoreResolve,(__bridge void *)core);
    MLNetworkSetBootstrapResolver(MLCoreBootstrap,(__bridge void *)core);
    core.flows = [NSMutableDictionary dictionary];
    core.started = core.sampleAt = MLMilliseconds();
    if (!MLIPCWriteFrame(control,@{@"port":@(ntohs(address.sin_port)),@"version":@1},NULL)) return 74;
    dispatch_semaphore_t capacity = dispatch_semaphore_create(MLMaxFlows);
    for (;;) { @autoreleasepool {
        struct pollfd events[] = {{control,POLLIN,0},{core.configuration ? listener : -1,POLLIN,0}};
        int ready = poll(events,2,1000);
        [core.scheduler tick];
        if(!ready)continue;
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) break;
        if (events[0].revents) {
            NSDictionary *request = MLIPCReadFrame(control,NULL);
            if (!MLIPCValidRequest(request)) break;
            NSDictionary *result = [core command:request[@"method"] params:request[@"params"]];
            if (!MLIPCWriteReply(control,request,MLIPCResponse(request,result,result ? nil : @"E_CORE_REQUEST",
                                                              @"核心拒绝请求或配置"))) break;
        }
        if (events[1].revents & POLLIN) {
            struct sockaddr_in peer; socklen_t peerSize = sizeof(peer);
            int client = accept(listener,(struct sockaddr *)&peer,&peerSize);
            if (client < 0) continue;
            if (dispatch_semaphore_wait(capacity,DISPATCH_TIME_NOW) != 0) { close(client); continue; }
            char ip[INET_ADDRSTRLEN] = "127.0.0.1";
            inet_ntop(AF_INET,&peer.sin_addr,ip,sizeof(ip));
            NSString *source = [NSString stringWithUTF8String:ip];
            uint16_t sourcePort = ntohs(peer.sin_port);
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{ @autoreleasepool {
                [core serve:client address:source port:sourcePort];
                close(client);
                dispatch_semaphore_signal(capacity);
            }});
        }
    }}
    [core.scheduler stop];[core.bridge stop];
    close(listener);
    return 0;
}}
