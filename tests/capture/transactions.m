#import "MLCaptureInternal.h"
#include <arpa/inet.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>

@interface FakeKernel : NSObject <MLCaptureBackend>
@property(nonatomic,strong) NSMutableDictionary *routes;
@property(nonatomic,copy) NSString *directory, *dnsNonce;
@property(nonatomic) unsigned interfaceIndex, additions, deletions, failAt;
@property(nonatomic) unsigned generation;
@property(nonatomic) BOOL dnsFail, withdrawFail;
@property(nonatomic) BOOL signatureFail;
@property(nonatomic,copy) NSDictionary *signature;
@property(nonatomic,copy) NSDictionary *path;
@end
@implementation FakeKernel
- (id)init { if ((self=[super init])) { _routes=[NSMutableDictionary dictionary]; _interfaceIndex=12; } return self; }
- (NSDictionary *)openDevice:(NSError **)error { (void)error; return @{@"fd":@42,@"interface":@"utun11",@"interfaceIndex":@12}; }
- (BOOL)closeDevice:(NSError **)error { (void)error; return YES; }
- (NSDictionary *)physicalPath:(NSError **)error { (void)error; return self.path ?: @{@"interface":@"en0",@"interfaceIndex":@5}; }
- (NSDictionary *)physicalSignature:(NSError **)error {
    if(self.signatureFail){if(error)*error=[NSError errorWithDomain:@"kernel" code:5 userInfo:@{NSLocalizedDescriptionKey:@"injected signature failure"}];return nil;}
    return self.signature ?: @{@"generation":@(self.generation)};
}
- (unsigned)indexForInterface:(NSString *)name { return [name isEqual:@"utun11"]?self.interfaceIndex:([name isEqual:@"en0"]?5:0); }
- (NSDictionary *)routeForDestination:(NSString *)destination prefix:(unsigned)prefix interfaceIndex:(unsigned)index error:(NSError **)error {
    (void)error; NSString *key=prefix?destination:[NSString stringWithFormat:@"%@/0/%u",destination,index];
    NSDictionary *route=self.routes[key];
    return route && (!index || [route[@"interfaceIndex"] unsignedIntValue]==index)?route:nil;
}
- (BOOL)addRoute:(NSDictionary *)route error:(NSError **)error {
    // Every kernel mutation must have a durable pending undo entry already.
    NSData *bytes=[NSData dataWithContentsOfFile:[self.directory stringByAppendingPathComponent:@"capture.json"]];
    NSDictionary *journal=[NSJSONSerialization JSONObjectWithData:bytes options:0 error:NULL];
    assert([journal[@"routes"] count]);
    NSDictionary *pending=[journal[@"routes"] lastObject];
    assert([pending[@"state"] isEqual:@"pending"]);
    assert([pending[@"destination"] isEqual:route[@"destination"]]);
    if (++self.additions==self.failAt) {
        if(error)*error=[NSError errorWithDomain:@"kernel" code:5 userInfo:@{NSLocalizedDescriptionKey:@"injected add failure"}]; return NO;
    }
    NSString *key=[route[@"prefix"] unsignedIntValue]?route[@"destination"]:[NSString stringWithFormat:@"%@/0/%@",route[@"destination"],route[@"interfaceIndex"]];
    self.routes[key]=[route copy]; return YES;
}
- (BOOL)deleteRoute:(NSDictionary *)route error:(NSError **)error {
    (void)error; self.deletions++;
    NSString *key=[route[@"prefix"] unsignedIntValue]?route[@"destination"]:[NSString stringWithFormat:@"%@/0/%@",route[@"destination"],route[@"interfaceIndex"]];
    [self.routes removeObjectForKey:key]; return YES;
}
- (BOOL)publishDNS:(NSString *)interface nonce:(NSString *)nonce error:(NSError **)error {
    assert([interface isEqual:@"utun11"]);
    if(self.dnsFail) { if(error)*error=[NSError errorWithDomain:@"dns" code:5 userInfo:@{}]; return NO; }
    self.dnsNonce=nonce; return YES;
}
- (BOOL)withdrawDNS:(NSString *)nonce error:(NSError **)error {
    if(self.withdrawFail) { if(error)*error=[NSError errorWithDomain:@"dns" code:5 userInfo:@{}]; return NO; }
    if([nonce isEqual:self.dnsNonce]) self.dnsNonce=nil; return YES;
}
@end
static NSDictionary *ready(void) { return @{@"ready":@YES,@"tcp":@YES,@"udp":@YES,@"ipv6":@YES,@"dns":@YES}; }
static NSString *workspace(void) {
    char path[]="/tmp/ml-capture-test.XXXXXX"; assert(mkdtemp(path));
    assert(chmod(path,0700)==0); return [NSString stringWithUTF8String:path];
}
static MLCaptureCoordinator *coordinator(FakeKernel *kernel,NSString *dir) {
    kernel.directory=dir; NSError *error=nil;
    MLCaptureCoordinator *c=[[MLCaptureCoordinator alloc] initWithStateDirectory:dir backend:kernel error:&error];
    assert(c && !error); assert([c prepare:&error]); assert(!error); return c;
}
static void cleanup(NSString *dir) { [[NSFileManager defaultManager] removeItemAtPath:dir error:NULL]; }
static void testIPv6SourceNetwork(void) {
    struct sockaddr_in6 mask = {0};
    mask.sin6_len = sizeof mask;
    struct in6_addr address;
    assert(inet_pton(AF_INET6,"ffff:ffff:ffff:ff80::",&mask.sin6_addr)==1);
    assert(inet_pton(AF_INET6,"2001:db8:42:abfe::1",&address)==1);
    assert([MLCaptureIPv6SourceNetwork(&address,&mask) isEqual:@"2001:db8:42:ab80::/57"]);
    assert(inet_pton(AF_INET6,"2001:db8:42:ab91:1234::2",&address)==1);
    assert([MLCaptureIPv6SourceNetwork(&address,&mask) isEqual:@"2001:db8:42:ab80::/57"]);
    assert(inet_pton(AF_INET6,"2001:db8:42:ab01::2",&address)==1);
    assert([MLCaptureIPv6SourceNetwork(&address,&mask) isEqual:@"2001:db8:42:ab00::/57"]);
    assert([MLCaptureIPv6SourceNetwork(&address,NULL) isEqual:@"2001:db8:42:ab01::2"]);
    assert(inet_pton(AF_INET6,"fe80::aa01",&address)==1);
    assert([MLCaptureIPv6SourceNetwork(&address,&mask) isEqual:@"fe80::aa01"]);
}
int main(void) { @autoreleasepool {
    testIPv6SourceNetwork();
    {
        NSDictionary *publication=MLCaptureDNSPublication(@"utun11",@"test-nonce");
        assert(publication.count==1 && publication[@"DNS"] && !publication[@"IPv4"] && !publication[@"IPv6"]);
        NSDictionary *dns=publication[@"DNS"];
        assert([dns[@"SupplementalMatchDomains"]isEqual:@[@""]] && [dns[@"SupplementalMatchOrders"]isEqual:@[@0]]);
        assert([dns[@"InterfaceName"]isEqual:@"utun11"] && [dns[@"MuyuClashCaptureNonce"]isEqual:@"test-nonce"]);
        for(NSString *key in @[@"Router",@"OverridePrimary",@"Addresses",@"DestAddresses",@"SubnetMasks"])assert(!dns[key]);
    }
    {
        NSString *dir=workspace(); FakeKernel *kernel=[FakeKernel new]; MLCaptureCoordinator *c=coordinator(kernel,dir);
        NSError *error=nil;
        assert((![c activateWithCoreReady:@{@"ready":@YES,@"tcp":@YES} error:&error]));
        assert(kernel.additions==0 && [c.status[@"coverage"][@"udp"] isEqual:@"未接管"]);
        BOOL changed=YES;assert([c checkPhysicalPathChanged:&changed error:NULL] && !changed);
        assert([c.status[@"lastPathCheck"][@"ok"] boolValue] && [c.status[@"lastPathCheck"][@"changedFields"]count]==0);
        kernel.generation++;assert([c checkPhysicalPathChanged:&changed error:NULL] && changed);assert(kernel.additions==0);
        assert([c.status[@"lastPathCheck"][@"changedFields"]isEqual:@[@"generation"]]);
        assert([c.status[@"lastPathCheck"][@"expectedSignature"][@"generation"]isEqual:@0]);
        assert([c.status[@"lastPathCheck"][@"observedSignature"][@"generation"]isEqual:@1]);
        assert([c restore:NULL]); cleanup(dir);
    }
    {
        NSString *dir=workspace();FakeKernel *kernel=[FakeKernel new];
        kernel.signature=@{@"default4":@{@"interface":@"en0",@"interfaceIndex":@5,@"gateway":@"192.0.2.1"},@"dns":@[@"192.0.2.1"]};
        MLCaptureCoordinator *c=coordinator(kernel,dir);BOOL changed=NO;
        kernel.signature=@{@"default4":@{@"interface":@"utun11",@"interfaceIndex":@12,@"gateway":@"198.18.0.2"},@"dns":@[]};
        assert([c checkPhysicalPathChanged:&changed error:NULL] && changed && kernel.additions==0 && kernel.deletions==0);
        NSArray *fields=c.status[@"lastPathCheck"][@"changedFields"];
        assert(([fields isEqual:@[@"default4.gateway",@"default4.interface",@"default4.interfaceIndex",@"dns"]]));
        NSDictionary *diagnostic=c.status[@"lastPathCheck"];assert([c restore:NULL]);
        assert([c.status[@"lastPathCheck"]isEqual:diagnostic] && [c.status[@"physicalSignature"]count]==0);
        cleanup(dir);
    }
    {
        NSString *dir=workspace();FakeKernel *kernel=[FakeKernel new];MLCaptureCoordinator *c=coordinator(kernel,dir);
        kernel.signatureFail=YES;BOOL changed=NO;NSError *error=nil;
        assert(![c checkPhysicalPathChanged:&changed error:&error] && changed && error.code==5 && kernel.additions==0);
        assert(![c.status[@"lastPathCheck"][@"ok"]boolValue] && [c.status[@"lastPathCheck"][@"error"][@"code"]isEqual:@5]);
        assert([c restore:NULL]);cleanup(dir);
    }
    {
        NSString *dir=workspace(); FakeKernel *kernel=[FakeKernel new]; kernel.failAt=3;
        kernel.routes[@"203.0.113.7"]=@{@"destination":@"203.0.113.7",@"prefix":@32,@"interfaceIndex":@4};
        MLCaptureCoordinator *c=coordinator(kernel,dir);
        assert(![c activateWithCoreReady:ready() error:NULL]);
        assert(kernel.additions==3 && kernel.deletions==2 && kernel.routes.count==1);
        assert(kernel.routes[@"203.0.113.7"]); assert(![[NSFileManager defaultManager] fileExistsAtPath:[dir stringByAppendingPathComponent:@"capture.json"]]); cleanup(dir);
    }
    {
        NSString *dir=workspace(); FakeKernel *kernel=[FakeKernel new];
        kernel.routes[@"0.0.0.0"]=@{@"destination":@"0.0.0.0",@"prefix":@1,@"interfaceIndex":@4};
        MLCaptureCoordinator *c=coordinator(kernel,dir);
        assert(![c activateWithCoreReady:ready() error:NULL]); assert(kernel.additions==0 && kernel.deletions==0 && kernel.routes.count==1); cleanup(dir);
    }
    {
        NSString *dir=workspace(); FakeKernel *kernel=[FakeKernel new]; MLCaptureCoordinator *c=coordinator(kernel,dir);
        assert([c activateWithCoreReady:ready() error:NULL]); assert(kernel.routes.count==4 && kernel.dnsNonce);
        // Without an independent guardian, strict crash protection cannot be
        // advertised. The process lifecycle is covered by guardian.py.
        assert(![c coreFailedWithStrictBlock:YES error:NULL]); assert(![c.status[@"strictBlockAvailable"] boolValue] && kernel.routes.count==4);
        assert([c restore:NULL]); assert(!kernel.routes.count && !kernel.dnsNonce); cleanup(dir);
    }
    {
        NSString *dir=workspace(); FakeKernel *kernel=[FakeKernel new]; kernel.dnsFail=YES;
        MLCaptureCoordinator *c=coordinator(kernel,dir); assert(![c activateWithCoreReady:ready() error:NULL]);
        assert(kernel.deletions==4 && !kernel.routes.count); cleanup(dir);
    }
    {
        NSString *dir=workspace(); FakeKernel *kernel=[FakeKernel new]; MLCaptureCoordinator *c=coordinator(kernel,dir);
        assert([c activateWithCoreReady:ready() error:NULL]);
        // A DNS cleanup failure must not strand all packet routes.
        kernel.withdrawFail=YES; assert(![c restore:NULL]); assert(!kernel.routes.count);
        assert([[NSFileManager defaultManager] fileExistsAtPath:[dir stringByAppendingPathComponent:@"capture.json"]]);
        kernel.withdrawFail=NO; assert([c restore:NULL]); cleanup(dir);
    }
    {
        NSString *dir=workspace(); FakeKernel *kernel=[FakeKernel new]; MLCaptureCoordinator *c=coordinator(kernel,dir);
        assert([c activateWithCoreReady:ready() error:NULL]);
        // Do not remove a route replaced by another interface after activation.
        NSMutableDictionary *replacement=[kernel.routes[@"128.0.0.0"] mutableCopy]; replacement[@"interfaceIndex"]=@99;
        kernel.routes[@"128.0.0.0"]=replacement;
        assert([c restore:NULL]); assert(kernel.routes.count==1 && kernel.routes[@"128.0.0.0"]); cleanup(dir);
    }
    {
        NSString *dir=workspace(); FakeKernel *kernel=[FakeKernel new]; MLCaptureCoordinator *c=coordinator(kernel,dir);
        assert([c activateWithCoreReady:ready() error:NULL]);
        kernel.interfaceIndex=34; // the name has been recycled since capture started
        assert([c restore:NULL]); assert(kernel.deletions==0); cleanup(dir);
    }
    {
        NSString *dir=workspace(); FakeKernel *kernel=[FakeKernel new]; kernel.directory=dir;
        NSDictionary *hostile=@{@"format":@1,@"nonce":@"nonce",@"interface":@"utun11",@"interfaceIndex":@12,
            @"routes":@[@{@"destination":@"203.0.113.7",@"prefix":@32,@"interface":@"utun11",@"interfaceIndex":@12,@"gatewayIsLink":@YES,@"state":@"applied"}]};
        NSString *path=[dir stringByAppendingPathComponent:@"capture.json"];
        assert([[NSJSONSerialization dataWithJSONObject:hostile options:0 error:NULL] writeToFile:path atomically:YES]); chmod(path.fileSystemRepresentation,0600);
        assert(!MLCaptureRecoverWithBackend(dir,kernel,NULL)); assert(kernel.deletions==0); cleanup(dir);
    }
    {
        NSString *dir=workspace(); FakeKernel *kernel=[FakeKernel new]; kernel.directory=dir;
        NSString *path=[dir stringByAppendingPathComponent:@"capture.json"];
        assert(symlink("/etc/passwd",path.fileSystemRepresentation)==0);
        assert(!MLCaptureRecoverWithBackend(dir,kernel,NULL)); assert(kernel.deletions==0); cleanup(dir);
    }
    {
        NSString *dir=workspace(); NSError *error=nil;
        MLCaptureCoordinator *c=[[MLCaptureCoordinator alloc] initWithStateDirectory:dir error:&error];
        assert(c && ![c prepare:&error] && error.code==ENOTSUP); cleanup(dir);
    }
    for(unsigned scenario=0;scenario<3;scenario++){
        NSString *dir=workspace();FakeKernel *kernel=[FakeKernel new];
        kernel.path=@{@"interface":@"en0",@"interfaceIndex":@5,@"gateway4":@"192.0.2.1",@"gateway6":@"fe80:5::1",@"haveIPv6Path":@YES};
        NSDictionary *existing=@{@"destination":@"0.0.0.0",@"prefix":@0,@"interface":@"en0",@"interfaceIndex":@5,@"gatewayIsLink":@NO,@"gateway":@"192.0.2.1",@"scoped":@YES};
        if(scenario==1)kernel.routes[@"0.0.0.0/0/5"]=existing;
        if(scenario==2)kernel.failAt=4;
        MLCaptureCoordinator *c=coordinator(kernel,dir);
        if(scenario==2){
            assert(![c activateWithCoreReady:ready() error:NULL]);
            assert(kernel.additions==4 && kernel.deletions==3 && !kernel.routes.count);
        }else{
            assert([c activateWithCoreReady:ready() error:NULL] && kernel.routes.count==6);
            if(scenario==0){
                // A persisted recovery must remove physical exits even after
                // utun disappears. It must preserve a replaced foreign exit.
                NSString *recovery=workspace();
                NSData *journal=[NSData dataWithContentsOfFile:[dir stringByAppendingPathComponent:@"capture.json"]];
                NSString *file=[recovery stringByAppendingPathComponent:@"capture.json"];
                assert([journal writeToFile:file atomically:YES]);chmod(file.fileSystemRepresentation,0600);
                kernel.interfaceIndex=0;
                for(NSString *destination in @[@"0.0.0.0",@"128.0.0.0",@"::",@"8000::"]) [kernel.routes removeObjectForKey:destination];
                NSMutableDictionary *foreign=[kernel.routes[@"::/0/5"] mutableCopy];foreign[@"gateway"]=@"fe80:5::2";kernel.routes[@"::/0/5"]=foreign;
                assert(MLCaptureRecoverWithBackend(recovery,kernel,NULL));
                assert(kernel.routes.count==1 && kernel.routes[@"::/0/5"]);cleanup(recovery);
            }
            assert([c restore:NULL] && kernel.routes.count==1);
            if(scenario==1)assert([kernel.routes[@"0.0.0.0/0/5"] isEqual:existing]);
        }
        cleanup(dir);
    }
    puts("PASS capture transaction ordering, rollback, identity, DNS failure and hostile journal checks");
}}
