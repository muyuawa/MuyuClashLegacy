#import "MLService.h"
#include <assert.h>
#include <sys/stat.h>
#include <stdlib.h>
static NSDictionary *Call(MLService *service, NSString *method, NSDictionary *params) {
    NSError *error = nil;
    NSDictionary *result = [service handleMethod:method params:params error:&error];
    if (!result) fprintf(stderr,"Unexpected error: %s\n",error.localizedDescription.UTF8String);
    assert(result); return result;
}
int main(void) { @autoreleasepool {
    char temporary[] = "/private/tmp/muyu-service-XXXXXX";
    assert(mkdtemp(temporary));
    NSString *dir = [NSString stringWithUTF8String:temporary];
    NSError *error = nil;
    MLService *service = [[MLService alloc] initWithDirectory:dir caPath:nil error:&error];
    assert(service);
    NSDictionary *status = Call(service,@"service.status",@{});
    assert([status[@"state"] isEqual:@"STOPPED"]);
    assert([status[@"coverage"][@"udp"] isEqual:@"未接管"]);
    assert(![service handleMethod:@"service.start" params:@{} error:&error]);
    assert(error != nil);
    status = Call(service,@"service.status",@{});
    assert(![status[@"state"] isEqual:@"RUNNING"]);
    NSDictionary *cap = Call(service,@"system.capabilities",@{});
    assert([cap[@"releaseReady"] isEqual:@NO]);
    assert([cap[@"capture"][@"strictBlockAvailable"] isEqual:@NO]);
    NSMutableDictionary *protocols = [NSMutableDictionary dictionary];
    for (NSDictionary *protocol in cap[@"protocols"]) protocols[protocol[@"name"]] = protocol;
    assert([protocols[@"wireguard"][@"integrated"] isEqual:@YES]);
    assert([protocols[@"amneziawg"][@"integrated"] isEqual:@YES]);
    assert([protocols[@"wireguard"][@"transport"] isEqual:@"TCP/UDP"]);
    assert([protocols[@"amneziawg"][@"transport"] isEqual:@"TCP/UDP"]);
    NSDictionary *report = Call(service,@"config.check",@{@"yaml":@"rules: ['MATCH,DIRECT']\n"});
    assert(report[@"document"] == nil);
    error = nil;
    assert((![service handleMethod:@"settings.set" params:@{@"key":@"protectionMode",@"value":@"strict"} error:&error]));
    assert(error);
    error = nil;
    assert((![service handleMethod:@"settings.set" params:@{@"key":@"maxProbeConcurrency",@"value":@1000} error:&error]));
    assert(error);
    Call(service,@"settings.set",@{@"key":@"logLevel",@"value":@"debug"});
    assert([Call(service,@"settings.get",@{})[@"values"][@"logLevel"] isEqual:@"debug"]);
    MLService *reopened = [[MLService alloc] initWithDirectory:dir caPath:nil error:&error];
    assert(reopened && [Call(reopened,@"settings.get",@{})[@"values"][@"logLevel"] isEqual:@"debug"]);
    error = nil;
    assert(![service handleMethod:@"connections.close" params:@{@"id":@"invented"} error:&error]);
    assert(error);
    Call(service,@"service.stop",@{});
    assert([Call(service,@"service.status",@{})[@"state"] isEqual:@"STOPPED"]);
    assert([Call(service,@"logs.list",@{})[@"items"] count] > 0);
    Call(service,@"logs.clear",@{});
    Call(service,@"settings.set",@{@"key":@"logLevel",@"value":@"error"});
    Call(service,@"service.stop",@{});
    assert([Call(service,@"logs.list",@{})[@"items"] count] == 0);
    error = nil;
    assert(![service handleMethod:@"service.start" params:@{} error:&error]);
    assert([Call(service,@"logs.list",@{})[@"items"] count] == 1);
    [[NSFileManager defaultManager] removeItemAtPath:dir error:NULL];
    puts("PASS service: honest coverage, blocked startup, settings validation/persistence");
} return 0; }
