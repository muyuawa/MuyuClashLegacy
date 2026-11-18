#import <Foundation/Foundation.h>
#import "../dns/MLFakeIP.h"
#include <assert.h>
#include <dispatch/dispatch.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

// Production uses mach_absolute_time. Deterministic time only enters through
// this private test override, so no wall-clock or test API reaches Core.
@interface MLTimedFakeIP : MLFakeIP
@property(nonatomic) NSTimeInterval testNow;
@end
@implementation MLTimedFakeIP
- (NSTimeInterval)monotonicNow { return self.testNow; }
@end
static MLTimedFakeIP *smallPool(NSUInteger capacity,NSTimeInterval now) {
    MLTimedFakeIP *pool=[[MLTimedFakeIP alloc]initWithRange:@"198.18.0.0/28" ipv6Range:@"fd00:5e4b:1::/112" capacity:capacity];
    pool.testNow=now;return pool;
}
static MLFakeIP *makePool(NSUInteger capacity) {
    return [[MLFakeIP alloc]initWithRange:@"198.18.0.0/16" ipv6Range:@"fd00:5e4b:1::/112" capacity:capacity];
}
static NSMutableDictionary *mutableSnapshot(NSDictionary *snapshot) {
    NSData *data=[NSJSONSerialization dataWithJSONObject:snapshot options:0 error:NULL];
    return [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:NULL];
}
static void rejected(MLFakeIP *pool,NSDictionary *bad) {
    NSDictionary *before=[pool snapshot]; NSError *error=nil;
    assert(![pool restoreSnapshot:bad error:&error] && error);
    assert([[pool snapshot]isEqual:before]);
}
static void persistence(void) {
    MLFakeIP *pool=makePool(2); __block NSDictionary *committed=nil; __block unsigned writes=0;
    pool.persistenceHandler=^BOOL(NSDictionary *snapshot){committed=snapshot;writes++;return YES;};
    NSString *first=[pool addressForHost:@"ONE.TEST." ipv6:NO];
    assert(first && writes==1 && [committed[@"entries"][0][@"host"]isEqual:@"one.test"]);
    NSString *six=[pool addressForHost:@"one.test" ipv6:YES];assert(six && writes==1);
    [pool retainAddress:first];
    NSString *second=[pool addressForHost:@"two.test" ipv6:NO];assert(second && writes==2);
    NSDictionary *before=[pool snapshot];
    pool.persistenceHandler=^BOOL(NSDictionary *snapshot){assert([snapshot[@"entries"]count]==2);return NO;};
    assert(![pool addressForHost:@"three.test" ipv6:NO]);
    assert([[pool snapshot]isEqual:before] && [pool statistics][@"pins"] && [[pool statistics][@"pins"]unsignedIntegerValue]==1);
    assert([[pool hostForAddress:second]isEqual:@"two.test"] && ![pool hostForAddress:@"198.18.0.6"]);
    assert([[pool statistics][@"persistenceFailures"]unsignedIntegerValue]==1);
    pool.persistenceHandler=^BOOL(NSDictionary *snapshot){committed=snapshot;return YES;};
    assert([pool addressForHost:@"three.test" ipv6:NO] && ![pool hostForAddress:second]);
    MLFakeIP *restored=makePool(2);assert([restored restoreSnapshot:committed error:NULL]);
    assert([[restored statistics][@"pins"]unsignedIntegerValue]==0);
    assert([[restored hostForAddress:first]isEqual:@"one.test"] && [[restored hostForAddress:six]isEqual:@"one.test"]);
    assert([[restored addressForHost:@"one.test" ipv6:NO]isEqual:first]);
    assert(![[restored addressForHost:@"four.test" ipv6:NO]isEqual:first]);
    MLFakeIP *empty=makePool(2);NSDictionary *emptyBefore=[empty snapshot];
    empty.persistenceHandler=^BOOL(NSDictionary *snapshot){(void)snapshot;[NSException raise:@"test" format:@"Persistence failure"];return YES;};
    assert(![empty addressForHost:@"failure.test" ipv6:NO] && [[empty snapshot]isEqual:emptyBefore]);
    __weak MLFakeIP *weakEmpty=empty;
    empty.persistenceHandler=^BOOL(NSDictionary *snapshot){assert(![weakEmpty addressForHost:@"recursive.test" ipv6:NO]);return [snapshot isEqual:[weakEmpty snapshot]];};
    assert([empty addressForHost:@"after-failure.test" ipv6:NO]);
    assert(![empty addressForHost:@"space name.test" ipv6:NO]);
    assert(![empty addressForHost:@"host..test" ipv6:NO]);
    assert(![empty addressForHost:@"中文.test" ipv6:NO]);
    MLFakeIP *small=[[MLFakeIP alloc]initWithRange:@"198.18.0.0/28" ipv6Range:nil capacity:512];
    for(unsigned i=0;i<11;i++)assert(([small addressForHost:[NSString stringWithFormat:@"small-%u.test",i] ipv6:NO]));
    NSDictionary *smallBefore=[small snapshot];small.persistenceHandler=^BOOL(NSDictionary *snapshot){(void)snapshot;return NO;};
    assert(![small addressForHost:@"small-full.test" ipv6:NO] && [[small snapshot]isEqual:smallBefore]);
    small.persistenceHandler=^BOOL(NSDictionary *snapshot){(void)snapshot;assert(!"Full small pool must not invoke persistence");return YES;};
    assert(![small addressForHost:@"small-full.test" ipv6:NO] && [[small snapshot]isEqual:smallBefore]);
    assert([[small statistics][@"entries"]unsignedIntegerValue]==11);
}
static void quarantine(void) {
    MLTimedFakeIP *pool=smallPool(1,1000);
    NSString *old=[pool addressForHost:@"recent.test" ipv6:NO],*old6=[pool addressForHost:@"recent.test" ipv6:YES];
    assert([old isEqual:@"198.18.0.4"]);
    pool.testNow=1299;assert([[pool addressForHost:@"recent.test" ipv6:NO]isEqual:old]);
    for(unsigned i=0;i<10;i++){
        NSString *value=[pool addressForHost:[NSString stringWithFormat:@"rotate-%u.test",i] ipv6:NO];
        assert(value && ![value isEqual:old]);
    }
    assert(![pool hostForAddress:old] && ![pool hostForAddress:old6]);
    assert([[pool statistics][@"retired"]unsignedIntegerValue]==10);
    NSDictionary *before=[pool snapshot];
    for(NSNumber *clock in @[@1300,@1598,@1100]){
        pool.testNow=clock.doubleValue;
        assert(![pool addressForHost:@"too-early.test" ipv6:NO]);
        assert([[pool snapshot]isEqual:before]);
    }
    // TTL starts from retirement after the recent DNS service, rather than
    // the much earlier allocation. A backward clock never frees a slot.
    pool.testNow=1599;
    pool.persistenceHandler=^BOOL(NSDictionary *snapshot){
        assert([snapshot[@"retired"]count]==1);
        assert([snapshot[@"entries"][0][@"v4"]isEqual:old]);return NO;
    };
    assert(![pool addressForHost:@"failed-reuse.test" ipv6:NO]);
    assert([[pool snapshot]isEqual:before]);
    assert([[pool hostForAddress:@"198.18.0.14"]isEqual:@"rotate-9.test"]);
    pool.persistenceHandler=^BOOL(NSDictionary *snapshot){(void)snapshot;return YES;};
    assert([[pool addressForHost:@"safe-reuse.test" ipv6:NO]isEqual:old]);
    assert([[pool addressForHost:@"safe-reuse.test" ipv6:YES]isEqual:old6]);
    assert([[pool statistics][@"retired"]unsignedIntegerValue]==1);

    MLTimedFakeIP *bounded=[[MLTimedFakeIP alloc]initWithRange:nil ipv6Range:@"fd00:5e4b:1::/112" capacity:512];
    bounded.testNow=1000;
    NSString *label=[@"a" stringByPaddingToLength:63 withString:@"a" startingAtIndex:0];
    for(unsigned i=0;i<1024;i++){
        NSString *tail=[[NSString stringWithFormat:@"h-%u-",i]stringByPaddingToLength:61 withString:@"z" startingAtIndex:0];
        NSString *host=[NSString stringWithFormat:@"%@.%@.%@.%@",label,label,label,tail];
        assert(host.length==253 && [bounded addressForHost:host ipv6:NO]);
    }
    before=[bounded snapshot];assert([before[@"entries"]count]==512 && [before[@"retired"]count]==512);
    assert(![bounded addressForHost:@"retired-limit.test" ipv6:NO] && [[bounded snapshot]isEqual:before]);
    assert([NSJSONSerialization dataWithJSONObject:before options:0 error:NULL].length<=256*1024);
    MLTimedFakeIP *restored=[[MLTimedFakeIP alloc]initWithRange:nil ipv6Range:@"fd00:5e4b:1::/112" capacity:512];
    restored.testNow=50000;assert([restored restoreSnapshot:before error:NULL]);
    assert(![restored addressForHost:@"still-full-after-restart.test" ipv6:NO]);
    restored.testNow=50299;assert(![restored addressForHost:@"still-cooling.test" ipv6:NO]);
    restored.testNow=50300;assert([restored addressForHost:@"cooled-after-restart.test" ipv6:NO]);
}
static void validation(void) {
    MLFakeIP *pool=makePool(512);[pool addressForHost:@"one.test" ipv6:NO];[pool addressForHost:@"two.test" ipv6:NO];
    NSDictionary *valid=[pool snapshot];NSMutableDictionary *bad;
    for(id value in @[@0,@2,@YES,@"1",[NSNull null]]){bad=mutableSnapshot(valid);bad[@"version"]=value;rejected(pool,bad);}
    for(id value in @[@3,@65535,@4.5,@YES,@"4",[NSNull null]]){bad=mutableSnapshot(valid);bad[@"next"]=value;rejected(pool,bad);}
    bad=mutableSnapshot(valid);bad[@"range"]=@"198.19.0.0/16";rejected(pool,bad);
    bad=mutableSnapshot(valid);bad[@"ipv6Range"]=@"fd00:42::/112";rejected(pool,bad);
    bad=mutableSnapshot(valid);[bad removeObjectForKey:@"next"];rejected(pool,bad);
    bad=mutableSnapshot(valid);bad[@"unknown"]=[NSMutableString stringWithCapacity:262144];rejected(pool,bad);
    rejected(pool,(id)@[]);rejected(pool,nil);
    for(NSString *value in @[@"",@"UPPER.test",@"one.test.",@"bad/name",@"bad name",@"a..test",@"中文.test",[@"x" stringByPaddingToLength:64 withString:@"x" startingAtIndex:0]]){
        bad=mutableSnapshot(valid);bad[@"entries"][0][@"host"]=value;rejected(pool,bad);
    }
    for(NSString *value in @[@"198.18.0.0",@"198.18.0.1",@"198.18.0.2",@"198.18.0.3",@"198.18.0.53",@"198.18.255.255",@"198.19.0.4",@"198.18.00.4"]){
        bad=mutableSnapshot(valid);bad[@"entries"][0][@"v4"]=value;rejected(pool,bad);
    }
    for(NSString *value in @[@"fd00:5e4b:1::1",@"fd00:5e4b:1::35",@"fd00:42::4",@"fd00:5e4b:1::5",@"FD00:5E4B:1::4"]){
        bad=mutableSnapshot(valid);bad[@"entries"][0][@"v6"]=value;rejected(pool,bad);
    }
    bad=mutableSnapshot(valid);bad[@"entries"][1][@"host"]=bad[@"entries"][0][@"host"];rejected(pool,bad);
    bad=mutableSnapshot(valid);bad[@"entries"][1][@"v4"]=bad[@"entries"][0][@"v4"];rejected(pool,bad);
    bad=mutableSnapshot(valid);bad[@"entries"][0][@"pins"]=@1;rejected(pool,bad);
    bad=mutableSnapshot(valid);[bad[@"entries"][0]removeObjectForKey:@"v6"];rejected(pool,bad);
    bad=mutableSnapshot(valid);bad[@"entries"]=@"bad";rejected(pool,bad);
    bad=mutableSnapshot(valid);bad[@"entries"]=@[@"bad"];rejected(pool,bad);
    bad=mutableSnapshot(valid);NSMutableArray *tooMany=[NSMutableArray array];
    for(unsigned i=0;i<513;i++)[tooMany addObject:valid[@"entries"][0]];bad[@"entries"]=tooMany;rejected(pool,bad);
    MLFakeIP *limited=makePool(1);rejected(limited,valid);
    MLFakeIP *capped=makePool(4096);assert([[capped statistics][@"capacity"]unsignedIntegerValue]==512);
    for(unsigned i=0;i<512;i++)assert(([capped addressForHost:[NSString stringWithFormat:@"bounded-%u.test",i]ipv6:NO]));
    NSData *encoded=[NSJSONSerialization dataWithJSONObject:[capped snapshot]options:0 error:NULL];assert(encoded.length<=256*1024);
    assert([makePool(512) restoreSnapshot:[capped snapshot]error:NULL]);
    MLFakeIP *retiring=makePool(1);
    [retiring addressForHost:@"old.test" ipv6:NO];[retiring addressForHost:@"new.test" ipv6:NO];
    NSDictionary *retiredValid=[retiring snapshot];assert([retiredValid[@"retired"]count]==1);
    bad=mutableSnapshot(retiredValid);[bad removeObjectForKey:@"retired"];
    assert([makePool(1) restoreSnapshot:bad error:NULL]); // Existing version-1 files remain readable.
    for(id value in @[@"bad",[NSNull null],@[@"bad"]]){
        bad=mutableSnapshot(retiredValid);bad[@"retired"]=value;rejected(retiring,bad);
    }
    bad=mutableSnapshot(retiredValid);bad[@"retired"]=[NSMutableArray arrayWithObject:retiredValid[@"retired"][0]];
    [bad[@"retired"]addObject:retiredValid[@"retired"][0]];rejected(retiring,bad);
    bad=mutableSnapshot(retiredValid);bad[@"retired"][0][@"v4"]=bad[@"entries"][0][@"v4"];rejected(retiring,bad);
    bad=mutableSnapshot(retiredValid);bad[@"retired"][0][@"v6"]=bad[@"entries"][0][@"v6"];rejected(retiring,bad);
    bad=mutableSnapshot(retiredValid);bad[@"retired"][0][@"host"]=@"old.test";rejected(retiring,bad);
    bad=mutableSnapshot(retiredValid);bad[@"retired"][0][@"until"]=@0;rejected(retiring,bad);
    bad=mutableSnapshot(retiredValid);[bad[@"retired"][0]removeObjectForKey:@"v6"];rejected(retiring,bad);
    for(NSString *value in @[@"198.18.0.1",@"198.18.0.53",@"198.18.255.255",@"198.19.0.4"]){
        bad=mutableSnapshot(retiredValid);bad[@"retired"][0][@"v4"]=value;rejected(retiring,bad);
    }
    bad=mutableSnapshot(retiredValid);tooMany=[NSMutableArray array];
    for(unsigned i=0;i<513;i++)[tooMany addObject:retiredValid[@"retired"][0]];
    bad[@"retired"]=tooMany;rejected(retiring,bad);
}
static void acknowledgment(void) {
    MLFakeIP *pool=makePool(2);
    dispatch_semaphore_t started=dispatch_semaphore_create(0),ack=dispatch_semaphore_create(0),finished=dispatch_semaphore_create(0);
    __block int returned=0;
    pool.persistenceHandler=^BOOL(NSDictionary *snapshot){assert([snapshot[@"entries"]count]==1);dispatch_semaphore_signal(started);dispatch_semaphore_wait(ack,DISPATCH_TIME_FOREVER);return YES;};
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{@autoreleasepool{
        assert([pool addressForHost:@"ack.test" ipv6:NO]);__atomic_store_n(&returned,1,__ATOMIC_RELEASE);dispatch_semaphore_signal(finished);
    }});
    assert(dispatch_semaphore_wait(started,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC))==0);
    assert(__atomic_load_n(&returned,__ATOMIC_ACQUIRE)==0);
    dispatch_semaphore_signal(ack);assert(dispatch_semaphore_wait(finished,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC))==0);
    assert(__atomic_load_n(&returned,__ATOMIC_ACQUIRE)==1);
}
static void crashRecovery(void) {
    char directory[]="/tmp/muyu-fake-crash.XXXXXX";assert(mkdtemp(directory));
    NSString *path=[[NSString stringWithUTF8String:directory]stringByAppendingPathComponent:@"snapshot.json"];
    pid_t child=fork();assert(child>=0);
    if(!child){@autoreleasepool{
        MLFakeIP *pool=makePool(2);
        pool.persistenceHandler=^BOOL(NSDictionary *snapshot){
            NSData *json=[NSJSONSerialization dataWithJSONObject:snapshot options:0 error:NULL];
            assert([json writeToFile:path options:NSDataWritingAtomic error:NULL]);
            kill(getpid(),SIGKILL);return NO;
        };
        [pool addressForHost:@"crash.test" ipv6:NO];_exit(20);
    }}
    int status;assert(waitpid(child,&status,0)==child && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
    NSDictionary *saved=[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:path]options:0 error:NULL];
    MLFakeIP *pool=makePool(2);assert([pool restoreSnapshot:saved error:NULL]);
    NSString *address=saved[@"entries"][0][@"v4"];
    assert([[pool hostForAddress:address]isEqual:@"crash.test"] && [[pool addressForHost:@"crash.test" ipv6:NO]isEqual:address]);
    assert(![[pool addressForHost:@"after-crash.test" ipv6:NO]isEqual:address]);
    assert(unlink(path.fileSystemRepresentation)==0 && rmdir(directory)==0);
}
static void quarantineCrashRecovery(void) {
    char directory[]="/tmp/muyu-retired-crash.XXXXXX";assert(mkdtemp(directory));
    NSString *path=[[NSString stringWithUTF8String:directory]stringByAppendingPathComponent:@"snapshot.json"];
    pid_t child=fork();assert(child>=0);
    if(!child){@autoreleasepool{
        MLTimedFakeIP *pool=smallPool(1,1000);
        assert([pool addressForHost:@"before-crash.test" ipv6:NO]);
        pool.testNow=1299;
        assert([pool addressForHost:@"new-before-crash.test" ipv6:NO]);
        pool.persistenceHandler=^BOOL(NSDictionary *snapshot){
            assert([snapshot[@"retired"]count]==2);
            NSData *json=[NSJSONSerialization dataWithJSONObject:snapshot options:0 error:NULL];
            assert([json writeToFile:path options:NSDataWritingAtomic error:NULL]);
            kill(getpid(),SIGKILL);return NO;
        };
        [pool addressForHost:@"ack-crash.test" ipv6:NO];_exit(20);
    }}
    int status;assert(waitpid(child,&status,0)==child && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
    NSDictionary *saved=[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:path]options:0 error:NULL];
    MLTimedFakeIP *pool=smallPool(1,50000);assert([pool restoreSnapshot:saved error:NULL]);
    assert(![pool hostForAddress:@"198.18.0.4"] && ![pool hostForAddress:@"fd00:5e4b:1::4"]);
    assert([[pool hostForAddress:@"198.18.0.6"]isEqual:@"ack-crash.test"]);
    for(unsigned i=0;i<8;i++)assert(([pool addressForHost:[NSString stringWithFormat:@"after-crash-%u.test",i] ipv6:NO]));
    pool.testNow=50299;NSDictionary *before=[pool snapshot];
    assert(![pool addressForHost:@"pre-expiry.test" ipv6:NO] && [[pool snapshot]isEqual:before]);
    pool.testNow=50300;assert([[pool addressForHost:@"post-expiry.test" ipv6:NO]isEqual:@"198.18.0.4"]);
    assert(unlink(path.fileSystemRepresentation)==0 && rmdir(directory)==0);
}
int main(void) { @autoreleasepool {
    MLFakeIP *pool=[[MLFakeIP alloc]initWithRange:@"198.18.0.0/16" ipv6Range:@"fd00:5e4b:1::/112" capacity:2];
    assert(pool);
    NSString *first=[pool addressForHost:@"one.test" ipv6:NO];
    [pool retainAddress:first];
    NSString *second=[pool addressForHost:@"two.test" ipv6:NO];
    [pool retainAddress:second];
    assert(![pool addressForHost:@"third.test" ipv6:NO]);
    assert([[pool hostForAddress:first]isEqual:@"one.test"]);
    assert([[pool hostForAddress:second]isEqual:@"two.test"]);
    [pool releaseAddress:second];
    NSString *third=[pool addressForHost:@"third.test" ipv6:NO];
    assert(third && ![pool hostForAddress:second]);
    assert([[pool hostForAddress:first]isEqual:@"one.test"]);
    NSString *six=[pool addressForHost:@"one.test" ipv6:YES];
    assert(six && [[pool hostForAddress:six]isEqual:@"one.test"]);
    assert([[pool statistics][@"pins"]unsignedIntegerValue]==1);
    assert(![[MLFakeIP alloc]initWithRange:@"not a range" ipv6Range:nil capacity:2]);
    [pool releaseAddress:first];
    MLFakeIP *many=[[MLFakeIP alloc]initWithRange:nil ipv6Range:nil capacity:512];
    for (unsigned i=0;i<512;i++) {
        NSString *host=[NSString stringWithFormat:@"host-%u.test",i];
        NSString *address=[many addressForHost:host ipv6:NO];
        assert((address && ![@[@"198.18.0.1",@"198.18.0.2",@"198.18.0.53"]containsObject:address]));
        assert([[many hostForAddress:address]isEqual:host]);
    }
    persistence();validation();quarantine();crashRecovery();quarantineCrashRecovery();acknowledgment();
    puts("PASS fake IP: ACK before DNS, retired TTL quarantine, wrap exhaustion, rollback, SIGKILL recovery, hostile snapshots, pinned eviction, dual-stack and bounded storage");
}}
