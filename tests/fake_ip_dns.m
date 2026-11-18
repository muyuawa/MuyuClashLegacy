#import <Foundation/Foundation.h>
#import "../dns/MLFakeIP.h"
#import "../dns/MLDNS.h"
#include <arpa/inet.h>
#include <assert.h>

@interface MLTimedFakeDNSPool : MLFakeIP
@property(nonatomic) NSTimeInterval testNow;
@end
@implementation MLTimedFakeDNSPool
- (NSTimeInterval)monotonicNow { return self.testNow; }
@end
static NSData *question(NSString *host,unsigned type) {
    unsigned char header[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0};
    NSMutableData *query=[NSMutableData dataWithBytes:header length:sizeof header];
    for(NSString *label in [host componentsSeparatedByString:@"."]){
        NSData *bytes=[label dataUsingEncoding:NSASCIIStringEncoding];uint8_t size=(uint8_t)bytes.length;
        [query appendBytes:&size length:1];[query appendData:bytes];
    }
    uint8_t tail[]={0,0,(uint8_t)type,0,1};[query appendBytes:tail length:sizeof tail];return query;
}
static MLDNS *resolver(MLFakeIP *pool) {
    MLDNS *dns=[[MLDNS alloc]initWithOptions:@{@"enable":@YES,@"ipv6":@YES,@"enhanced-mode":@"fake-ip",@"nameserver":@[]} ipv6:YES];
    dns.fakeIP=pool;return dns;
}
static void answer(MLDNS *dns,NSString *host,unsigned type,unsigned expected) {
    NSData *query=question(host,type),*wire=[dns answerQuery:query application:YES];assert(wire.length>=12);
    const uint8_t *bytes=wire.bytes;assert(bytes[0]==0x12 && bytes[1]==0x34 && (bytes[3]&15)==expected);
    assert(bytes[6]==0 && bytes[7]==(expected?0:1));
    if(!expected){
        // The quarantine must cover the actual TTL advertised on the wire.
        NSUInteger offset=query.length+6;assert(wire.length>=offset+4);
        uint32_t ttl=((uint32_t)bytes[offset]<<24)|((uint32_t)bytes[offset+1]<<16)|((uint32_t)bytes[offset+2]<<8)|bytes[offset+3];
        assert(ttl==300);
    }
}
int main(void){@autoreleasepool{
    MLFakeIP *pool=[[MLFakeIP alloc]initWithRange:nil ipv6Range:@"fd00:5e4b:1::/112" capacity:512];
    MLDNS *dns=resolver(pool);
    pool.persistenceHandler=^BOOL(NSDictionary *snapshot){(void)snapshot;return NO;};
    answer(dns,@"crash.test",1,2);answer(dns,@"crash.test",28,2);
    assert([[pool statistics][@"entries"]unsignedIntegerValue]==0);
    __block NSDictionary *committed;
    pool.persistenceHandler=^BOOL(NSDictionary *snapshot){committed=snapshot;return YES;};
    answer(dns,@"crash.test",1,0);
    NSString *v4=[pool addressForHost:@"crash.test" ipv6:NO],*v6=[pool addressForHost:@"crash.test" ipv6:YES];
    assert(v4 && v6 && committed);
    MLFakeIP *replacement=[[MLFakeIP alloc]initWithRange:nil ipv6Range:@"fd00:5e4b:1::/112" capacity:512];
    assert([replacement restoreSnapshot:committed error:NULL]);
    replacement.persistenceHandler=^BOOL(NSDictionary *snapshot){(void)snapshot;return NO;};
    MLDNS *after=resolver(replacement);
    answer(after,@"crash.test",1,0);answer(after,@"crash.test",28,0);
    assert([[after hostForFakeAddress:v4]isEqual:@"crash.test"] && [[after hostForFakeAddress:v6]isEqual:@"crash.test"]);
    answer(after,@"new.test",1,2);assert([[replacement statistics][@"entries"]unsignedIntegerValue]==1);
    MLTimedFakeDNSPool *small=[[MLTimedFakeDNSPool alloc]initWithRange:@"198.18.0.0/28" ipv6Range:@"fd00:5e4b:1::/112" capacity:1];
    small.testNow=1000;MLDNS *smallDNS=resolver(small);
    answer(smallDNS,@"old.test",1,0);answer(smallDNS,@"old.test",28,0);
    NSString *old4=[small addressForHost:@"old.test" ipv6:NO],*old6=[small addressForHost:@"old.test" ipv6:YES];
    small.testNow=1299;answer(smallDNS,@"old.test",1,0);
    for(unsigned i=0;i<10;i++)answer(smallDNS,[NSString stringWithFormat:@"wrap-%u.test",i],1,0);
    NSDictionary *before=[small snapshot];
    small.testNow=1598;answer(smallDNS,@"overflow.test",1,2);answer(smallDNS,@"overflow.test",28,2);
    assert([[small snapshot]isEqual:before] && ![smallDNS hostForFakeAddress:old4] && ![smallDNS hostForFakeAddress:old6]);
    small.testNow=1599;
    small.persistenceHandler=^BOOL(NSDictionary *snapshot){(void)snapshot;return NO;};
    answer(smallDNS,@"overflow.test",1,2);assert([[small snapshot]isEqual:before]);
    small.persistenceHandler=^BOOL(NSDictionary *snapshot){(void)snapshot;return YES;};
    answer(smallDNS,@"overflow.test",1,0);answer(smallDNS,@"overflow.test",28,0);
    assert([[small addressForHost:@"overflow.test" ipv6:NO]isEqual:old4] && [[small addressForHost:@"overflow.test" ipv6:YES]isEqual:old6]);
    MLFakeIP *full=[[MLFakeIP alloc]initWithRange:@"198.18.0.0/28" ipv6Range:@"fd00:5e4b:1::/112" capacity:512];
    MLDNS *fullDNS=resolver(full);
    for(unsigned i=0;i<11;i++)answer(fullDNS,[NSString stringWithFormat:@"full-%u.test",i],1,0);
    before=[full snapshot];answer(fullDNS,@"full-overflow.test",1,2);answer(fullDNS,@"full-overflow.test",28,2);
    assert([[full snapshot]isEqual:before]);answer(fullDNS,@"full-0.test",1,0);answer(fullDNS,@"full-0.test",28,0);
    puts("PASS DNS Fake-IP TTL300, SERVFAIL on exhaustion/failed ACK, retired wrap quarantine and cached dual-stack recovery");return 0;
}}
