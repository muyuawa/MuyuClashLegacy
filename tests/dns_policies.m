#import <Foundation/Foundation.h>
#import "../dns/MLDNS.h"
#import "../dns/MLFakeIP.h"
#import "../providers/MLGeoFormat.h"
#include <CommonCrypto/CommonDigest.h>
#import "../config/MLConfig.h"
#include <assert.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *hashData(NSData *data) { unsigned char digest[32]; CC_SHA256(data.bytes,(CC_LONG)data.length,digest); NSMutableString *hash=[NSMutableString string]; for (NSUInteger i=0;i<32;++i) [hash appendFormat:@"%02x",digest[i]]; return hash; }
static NSData *query(NSString *host,unsigned type) {
    uint8_t header[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0}; NSMutableData *data=[NSMutableData dataWithBytes:header length:12];
    for (NSString *label in [host componentsSeparatedByString:@"."]) { NSData *part=[label dataUsingEncoding:NSASCIIStringEncoding]; uint8_t size=(uint8_t)part.length; [data appendBytes:&size length:1]; [data appendData:part]; }
    uint8_t tail[]={0,0,(uint8_t)type,0,1}; [data appendBytes:tail length:5]; return data;
}
static NSData *response(NSData *query,NSString *address) {
    NSMutableData *data=[query mutableCopy]; uint8_t *bytes=data.mutableBytes; unsigned type=bytes[data.length-3]; bytes[2]=0x81; bytes[3]=0x80;
    if (type!=1 && type!=28) return data;
    uint8_t ip[16]; unsigned size=type==1 ? 4 : 16;
    if (inet_pton(type==1 ? AF_INET : AF_INET6,address.UTF8String,ip)!=1) return data;
    bytes[7]=1; uint8_t record[]={0xc0,0x0c,0,(uint8_t)type,0,1,0,0,0,30,0,(uint8_t)size}; [data appendBytes:record length:12]; [data appendBytes:ip length:size]; return data;
}
static NSString *wireAddress(NSData *answer) {
    const uint8_t *bytes=answer.bytes; if (answer.length<16 || !bytes[7]) return nil;
    unsigned type=bytes[answer.length-6]; (void)type;
    char text[INET6_ADDRSTRLEN]; if (!inet_ntop(AF_INET,bytes+answer.length-4,text,sizeof text)) return nil; return [NSString stringWithUTF8String:text];
}
static MLDNS *make(NSDictionary *options,NSDictionary *base,NSMutableArray *calls) {
    NSMutableDictionary *document=[base mutableCopy]; document[@"dns"]=options;
    MLDNS *dns=[[MLDNS alloc] initWithOptions:options ipv6:NO]; NSError *error=nil; assert([dns installPreparedDocument:document error:&error] && !error);
    dns.exchangeHandler=^NSData *(NSString *server,NSData *question,double deadline,NSString *context) {
        assert(deadline>[NSProcessInfo processInfo].systemUptime); [calls addObject:@{@"server":server,@"context":context}];
        NSString *address=[server hasPrefix:@"udp://127.0.0.1:5354"] ? @"198.51.100.20" : ([server hasPrefix:@"udp://127.0.0.1:5355"] ? @"198.51.100.30" : @"203.0.113.10");
        return response(question,address);
    }; return dns;
}
int main(int argc,char **argv) { @autoreleasepool {
    if (argc>1) {
        NSDictionary *options=@{@"enable":@YES,@"nameserver":@[[NSString stringWithUTF8String:argv[1]]]};
        MLDNS *direct=[[MLDNS alloc] initWithOptions:options ipv6:NO]; assert([direct installPreparedDocument:@{@"dns":options} error:NULL]);
        assert([[direct lookup:@"direct.test"][@"addresses"][0] isEqual:@"192.0.2.77"]);
        assert([wireAddress([direct answerQuery:query(@"direct-wire.test",1) application:YES]) isEqual:@"192.0.2.77"]);
        puts("PASS actual UDP #DIRECT with default DNS exchange and wire responses"); return 0;
    }
    char temporary[]="/private/tmp/muyu-dns-policies.XXXXXX"; assert(mkdtemp(temporary)); NSString *directory=[NSString stringWithUTF8String:temporary];
    unsigned char range[33]={4}; assert(inet_pton(AF_INET,"198.51.100.0",range+1)==1); assert(inet_pton(AF_INET,"198.51.100.255",range+17)==1);
    NSMutableData *sites=[NSMutableData data]; NSData *domain=[@"geo.test" dataUsingEncoding:NSUTF8StringEncoding]; unsigned char header[]={2,0,(unsigned char)domain.length}; [sites appendBytes:header length:3]; [sites appendData:domain];
    NSMutableData *ranges=[NSMutableData dataWithBytes:range length:33]; unsigned char range6[33]={6}; assert(inet_pton(AF_INET6,"2001:db8:2::",range6+1)==1); assert(inet_pton(AF_INET6,"2001:db8:2:0:ffff:ffff:ffff:ffff",range6+17)==1); [ranges appendBytes:range6 length:33];
    NSData *index=MLGeoEncodeIndex(@{@"geoip:cn":@{@"kind":@"geoip",@"key":@"cn",@"payload":ranges,@"count":@2,@"inverse":@NO},@"geosite:test":@{@"kind":@"geosite",@"key":@"test",@"payload":sites,@"count":@1,@"inverse":@NO}},NULL); assert(index);
    NSString *path=[directory stringByAppendingPathComponent:@"fixture.index"]; assert([index writeToFile:path atomically:NO]); assert(chmod(path.fileSystemRepresentation,0444)==0);
    NSDictionary *base=@{@"_geo-index":@{@"path":path,@"owner":@(geteuid()),@"size":@(index.length),@"sha256":hashData(index)},@"_rule-provider-payloads":@{@"Domains":@{@"behavior":@"domain",@"payload":@[@"+.rules.test"]},@"Classical":@{@"behavior":@"classical",@"payload":@[@"DOMAIN-SUFFIX,classical.test",@"IP-CIDR,0.0.0.0/0"]}}};
    NSString *main=@"udp://127.0.0.1:5353", *fallback=@"udp://127.0.0.1:5354", *special=@"udp://127.0.0.1:5355"; NSMutableArray *calls=[NSMutableArray array];
    NSDictionary *options=@{@"enable":@YES,@"nameserver":@[main],@"fallback":@[fallback],@"fallback-filter":@{@"geoip":@YES,@"geoip-code":@"CN",@"domain":@[@"+.force.test"],@"geosite":@[@"test"]}};
    MLDNS *dns=make(options,base,calls); assert([[dns lookup:@"outside.test"][@"addresses"][0] isEqual:@"198.51.100.20"]); assert(calls.count==2);
    [calls removeAllObjects]; assert([wireAddress([dns answerQuery:query(@"outside-wire.test",1) application:YES]) isEqual:@"198.51.100.20"]); assert(calls.count==2);
    [calls removeAllObjects]; assert([wireAddress([dns answerQuery:query(@"x.force.test",1) application:YES]) isEqual:@"198.51.100.20"]); assert(calls.count==1 && [calls[0][@"server"] isEqual:fallback]);
    [calls removeAllObjects]; assert([[dns lookup:@"x.geo.test"][@"source"] isEqual:fallback]); assert(calls.count==1);
    [calls removeAllObjects]; assert([dns answerQuery:query(@"x.geo.test",16) application:YES]); assert(calls.count==1 && [calls[0][@"server"] isEqual:main]);
    dns=make(options,base,calls); [calls removeAllObjects]; dns.exchangeHandler=^NSData *(NSString *server,NSData *question,double deadline,NSString *context) { (void)deadline; (void)context; [calls addObject:server]; return response(question,@"192.168.1.2"); };
    assert([[dns lookup:@"private.test"][@"source"] isEqual:main]); assert(calls.count==1);
    NSMutableDictionary *sixOptions=[options mutableCopy]; sixOptions[@"ipv6"]=@YES; MLDNS *six=[[MLDNS alloc] initWithOptions:sixOptions ipv6:YES]; NSMutableDictionary *sixDocument=[base mutableCopy]; sixDocument[@"dns"]=sixOptions; assert([six installPreparedDocument:sixDocument error:NULL]);
    six.exchangeHandler=^NSData *(NSString *server,NSData *question,double deadline,NSString *context) { (void)deadline;(void)context; const uint8_t *q=question.bytes; BOOL v6=q[question.length-3]==28; return response(question,[server isEqual:fallback] ? (v6 ? @"2001:db8:2::20" : @"198.51.100.20") : (v6 ? @"2001:db8:1::10" : @"203.0.113.10")); };
    NSData *sixAnswer=[six answerQuery:query(@"six.test",28) application:YES]; assert(sixAnswer.length>=28); char sixText[INET6_ADDRSTRLEN]; assert(inet_ntop(AF_INET6,(const uint8_t *)sixAnswer.bytes+sixAnswer.length-16,sixText,sizeof sixText)); assert(!strcmp(sixText,"2001:db8:2::20"));
    NSMutableDictionary *filtered=[options mutableCopy]; filtered[@"fallback-filter"]=@{@"geoip":@NO,@"ipcidr":@[@"203.0.113.10/32"]}; dns=make(filtered,base,calls); assert([[dns lookup:@"cidr.test"][@"source"] isEqual:fallback]);
    filtered[@"fallback-filter"]=@{@"geoip":@NO}; dns=make(filtered,base,calls); assert([[dns lookup:@"normal.test"][@"source"] isEqual:main]);
    NSMutableDictionary *policy=[filtered mutableCopy]; policy[@"nameserver-policy"]=@{@"geosite:test":special,@"rule-set:Domains,Classical":@[special]};
    NSMutableDictionary *ordered=[base mutableCopy]; ordered[@"_dns-policy-order"]=@[@"geosite:test",@"rule-set:Domains,Classical"];
    dns=make(policy,ordered,calls); assert([[dns lookup:@"x.geo.test"][@"source"] isEqual:special]); assert([[dns lookup:@"x.rules.test"][@"source"] isEqual:special]); assert([[dns lookup:@"x.classical.test"][@"source"] isEqual:special]); assert([[dns lookup:@"unmatched.test"][@"source"] isEqual:main]);
    NSMutableDictionary *fake=[policy mutableCopy]; fake[@"enhanced-mode"]=@"fake-ip"; fake[@"fake-ip-filter"]=@[@"geosite:test",@"rule-set:Domains"];
    dns=make(fake,ordered,calls); dns.fakeIP=[[MLFakeIP alloc] initWithRange:nil ipv6Range:nil capacity:32];
    assert([wireAddress([dns answerQuery:query(@"x.rules.test",1) application:YES]) isEqual:@"198.51.100.30"]);
    assert([wireAddress([dns answerQuery:query(@"fake.test",1) application:YES]) hasPrefix:@"198.18."]);
    fake[@"fake-ip-filter-mode"]=@"whitelist"; dns=make(fake,ordered,calls); dns.fakeIP=[[MLFakeIP alloc] initWithRange:nil ipv6Range:nil capacity:32];
    assert([wireAddress([dns answerQuery:query(@"x.rules.test",1) application:YES]) hasPrefix:@"198.18."]); assert([wireAddress([dns answerQuery:query(@"real.test",1) application:YES]) isEqual:@"203.0.113.10"]);
    NSDictionary *contexts=@{@"enable":@YES,@"nameserver":@[main],@"default-nameserver":@[main],@"proxy-server-nameserver":@[main],@"direct-nameserver":@[main],@"respect-rules":@YES};
    dns=make(contexts,base,calls); [calls removeAllObjects]; assert([dns lookupBootstrap:@"boot.test"] && [dns lookupProxyServer:@"proxy.test"] && [dns lookupDirect:@"direct.test"] && [dns lookup:@"app.test"]);
    assert(calls.count==4); assert([calls[0][@"context"] isEqual:@"bootstrap"]); assert([calls[1][@"context"] isEqual:@"proxy"]); assert([calls[2][@"context"] isEqual:@"direct"]); assert([calls[3][@"context"] isEqual:@"application"]);
    dns.exchangeHandler=^NSData *(NSString *server,NSData *question,double deadline,NSString *context) { (void)server;(void)question;(void)deadline;(void)context; return nil; }; assert(![dns lookup:@"failed.test"]);
    NSData *failed=[dns answerQuery:query(@"wire-failed.test",1) application:YES]; assert(failed && (((const uint8_t *)failed.bytes)[3]&15)==2);
    NSError *error=nil; MLDNS *missing=[[MLDNS alloc] initWithOptions:policy ipv6:NO]; assert(![missing installPreparedDocument:@{} error:&error] && error);
    NSDictionary *report=[MLConfig checkYAML:@"dns:\n  enable: true\n  nameserver: [127.0.0.1]\n  nameserver-policy:\n    geosite:test: 127.0.0.2\n    '+.geo.test': 127.0.0.3\n    geosite:other: 127.0.0.4\n"]; assert([report[@"valid"] boolValue]); assert(([report[@"document"][@"_dns-policy-order"] isEqual:@[@"geosite:test",@"+.geo.test",@"geosite:other"]]));
    for (id bad in @[[NSNull null],@1,@{}]) { assert(MLDNSUnsupportedField(@{@"fallback-filter":@{@"ipcidr":bad}})); }
    assert(MLDNSUnsupportedField(@{@"proxy-server-nameserver":@[@"127.0.0.1#PROXY"]}));
    assert(MLDNSUnsupportedField(@{@"default-nameserver":@[@"127.0.0.1#PROXY"]}));
    assert(!MLDNSUnsupportedField(@{@"default-nameserver":@[@"127.0.0.1#DIRECT"]}));
    [[NSFileManager defaultManager] removeItemAtPath:directory error:NULL]; puts("PASS DNS Geo/Provider policies, ordered preparation, fallback domain/GeoIP/CIDR, Fake-IP filters and exchange contexts");
} return 0; }
