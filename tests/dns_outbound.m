#import <Foundation/Foundation.h>
#import "../dns/MLDNSOutbound.h"
#include <assert.h>
#include <stdlib.h>
int main(int argc,const char **argv){@autoreleasepool{
    if(argc!=7)return 64;
    NSString *url=[NSString stringWithUTF8String:argv[1]],*ca=[NSString stringWithUTF8String:argv[2]];
    NSArray *chain=[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:[NSString stringWithUTF8String:argv[3]]] options:0 error:NULL];
    NSString *context=[NSString stringWithUTF8String:argv[4]];BOOL respect=atoi(argv[5]),expected=atoi(argv[6]);
    const uint8_t question[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,3,'d','n','s',7,'f','i','x','t','u','r','e',0,0,1,0,1};
    __block unsigned routes=0;
    NSData *answer=MLDNSOutboundQuery(url,[NSData dataWithBytes:question length:sizeof question],[NSProcessInfo processInfo].systemUptime+2,context,ca.length?ca:nil,respect,^NSDictionary *(NSString *host,NSString *ip,uint16_t port,NSString *network,NSString *group){
        (void)host;(void)port;(void)network;routes++;
        if([group isEqual:@"REJECT"])return nil;
        return @{@"target":ip,@"chain":chain};
    });
    BOOL passed=NO;
    if(answer.length>=16){const uint8_t *bytes=answer.bytes;const uint8_t target[]={203,0,113,7};passed=bytes[0]==0x12&&bytes[1]==0x34&&(bytes[3]&15)==0&&bytes[7]==1&&!memcmp(bytes+answer.length-4,target,4);}
    if(passed!=expected){fprintf(stderr,"DNS outbound expected=%d got=%d bytes=%lu routes=%u\n",expected,passed,(unsigned long)answer.length,routes);return 1;}
    if(expected&&respect&&[context isEqual:@"application"]&&routes==0)return 2;
    printf("PASS DNS outbound expected=%d routes=%u\n",expected,routes);return 0;
}}
