#import <Foundation/Foundation.h>
#import "../dns/MLDNS.h"
#import "../config/MLConfig.h"
#include <stdlib.h>
#include <stdio.h>
int main(int argc,const char **argv) { @autoreleasepool {
    if (argc!=5) return 64;
    NSString *url=[NSString stringWithUTF8String:argv[1]],*ca=[NSString stringWithUTF8String:argv[2]];
    BOOL expected=atoi(argv[3]),valid=atoi(argv[4]);
    NSDictionary *options=@{@"enable":@YES,@"nameserver":@[url]},*document=@{@"dns":options};
    NSString *text=[[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:document options:0 error:NULL] encoding:NSUTF8StringEncoding];
    if ([[MLConfig checkYAML:text][@"valid"] boolValue]!=valid) return 1;
    MLDNS *dns=[[MLDNS alloc] initWithOptions:options ipv6:NO]; dns.caPath=ca;
    if ([dns installPreparedDocument:document error:NULL]!=valid) return 2;
    if (!valid) { puts("PASS default DNS rejected unsupported endpoint"); return 0; }
    if (dns.exchangeHandler) return 3;
    NSDictionary *lookup=[dns lookup:@"dns.fixture"];
    BOOL resolved=[lookup[@"addresses"] containsObject:@"203.0.113.7"];
    const uint8_t bytes[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,3,'d','n','s',7,'f','i','x','t','u','r','e',0,0,1,0,1};
    NSData *answer=[dns answerQuery:[NSData dataWithBytes:bytes length:sizeof bytes] application:YES];
    const uint8_t *wire=answer.bytes; BOOL forwarded=answer.length>=16 && wire[0]==0x12 && wire[1]==0x34 && (wire[3]&15)==0 && wire[7]==1;
    if (resolved!=expected || forwarded!=expected) { fprintf(stderr,"default DNS expected=%d lookup=%d wire=%d\n",expected,resolved,forwarded); return 4; }
    puts("PASS default DNS without handler: verified DoQ, lookup and original wire ID"); return 0;
} }
