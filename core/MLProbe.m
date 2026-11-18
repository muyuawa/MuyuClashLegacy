#import "MLProbe.h"
#import "MLRelay.h"
#include <errno.h>
#include <poll.h>
#include <TargetConditionals.h>
#ifndef MLPROBE_CA_BUNDLE
#define MLPROBE_CA_BUNDLE "/usr/share/muyuclash/cacert.pem"
#endif

BOOL MLProbeURLIsValid(NSString *text) {
    if (![text isKindOfClass:[NSString class]] || text.length > 1024 ||
        (![[text lowercaseString]hasPrefix:@"http://"]&&![[text lowercaseString]hasPrefix:@"https://"])) return NO;
    if ([text rangeOfCharacterFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].location != NSNotFound ||
        [text rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location != NSNotFound) return NO;
    NSURL *url=[NSURL URLWithString:text];
    return url.host.length&&!url.user&&!url.password&&!url.fragment&&
        (!url.port||(url.port.integerValue>0&&url.port.integerValue<=UINT16_MAX));
}
NSDictionary *MLProbeStreamWithTimeout(NSString *node, NSString *urlText, NSUInteger timeout) {
    if (!MLProbeURLIsValid(urlText)||timeout<100||timeout>30000) return @{@"health":@"invalid"};
    NSURL *url=[NSURL URLWithString:urlText];
    BOOL tls=[url.scheme.lowercaseString isEqual:@"https"];
    NSString *host=url.host;
    if ([host hasPrefix:@"["]&&[host hasSuffix:@"]"]) host=[host substringWithRange:NSMakeRange(1,host.length-2)];
    uint16_t port=url.port?(uint16_t)url.port.integerValue:(tls?443:80);
    NSUInteger prefix=tls?8:7;
    NSRange slash=[urlText rangeOfString:@"/" options:0 range:NSMakeRange(prefix,urlText.length-prefix)];
    NSRange question=[urlText rangeOfString:@"?" options:0 range:NSMakeRange(prefix,urlText.length-prefix)];
    NSUInteger end=slash.location==NSNotFound?urlText.length:slash.location;
    if (question.location!=NSNotFound&&question.location<end) end=question.location;
    NSString *authority=[urlText substringWithRange:NSMakeRange(prefix,end-prefix)];
    NSString *resource=end==urlText.length?@"/":[urlText substringFromIndex:end];
    if ([resource hasPrefix:@"?"]) resource=[@"/" stringByAppendingString:resource];
    NSData *payload=[[NSString stringWithFormat:@"HEAD %@ HTTP/1.1\r\nHost: %@\r\nConnection: close\r\n\r\n",resource,authority]dataUsingEncoding:NSASCIIStringEncoding];
    if (!payload) return @{@"health":@"invalid"};
    uint64_t started=MLMilliseconds(),deadline=started+timeout;
    BOOL chain=[[node stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] hasPrefix:@"["];
    MLStream *stream=chain?MLStreamOpenChain(node.UTF8String,host.UTF8String,port,(unsigned)timeout):MLStreamOpen(node.UTF8String,host.UTF8String,port,(unsigned)timeout);
    if (!stream) return @{@"health":errno==ETIMEDOUT?@"timeout":@"failed"};
    if (tls) {
        uint64_t now=MLMilliseconds();
        MLStream *wrapped=now<deadline?MLStreamWrapTLS(stream,host.UTF8String,MLPROBE_CA_BUNDLE,(unsigned)(deadline-now)):NULL;
        if (!wrapped) { MLStreamClose(stream); return @{@"health":errno==ETIMEDOUT?@"timeout":@"failed"}; }
        stream=wrapped;
    }
    size_t sent=0,received=0;
    char header[4096];
    NSString *health=@"timeout";
    unsigned status=0;
    while (MLMilliseconds()<deadline) {
        if (sent<payload.length) {
            ssize_t n=MLStreamWrite(stream,(const char *)payload.bytes+sent,payload.length-sent);
            if (n>0) sent+=(size_t)n;
            else if (n==0||(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)) { health=@"failed"; break; }
        }
        if (MLStreamPump(stream)<0) { health=@"failed"; break; }
        ssize_t n=MLStreamRead(stream,header+received,sizeof(header)-1-received);
        if (n>0) {
            received+=(size_t)n; header[received]=0;
            for (;;) {
                char *line=strstr(header,"\r\n");
                if (!line) break;
                unsigned code=0;
                if (sscanf(header,"HTTP/%*u.%*u %u",&code)!=1||code<100||code>599) { health=@"failed"; break; }
                char *endHeader=strstr(header,"\r\n\r\n");
                if (endHeader&&(code>=200||code==101)) { status=code; health=@"healthy"; break; }
                if (endHeader) {
                    size_t consumed=(size_t)(endHeader-header)+4;
                    memmove(header,header+consumed,received-consumed); received-=consumed;
                    header[received]=0;
                } else break;
            }
            if (status || [health isEqual:@"failed"]) break;
            if (received==sizeof(header)-1) { health=@"failed"; break; }
        } else if (n==0||(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)) { health=@"failed"; break; }
        if (MLStreamPendingRead(stream)) continue;
        uint64_t now=MLMilliseconds(); if (now>=deadline) break;
        struct pollfd ready={MLStreamFD(stream),MLStreamEvents(stream,1,sent<payload.length),0};
        if (poll(&ready,1,(int)(deadline-now))<0&&errno!=EINTR) { health=@"failed"; break; }
    }
    MLStreamClose(stream);
    if (!status) return @{@"health":health};
    return @{@"health":health,@"status":@(status),@"delay":@(MAX(1,MLMilliseconds()-started))};
}
NSDictionary *MLProbeStream(NSString *node,NSString *url) { return MLProbeStreamWithTimeout(node,url,3500); }
