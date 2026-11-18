#import "MLDNSOutbound.h"
#import "MLDoH.h"
#import "MLDNSWire.h"
#import "../protocols/MLStream.h"
#import "../protocols/MLDNSDoQ.h"
#import "../transport/MLNetworkBinding.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>

static unsigned MLRemaining(double deadline) {
    double ms=(deadline-[NSProcessInfo processInfo].systemUptime)*1000;
    return ms>0?(unsigned)MIN(ms,120000.0):0;
}
static BOOL MLWaitStream(MLStream *stream,double deadline,BOOL write) {
    unsigned left=MLRemaining(deadline);if(!left)return NO;
    if(!write&&MLStreamPendingRead(stream))return YES;
    struct pollfd fd={MLStreamFD(stream),MLStreamEvents(stream,!write,write),0};
    int rc=poll(&fd,1,(int)MIN(left,100U));
    if(rc<0&&errno!=EINTR)return NO;
    return MLStreamPump(stream)>=0&&MLRemaining(deadline)>0;
}
static BOOL MLWriteStream(MLStream *stream,NSData *data,double deadline) {
    size_t offset=0;
    while(offset<data.length) {
        if(!MLRemaining(deadline))return NO;
        ssize_t n=MLStreamWrite(stream,(const uint8_t *)data.bytes+offset,data.length-offset);
        if(n>0){offset+=(size_t)n;continue;}
        if(n==0||(errno!=EAGAIN&&errno!=EWOULDBLOCK)||!MLWaitStream(stream,deadline,YES))return NO;
    }
    while(MLStreamWritePending(stream))if(!MLWaitStream(stream,deadline,YES))return NO;
    return YES;
}
static ssize_t MLReadStream(MLStream *stream,void *buffer,size_t length,double deadline) {
    while(MLRemaining(deadline)) {
        ssize_t n=MLStreamRead(stream,buffer,length);
        if(n>=0)return n;
        if((errno!=EAGAIN&&errno!=EWOULDBLOCK)||!MLWaitStream(stream,deadline,NO))return -1;
    }
    errno=ETIMEDOUT;return -1;
}
static NSData *MLExactStream(MLStream *stream,size_t length,double deadline) {
    if(length>4096)return nil;
    NSMutableData *data=[NSMutableData dataWithLength:length];size_t offset=0;
    while(offset<length) {
        ssize_t n=MLReadStream(stream,(uint8_t *)data.mutableBytes+offset,length-offset,deadline);
        if(n<=0)return nil;offset+=(size_t)n;
    }
    return data;
}
static BOOL MLFillBody(NSMutableData *body,MLStream *stream,NSUInteger minimum,double deadline) {
    if(minimum>16384)return NO;
    while(body.length<minimum) {
        uint8_t part[1024];ssize_t n=MLReadStream(stream,part,MIN(sizeof(part),16384-body.length),deadline);
        if(n<=0)return NO;[body appendBytes:part length:(NSUInteger)n];
    }
    return YES;
}
static NSData *MLHTTPAnswer(MLStream *stream,double deadline) {
    NSMutableData *bytes=[NSMutableData data];NSData *marker=[@"\r\n\r\n" dataUsingEncoding:NSASCIIStringEncoding];NSRange end;
    for(;;) {
        end=[bytes rangeOfData:marker options:0 range:NSMakeRange(0,bytes.length)];
        if(end.location!=NSNotFound)break;
        if(bytes.length>=8192)return nil;
        uint8_t part[1024];ssize_t n=MLReadStream(stream,part,MIN(sizeof(part),8192-bytes.length),deadline);
        if(n<=0)return nil;[bytes appendBytes:part length:(NSUInteger)n];
    }
    NSString *headers=[[NSString alloc]initWithData:[bytes subdataWithRange:NSMakeRange(0,end.location)] encoding:NSASCIIStringEncoding];
    NSArray *lines=[headers componentsSeparatedByString:@"\r\n"];
    if(!([lines[0] hasPrefix:@"HTTP/1.1 200 "]||[lines[0] hasPrefix:@"HTTP/1.0 200 "]))return nil;
    NSMutableDictionary *fields=[NSMutableDictionary dictionary];
    for(NSUInteger i=1;i<lines.count;i++) {
        NSRange colon=[lines[i] rangeOfString:@":"];if(colon.location==NSNotFound||colon.location==0)return nil;
        NSString *name=[[lines[i] substringToIndex:colon.location] lowercaseString];
        NSString *value=[[lines[i] substringFromIndex:colon.location+1] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if([@[@"content-length",@"transfer-encoding",@"content-type"] containsObject:name]&&fields[name])return nil;
        fields[name]=value;
    }
    if(![[fields[@"content-type"] lowercaseString] isEqual:@"application/dns-message"]||fields[@"content-encoding"])return nil;
    NSMutableData *body=[[bytes subdataWithRange:NSMakeRange(NSMaxRange(end),bytes.length-NSMaxRange(end))] mutableCopy];
    NSString *length=fields[@"content-length"],*transfer=[fields[@"transfer-encoding"] lowercaseString];
    if(length&&transfer)return nil;
    if(length) {
        if(!length.length||length.length>4||[length rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789"] invertedSet]].location!=NSNotFound)return nil;
        NSUInteger count=length.integerValue;if(count<12||count>4096||body.length>count)return nil;
        NSData *rest=MLExactStream(stream,count-body.length,deadline);if(!rest)return nil;[body appendData:rest];return body;
    }
    if(transfer&&![transfer isEqual:@"chunked"])return nil;
    if(transfer) {
        NSMutableData *decoded=[NSMutableData data];NSUInteger offset=0;
        for(;;) {
            NSUInteger start=offset;const uint8_t *raw;
            for(;;) {
                if(!MLFillBody(body,stream,offset+2,deadline))return nil;raw=body.bytes;
                if(raw[offset]==13&&raw[offset+1]==10)break;
                if(offset-start>=16)return nil;offset++;
            }
            if(offset==start)return nil;size_t count=0;
            for(NSUInteger i=start;i<offset;i++) {
                unsigned c=raw[i],digit=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:16;
                if(digit>=16||count>4096/16)return nil;count=count*16+digit;
            }
            offset+=2;
            if(count>4096-decoded.length||!MLFillBody(body,stream,offset+count+2,deadline))return nil;
            raw=body.bytes;
            if(raw[offset+count]!=13||raw[offset+count+1]!=10)return nil;
            if(!count)return decoded.length>=12&&body.length==offset+2?decoded:nil;
            [decoded appendBytes:raw+offset length:count];offset+=count+2;
        }
    }
    NSUInteger maximum=4096;
    for(;;) {
        uint8_t part[1024];ssize_t n=MLReadStream(stream,part,sizeof(part),deadline);
        if(n<0)return nil;if(!n)break;
        if(body.length+(NSUInteger)n>maximum)return nil;[body appendBytes:part length:(NSUInteger)n];
    }
    return body.length>=12?body:nil;
}
static NSData *MLDatagramAnswer(NSArray *chain,NSString *target,uint16_t port,NSData *query,double deadline) {
    if(chain.count>1)return nil;
    NSDictionary *node=chain.firstObject;
    if([node[@"type"] isEqual:@"direct"])node=nil;
    NSData *json=node?[NSJSONSerialization dataWithJSONObject:node options:0 error:NULL]:nil;
    NSString *text=json?[[NSString alloc]initWithData:json encoding:NSUTF8StringEncoding]:nil;
    if(node&&!text)return nil;
    MLDatagram *datagram=MLDatagramOpen(text.UTF8String,target.UTF8String,port,MLRemaining(deadline));if(!datagram)return nil;
    NSData *answer=nil;BOOL sent=NO;
    while(MLRemaining(deadline)) {
        ssize_t n;
        if(!sent) {
            n=MLDatagramWrite(datagram,query.bytes,query.length);
            if(n==(ssize_t)query.length){sent=YES;continue;}
        } else {
            uint8_t bytes[4096];n=MLDatagramRead(datagram,bytes,sizeof(bytes));
            if(n>0){answer=[NSData dataWithBytes:bytes length:(NSUInteger)n];break;}
        }
        if(n>=0||(errno!=EAGAIN&&errno!=EWOULDBLOCK))break;
        struct pollfd fd={MLDatagramFD(datagram),sent?POLLIN:POLLOUT,0};
        if(poll(&fd,1,(int)MIN(MLRemaining(deadline),100U))<0&&errno!=EINTR)break;
    }
    MLDatagramClose(datagram);return answer;
}
static NSData *MLDoQAnswer(NSString *target,uint16_t port,NSString *serverName,NSString *caPath,NSData *query,double deadline) {
    uint8_t response[4096];char error[256];unsigned left=MLRemaining(deadline);if(left<100)return nil;
    ssize_t count=MLDNSDoQQuery(target.UTF8String,port,serverName.UTF8String,caPath.fileSystemRepresentation,query.bytes,query.length,response,sizeof(response),MIN(left,60000U),error,sizeof(error));
    if(count<12)return nil;const uint8_t *request=query.bytes;response[0]=request[0];response[1]=request[1];
    return [NSData dataWithBytes:response length:(NSUInteger)count];
}
NSData *MLDNSOutboundQuery(NSString *serverText,NSData *query,double deadline,NSString *context,
    NSString *caPath,BOOL respectRules,MLDNSOutboundRoute route) {
    if(!MLRemaining(deadline)||query.length<12||query.length>4096)return nil;
    NSRange hash=[serverText rangeOfString:@"#"];NSString *group=nil;
    if(hash.location!=NSNotFound){group=[[serverText substringFromIndex:hash.location+1] stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];serverText=[serverText substringToIndex:hash.location];if(!group.length)return nil;}
    BOOL bootstrap=[context isEqual:@"bootstrap"]||[context isEqual:@"proxy"];
    if(bootstrap&&group&&![group isEqual:@"DIRECT"])return nil;
    NSString *urlText=[serverText rangeOfString:@"://"].location==NSNotFound?[@"udp://" stringByAppendingString:serverText]:serverText;
    NSURL *url=[NSURL URLWithString:urlText];NSString *scheme=url.scheme.lowercaseString,*host=url.host;
    if([host hasPrefix:@"["]&&[host hasSuffix:@"]"])host=[host substringWithRange:NSMakeRange(1,host.length-2)];
    BOOL doh=[scheme isEqual:@"https"],tls=[scheme isEqual:@"tls"],doq=[scheme isEqual:@"quic"],tcp=doh||tls||[scheme isEqual:@"tcp"];
    if(!host.length||url.user||url.password||url.fragment||(!tcp&&!doq&&![scheme isEqual:@"udp"]))return nil;
    if(!doh&&((url.path.length&&![url.path isEqual:@"/"])||url.query))return nil;
    NSUInteger port=url.port?url.port.unsignedIntegerValue:(doh?443:(tls||doq)?853:53);if(!port||port>65535)return nil;
    NSCharacterSet *unsafe=[NSCharacterSet whitespaceAndNewlineCharacterSet];
    if([host rangeOfCharacterFromSet:unsafe].location!=NSNotFound||
       (url.path&&[url.path rangeOfCharacterFromSet:unsafe].location!=NSNotFound)||
       (url.query&&[url.query rangeOfCharacterFromSet:unsafe].location!=NSNotFound))return nil;
    BOOL routed=!bootstrap&&![group isEqual:@"DIRECT"]&&(group.length||(respectRules&&[context isEqual:@"application"]));
    // curl already handles bounded direct DoH, trust validation and bootstrap.
    if(doh&&!routed)return MLDoHQuery(serverText,query,caPath,MLRemaining(deadline));
    if(doq&&!routed)return MLDoQAnswer(host,(uint16_t)port,host,caPath,query,deadline);
    struct addrinfo hints={0},*addresses=NULL;hints.ai_socktype=tcp?SOCK_STREAM:SOCK_DGRAM;
    if(MLNetworkResolveBootstrapHost(host.UTF8String,[@(port) stringValue].UTF8String,&hints,&addresses))return nil;
    NSData *answer=nil;
    for(struct addrinfo *entry=addresses;entry&&MLRemaining(deadline);entry=entry->ai_next) {
        char ip[INET6_ADDRSTRLEN];if(getnameinfo(entry->ai_addr,entry->ai_addrlen,ip,sizeof(ip),NULL,0,NI_NUMERICHOST))continue;
        NSString *target=[NSString stringWithUTF8String:ip];NSArray *chain=@[];
        if(routed) {
            NSDictionary *decision=route?route(host,target,(uint16_t)port,tcp?@"TCP":@"UDP",group):nil;
            if(!decision||[decision[@"reject"] boolValue])continue;
            target=decision[@"target"]?:target;chain=decision[@"chain"];if(![chain isKindOfClass:[NSArray class]])continue;
        }
        if(doq) {
            // The native QUIC engine owns a physically bound UDP socket.
            // Proxy nesting is refused until that engine accepts a datagram IO.
            if(chain.count)continue;
            double attemptDeadline=entry->ai_next?MIN(deadline,[NSProcessInfo processInfo].systemUptime+MAX(.1,MLRemaining(deadline)/2000.0)):deadline;
            answer=MLDoQAnswer(target,(uint16_t)port,host,caPath,query,attemptDeadline);
        } else if(!tcp) {
            answer=MLDatagramAnswer(chain,target,(uint16_t)port,query,deadline);
            if(answer.length>=12&&(((const uint8_t *)answer.bytes)[2]&2)) {
                NSString *retry=[NSString stringWithFormat:@"tcp://%@:%lu%@",entry->ai_family==AF_INET6?[@"[" stringByAppendingString:[target stringByAppendingString:@"]"]]:target,(unsigned long)port,group?[@"#" stringByAppendingString:group]:@""];
                answer=MLDNSOutboundQuery(retry,query,deadline,context,caPath,respectRules,route);
            }
        } else {
            NSData *nodes=[NSJSONSerialization dataWithJSONObject:chain options:0 error:NULL];
            NSString *json=nodes?[[NSString alloc]initWithData:nodes encoding:NSUTF8StringEncoding]:nil;
            if(!json)continue;
            MLStream *stream=chain.count?MLStreamOpenChain(json.UTF8String,target.UTF8String,(uint16_t)port,MLRemaining(deadline)):MLStreamOpen(NULL,target.UTF8String,(uint16_t)port,MLRemaining(deadline));
            if(!stream)continue;
            if(tls||doh){MLStream *wrapped=MLStreamWrapTLS(stream,host.UTF8String,caPath.fileSystemRepresentation,MLRemaining(deadline));if(!wrapped){MLStreamClose(stream);continue;}stream=wrapped;}
            if(doh) {
                NSString *path=url.path.length?url.path:@"/";if(url.query)path=[path stringByAppendingFormat:@"?%@",url.query];
                NSString *authority=[host rangeOfString:@":"].location==NSNotFound?host:[NSString stringWithFormat:@"[%@]",host];if(port!=443)authority=[authority stringByAppendingFormat:@":%lu",(unsigned long)port];
                NSData *headers=[[NSString stringWithFormat:@"POST %@ HTTP/1.1\r\nHost: %@\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n",path,authority,(unsigned long)query.length] dataUsingEncoding:NSASCIIStringEncoding];
                if(headers&&MLWriteStream(stream,headers,deadline)&&MLWriteStream(stream,query,deadline))answer=MLHTTPAnswer(stream,deadline);
            } else {
                uint8_t prefix[2]={(uint8_t)(query.length>>8),(uint8_t)query.length};NSMutableData *request=[NSMutableData dataWithBytes:prefix length:2];[request appendData:query];
                if(MLWriteStream(stream,request,deadline)){NSData *header=MLExactStream(stream,2,deadline);if(header){const uint8_t *n=header.bytes;NSUInteger length=((NSUInteger)n[0]<<8)|n[1];if(length>=12&&length<=4096)answer=MLExactStream(stream,length,deadline);}}
            }
            MLStreamClose(stream);
        }
        if(answer)break;
    }
    freeaddrinfo(addresses);return answer;
}
