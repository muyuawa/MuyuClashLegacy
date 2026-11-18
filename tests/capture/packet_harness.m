#import "MLPacketBridge.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
static volatile sig_atomic_t stopping=0, report=0;
static void signalHandler(int number) { if(number==SIGUSR1)report=1;else stopping=1; }
@interface Datagram : NSObject <MLPacketDatagram>
@property(nonatomic) int fileDescriptor;
@end
@implementation Datagram
- (BOOL)sendData:(NSData *)data error:(NSError **)error {
    ssize_t n=send(self.fileDescriptor,data.bytes,data.length,MSG_DONTWAIT);
    if(n==(ssize_t)data.length)return YES;
    if(error)*error=[NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:@{}];return NO;
}
- (NSData *)receiveData:(NSError **)error {
    unsigned char bytes[8192]; ssize_t n=recv(self.fileDescriptor,bytes,sizeof bytes,MSG_DONTWAIT);
    if(n>=0)return [NSData dataWithBytes:bytes length:n];
    if(error)*error=[NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:@{}];return nil;
}
- (short)eventsForRead:(BOOL)read write:(BOOL)write { return (read?POLLIN:0)|(write?POLLOUT:0); }
- (void)close { if(_fileDescriptor>=0){close(_fileDescriptor);_fileDescriptor=-1;} }
- (void)dealloc { [self close]; }
@end
static int openUDP(NSString *host,uint16_t port) {
    BOOL ipv6=[host rangeOfString:@":"].location!=NSNotFound;
    int fd=socket(ipv6?AF_INET6:AF_INET,SOCK_DGRAM,0); if(fd<0)return -1;
    int code;
    if(ipv6){struct sockaddr_in6 address={0};address.sin6_family=AF_INET6;address.sin6_port=htons(port);inet_pton(AF_INET6,host.UTF8String,&address.sin6_addr);code=connect(fd,(struct sockaddr *)&address,sizeof address);}
    else {struct sockaddr_in address={0};address.sin_family=AF_INET;address.sin_port=htons(port);inet_pton(AF_INET,host.UTF8String,&address.sin_addr);code=connect(fd,(struct sockaddr *)&address,sizeof address);}
    if(code){close(fd);return -1;}return fd;
}
int main(int argc,char **argv) { @autoreleasepool {
    if(argc!=2)return 64;uint16_t dnsPort=(uint16_t)atoi(argv[1]);
    signal(SIGTERM,signalHandler);signal(SIGINT,signalHandler);signal(SIGUSR1,signalHandler);signal(SIGPIPE,SIG_IGN);
    __block unsigned retained=0,released=0;
    MLPacketBridge *bridge=[[MLPacketBridge alloc] initWithFileDescriptor:0 interfaceName:@"utun-test"
        route:^NSDictionary *(NSString *destination,NSString *source,uint16_t sourcePort,uint16_t destinationPort,NSString *network) {
            (void)source;(void)sourcePort;(void)destinationPort;(void)network;
            NSString *host=[destination isEqual:@"198.18.1.20"]?@"127.0.0.1":destination;
            return @{@"host":host,@"metadata":@{@"actual":@"DIRECT",@"configID":@"packet-test"}};
        }
        datagram:^id<MLPacketDatagram>(NSDictionary *route,uint16_t port,NSError **error) {
            int fd=openUDP(route[@"host"],port);
            if(fd<0){if(error)*error=[NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:@{}];return nil;}
            fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0)|O_NONBLOCK);Datagram *datagram=[Datagram new];datagram.fileDescriptor=fd;return datagram;
        }
        dns:^NSData *(NSData *query) {
            int fd=openUDP(@"127.0.0.1",dnsPort);if(fd<0)return nil;
            struct timeval timeout={2,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout);
            NSData *result=nil;unsigned char response[4096];
            if(send(fd,query.bytes,query.length,0)==(ssize_t)query.length){ssize_t n=recv(fd,response,sizeof response,0);if(n>0)result=[NSData dataWithBytes:response length:n];}
            close(fd);return result;
        }
        retainAddress:^(NSString *address){(void)address;__sync_fetch_and_add(&retained,1);}
        releaseAddress:^(NSString *address){(void)address;__sync_fetch_and_add(&released,1);}];
    NSError *error=nil;
    if(!bridge || ![bridge start:&error]){fprintf(stderr,"%s\n",error.localizedDescription.UTF8String);return 1;}
    puts("ready");fflush(stdout);
    while(!stopping && bridge.running){
        if(report){report=0;NSData *data=[NSJSONSerialization dataWithJSONObject:@{@"statistics":bridge.statistics,@"connections":bridge.connections,@"retained":@(retained),@"released":@(released)} options:0 error:NULL];fwrite(data.bytes,1,data.length,stdout);putchar('\n');fflush(stdout);}
        usleep(10000);
    }
    [bridge stop];
    printf("stopped retained=%u released=%u\n",retained,released);fflush(stdout);
    return retained==released?0:1;
}}
