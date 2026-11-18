#import "MLProcessOwner.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
static int bindLoopback(int family,int type,uint16_t port,BOOL reuse,uint16_t *bound){
    int fd=socket(family,type,0);if(fd<0)return -1;if(reuse){int yes=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);setsockopt(fd,SOL_SOCKET,SO_REUSEPORT,&yes,sizeof yes);}
    struct sockaddr_storage storage;memset(&storage,0,sizeof storage);socklen_t length;
    if(family==AF_INET){struct sockaddr_in *a=(struct sockaddr_in *)&storage;a->sin_family=family;a->sin_addr.s_addr=htonl(INADDR_LOOPBACK);a->sin_port=htons(port);length=sizeof *a;}
    else{struct sockaddr_in6 *a=(struct sockaddr_in6 *)&storage;a->sin6_family=family;a->sin6_addr=in6addr_loopback;a->sin6_port=htons(port);length=sizeof *a;}
    if(bind(fd,(struct sockaddr *)&storage,length) || getsockname(fd,(struct sockaddr *)&storage,&length)){close(fd);return -1;}
    *bound=ntohs(family==AF_INET?((struct sockaddr_in *)&storage)->sin_port:((struct sockaddr_in6 *)&storage)->sin6_port);return fd;
}
static NSDictionary *lookup(int family,int type,BOOL connected,BOOL duplicate){
    uint16_t serverPort=0,sourcePort=0,duplicatePort=0;int server=bindLoopback(family,type,0,NO,&serverPort);
    int client=bindLoopback(family,type,0,duplicate,&sourcePort);int other=-1,accepted=-1;
    if(server<0 || client<0)goto failed;
    if(type==SOCK_STREAM && listen(server,2))goto failed;
    if(connected){
        struct sockaddr_storage remote;socklen_t length=sizeof remote;if(getsockname(server,(struct sockaddr *)&remote,&length) || connect(client,(struct sockaddr *)&remote,length))goto failed;
        if(type==SOCK_STREAM){accepted=accept(server,NULL,NULL);if(accepted<0)goto failed;}
    }
    if(duplicate){other=bindLoopback(family,type,sourcePort,YES,&duplicatePort);if(other<0 || duplicatePort!=sourcePort)goto failed;}
    {
        MLProcessOwner *owner=[[MLProcessOwner alloc]initWithBudgetMilliseconds:150];
        NSDictionary *result=[owner lookupSource:family==AF_INET?@"127.0.0.1":@"::1" sourcePort:sourcePort destination:family==AF_INET?@"127.0.0.1":@"::1" destinationPort:serverPort network:type==SOCK_STREAM?@"TCP":@"UDP"];
        BOOL success=duplicate?(![result[@"verified"] boolValue] && [result[@"reason"] isEqual:@"ambiguous"]):([result[@"verified"] boolValue] && [result[@"pid"] intValue]==getpid());
        NSMutableDictionary *report=[@{@"family":family==AF_INET?@"IPv4":@"IPv6",@"network":type==SOCK_STREAM?@"TCP":@"UDP",@"connected":@(connected),@"duplicate":@(duplicate),@"passed":@(success),@"lookup":result,@"status":owner.status} mutableCopy];
        close(server);close(client);if(other>=0)close(other);if(accepted>=0)close(accepted);return report;
    }
failed:if(server>=0)close(server);if(client>=0)close(client);if(other>=0)close(other);if(accepted>=0)close(accepted);return @{@"passed":@NO,@"reason":@"loopback-fixture"};
}
int main(void){@autoreleasepool{
    if(geteuid()!=0)return 77;NSMutableArray *stages=[NSMutableArray array];BOOL passed=YES;
    for(unsigned f=0;f<2;f++){
        int family=f?AF_INET6:AF_INET;
        for(unsigned stage=0;stage<4;stage++){
            NSDictionary *result=lookup(family,stage?SOCK_DGRAM:SOCK_STREAM,stage<2,stage==3);[stages addObject:result];if(![result[@"passed"] boolValue])passed=NO;
        }
    }
    NSData *data=[NSJSONSerialization dataWithJSONObject:@{@"preflight":@"root-process-owner",@"passed":@(passed),@"networkModified":@NO,@"externalConnections":@NO,@"stages":stages} options:NSJSONWritingPrettyPrinted error:NULL];fwrite(data.bytes,1,data.length,stdout);putchar('\n');return passed?0:1;
}}
