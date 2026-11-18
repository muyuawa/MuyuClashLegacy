// Read-only iOS 6 process/socket ABI probe. All sockets are local loopback.
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
typedef int (*MLProcInfo)(int,int,int,uint64_t,void *,int);
struct MLSocketFD {uint8_t file[24],stat[136];uint64_t socket,pcb;int32_t type,protocol,family;int16_t flags[8];uint32_t oob;uint8_t receive[24],send[24];int32_t kind;uint32_t reserved;uint64_t transport[66];};
_Static_assert(sizeof(struct MLSocketFD)==792,"XNU 2050 socket_fdinfo ABI");
_Static_assert(offsetof(struct MLSocketFD,transport)==264,"XNU 2050 socket protocol offset");
static MLProcInfo information;
static int syscallInfo(int call,int pid,int flavor,uint64_t argument,void *buffer,int size){return (int)syscall(SYS_proc_info,call,pid,flavor,argument,buffer,size);}
static int inspect(int family,int type){
    int fd=socket(family,type,0);if(fd<0)return 0;
    struct sockaddr_storage local;memset(&local,0,sizeof local);socklen_t length;
    if(family==AF_INET){struct sockaddr_in *p=(struct sockaddr_in *)&local;p->sin_family=family;p->sin_addr.s_addr=htonl(INADDR_LOOPBACK);length=sizeof *p;}
    else{struct sockaddr_in6 *p=(struct sockaddr_in6 *)&local;p->sin6_family=family;p->sin6_addr=in6addr_loopback;length=sizeof *p;}
    if(bind(fd,(struct sockaddr *)&local,length)){close(fd);return 0;}
    if(getsockname(fd,(struct sockaddr *)&local,&length)){close(fd);return 0;}
    struct MLSocketFD result;memset(&result,0,sizeof result);int got=information(3,getpid(),3,fd,&result,sizeof result);
    const uint8_t *in=(const uint8_t *)result.transport;int32_t port=0;memcpy(&port,in+4,4);
    uint16_t expected=family==AF_INET?((struct sockaddr_in *)&local)->sin_port:((struct sockaddr_in6 *)&local)->sin6_port;
    int address=family==AF_INET?!memcmp(in+48+12,&((struct sockaddr_in *)&local)->sin_addr,4):!memcmp(in+48,&((struct sockaddr_in6 *)&local)->sin6_addr,16);
    int okay=got==792 && result.type==type && result.protocol==(type==SOCK_STREAM?6:17) && result.family==family && (uint16_t)port==expected && address;
    printf("%s%s%s",family==AF_INET?"\"ipv4":"\"ipv6",type==SOCK_STREAM?"TCP\":" : "UDP\":",okay?"true":"false");close(fd);return okay;
}
int main(void){
    if(geteuid()!=0){fputs("process owner probe requires root\n",stderr);return 77;}
    void *symbol=dlsym(RTLD_DEFAULT,"__proc_info");if(symbol)memcpy(&information,&symbol,sizeof information);else information=syscallInfo;
    int pids[1024]={0};int listed=information(1,1,0,0,pids,sizeof pids);int own=0;if(listed>0 && listed<=(int)sizeof pids)for(int i=0;i<listed/(int)sizeof(int);i++)if(pids[i]==getpid())own=1;
    char path[4096]={0};int returned=information(2,getpid(),11,0,path,sizeof path);
    int descriptors[2048]={0};int fds=information(2,getpid(),1,0,descriptors,sizeof descriptors);
    printf("{\"preflight\":\"socket-owner-ABI\",\"procInfoSymbol\":%s,\"pidList\":%s,\"fdList\":%s,\"processPath\":%s,\"pathReturn\":%d,\"socketInfoBytes\":792,",symbol?"true":"false",own?"true":"false",fds>0?"true":"false",path[0]?"true":"false",returned);
    int v4t=inspect(AF_INET,SOCK_STREAM);putchar(',');int v4u=inspect(AF_INET,SOCK_DGRAM);putchar(',');int v6t=inspect(AF_INET6,SOCK_STREAM);putchar(',');int v6u=inspect(AF_INET6,SOCK_DGRAM);
    int passed=own && fds>0 && returned>=0 && path[0] && v4t && v4u && v6t && v6u;printf(",\"passed\":%s,\"externalConnections\":false,\"networkModified\":false}\n",passed?"true":"false");return passed?0:1;
}
