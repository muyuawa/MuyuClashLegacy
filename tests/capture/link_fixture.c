// Test-only physical interface down/up. Never writes Wi-Fi preferences.
#include <TargetConditionals.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t finished;
// IFT_ETHER is the AF_LINK ABI value 6 in XNU/BSD; SDK 7.1 omits if_types.h.
enum { MLPhysicalEthernetType = 6 };
static void stop(int number) { finished=number; }
struct identity { unsigned index; unsigned char mac[6]; int physical,assigned; };
static int interface_name(const char *name) {
    size_t length=strlen(name);
    if(length<3||length>=IF_NAMESIZE||name[0]!='e'||name[1]!='n')return 0;
    for(size_t i=2;i<length;i++)if(name[i]<'0'||name[i]>'9')return 0;
    return 1;
}
static int identity(const char *name,const struct in_addr *expected,struct identity *out) {
    memset(out,0,sizeof *out);out->index=if_nametoindex(name);if(!out->index)return -1;
    struct ifaddrs *list=NULL;if(getifaddrs(&list))return -1;
    for(struct ifaddrs *row=list;row;row=row->ifa_next){
        if(strcmp(row->ifa_name,name)||!row->ifa_addr)continue;
        if(row->ifa_addr->sa_family==AF_LINK){
            const struct sockaddr_dl *link=(const struct sockaddr_dl *)row->ifa_addr;
            if(link->sdl_type==MLPhysicalEthernetType&&link->sdl_alen==sizeof out->mac&&link->sdl_index==out->index){
                memcpy(out->mac,LLADDR(link),sizeof out->mac);out->physical=1;
            }
        }else if(expected&&row->ifa_addr->sa_family==AF_INET&&
                 ((const struct sockaddr_in *)row->ifa_addr)->sin_addr.s_addr==expected->s_addr)out->assigned=1;
    }
    freeifaddrs(list);return out->physical?0:-1;
}
static int flags(int socket,const char *name,uint16_t *value,int set) {
    struct ifreq request;memset(&request,0,sizeof request);strlcpy(request.ifr_name,name,sizeof request.ifr_name);
    if(set)request.ifr_flags=(short)*value;
    int result=ioctl(socket,set?SIOCSIFFLAGS:SIOCGIFFLAGS,&request);
    if(!result&&!set)*value=(uint16_t)request.ifr_flags;return result;
}
static void status(const char *name,const struct identity *who,uint16_t value) {
    printf("{\"interface\":\"%s\",\"interfaceIndex\":%u,\"physicalEthernet\":true,\"flags\":%u,\"up\":%s,\"running\":%s,\"mac\":\"",
           name,who->index,value,value&IFF_UP?"true":"false",value&IFF_RUNNING?"true":"false");
    for(unsigned i=0;i<sizeof who->mac;i++)printf("%s%02x",i?":":"",who->mac[i]);
    puts("\"}");fflush(stdout);
}
int main(int argc,char **argv) {
    int hold=argc==6&&!strcmp(argv[1],"hold"),query=argc==4&&!strcmp(argv[1],"status");
    if((!hold&&!query)||geteuid()!=0)return 77;
    const char *name=argv[2];if(!interface_name(name))return 77;
    char *end=NULL;unsigned long number=strtoul(argv[hold?4:3],&end,10);
    if(!end||*end||!number||number>UINT_MAX)return 64;
    struct in_addr address,*expected=NULL;
    if(hold){
        if(inet_pton(AF_INET,argv[3],&address)!=1||address.s_addr==INADDR_ANY||strlen(argv[5])!=16)return 64;
        for(unsigned i=0;i<16;i++)if(!strchr("0123456789abcdef",argv[5][i]))return 64;
        expected=&address;
    }
    struct identity original;
    if(identity(name,expected,&original)||original.index!=(unsigned)number)return 77;
    int descriptor=socket(AF_INET,SOCK_DGRAM,0);uint16_t saved=0;
    if(descriptor<0||flags(descriptor,name,&saved,0)){if(descriptor>=0)close(descriptor);return 1;}
    if(query){status(name,&original,saved);close(descriptor);return 0;}
#if !TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
    close(descriptor);fputs("Physical link mutation requires a real root iOS device.\n",stderr);return 77;
#else
    if(!original.assigned||!(saved&IFF_UP)||(saved&(IFF_LOOPBACK|IFF_POINTOPOINT))){close(descriptor);return 77;}
    signal(SIGTERM,stop);signal(SIGINT,stop);signal(SIGHUP,stop);signal(SIGALRM,stop);signal(SIGPIPE,SIG_IGN);
    // Arm before the first mutation. A lost parent/SSH pipe, signal or alarm
    // all flow through the same identity-checked restoration below.
    alarm(30);uint16_t down=(uint16_t)(saved&~IFF_UP),observed=0;int changed=0,result=1;
    // Even a failed driver ioctl can have changed flags before reporting an
    // error. Once attempted, always submit the saved flags in the finally.
    changed=1;
    if(flags(descriptor,name,&down,1)){perror("SIOCSIFFLAGS down");goto restore;}
    if(flags(descriptor,name,&observed,0)||(observed&IFF_UP)){fputs("Interface did not stay down.\n",stderr);goto restore;}
    printf("{\"ready\":true,\"pid\":%d,\"interface\":\"%s\",\"interfaceIndex\":%u,\"originalFlags\":%u,\"downFlags\":%u,\"up\":false,\"alarmSeconds\":30,\"preferencesModified\":false,\"nonce\":\"%s\"}\n",
           getpid(),name,original.index,saved,observed,argv[5]);fflush(stdout);result=0;
    while(!finished){
        struct pollfd input={STDIN_FILENO,POLLIN|POLLHUP,0};int ready=poll(&input,1,100);
        if(ready<0&&errno!=EINTR){result=1;break;}
        if(ready>0){char command[32];ssize_t count=read(STDIN_FILENO,command,sizeof command);
            if(count<=0||(count>=7&&!memcmp(command,"restore",7)))break;}
    }
restore:
    if(changed){
        struct identity current;int verified=!identity(name,NULL,&current)&&current.index==original.index&&
            !memcmp(current.mac,original.mac,sizeof current.mac);
        int restored=verified&&!flags(descriptor,name,&saved,1)&&!flags(descriptor,name,&observed,0)&&
            (observed&~IFF_RUNNING)==(saved&~IFF_RUNNING);
        printf("{\"released\":%s,\"originalFlags\":%u,\"observedFlags\":%u,\"up\":%s,\"interfaceIdentityVerified\":%s,\"signal\":%d,\"preferencesModified\":false}\n",
               restored?"true":"false",saved,observed,observed&IFF_UP?"true":"false",verified?"true":"false",(int)finished);
        fflush(stdout);if(!restored)result=1;
    }
    alarm(0);close(descriptor);return result;
#endif
}
