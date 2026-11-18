// Fault-inject the helper's kernel calls; this never opens a real interface.
#include <TargetConditionals.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int fake_getifaddrs(struct ifaddrs **),fake_ioctl(int,unsigned long,...),fake_socket(int,int,int),fake_close(int),fake_poll(struct pollfd *,nfds_t,int);
static void fake_freeifaddrs(struct ifaddrs *);
static unsigned fake_if_nametoindex(const char *),fake_alarm(unsigned);
static uid_t fake_geteuid(void);
static ssize_t fake_read(int,void *,size_t);
#undef TARGET_OS_IPHONE
#undef TARGET_IPHONE_SIMULATOR
#define TARGET_OS_IPHONE 1
#define TARGET_IPHONE_SIMULATOR 0
#define getifaddrs fake_getifaddrs
#define freeifaddrs fake_freeifaddrs
#define if_nametoindex fake_if_nametoindex
#define ioctl fake_ioctl
#define socket fake_socket
#define close fake_close
#define poll fake_poll
#define alarm fake_alarm
#define geteuid fake_geteuid
#define read fake_read
#define main fixture_main
#include "link_fixture.c"
#undef main

enum { MANUAL, EOF_MODE, ALARM_MODE, SIGNAL_MODE, FAILED_DOWN, REUSED_INTERFACE };
static unsigned currentFlags,setCount,armed,mode,identityCalls;
static struct ifaddrs linkRow,addressRow;
static struct sockaddr_dl linkAddress;
static struct sockaddr_in ipv4;
static void reset(unsigned selected) {
    currentFlags=IFF_UP|IFF_BROADCAST|IFF_RUNNING|IFF_MULTICAST;setCount=armed=identityCalls=0;mode=selected;finished=0;
    memset(&linkRow,0,sizeof linkRow);memset(&addressRow,0,sizeof addressRow);memset(&linkAddress,0,sizeof linkAddress);memset(&ipv4,0,sizeof ipv4);
    linkAddress.sdl_len=sizeof linkAddress;linkAddress.sdl_family=AF_LINK;linkAddress.sdl_type=6;linkAddress.sdl_index=2;linkAddress.sdl_nlen=3;linkAddress.sdl_alen=6;
    memcpy(linkAddress.sdl_data,"en0",3);memcpy(LLADDR(&linkAddress),"abcdef",6);
    ipv4.sin_len=sizeof ipv4;ipv4.sin_family=AF_INET;assert(inet_pton(AF_INET,"192.0.2.10",&ipv4.sin_addr)==1);
    linkRow.ifa_name=addressRow.ifa_name="en0";linkRow.ifa_addr=(struct sockaddr *)&linkAddress;linkRow.ifa_next=&addressRow;addressRow.ifa_addr=(struct sockaddr *)&ipv4;
}
static int fake_getifaddrs(struct ifaddrs **rows) {
    identityCalls++;if(mode==REUSED_INTERFACE&&identityCalls>1){linkAddress.sdl_index=3;((unsigned char *)LLADDR(&linkAddress))[0]='x';}
    *rows=&linkRow;return 0;
}
static void fake_freeifaddrs(struct ifaddrs *rows) { assert(rows==&linkRow); }
static unsigned fake_if_nametoindex(const char *name) { assert(!strcmp(name,"en0"));return mode==REUSED_INTERFACE&&identityCalls?3:2; }
static uid_t fake_geteuid(void) { return 0; }
static int fake_socket(int family,int type,int protocol) { assert(family==AF_INET&&type==SOCK_DGRAM&&!protocol);return 47; }
static int fake_close(int descriptor) { assert(descriptor==47);return 0; }
static unsigned fake_alarm(unsigned seconds) { assert(!seconds||seconds==30);armed=seconds;return 0; }
static int fake_ioctl(int descriptor,unsigned long request,...) {
    assert(descriptor==47);va_list args;va_start(args,request);struct ifreq *value=va_arg(args,struct ifreq *);va_end(args);assert(!strcmp(value->ifr_name,"en0"));
    if(request==SIOCGIFFLAGS){value->ifr_flags=(short)currentFlags;return 0;}
    assert(request==SIOCSIFFLAGS&&armed==30);setCount++;currentFlags=(uint16_t)value->ifr_flags;
    if(!(currentFlags&IFF_UP))currentFlags&=~IFF_RUNNING;
    if(mode==FAILED_DOWN&&setCount==1){errno=EIO;return -1;}return 0;
}
static int fake_poll(struct pollfd *items,nfds_t count,int timeout) {
    assert(count==1&&timeout==100&&items[0].fd==STDIN_FILENO);
    if(mode==ALARM_MODE){stop(SIGALRM);errno=EINTR;return -1;}
    if(mode==SIGNAL_MODE){raise(SIGTERM);errno=EINTR;return -1;}
    items[0].revents=POLLIN|POLLHUP;return 1;
}
static ssize_t fake_read(int descriptor,void *bytes,size_t size) {
    assert(descriptor==STDIN_FILENO&&size>=8);if(mode==EOF_MODE)return 0;memcpy(bytes,"restore\n",8);return 8;
}
int main(void) {
    char *arguments[]={"fixture","hold","en0","192.0.2.10","2","0011223344556677",NULL};
    for(unsigned selected=MANUAL;selected<=FAILED_DOWN;selected++){
        reset(selected);assert(fixture_main(6,arguments)==(selected==FAILED_DOWN?1:0));
        assert(setCount==2&&currentFlags==(IFF_UP|IFF_BROADCAST|IFF_RUNNING|IFF_MULTICAST)&&!armed);
    }
    reset(MANUAL);currentFlags&=~IFF_UP;assert(fixture_main(6,arguments)==77&&!setCount&&!armed);
    reset(MANUAL);arguments[3]="192.0.2.11";assert(fixture_main(6,arguments)==77&&!setCount);arguments[3]="192.0.2.10";
    reset(MANUAL);arguments[2]="utun0";assert(fixture_main(6,arguments)==77&&!setCount);arguments[2]="en0";
    reset(REUSED_INTERFACE);assert(fixture_main(6,arguments)==1&&setCount==1&&!(currentFlags&IFF_UP));
    puts("PASS link fixture: manual/EOF/alarm/signal restore, partial ioctl rollback and physical identity restrictions");
}
