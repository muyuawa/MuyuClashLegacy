/* A private raw lwIP stack carries outbound TCP/UDP inside authenticated
   WireGuard/AmneziaWG IP packets. No system interface or route is created. */
#include "MLWireGuard.h"
#include "../transport/MLNetworkBinding.h"
#include "awg_link.h"
#include "core/senko_time.h"
#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/timeouts.h"
#include "lwip/priv/tcp_priv.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define WG_CONTEXTS 4
#define WG_SESSIONS 64
typedef struct WGContext WGContext;
struct MLWGSession {
    WGContext *context;vless_dest_t dest;int pair[2],udp,phase,failed,closing,localEOF,remoteEOF;
    struct tcp_pcb *tcp;struct udp_pcb *packet;struct pbuf *incoming;size_t incomingOffset;
    uint8_t upload[4096];size_t uploadSize;
};
struct WGContext {awg_config_t config;awg_link_t link;struct netif netif;ip_addr_t source4,source6;unsigned refs,interfaceIndex;int initialized,failed;};
static WGContext *wgContexts[WG_CONTEXTS];static MLWGSession *wgSessions[WG_SESSIONS];
static pthread_mutex_t wgLock=PTHREAD_MUTEX_INITIALIZER;static pthread_cond_t wgChanged=PTHREAD_COND_INITIALIZER;
static pthread_once_t wgOnce=PTHREAD_ONCE_INIT;static int wgWake[2]={-1,-1},wgInitError;
static void wakeWorker(void){if(wgWake[0]>=0)(void)send(wgWake[0],"w",1,0);}
static int nonblock(int fd){return fcntl(fd,F_SETFL,O_NONBLOCK)||fcntl(fd,F_SETFD,FD_CLOEXEC);}
static int numericAddress(const char *value,ip_addr_t *address){char host[64];size_t n=strcspn(value,"/");if(!n||n>=sizeof host)return 0;memcpy(host,value,n);host[n]=0;return ipaddr_aton(host,address);}
int MLWGDestinationPrefix(const awg_config_t *cfg,const vless_dest_t *dest){
    if(!cfg->allowed_ips[0])return 0;const char *start=cfg->allowed_ips;int best=-1;
    while(*start){while(*start==' '||*start==',')start++;const char *end=strchr(start,',');size_t n=end?(size_t)(end-start):strlen(start);char cidr[80];
        if(n>=sizeof cidr)return -1;memcpy(cidr,start,n);cidr[n]=0;char *slash=strchr(cidr,'/'),*tail=NULL;
        if(!slash)return -1;*slash++=0;unsigned bits=(unsigned)strtoul(slash,&tail,10);if(tail==slash)return -1;while(*tail==' ')tail++;if(*tail)return -1;
        uint8_t address[16];int family=strchr(cidr,':')?AF_INET6:AF_INET;unsigned width=family==AF_INET6?128:32;
        if(bits>width||inet_pton(family,cidr,address)!=1)return -1;
        if((dest->atyp==VLESS_ADDR_IPV4&&family==AF_INET)||(dest->atyp==VLESS_ADDR_IPV6&&family==AF_INET6)){
            unsigned bytes=bits/8,extra=bits%8;if(!memcmp(address,dest->host_addr,bytes)&&(!extra||((address[bytes]^dest->host_addr[bytes])&(0xffu<<(8-extra)))==0)&&(int)bits>best)best=(int)bits;
        }if(!end)break;start=end+1;
    }return best;
}
static int allowedDestination(const awg_config_t *cfg,const vless_dest_t *dest){return MLWGDestinationPrefix(cfg,dest)>=0;}
int MLWGDestinationAllowed(const awg_config_t *cfg,const vless_dest_t *dest){return allowedDestination(cfg,dest);}
static void failSession(MLWGSession *s,int error){if(!s->failed)s->failed=error;s->phase=2;if(s->udp)(void)send(s->pair[1],"",0,0);(void)shutdown(s->pair[1],SHUT_RDWR);pthread_cond_broadcast(&wgChanged);}
static err_t outputPacket(struct netif *netif,struct pbuf *p){WGContext *c=netif->state;uint8_t packet[65535];if(c->failed||p->tot_len>sizeof packet)return ERR_IF;
    pbuf_copy_partial(p,packet,p->tot_len,0);if(awg_link_send_packet(&c->link,packet,p->tot_len)){c->failed=ENETDOWN;return ERR_IF;}return ERR_OK;
}
static err_t output4(struct netif *n,struct pbuf *p,const ip4_addr_t *address){(void)address;return outputPacket(n,p);}
static err_t output6(struct netif *n,struct pbuf *p,const ip6_addr_t *address){(void)address;return outputPacket(n,p);}
static err_t setupNetif(struct netif *n){n->name[0]='w';n->name[1]='g';n->output=output4;n->output_ip6=output6;n->mtu=((WGContext *)n->state)->config.mtu;return ERR_OK;}
static utun_device_status_t inputPacket(void *context,const uint8_t *frame,size_t n){
    WGContext *c=context;if(n<=4||n>65539)return UTUN_DEVICE_AGAIN;struct pbuf *p=pbuf_alloc(PBUF_RAW,(u16_t)(n-4),PBUF_POOL);
    if(!p)return UTUN_DEVICE_AGAIN;if(pbuf_take(p,frame+4,n-4)||ip_input(p,&c->netif)!=ERR_OK){pbuf_free(p);return UTUN_DEVICE_AGAIN;}return UTUN_DEVICE_OK;
}
static void configureContext(WGContext *c){
    ip4_addr_t zero={0};c->source4.type=IPADDR_TYPE_V4;c->source6.type=IPADDR_TYPE_V6;
    for(size_t i=0;i<c->config.address_count;i++){ip_addr_t address;if(!numericAddress(c->config.addresses[i],&address)){c->failed=EINVAL;return;}
        if(IP_IS_V4(&address)&&ip4_addr_isany(ip_2_ip4(&c->source4)))c->source4=address;
        if(IP_IS_V6(&address)&&ip6_addr_isany(ip_2_ip6(&c->source6)))c->source6=address;
    }
    if(!netif_add(&c->netif,ip_2_ip4(&c->source4),&zero,&zero,c,setupNetif,ip_input)){c->failed=ENOMEM;return;}
    if(!ip6_addr_isany(ip_2_ip6(&c->source6))){netif_ip6_addr_set(&c->netif,0,ip_2_ip6(&c->source6));netif_ip6_addr_set_state(&c->netif,0,IP6_ADDR_PREFERRED);}
    netif_set_up(&c->netif);netif_set_link_up(&c->netif);if(!netif_default)netif_set_default(&c->netif);
    c->link.write_frame=inputPacket;c->link.write_ctx=c;char reason[256];if(awg_link_begin(&c->link,reason,sizeof reason)!=AWG_LINK_RUNNING)c->failed=ENETDOWN;c->initialized=1;
}
static void tcpFailed(void *context,err_t err){(void)err;MLWGSession *s=context;s->tcp=NULL;failSession(s,ECONNRESET);}
static err_t tcpReceived(void *context,struct tcp_pcb *pcb,struct pbuf *p,err_t error){(void)pcb;MLWGSession *s=context;
    if(error!=ERR_OK)return error;if(!p){s->remoteEOF=1;return ERR_OK;}if(s->incoming)return ERR_MEM;s->incoming=p;s->incomingOffset=0;return ERR_OK;
}
static err_t tcpConnected(void *context,struct tcp_pcb *pcb,err_t error){(void)pcb;MLWGSession *s=context;if(error!=ERR_OK){failSession(s,ECONNREFUSED);return error;}s->phase=1;pthread_cond_broadcast(&wgChanged);return ERR_OK;}
static void udpReceived(void *context,struct udp_pcb *pcb,struct pbuf *p,const ip_addr_t *address,u16_t port){(void)pcb;(void)address;(void)port;MLWGSession *s=context;
    if(p&&p->tot_len&&p->tot_len<=1500){uint8_t bytes[1500];pbuf_copy_partial(p,bytes,p->tot_len,0);(void)send(s->pair[1],bytes,p->tot_len,0);}if(p)pbuf_free(p);
}
static void configureSession(MLWGSession *s){
    WGContext *c=s->context;if(c->failed){failSession(s,c->failed);return;}ip_addr_t target;char text[46];
    int family=s->dest.atyp==VLESS_ADDR_IPV4?AF_INET:AF_INET6;
    if(!inet_ntop(family,s->dest.host_addr,text,sizeof text)||!ipaddr_aton(text,&target)){failSession(s,EINVAL);return;}
    const ip_addr_t *source=IP_IS_V4(&target)?&c->source4:&c->source6;if(ip_addr_isany(source)){failSession(s,EADDRNOTAVAIL);return;}
    if(s->udp){s->packet=udp_new_ip_type(IP_GET_TYPE(&target));if(!s->packet){failSession(s,ENOMEM);return;}udp_bind_netif(s->packet,&c->netif);
        if(udp_bind(s->packet,source,0)!=ERR_OK||udp_connect(s->packet,&target,s->dest.port)!=ERR_OK){failSession(s,ENETUNREACH);return;}
        udp_recv(s->packet,udpReceived,s);s->phase=1;pthread_cond_broadcast(&wgChanged);
    }else{s->tcp=tcp_new_ip_type(IP_GET_TYPE(&target));if(!s->tcp){failSession(s,ENOMEM);return;}tcp_bind_netif(s->tcp,&c->netif);tcp_arg(s->tcp,s);tcp_recv(s->tcp,tcpReceived);tcp_err(s->tcp,tcpFailed);
        unsigned overhead=IP_IS_V4(&target)?40:60;s->tcp->mss=(u16_t)(c->config.mtu-overhead);if(s->tcp->mss>TCP_MSS)s->tcp->mss=TCP_MSS;
        if(tcp_bind(s->tcp,source,0)!=ERR_OK||tcp_connect(s->tcp,&target,s->dest.port,tcpConnected)!=ERR_OK){failSession(s,ENETUNREACH);return;}s->phase=3;
    }
}
static void flushIncoming(MLWGSession *s){
    if(s->incoming){uint8_t data[4096];size_t left=s->incoming->tot_len-s->incomingOffset,take=left>sizeof data?sizeof data:left;
        pbuf_copy_partial(s->incoming,data,(u16_t)take,(u16_t)s->incomingOffset);ssize_t n=send(s->pair[1],data,take,0);
        if(n>0){s->incomingOffset+=n;if(s->tcp)tcp_recved(s->tcp,(u16_t)n);if(s->incomingOffset==s->incoming->tot_len){pbuf_free(s->incoming);s->incoming=NULL;s->incomingOffset=0;}}
        else if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=ENOBUFS)failSession(s,EPIPE);
    }
    if(s->remoteEOF&&!s->incoming)(void)shutdown(s->pair[1],SHUT_WR);
}
static void pumpSession(MLWGSession *s){
    if(s->closing||s->failed||s->phase!=1)return;if(s->context->failed){failSession(s,s->context->failed);return;}
    if(s->udp){for(unsigned k=0;k<16;k++){uint8_t bytes[1501];ssize_t n=recv(s->pair[1],bytes,sizeof bytes,0);if(n<0)break;if(!n||n>1500)continue;
        struct pbuf *p=pbuf_alloc(PBUF_TRANSPORT,(u16_t)n,PBUF_RAM);if(!p)continue;if(pbuf_take(p,bytes,(u16_t)n)==ERR_OK)(void)udp_send(s->packet,p);pbuf_free(p);
    }return;}
    flushIncoming(s);if(!s->tcp)return;
    if(!s->uploadSize&&!s->localEOF&&tcp_sndbuf(s->tcp)){size_t room=tcp_sndbuf(s->tcp);if(room>sizeof s->upload)room=sizeof s->upload;ssize_t n=recv(s->pair[1],s->upload,room,0);
        if(n>0)s->uploadSize=n;else if(!n)s->localEOF=1;else if(errno!=EAGAIN&&errno!=EWOULDBLOCK)failSession(s,EPIPE);
    }
    if(s->uploadSize){err_t r=tcp_write(s->tcp,s->upload,(u16_t)s->uploadSize,TCP_WRITE_FLAG_COPY);if(r==ERR_OK){s->uploadSize=0;(void)tcp_output(s->tcp);}else if(r!=ERR_MEM)failSession(s,EPIPE);}
    if(s->localEOF&&!s->uploadSize&&s->tcp){(void)tcp_shutdown(s->tcp,0,1);
        if(s->remoteEOF&&!s->incoming){struct tcp_pcb *pcb=s->tcp;tcp_arg(pcb,NULL);tcp_recv(pcb,NULL);tcp_err(pcb,NULL);
            if(tcp_close(pcb)==ERR_OK)s->tcp=NULL;else{tcp_arg(pcb,s);tcp_recv(pcb,tcpReceived);tcp_err(pcb,tcpFailed);}
        }
    }
}
static void destroySession(MLWGSession *s){
    if(s->tcp){tcp_arg(s->tcp,NULL);tcp_recv(s->tcp,NULL);tcp_err(s->tcp,NULL);tcp_abort(s->tcp);s->tcp=NULL;}
    if(s->packet){udp_remove(s->packet);s->packet=NULL;}if(s->incoming){pbuf_free(s->incoming);s->incoming=NULL;}
    for(unsigned i=0;i<WG_SESSIONS;i++)if(wgSessions[i]==s)wgSessions[i]=NULL;
    s->context->refs--;s->phase=-1;pthread_cond_broadcast(&wgChanged);
}
static void destroyContext(WGContext *c){
    if(c->initialized){struct tcp_pcb **lists[]={&tcp_active_pcbs,&tcp_bound_pcbs,&tcp_tw_pcbs};
        for(unsigned j=0;j<3;j++){struct tcp_pcb *p=*lists[j];while(p){struct tcp_pcb *next=p->next;if(p->netif_idx==netif_get_index(&c->netif))tcp_abort(p);p=next;}}
        netif_remove(&c->netif);
    }close(c->link.udp_fd);awg_link_clear(&c->link);OPENSSL_cleanse(c,sizeof *c);free(c);
}
static void *wgWorker(void *unused){(void)unused;lwip_init();
    for(;;){pthread_mutex_lock(&wgLock);
        for(unsigned i=0;i<WG_CONTEXTS;i++)if(wgContexts[i]&&!wgContexts[i]->initialized&&!wgContexts[i]->failed)configureContext(wgContexts[i]);
        for(unsigned i=0;i<WG_SESSIONS;i++){MLWGSession *s=wgSessions[i];if(!s)continue;if(s->closing){destroySession(s);continue;}if(!s->phase)configureSession(s);pumpSession(s);}
        for(unsigned i=0;i<WG_CONTEXTS;i++){WGContext *c=wgContexts[i];if(c&&!c->refs){wgContexts[i]=NULL;destroyContext(c);}}
        sys_check_timeouts();struct pollfd fds[1+WG_CONTEXTS+WG_SESSIONS];size_t used=1;fds[0]=(struct pollfd){wgWake[1],POLLIN,0};
        for(unsigned i=0;i<WG_CONTEXTS;i++)if(wgContexts[i]&&!wgContexts[i]->failed)fds[used++]=(struct pollfd){wgContexts[i]->link.udp_fd,POLLIN,0};
        for(unsigned i=0;i<WG_SESSIONS;i++){MLWGSession *s=wgSessions[i];if(s&&s->phase==1&&!s->failed&&!s->localEOF&&(s->udp||(s->tcp&&!s->uploadSize&&tcp_sndbuf(s->tcp))))fds[used++]=(struct pollfd){s->pair[1],POLLIN,0};}
        pthread_mutex_unlock(&wgLock);(void)poll(fds,(nfds_t)used,10);pthread_mutex_lock(&wgLock);
        uint8_t wake[64];while(recv(wgWake[1],wake,sizeof wake,0)>0){}
        for(unsigned i=0;i<WG_CONTEXTS;i++){WGContext *c=wgContexts[i];if(c&&c->initialized&&!c->failed){char reason[256];if(awg_link_service(&c->link,1,reason,sizeof reason)!=AWG_LINK_RUNNING)c->failed=ENETDOWN;}}
        pthread_mutex_unlock(&wgLock);
    }return NULL;
}
static void initWorker(void){pthread_t thread;if(socketpair(AF_UNIX,SOCK_DGRAM,0,wgWake)||nonblock(wgWake[0])||nonblock(wgWake[1])){wgInitError=errno;return;}
    int error=pthread_create(&thread,NULL,wgWorker,NULL);if(error)wgInitError=error;else pthread_detach(thread);
}
static void waitChanged(uint64_t deadline){struct timeval now;gettimeofday(&now,NULL);uint64_t left=deadline>senko_now_ms()?deadline-senko_now_ms():0;if(left>50)left=50;
    struct timespec until={now.tv_sec,((long)now.tv_usec+(long)left*1000)*1000};if(until.tv_nsec>=1000000000){until.tv_sec++;until.tv_nsec-=1000000000;}pthread_cond_timedwait(&wgChanged,&wgLock,&until);
}
int MLWGParseProfile(const char *profile,awg_config_t *cfg,char *error,size_t cap){if(!profile||!cfg)return -1;return awg_config_parse(profile,strlen(profile),cfg,error,cap)==AWG_CFG_OK?0:-1;}
MLWGSession *MLWGOpen(const awg_config_t *cfg,const vless_dest_t *dest,int udp,unsigned timeoutMS){
    if(!cfg||!dest||!dest->port||(dest->atyp!=VLESS_ADDR_IPV4&&dest->atyp!=VLESS_ADDR_IPV6)||cfg->mtu<576||(dest->atyp==VLESS_ADDR_IPV6&&cfg->mtu<1280)||timeoutMS<100||timeoutMS>60000){errno=EINVAL;return NULL;}
    if(!allowedDestination(cfg,dest)){errno=EACCES;return NULL;}pthread_once(&wgOnce,initWorker);if(wgInitError){errno=wgInitError;return NULL;}uint64_t deadline=senko_now_ms()+timeoutMS;
    pthread_mutex_lock(&wgLock);WGContext *context=NULL;unsigned slot=WG_CONTEXTS;
    for(unsigned i=0;i<WG_CONTEXTS;i++){if(wgContexts[i]&&!wgContexts[i]->failed&&wgContexts[i]->interfaceIndex==MLNetworkInterfaceIndex()&&!memcmp(&wgContexts[i]->config,cfg,sizeof *cfg)){context=wgContexts[i];context->refs++;break;}if(!wgContexts[i])slot=i;}
    pthread_mutex_unlock(&wgLock);
    if(!context){if(slot==WG_CONTEXTS){errno=EBUSY;return NULL;}struct addrinfo hints={0},*addresses=NULL;char service[6];snprintf(service,sizeof service,"%u",cfg->endpoint_port);hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_DGRAM;
        if(MLNetworkResolveBootstrapHost(cfg->endpoint_host,service,&hints,&addresses)){errno=EHOSTUNREACH;return NULL;}int fd=-1;
        for(struct addrinfo *a=addresses;a;a=a->ai_next){fd=socket(a->ai_family,SOCK_DGRAM,0);if(fd<0)continue;if(MLNetworkBindSocket(fd,a->ai_family)||nonblock(fd)||connect(fd,a->ai_addr,a->ai_addrlen)){close(fd);fd=-1;continue;}break;}
        freeaddrinfo(addresses);if(fd<0)return NULL;context=calloc(1,sizeof *context);if(!context){close(fd);return NULL;}context->config=*cfg;context->interfaceIndex=MLNetworkInterfaceIndex();
        awg_handshake_t handshake;char reason[256];uint64_t now=senko_now_ms();if(now>=deadline||awg_handshake_establish_fd(fd,-1,&context->config,(int)(deadline-now),&handshake,reason,sizeof reason)!=AWG_HS_OK){close(fd);OPENSSL_cleanse(context,sizeof *context);free(context);errno=EACCES;return NULL;}
        awg_link_init(&context->link,&context->config,NULL,fd,-1,&handshake,senko_now_ms());OPENSSL_cleanse(&handshake,sizeof handshake);
        pthread_mutex_lock(&wgLock);slot=WG_CONTEXTS;for(unsigned i=0;i<WG_CONTEXTS;i++)if(!wgContexts[i]){slot=i;break;}
        if(slot==WG_CONTEXTS){pthread_mutex_unlock(&wgLock);destroyContext(context);errno=EBUSY;return NULL;}wgContexts[slot]=context;context->refs=1;pthread_mutex_unlock(&wgLock);
    }
    MLWGSession *s=calloc(1,sizeof *s);if(s){s->pair[0]=s->pair[1]=-1;s->context=context;s->dest=*dest;s->udp=udp;
        if(socketpair(AF_UNIX,udp?SOCK_DGRAM:SOCK_STREAM,0,s->pair)||nonblock(s->pair[0])||nonblock(s->pair[1])){if(s->pair[0]>=0)close(s->pair[0]);if(s->pair[1]>=0)close(s->pair[1]);free(s);s=NULL;}}
    if(s){int on=1;
#ifdef SO_NOSIGPIPE
        (void)setsockopt(s->pair[0],SOL_SOCKET,SO_NOSIGPIPE,&on,sizeof on);(void)setsockopt(s->pair[1],SOL_SOCKET,SO_NOSIGPIPE,&on,sizeof on);
#endif
        int buffer=65536;for(unsigned i=0;i<2;i++){(void)setsockopt(s->pair[i],SOL_SOCKET,SO_SNDBUF,&buffer,sizeof buffer);(void)setsockopt(s->pair[i],SOL_SOCKET,SO_RCVBUF,&buffer,sizeof buffer);}
    }
    pthread_mutex_lock(&wgLock);slot=WG_SESSIONS;for(unsigned i=0;i<WG_SESSIONS;i++)if(!wgSessions[i]){slot=i;break;}
    if(!s||slot==WG_SESSIONS){context->refs--;pthread_mutex_unlock(&wgLock);wakeWorker();if(s){close(s->pair[0]);close(s->pair[1]);free(s);}errno=EBUSY;return NULL;}
    wgSessions[slot]=s;wakeWorker();while(s->phase==0||s->phase==3){if((uint64_t)senko_now_ms()>=deadline){s->failed=ETIMEDOUT;break;}waitChanged(deadline);}
    int error=s->failed;pthread_mutex_unlock(&wgLock);if(error){MLWGClose(s);errno=error;return NULL;}return s;
}
int MLWGFD(const MLWGSession *s){return s->pair[0];}
ssize_t MLWGRead(MLWGSession *s,void *data,size_t cap){pthread_mutex_lock(&wgLock);int error=s->failed;pthread_mutex_unlock(&wgLock);if(error){errno=error;return -1;}
    if(s->udp){uint8_t wire[1501];ssize_t n=recv(s->pair[0],wire,sizeof wire,0);if(n<0){if(errno==EWOULDBLOCK)errno=EAGAIN;return -1;}if(n>cap){errno=EMSGSIZE;return -1;}memcpy(data,wire,n);return n;}
    ssize_t n=recv(s->pair[0],data,cap,0);if(n<0&&errno==EWOULDBLOCK)errno=EAGAIN;wakeWorker();return n;
}
ssize_t MLWGWrite(MLWGSession *s,const void *data,size_t n){if(s->udp&&(!n||n>1500)){errno=EMSGSIZE;return -1;}pthread_mutex_lock(&wgLock);int error=s->failed;pthread_mutex_unlock(&wgLock);if(error){errno=error;return -1;}
    ssize_t written=send(s->pair[0],data,n,0);if(written<0&&(errno==EWOULDBLOCK||errno==ENOBUFS))errno=EAGAIN;wakeWorker();return written;
}
void MLWGShutdown(MLWGSession *s){(void)shutdown(s->pair[0],SHUT_WR);wakeWorker();}
void MLWGClose(MLWGSession *s){if(!s)return;pthread_mutex_lock(&wgLock);s->closing=1;wakeWorker();while(s->phase!=-1)waitChanged(senko_now_ms()+100);pthread_mutex_unlock(&wgLock);close(s->pair[0]);close(s->pair[1]);OPENSSL_cleanse(s,sizeof *s);free(s);}
static int dnsNameEnd(const uint8_t *wire,size_t n,size_t *offset){unsigned labels=0;while(*offset<n&&labels++<128){uint8_t length=wire[(*offset)++];if(!length)return 0;
    if((length&0xc0)==0xc0){if(*offset>=n)return -1;size_t pointer=((size_t)(length&63)<<8)|wire[(*offset)++];return pointer<n?0:-1;}
    if(length>63||length>n-*offset)return -1;*offset+=length;}return -1;
}
int MLWGResolve(const awg_config_t *cfg,const char *host,vless_dest_t *dest,unsigned timeoutMS){
    if(!cfg||!host||!dest||!cfg->dns_count){errno=EINVAL;return -1;}uint8_t query[512]={0},response[1500];uint16_t id=(uint16_t)arc4random();query[0]=id>>8;query[1]=id;query[2]=1;query[5]=1;
    size_t used=12;const char *label=host;while(*label){const char *end=strchr(label,'.');size_t length=end?(size_t)(end-label):strlen(label);if(!length||length>63||used+length+6>sizeof query){errno=EINVAL;return -1;}query[used++]=length;memcpy(query+used,label,length);used+=length;if(!end)break;label=end+1;}
    query[used++]=0;int ipv4=0;for(size_t i=0;i<cfg->address_count;i++)if(!strchr(cfg->addresses[i],':'))ipv4=1;unsigned type=ipv4?1:28;query[used++]=0;query[used++]=type;query[used++]=0;query[used++]=1;
    uint64_t deadline=senko_now_ms()+timeoutMS;
    for(size_t server=0;server<cfg->dns_count;server++){vless_dest_t target={.port=53};target.atyp=strchr(cfg->dns[server],':')?VLESS_ADDR_IPV6:VLESS_ADDR_IPV4;
        if(inet_pton(target.atyp==VLESS_ADDR_IPV4?AF_INET:AF_INET6,cfg->dns[server],target.host_addr)!=1)continue;uint64_t now=senko_now_ms();if(now>=deadline)break;
        MLWGSession *s=MLWGOpen(cfg,&target,1,(unsigned)(deadline-now));if(!s)continue;if(MLWGWrite(s,query,used)!=used){MLWGClose(s);continue;}
        struct pollfd fd={MLWGFD(s),POLLIN,0};now=senko_now_ms();int ready=now<deadline?poll(&fd,1,(int)(deadline-now)):0;ssize_t n=ready>0?MLWGRead(s,response,sizeof response):-1;MLWGClose(s);
        if(n<(ssize_t)used||response[0]!=query[0]||response[1]!=query[1]||!(response[2]&0x80)||(response[2]&0x78)||(response[2]&2)||(response[3]&15)||response[4]||response[5]!=1||memcmp(response+12,query+12,used-12))continue;
        unsigned records=(unsigned)response[6]<<8|response[7];size_t offset=used;
        for(unsigned i=0;i<records;i++){if(dnsNameEnd(response,n,&offset)||offset+10>(size_t)n)break;unsigned kind=(unsigned)response[offset]<<8|response[offset+1],class=(unsigned)response[offset+2]<<8|response[offset+3],length=(unsigned)response[offset+8]<<8|response[offset+9];offset+=10;if(length>(size_t)n-offset)break;
            if(class==1&&kind==type&&length==(ipv4?4:16)){memset(dest->host_addr,0,16);memcpy(dest->host_addr,response+offset,length);dest->atyp=ipv4?VLESS_ADDR_IPV4:VLESS_ADDR_IPV6;dest->domain[0]=0;return 0;}offset+=length;
        }
    }errno=EHOSTUNREACH;return -1;
}
