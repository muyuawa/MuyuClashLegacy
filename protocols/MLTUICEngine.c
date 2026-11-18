/* TUIC v5 on the pinned QUIC scheduler. Authentication uses the TLS exporter;
   UDP supports both DATAGRAM and reliable unidirectional streams. */
#include "MLTUICEngine.h"
#include "../transport/MLNetworkBinding.h"
#include <errno.h>
#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static const MLTUICConfig *ml_tuic_starting;
static void *ml_tuic_start_context;
static pthread_mutex_t startLock=PTHREAD_MUTEX_INITIALIZER;
static int ml_tuic_socket(int family,int type,int protocol){int fd=socket(family,type,protocol);if(fd>=0&&(family==AF_INET||family==AF_INET6)&&MLNetworkBindSocket(fd,family)){int error=errno;close(fd);errno=error;return -1;}return fd;}
static void ml_tuic_ready(hy2_engine_t *);
static void ml_tuic_drop(hy2_engine_t *);
static void ml_tuic_recv_uni(hy2_engine_t *,int64_t,const uint8_t *,size_t,int);
static void ml_tuic_ack(hy2_engine_t *,int64_t,uint64_t,uint64_t);
static void ml_tuic_closed_uni(hy2_engine_t *,int64_t);
static int ml_tuic_recv_datagram(ngtcp2_conn *,uint32_t,const uint8_t *,size_t,void *);
static ngtcp2_ssize ml_tuic_write_stream(ngtcp2_conn *,ngtcp2_path *,ngtcp2_pkt_info *,uint8_t *,size_t,ngtcp2_ssize *,uint32_t,int64_t,const ngtcp2_vec *,size_t,ngtcp2_tstamp);
#define socket ml_tuic_socket
#define hy2_engine_start ml_tuic_engine_start
#define hy2_engine_dial ml_tuic_engine_dial
#define hy2_engine_cancel ml_tuic_engine_cancel
#define hy2_engine_stop ml_tuic_engine_stop_impl
#define transport_hy2 ml_tuic_transport
#undef ngtcp2_conn_writev_stream
#define ngtcp2_conn_writev_stream ml_tuic_write_stream
#include "transport_tuic_muyu.c"
#undef socket
#undef hy2_engine_start
#undef hy2_engine_dial
#undef hy2_engine_cancel
#undef hy2_engine_stop
#undef transport_hy2
#undef ngtcp2_conn_writev_stream

#define TUIC_SESSIONS 64
#define TUIC_QUEUE 128
#define TUIC_FRAGMENT 1000
typedef struct Frame {struct Frame *next;int64_t stream;size_t size,sent,acked;int reliable,fin;uint8_t acknowledgment[225],bytes[1800];} Frame;
typedef struct {uint16_t id;uint8_t count,seen;uint64_t started;uint8_t *parts[8];uint16_t lengths[8];} Partial;
typedef struct {int64_t id;size_t size;int active,discard;uint8_t bytes[2048];} Incoming;
typedef struct Context Context;
struct MLTUICUDP {Context *context;int pair[2],failed,reliable;uint16_t id,packet;vless_dest_t target;Partial partial[2];};
struct Context {Context *next;hy2_engine_t *engine;ngtcp2_conn *conn;pthread_mutex_t lock;int ready;unsigned heartbeat,maxPayload;uint64_t lastHeartbeat;MLTUICUDP *sessions[TUIC_SESSIONS];uint8_t used[8192];uint16_t nextID;Frame *first,*last;size_t queued;Incoming incoming[16];};
static pthread_mutex_t contextsLock=PTHREAD_MUTEX_INITIALIZER;
static Context *contexts;
static uint16_t get16(const uint8_t *p){return (uint16_t)p[0]<<8|p[1];}
static void put16(uint8_t *p,unsigned n){p[0]=n>>8;p[1]=n;}
size_t MLTUICAddress(const vless_dest_t *dest,uint8_t *out,size_t cap){
    if(!dest||!dest->port||!out)return 0;size_t n=dest->atyp==VLESS_ADDR_IPV4?4:dest->atyp==VLESS_ADDR_IPV6?16:strnlen(dest->domain,256);
    size_t length=n+(dest->atyp==VLESS_ADDR_DOMAIN?4:3);if(!n||n>255||cap<length)return 0;
    if(dest->atyp==VLESS_ADDR_DOMAIN){out[0]=0;out[1]=n;memcpy(out+2,dest->domain,n);n+=2;}
    else{out[0]=dest->atyp==VLESS_ADDR_IPV4?1:2;memcpy(out+1,dest->host_addr,n);n++;}
    put16(out+n,dest->port);return n+2;
}
static size_t parseAddress(const uint8_t *p,size_t n,vless_dest_t *dest){
    if(!n)return 0;memset(dest,0,sizeof *dest);if(p[0]==255)return 1;size_t size,offset=1;
    if(p[0]==1){size=4;dest->atyp=VLESS_ADDR_IPV4;}else if(p[0]==2){size=16;dest->atyp=VLESS_ADDR_IPV6;}else if(p[0]==0&&n>=2&&p[1]){size=p[1];offset=2;dest->atyp=VLESS_ADDR_DOMAIN;}else return 0;
    if(n<offset+size+2)return 0;if(dest->atyp==VLESS_ADDR_DOMAIN){if(memchr(p+offset,0,size))return 0;memcpy(dest->domain,p+offset,size);}else memcpy(dest->host_addr,p+offset,size);
    dest->port=get16(p+offset+size);return dest->port?offset+size+2:0;
}
static int matchAddress(const MLTUICUDP *s,const vless_dest_t *dest){
    if(dest->port!=s->target.port)return 0;if(s->target.atyp==VLESS_ADDR_DOMAIN){return dest->atyp==VLESS_ADDR_IPV4||dest->atyp==VLESS_ADDR_IPV6||(dest->atyp==VLESS_ADDR_DOMAIN&&!strcmp(dest->domain,s->target.domain));}
    return dest->atyp==s->target.atyp&&!memcmp(dest->host_addr,s->target.host_addr,16);
}
static void clearPartial(Partial *p){for(unsigned i=0;i<8;i++)free(p->parts[i]);memset(p,0,sizeof *p);}
static void packet(Context *c,const uint8_t *wire,size_t n){
    if(n<11||wire[0]!=5||wire[1]!=2)return;uint16_t assoc=get16(wire+2),id=get16(wire+4);unsigned count=wire[6],fragment=wire[7],size=get16(wire+8);
    if(!count||count>8||fragment>=count||!size||size>c->maxPayload)return;vless_dest_t source;size_t address=parseAddress(wire+10,n-10,&source);
    if(!address||n!=10+address+size||(fragment&&wire[10]!=255))return;
    MLTUICUDP *s=NULL;for(unsigned i=0;i<TUIC_SESSIONS;i++)if(c->sessions[i]&&c->sessions[i]->id==assoc){s=c->sessions[i];break;}
    if(!s||s->failed||(!fragment&&!matchAddress(s,&source)))return;const uint8_t *data=wire+10+address;
    if(count==1){(void)send(s->pair[1],data,size,0);return;}
    Partial *p=NULL;uint64_t now=senko_now_ms();for(unsigned i=0;i<2;i++){if(s->partial[i].count&&now-s->partial[i].started>1500)clearPartial(&s->partial[i]);if(s->partial[i].count&&s->partial[i].id==id)p=&s->partial[i];}
    if(!p)for(unsigned i=0;i<2;i++)if(!s->partial[i].count){p=&s->partial[i];break;}if(!p)return;
    if(!p->count){p->id=id;p->count=count;p->started=now;}if(p->count!=count||(p->seen&(1u<<fragment)))return;
    p->parts[fragment]=malloc(size);if(!p->parts[fragment])return;memcpy(p->parts[fragment],data,size);p->lengths[fragment]=size;p->seen|=1u<<fragment;
    if(p->seen==(1u<<count)-1){uint8_t assembled[1500];size_t used=0;for(unsigned i=0;i<count;i++){if(p->lengths[i]>c->maxPayload-used){used=0;break;}memcpy(assembled+used,p->parts[i],p->lengths[i]);used+=p->lengths[i];}if(used)(void)send(s->pair[1],assembled,used,0);clearPartial(p);}
}
static void ml_tuic_ready(hy2_engine_t *e){Context *c=e->tuic_context;if(!c)return;pthread_mutex_lock(&contextsLock);pthread_mutex_lock(&c->lock);c->engine=e;c->conn=e->conn;c->ready=1;c->lastHeartbeat=senko_now_ms();pthread_mutex_unlock(&c->lock);pthread_mutex_unlock(&contextsLock);}
static void ml_tuic_drop(hy2_engine_t *e){Context *c=e->tuic_context;if(!c)return;pthread_mutex_lock(&contextsLock);pthread_mutex_lock(&c->lock);c->conn=NULL;c->ready=0;while(c->first){Frame *f=c->first;c->first=f->next;free(f);}c->last=NULL;c->queued=0;memset(c->incoming,0,sizeof c->incoming);
    for(unsigned i=0;i<TUIC_SESSIONS;i++)if(c->sessions[i]){c->sessions[i]->failed=ECONNRESET;(void)send(c->sessions[i]->pair[1],"",0,0);}pthread_mutex_unlock(&c->lock);pthread_mutex_unlock(&contextsLock);}
static int ml_tuic_recv_datagram(ngtcp2_conn *conn,uint32_t flags,const uint8_t *data,size_t n,void *user){(void)conn;(void)flags;hy2_engine_t *e=user;Context *c=e->tuic_context;if(c){pthread_mutex_lock(&c->lock);packet(c,data,n);pthread_mutex_unlock(&c->lock);}return 0;}
static void ml_tuic_recv_uni(hy2_engine_t *e,int64_t id,const uint8_t *data,size_t n,int fin){
    Context *c=e->tuic_context;if(!c)return;pthread_mutex_lock(&c->lock);Incoming *p=NULL;
    for(unsigned i=0;i<16;i++)if(c->incoming[i].active&&c->incoming[i].id==id){p=&c->incoming[i];break;}
    if(!p)for(unsigned i=0;i<16;i++)if(!c->incoming[i].active){p=&c->incoming[i];p->active=1;p->id=id;break;}
    if(p){if(n>sizeof p->bytes-p->size)p->discard=1;if(!p->discard){memcpy(p->bytes+p->size,data,n);p->size+=n;}if(fin){if(!p->discard)packet(c,p->bytes,p->size);memset(p,0,sizeof *p);}}pthread_mutex_unlock(&c->lock);
}
static void removeFrame(Context *c,Frame **where){Frame *f=*where;*where=f->next;if(c->last==f){c->last=NULL;for(Frame *p=c->first;p;p=p->next)c->last=p;}c->queued--;free(f);}
static void ml_tuic_ack(hy2_engine_t *e,int64_t id,uint64_t offset,uint64_t n){Context *c=e->tuic_context;if(!c)return;pthread_mutex_lock(&c->lock);Frame **p=&c->first;while(*p){Frame *f=*p;if(f->reliable&&f->stream==id){if(offset<f->size){uint64_t end=n>f->size-offset?f->size:offset+n;for(uint64_t i=offset;i<end;i++){uint8_t bit=1u<<(i%8);if(!(f->acknowledgment[i/8]&bit)){f->acknowledgment[i/8]|=bit;f->acked++;}}}if(f->acked==f->size)removeFrame(c,p);break;}p=&(*p)->next;}pthread_mutex_unlock(&c->lock);}
static void ml_tuic_closed_uni(hy2_engine_t *e,int64_t id){Context *c=e->tuic_context;if(!c)return;pthread_mutex_lock(&c->lock);Frame **p=&c->first;while(*p){if((*p)->reliable&&(*p)->stream==id){removeFrame(c,p);break;}p=&(*p)->next;}for(unsigned i=0;i<16;i++)if(c->incoming[i].active&&c->incoming[i].id==id)memset(&c->incoming[i],0,sizeof c->incoming[i]);pthread_mutex_unlock(&c->lock);}
static ngtcp2_ssize ml_tuic_write_stream(ngtcp2_conn *conn,ngtcp2_path *path,ngtcp2_pkt_info *info,uint8_t *wire,size_t cap,ngtcp2_ssize *written,uint32_t flags,int64_t stream,const ngtcp2_vec *vec,size_t count,ngtcp2_tstamp time){
    pthread_mutex_lock(&contextsLock);Context *c=NULL;for(Context *p=contexts;p;p=p->next)if(p->conn==conn){c=p;break;}hy2_engine_t *e=c?c->engine:NULL;pthread_mutex_unlock(&contextsLock);ngtcp2_ssize n=0;
    if(c&&e->auth_done&&e->tuic_auth_sent==sizeof e->tuic_auth){pthread_mutex_lock(&c->lock);Frame **where=&c->first;while(*where&&(*where)->reliable&&(*where)->fin)where=&(*where)->next;Frame *f=*where;
        if(f){ngtcp2_vec bytes={f->bytes+f->sent,f->size-f->sent};
            if(f->reliable){if(f->stream<0){int r=ngtcp2_conn_open_uni_stream(conn,&f->stream,NULL);if(r){pthread_mutex_unlock(&c->lock);goto ordinary;}}
                ngtcp2_ssize sent=-1;n=ngtcp2_conn_writev_stream_versioned(conn,path,NGTCP2_PKT_INFO_VERSION,info,wire,cap,&sent,NGTCP2_WRITE_STREAM_FLAG_FIN,f->stream,&bytes,1,time);if(sent>=0){f->sent+=sent;if(f->sent==f->size)f->fin=1;}
            }else{int accepted=0;n=ngtcp2_conn_writev_datagram_versioned(conn,path,NGTCP2_PKT_INFO_VERSION,info,wire,cap,&accepted,0,0,&bytes,1,time);if(accepted)removeFrame(c,where);}
        }else if((uint64_t)senko_now_ms()-c->lastHeartbeat>=c->heartbeat){int active=0;for(unsigned i=0;i<TUIC_SESSIONS;i++)if(c->sessions[i])active=1;for(unsigned i=0;i<HY2_STREAMS_MAX;i++)if(e->streams[i].in_use)active=1;
            if(active){uint8_t beat[2]={5,4};ngtcp2_vec bytes={beat,2};int accepted=0;n=ngtcp2_conn_writev_datagram_versioned(conn,path,NGTCP2_PKT_INFO_VERSION,info,wire,cap,&accepted,0,0,&bytes,1,time);if(accepted)c->lastHeartbeat=senko_now_ms();}}
        pthread_mutex_unlock(&c->lock);if(n>0){*written=-1;return n;}if(n<0&&n!=NGTCP2_ERR_INVALID_STATE&&n!=NGTCP2_ERR_INVALID_ARGUMENT&&n!=NGTCP2_ERR_STREAM_DATA_BLOCKED)return n;
    }
ordinary:return ngtcp2_conn_writev_stream_versioned(conn,path,NGTCP2_PKT_INFO_VERSION,info,wire,cap,written,flags,stream,vec,count,time);
}
hy2_engine_t *MLTUICStart(const MLTUICConfig *config,char *error,size_t cap){
    if(!config||!config->alpnLength||config->alpnLength>256||config->congestion>NGTCP2_CC_ALGO_BBR||config->maxUDPPayload>1500){errno=EINVAL;return NULL;}
    Context *c=calloc(1,sizeof *c);if(!c)return NULL;pthread_mutex_init(&c->lock,NULL);c->heartbeat=config->heartbeatMS?config->heartbeatMS:10000;c->maxPayload=config->maxUDPPayload?config->maxUDPPayload:1500;
    pthread_mutex_lock(&contextsLock);c->next=contexts;contexts=c;pthread_mutex_unlock(&contextsLock);
    pthread_mutex_lock(&startLock);ml_tuic_starting=config;ml_tuic_start_context=c;hy2_engine_t *e=ml_tuic_engine_start(&config->quic,error,cap);ml_tuic_starting=NULL;ml_tuic_start_context=NULL;pthread_mutex_unlock(&startLock);
    if(!e){pthread_mutex_lock(&contextsLock);Context **p=&contexts;while(*p&&*p!=c)p=&(*p)->next;if(*p)*p=c->next;pthread_mutex_unlock(&contextsLock);pthread_mutex_destroy(&c->lock);free(c);return NULL;}return e;
}
int MLTUICDial(hy2_engine_t *e,char *error,size_t cap){return ml_tuic_engine_dial(e,error,cap);}
void MLTUICStop(hy2_engine_t *e){if(!e)return;Context *c=e->tuic_context;ml_tuic_engine_stop_impl(e);pthread_mutex_lock(&contextsLock);Context **p=&contexts;while(*p&&*p!=c)p=&(*p)->next;if(*p)*p=c->next;pthread_mutex_unlock(&contextsLock);pthread_mutex_destroy(&c->lock);free(c);}
MLTUICUDP *MLTUICUDPOpen(hy2_engine_t *e,const vless_dest_t *dest,int reliable){
    if(!e||!dest||!dest->port){errno=EINVAL;return NULL;}Context *c=e->tuic_context;uint64_t deadline=senko_now_ms()+e->config.connect_timeout_ms+1000;
    for(;;){pthread_mutex_lock(&c->lock);if(c->ready)break;pthread_mutex_unlock(&c->lock);pthread_mutex_lock(&e->lock);int failed=e->state==HY2_STATE_FAILED||e->stop;struct timeval now;gettimeofday(&now,NULL);struct timespec until={now.tv_sec,(now.tv_usec+50000)*1000};if(until.tv_nsec>=1000000000){until.tv_sec++;until.tv_nsec-=1000000000;}if(!failed)pthread_cond_timedwait(&e->changed,&e->lock,&until);pthread_mutex_unlock(&e->lock);if(failed||(uint64_t)senko_now_ms()>=deadline){errno=ETIMEDOUT;return NULL;}}
    unsigned slot=TUIC_SESSIONS;for(unsigned i=0;i<TUIC_SESSIONS;i++)if(!c->sessions[i]){slot=i;break;}if(slot==TUIC_SESSIONS){pthread_mutex_unlock(&c->lock);errno=EBUSY;return NULL;}
    unsigned attempts=0;uint16_t id=c->nextID;while((c->used[id/8]&(1u<<(id%8)))&&attempts<65536){id++;attempts++;}if(attempts==65536){pthread_mutex_unlock(&c->lock);errno=EBUSY;return NULL;}
    MLTUICUDP *s=calloc(1,sizeof *s);if(!s){pthread_mutex_unlock(&c->lock);return NULL;}s->pair[0]=s->pair[1]=-1;
    if(socketpair(AF_UNIX,SOCK_DGRAM,0,s->pair)||set_nonblocking(s->pair[0])||set_nonblocking(s->pair[1])){if(s->pair[0]>=0)close(s->pair[0]);if(s->pair[1]>=0)close(s->pair[1]);free(s);pthread_mutex_unlock(&c->lock);return NULL;}
    int size=65536;setsockopt(s->pair[1],SOL_SOCKET,SO_SNDBUF,&size,sizeof size);setsockopt(s->pair[0],SOL_SOCKET,SO_RCVBUF,&size,sizeof size);s->id=id;s->target=*dest;s->reliable=reliable;s->context=c;c->sessions[slot]=s;c->used[id/8]|=1u<<(id%8);c->nextID=id+1;pthread_mutex_unlock(&c->lock);return s;
}
int MLTUICUDPFD(const MLTUICUDP *s){return s->pair[0];}
ssize_t MLTUICUDPSend(MLTUICUDP *s,const void *data,size_t n){
    if(!n||n>s->context->maxPayload){errno=EMSGSIZE;return -1;}uint8_t addr[259];size_t address=MLTUICAddress(&s->target,addr,sizeof addr);if(!address){errno=EINVAL;return -1;}
    size_t room=TUIC_FRAGMENT-10-address,fragments=s->reliable?1:(n+room-1)/room;uint16_t packetID=++s->packet;Frame *first=NULL,*last=NULL;size_t offset=0;
    for(unsigned i=0;i<fragments;i++){Frame *f=calloc(1,sizeof *f);if(!f)goto bad;f->stream=-1;f->reliable=s->reliable;f->bytes[0]=5;f->bytes[1]=2;put16(f->bytes+2,s->id);put16(f->bytes+4,packetID);f->bytes[6]=fragments;f->bytes[7]=i;
        size_t header=10;if(i==0){memcpy(f->bytes+header,addr,address);header+=address;}else f->bytes[header++]=255;size_t take=n-offset;if(!s->reliable&&take>room)take=room;put16(f->bytes+8,take);memcpy(f->bytes+header,(const uint8_t *)data+offset,take);f->size=header+take;offset+=take;if(last)last->next=f;else first=f;last=f;}
    Context *c=s->context;pthread_mutex_lock(&c->lock);if(s->failed||!c->conn||c->queued+fragments>TUIC_QUEUE){errno=s->failed?s->failed:EAGAIN;pthread_mutex_unlock(&c->lock);goto bad;}if(c->last)c->last->next=first;else c->first=first;c->last=last;c->queued+=fragments;wake_thread(c->engine);pthread_mutex_unlock(&c->lock);return n;
bad:while(first){Frame *f=first;first=f->next;free(f);}return -1;
}
ssize_t MLTUICUDPReceive(MLTUICUDP *s,void *data,size_t cap){pthread_mutex_lock(&s->context->lock);int failed=s->failed;pthread_mutex_unlock(&s->context->lock);if(failed){errno=failed;return -1;}uint8_t wire[1501];ssize_t n=recv(s->pair[0],wire,sizeof wire,0);if(n<0){if(errno==EWOULDBLOCK)errno=EAGAIN;return -1;}if((size_t)n>cap){errno=EMSGSIZE;return -1;}memcpy(data,wire,n);return n;}
void MLTUICUDPClose(MLTUICUDP *s){if(!s)return;Context *c=s->context;pthread_mutex_lock(&c->lock);for(unsigned i=0;i<TUIC_SESSIONS;i++)if(c->sessions[i]==s)c->sessions[i]=NULL;
    Frame **p=&c->first;while(*p){if((*p)->size>=4&&get16((*p)->bytes+2)==s->id&&(*p)->stream<0)removeFrame(c,p);else p=&(*p)->next;}
    if(c->conn&&c->queued<TUIC_QUEUE){Frame *f=calloc(1,sizeof *f);if(f){f->stream=-1;f->reliable=1;f->bytes[0]=5;f->bytes[1]=3;put16(f->bytes+2,s->id);f->size=4;if(c->last)c->last->next=f;else c->first=f;c->last=f;c->queued++;wake_thread(c->engine);}}
    pthread_mutex_unlock(&c->lock);close(s->pair[0]);close(s->pair[1]);for(unsigned i=0;i<2;i++)clearPartial(&s->partial[i]);free(s);
}
