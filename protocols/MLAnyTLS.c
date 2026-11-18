/* AnyTLS v2: verified wire supplied by MLStream, sequential session reuse,
   server padding updates, SYNACK, keepalive replies and bounded framing. */
#include "MLAnyTLS.h"
#include <errno.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define PACKETS 64
#define STEPS 32
#define CLIENTS 8
#define SESSIONS 8
#define RAW_CAP 16384
#define SEGMENT_CAP 65542
#define WIRE_CAP 73728
static const char defaultScheme[]="stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
typedef struct { uint16_t min,max; int check; } Range;
typedef struct { unsigned count; Range steps[STEPS]; } Rule;
typedef struct { char raw[8193],md5[33];unsigned stop;Rule rules[PACKETS]; } Padding;
typedef struct Client Client;
typedef struct Session Session;
struct Client { char identity[129];Padding padding;unsigned check,idle,minIdle;uint64_t sequence; };
struct MLAnyTLS { Session *session;int pair[2],failed,closing,shutdown,writeClosing,synSent,finSent,remoteFIN,ready,udp;uint32_t id;uint64_t opened;vless_dest_t target; };
struct Session {
    Client *client;MLStream *wire;Padding padding;MLAnyTLS *current;
    uint64_t sequence,idleSince,lastCheck;uint32_t streamID,packet;
    int failed,finished,refs,version,heartPending;uint32_t heartID;
    uint8_t raw[RAW_CAP],segment[SEGMENT_CAP],incoming[WIRE_CAP],download[65535];
    size_t rawLength,rawOffset,segmentLength,segmentOffset,incomingLength,downloadLength,downloadOffset;
    unsigned step;int processing;
};
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed=PTHREAD_COND_INITIALIZER;
static Client clients[CLIENTS];static Session *sessions[SESSIONS];
static uint64_t millis(void){mach_timebase_info_data_t tb;mach_timebase_info(&tb);uint64_t t=mach_absolute_time();return t/1000000*tb.numer/tb.denom;}
static uint16_t read16(const uint8_t *p){return (uint16_t)p[0]<<8|p[1];}
static uint32_t read32(const uint8_t *p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static void write16(uint8_t *p,size_t n){p[0]=n>>8;p[1]=n;}
static void write32(uint8_t *p,uint32_t n){p[0]=n>>24;p[1]=n>>16;p[2]=n>>8;p[3]=n;}
static int digits(const char *p,unsigned *out){if(!*p)return -1;unsigned n=0;for(;*p;p++){if(*p<'0'||*p>'9'||n>65535)return -1;n=n*10+(*p-'0');}if(n>65535)return -1;*out=n;return 0;}
static int parsePadding(const char *raw,size_t n,Padding *out){
    if(!n||n>8192||memchr(raw,0,n))return -1;Padding *p=calloc(1,sizeof *p);if(!p)return -1;
    memcpy(p->raw,raw,n);char text[8193];memcpy(text,raw,n);text[n]=0;char *lineState=NULL;int stop=0;
    for(char *line=strtok_r(text,"\n",&lineState);line;line=strtok_r(NULL,"\n",&lineState)){
        char *equals=strchr(line,'=');if(!equals)goto bad;*equals++=0;
        if(!strcmp(line,"stop")){if(stop++||digits(equals,&p->stop)||p->stop>PACKETS)goto bad;continue;}
        unsigned number;if(digits(line,&number)||number>=PACKETS||p->rules[number].count)goto bad;char *rangeState=NULL;
        for(char *item=strtok_r(equals,",",&rangeState);item;item=strtok_r(NULL,",",&rangeState)){
            Rule *r=&p->rules[number];if(r->count>=STEPS)goto bad;Range *v=&r->steps[r->count++];
            if(!strcmp(item,"c")){v->check=1;continue;}char *dash=strchr(item,'-');if(!dash)goto bad;*dash++=0;unsigned a,b;
            if(digits(item,&a)||digits(dash,&b)||!a||!b)goto bad;v->min=a<b?a:b;v->max=a>b?a:b;
        }
    }
    if(!stop||p->rules[0].count!=1||p->rules[0].steps[0].check)goto bad;
    uint8_t digest[16];unsigned size=0;if(EVP_Digest(raw,n,digest,&size,EVP_md5(),NULL)!=1||size!=16)goto bad;
    for(unsigned i=0;i<16;i++)snprintf(p->md5+i*2,3,"%02x",digest[i]);memcpy(out,p,sizeof *p);free(p);return 0;
bad:free(p);return -1;
}
static unsigned choose(Range r){if(r.min==r.max)return r.min;uint32_t n;if(RAND_bytes((uint8_t *)&n,4)!=1)return r.min;return r.min+n%(r.max-r.min);}
static size_t address(const vless_dest_t *dest,uint8_t out[259]){
    size_t n;if(dest->atyp==VLESS_ADDR_IPV4||dest->atyp==VLESS_ADDR_IPV6){n=dest->atyp==VLESS_ADDR_IPV4?4:16;out[0]=n==4?1:4;memcpy(out+1,dest->host_addr,n);n++;}
    else if(dest->atyp==VLESS_ADDR_DOMAIN&&(n=strnlen(dest->domain,256))&&n<=255){out[0]=3;out[1]=n;memcpy(out+2,dest->domain,n);n+=2;}else return 0;
    write16(out+n,dest->port);return n+2;
}
static size_t frame(uint8_t *out,unsigned command,uint32_t id,const void *data,size_t n){out[0]=command;write32(out+1,id);write16(out+5,n);if(n)memcpy(out+7,data,n);return n+7;}
static void release(Session *s){if(--s->refs==0){OPENSSL_cleanse(s,sizeof *s);free(s);}}
static void timedWait(unsigned ms){struct timeval tv;gettimeofday(&tv,NULL);struct timespec ts={tv.tv_sec+(tv.tv_usec+(uint64_t)ms*1000)/1000000,(tv.tv_usec+(uint64_t)ms*1000)%1000000*1000};pthread_cond_timedwait(&changed,&lock,&ts);}
static int failure(Session *s,int error){s->failed=error;if(s->current){s->current->failed=error;shutdown(s->current->pair[1],SHUT_RDWR);}pthread_cond_broadcast(&changed);return -1;}
static int writeInitial(MLStream *wire,const uint8_t *bytes,size_t n,unsigned timeout){
    uint64_t deadline=millis()+timeout;size_t offset=0;
    while(offset<n||MLStreamWritePending(wire)){
        if(MLStreamPump(wire)<0)return -1;if(offset<n){ssize_t w=MLStreamWrite(wire,bytes+offset,n-offset);if(w>0){offset+=w;continue;}if(w<0&&errno!=EAGAIN)return -1;}
        uint64_t now=millis();if(now>=deadline){errno=ETIMEDOUT;return -1;}struct pollfd fd={MLStreamFD(wire),MLStreamEvents(wire,0,1),0};if(poll(&fd,1,(int)(deadline-now))<=0){errno=ETIMEDOUT;return -1;}
    }return 0;
}
static void startRaw(Session *s,size_t n){s->rawLength=n;s->rawOffset=0;s->step=0;s->processing=1;s->packet++;}
static int nextSegment(Session *s){
    if(!s->processing)return 0;Rule *r=s->packet<s->padding.stop?&s->padding.rules[s->packet]:NULL;
    while(r&&s->step<r->count){Range v=r->steps[s->step++];size_t remain=s->rawLength-s->rawOffset;
        if(v.check){if(!remain){s->processing=0;return 0;}continue;}
        size_t n=choose(v),take=remain<n?remain:n;memcpy(s->segment,s->raw+s->rawOffset,take);s->rawOffset+=take;
        if(remain==0){memset(s->segment,0,n+7);frame(s->segment,0,0,NULL,0);write16(s->segment+5,n);s->segmentLength=n+7;}
        else if(n>take+7){memset(s->segment+take,0,n-take);frame(s->segment+take,0,0,NULL,0);write16(s->segment+take+5,n-take-7);s->segmentLength=n;}
        else s->segmentLength=take;
        s->segmentOffset=0;return 1;
    }
    size_t remain=s->rawLength-s->rawOffset;if(remain){memcpy(s->segment,s->raw+s->rawOffset,remain);s->segmentLength=remain;s->segmentOffset=0;s->rawOffset=s->rawLength;return 1;}
    s->processing=0;return 0;
}
static int pumpOutput(Session *s){
    for(unsigned burst=0;burst<16;burst++){
        if(s->segmentOffset==s->segmentLength){s->segmentLength=s->segmentOffset=0;if(!nextSegment(s))return 0;}
        ssize_t n=MLStreamWrite(s->wire,s->segment+s->segmentOffset,s->segmentLength-s->segmentOffset);
        if(n>0)s->segmentOffset+=n;else if(n<0&&errno==EAGAIN)return 0;else return -1;
    }return 0;
}
static int parseFrames(Session *s){
    while(s->incomingLength>=7&&!s->downloadLength){uint8_t *p=s->incoming;unsigned command=p[0];uint32_t id=read32(p+1);size_t n=read16(p+5);if(s->incomingLength<n+7)break;
        MLAnyTLS *h=s->current;uint8_t *data=p+7;
        if(command==2){if(h&&id==h->id&&!h->remoteFIN){memcpy(s->download,data,n);s->downloadLength=n;s->downloadOffset=0;}}
        else if(command==3){if(n)return -1;if(h&&id==h->id){h->remoteFIN=1;shutdown(h->pair[1],SHUT_WR);}}
        else if(command==7){if(h&&id==h->id){if(n){h->failed=ECONNREFUSED;shutdown(h->pair[1],SHUT_RDWR);}else h->ready=1;pthread_cond_broadcast(&changed);}}
        else if(command==6){Padding *padding=malloc(sizeof *padding);if(!padding)return -1;int r=parsePadding((char *)data,n,padding);if(!r)memcpy(&s->client->padding,padding,sizeof *padding);free(padding);if(r)return -1;}
        else if(command==10){if(!n||n>1024||memchr(data,0,n))return -1;char text[1025];memcpy(text,data,n);text[n]=0;s->version=strstr(text,"v=2")?2:1;pthread_cond_broadcast(&changed);}
        else if(command==8){if(n)return -1;s->heartPending=1;s->heartID=id;}
        else if(command==0||command==9){if(command==9&&n)return -1;}
        else if(command==5)return -1;
        else if(n)return -1;
        memmove(s->incoming,p+n+7,s->incomingLength-n-7);s->incomingLength-=n+7;
    }return 0;
}
static int expired(Session *s,uint64_t now){
    if(s->current||now-s->lastCheck<(uint64_t)s->client->check*1000)return 0;s->lastCheck=now;
    if(now-s->idleSince<(uint64_t)s->client->idle*1000)return 0;unsigned newer=0;
    for(unsigned i=0;i<SESSIONS;i++)if(sessions[i]&&sessions[i]->client==s->client&&!sessions[i]->current&&sessions[i]->sequence>s->sequence)newer++;
    return newer>=s->client->minIdle;
}
static void *worker(void *context){
    Session *s=context;
    for(;;){
        if(MLStreamPump(s->wire)<0){pthread_mutex_lock(&lock);failure(s,errno);pthread_mutex_unlock(&lock);break;}
        pthread_mutex_lock(&lock);MLAnyTLS *h=s->current;uint64_t now=millis();
        if(s->failed||expired(s,now)){pthread_mutex_unlock(&lock);break;}
        if(!s->processing&&!s->segmentLength&&!MLStreamWritePending(s->wire)){
            if(h&&!h->synSent){uint8_t target[520];size_t n;
                if(h->udp){vless_dest_t magic={.atyp=VLESS_ADDR_DOMAIN};strcpy(magic.domain,"sp.v2.udp-over-tcp.arpa");n=address(&magic,target);target[n++]=1;n+=address(&h->target,target+n);}else n=address(&h->target,target);
                size_t used=0;
                if(s->streamID==1){char settings[160];int len=snprintf(settings,sizeof settings,"v=2\nclient=MuyuClashLegacy/1.0\npadding-md5=%s",s->padding.md5);used=frame(s->raw,4,0,settings,len);}
                used+=frame(s->raw+used,1,h->id,NULL,0);used+=frame(s->raw+used,2,h->id,target,n);h->synSent=1;startRaw(s,used);
            }else if(h&&(h->closing||h->shutdown)&&!h->finSent){startRaw(s,frame(s->raw,3,h->id,NULL,0));h->finSent=1;}
            else if(h&&h->closing&&h->finSent){s->current=NULL;s->idleSince=now;s->downloadLength=s->downloadOffset=0;pthread_cond_broadcast(&changed);h=NULL;}
            else if(h&&h->shutdown&&h->finSent&&!h->remoteFIN){h->remoteFIN=1;shutdown(h->pair[1],SHUT_WR);}
            else if(s->heartPending){startRaw(s,frame(s->raw,9,s->heartID,NULL,0));s->heartPending=0;}
        }
        if(h&&!h->ready&&s->version==0&&h->synSent&&!s->processing&&!s->segmentLength&&now-h->opened>=500){h->ready=1;pthread_cond_broadcast(&changed);}
        if(s->downloadLength&&h&&!h->closing){ssize_t n=send(h->pair[1],s->download+s->downloadOffset,s->downloadLength-s->downloadOffset,0);
            if(n>0){s->downloadOffset+=n;if(s->downloadOffset==s->downloadLength)s->downloadLength=s->downloadOffset=0;}
            else if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK){h->failed=errno;h->closing=1;}
        }
        int canUpload=h&&h->ready&&!h->closing&&!h->shutdown&&!h->remoteFIN&&!s->processing&&!s->segmentLength;
        if(canUpload){uint8_t bytes[8192];ssize_t n=recv(h->pair[1],bytes,sizeof bytes,0);if(n>0)startRaw(s,frame(s->raw,2,h->id,bytes,n));else if(n==0)h->shutdown=1;else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){h->failed=errno;h->closing=1;}}
        pthread_mutex_unlock(&lock);
        if(pumpOutput(s)<0){pthread_mutex_lock(&lock);failure(s,errno);pthread_mutex_unlock(&lock);break;}
        pthread_mutex_lock(&lock);int bad=parseFrames(s);int canRead=!s->downloadLength&&s->incomingLength<=WIRE_CAP-4096;pthread_mutex_unlock(&lock);
        if(bad){pthread_mutex_lock(&lock);failure(s,EPROTO);pthread_mutex_unlock(&lock);break;}
        if(canRead){uint8_t bytes[4096];ssize_t n=MLStreamRead(s->wire,bytes,sizeof bytes);if(n>0){pthread_mutex_lock(&lock);memcpy(s->incoming+s->incomingLength,bytes,n);s->incomingLength+=n;bad=parseFrames(s);pthread_mutex_unlock(&lock);if(bad){pthread_mutex_lock(&lock);failure(s,EPROTO);pthread_mutex_unlock(&lock);break;}}
            else if(n==0||(n<0&&errno!=EAGAIN)){pthread_mutex_lock(&lock);failure(s,n==0?ECONNRESET:errno);pthread_mutex_unlock(&lock);break;}}
        pthread_mutex_lock(&lock);h=s->current;struct pollfd fds[2]={{MLStreamFD(s->wire),MLStreamEvents(s->wire,canRead,s->processing||s->segmentLength),0},{h?h->pair[1]:-1,0,0}};
        if(h&&!h->closing){if(!h->shutdown&&!h->remoteFIN&&!s->processing&&!s->segmentLength)fds[1].events|=POLLIN;if(s->downloadLength)fds[1].events|=POLLOUT;}
        pthread_mutex_unlock(&lock);if(!MLStreamPendingRead(s->wire))poll(fds,2,50);
    }
    MLStreamClose(s->wire);s->wire=NULL;
    pthread_mutex_lock(&lock);if(s->current){if(!s->current->failed)s->current->failed=s->failed?s->failed:ECONNRESET;shutdown(s->current->pair[1],SHUT_RDWR);s->current=NULL;}
    for(unsigned i=0;i<SESSIONS;i++)if(sessions[i]==s)sessions[i]=NULL;s->finished=1;pthread_cond_broadcast(&changed);release(s);pthread_mutex_unlock(&lock);return NULL;
}
static MLAnyTLS *openAnyTLS(const char *identity,const char *password,const vless_dest_t *dest,unsigned check,unsigned idle,unsigned minIdle,unsigned timeout,MLAnyTLSFactory factory,void *context,int udp){
    uint8_t target[259];if(!identity||strlen(identity)>=129||!password||!dest||!dest->port||!address(dest,target)||!factory||minIdle>SESSIONS){errno=EINVAL;return NULL;}
    MLAnyTLS *h=calloc(1,sizeof *h);if(!h)return NULL;h->pair[0]=h->pair[1]=-1;h->target=*dest;h->opened=millis();h->udp=udp;
    if(socketpair(AF_UNIX,SOCK_STREAM,0,h->pair)||fcntl(h->pair[0],F_SETFL,O_NONBLOCK)||fcntl(h->pair[1],F_SETFL,O_NONBLOCK))goto bad;
    fcntl(h->pair[0],F_SETFD,FD_CLOEXEC);fcntl(h->pair[1],F_SETFD,FD_CLOEXEC);
    pthread_mutex_lock(&lock);Client *client=NULL;
    for(unsigned i=0;i<CLIENTS;i++)if(!strcmp(clients[i].identity,identity)){client=&clients[i];break;}
    if(!client){for(unsigned i=0;i<CLIENTS;i++)if(!clients[i].identity[0]){client=&clients[i];break;}}
    if(!client){for(unsigned i=0;i<CLIENTS;i++){int used=0;for(unsigned j=0;j<SESSIONS;j++)if(sessions[j]&&sessions[j]->client==&clients[i])used=1;if(!used){memset(&clients[i],0,sizeof clients[i]);client=&clients[i];break;}}}
    if(!client){pthread_mutex_unlock(&lock);errno=EBUSY;goto bad;}
    if(!client->identity[0]){strcpy(client->identity,identity);parsePadding(defaultScheme,sizeof defaultScheme-1,&client->padding);client->check=check?check:30;client->idle=idle?idle:60;client->minIdle=minIdle;}
    Session *s=NULL;for(unsigned i=0;i<SESSIONS;i++)if(sessions[i]&&sessions[i]->client==client&&!sessions[i]->current&&!sessions[i]->failed&&sessions[i]->streamID<UINT32_MAX&&(!s||sessions[i]->sequence>s->sequence))s=sessions[i];
    if(s){s->refs++;h->session=s;h->id=++s->streamID;s->current=h;pthread_mutex_unlock(&lock);}
    else{
        unsigned slot=SESSIONS;for(unsigned i=0;i<SESSIONS;i++)if(!sessions[i]){slot=i;break;}
        if(slot==SESSIONS){pthread_mutex_unlock(&lock);errno=EBUSY;goto bad;}
        s=calloc(1,sizeof *s);if(!s){pthread_mutex_unlock(&lock);goto bad;}s->refs=1;s->client=client;s->padding=client->padding;s->sequence=++client->sequence;s->streamID=1;s->current=h;h->session=s;h->id=1;
        sessions[slot]=s;pthread_mutex_unlock(&lock);
        s->wire=factory(context,timeout);if(!s->wire)goto newBad;
        size_t pad=choose(s->padding.rules[0].steps[0]);uint8_t *auth=calloc(1,34+pad);if(!auth)goto newBad;unsigned n=0;
        int good=EVP_Digest(password,strlen(password),auth,&n,EVP_sha256(),NULL)==1&&n==32;write16(auth+32,pad);if(good)good=writeInitial(s->wire,auth,34+pad,timeout)==0;OPENSSL_cleanse(auth,34+pad);free(auth);if(!good)goto newBad;
        pthread_t thread;pthread_mutex_lock(&lock);s->refs++;pthread_mutex_unlock(&lock);int r=pthread_create(&thread,NULL,worker,s);if(r){pthread_mutex_lock(&lock);s->refs--;pthread_mutex_unlock(&lock);errno=r;goto newBad;}pthread_detach(thread);
    }
    pthread_mutex_lock(&lock);uint64_t deadline=h->opened+timeout;
    while(!h->ready&&!h->failed&&millis()<deadline)timedWait(50);
    int error=h->failed?h->failed:!h->ready?ETIMEDOUT:0;pthread_mutex_unlock(&lock);if(error){errno=error;goto bad;}return h;
newBad:{int error=errno;if(s->wire)MLStreamClose(s->wire);s->wire=NULL;pthread_mutex_lock(&lock);for(unsigned i=0;i<SESSIONS;i++)if(sessions[i]==s)sessions[i]=NULL;s->current=NULL;s->finished=1;pthread_mutex_unlock(&lock);errno=error;}
bad:{int error=errno;MLAnyTLSClose(h);errno=error;return NULL;}
}
MLAnyTLS *MLAnyTLSOpen(const char *identity,const char *password,const vless_dest_t *dest,unsigned check,unsigned idle,unsigned minIdle,unsigned timeout,MLAnyTLSFactory factory,void *context){return openAnyTLS(identity,password,dest,check,idle,minIdle,timeout,factory,context,0);}
MLAnyTLS *MLAnyTLSOpenUDP(const char *identity,const char *password,const vless_dest_t *dest,unsigned check,unsigned idle,unsigned minIdle,unsigned timeout,MLAnyTLSFactory factory,void *context){return openAnyTLS(identity,password,dest,check,idle,minIdle,timeout,factory,context,1);}
int MLAnyTLSFD(const MLAnyTLS *h){return h->pair[0];}
int MLAnyTLSPump(MLAnyTLS *h){pthread_mutex_lock(&lock);int error=h->failed;pthread_mutex_unlock(&lock);if(error){errno=error;return -1;}return 0;}
ssize_t MLAnyTLSRead(MLAnyTLS *h,void *data,size_t n){if(MLAnyTLSPump(h))return -1;ssize_t r=recv(h->pair[0],data,n,0);if(r<0&&errno==EWOULDBLOCK)errno=EAGAIN;return r;}
ssize_t MLAnyTLSWrite(MLAnyTLS *h,const void *data,size_t n){if(MLAnyTLSPump(h))return -1;pthread_mutex_lock(&lock);int ended=h->writeClosing||h->shutdown||h->remoteFIN;pthread_mutex_unlock(&lock);if(ended){errno=EPIPE;return -1;}ssize_t r=send(h->pair[0],data,n,0);if(r<0&&errno==EWOULDBLOCK)errno=EAGAIN;return r;}
void MLAnyTLSShutdown(MLAnyTLS *h){pthread_mutex_lock(&lock);h->writeClosing=1;shutdown(h->pair[0],SHUT_WR);pthread_mutex_unlock(&lock);}
void MLAnyTLSClose(MLAnyTLS *h){if(!h)return;pthread_mutex_lock(&lock);Session *s=h->session;h->closing=1;if(s){uint64_t deadline=millis()+2000;while(s->current==h&&!s->finished&&millis()<deadline)timedWait(50);if(s->current==h){failure(s,ECANCELED);while(s->current==h&&!s->finished)timedWait(50);}release(s);}pthread_mutex_unlock(&lock);if(h->pair[0]>=0)close(h->pair[0]);if(h->pair[1]>=0)close(h->pair[1]);free(h);}
unsigned long long MLAnyTLSSequence(const MLAnyTLS *h){return h->session->sequence;}
int MLAnyTLSPaddingMD5(const MLAnyTLS *h,char out[33]){if(!h||!out)return -1;pthread_mutex_lock(&lock);memcpy(out,h->session->client->padding.md5,33);pthread_mutex_unlock(&lock);return 0;}
int MLAnyTLSSessionPaddingMD5(const MLAnyTLS *h,char out[33]){if(!h||!out)return -1;pthread_mutex_lock(&lock);memcpy(out,h->session->padding.md5,33);pthread_mutex_unlock(&lock);return 0;}
