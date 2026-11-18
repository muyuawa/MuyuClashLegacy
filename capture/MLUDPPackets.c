#include "MLUDPPackets.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#define ML_MTU 1500
#define ML_MAX 65535
#define ML_SLOTS 8
#define ML_QUEUE 128
struct MLFragment {
    uint8_t source[16],destination[16],family,used,final;
    uint32_t identifier;
    uint64_t created;
    size_t total,received,extent;
    uint8_t bytes[ML_MAX],present[(ML_MAX+7)/8];
};
struct MLFrame { size_t length; uint64_t created; uint8_t bytes[ML_MTU+4]; };
struct MLUDPPackets {
    struct MLFragment fragments[ML_SLOTS];
    struct MLFrame queue[ML_QUEUE];
    size_t head,count;
    uint32_t identifier;
    uint64_t input,output,invalid;
};
static uint16_t get16(const uint8_t *p){return (uint16_t)((p[0]<<8)|p[1]);}
static uint32_t get32(const uint8_t *p){return ((uint32_t)get16(p)<<16)|get16(p+2);}
static void put16(uint8_t *p,uint16_t n){p[0]=n>>8;p[1]=n;}
static void put32(uint8_t *p,uint32_t n){put16(p,n>>16);put16(p+2,n);}
static uint32_t sum(const uint8_t *p,size_t n,uint32_t value){while(n>=2){value+=get16(p);p+=2;n-=2;}if(n)value+=(uint32_t)p[0]<<8;return value;}
static uint16_t digest(uint32_t n){while(n>>16)n=(n&65535)+(n>>16);return (uint16_t)~n;}
static uint32_t pseudo(const uint8_t *source,const uint8_t *destination,unsigned family,size_t length){
    uint32_t n=sum(source,family,0);n=sum(destination,family,n);n+=17;n+=length;return n;
}
static int reserved(const uint8_t *p,unsigned family){
    static const uint8_t v6[14]={0xfd,0,0x5e,0x4b,0,0,0,0,0,0,0,0,0,0};
    if(family==4)return p[0]==198 && p[1]==18 && p[2]==0 && (p[3]==1 || p[3]==2);
    return !memcmp(p,v6,14) && p[14]==0 && (p[15]==1 || p[15]==2);
}
MLUDPPackets *MLUDPPacketsCreate(void){return calloc(1,sizeof(MLUDPPackets));}
void MLUDPPacketsDestroy(MLUDPPackets *s){if(s){memset(s,0,sizeof *s);free(s);}}
static int deliver(MLUDPPackets *s,const uint8_t *source,const uint8_t *destination,unsigned family,const uint8_t *payload,size_t length,MLUDPPacketReceive receive,void *ctx){
    // iOS may select the configured utun address (.1) as an ordinary app's
    // source. Only destinations are reserved; outbound interface binding,
    // rather than a source-address guess, keeps proxy sockets out of utun.
    if(length<8 || length>ML_MAX || get16(payload+4)!=length || !get16(payload) || !get16(payload+2) || reserved(destination,family) ||
        (family==16 && !get16(payload+6)) || (get16(payload+6) && digest(sum(payload,length,pseudo(source,destination,family,length)))!=0)){s->invalid++;return 1;}
    tun_flow_key_t key;memset(&key,0,sizeof key);key.address_len=family;key.protocol=TUN_FLOW_UDP;
    memcpy(key.source,source,family);memcpy(key.destination,destination,family);key.source_port=get16(payload);key.destination_port=get16(payload+2);
    if(receive(ctx,&key,payload+8,length-8)<0)s->invalid++;
    return 1;
}
static int fragment(MLUDPPackets *s,const uint8_t *source,const uint8_t *destination,unsigned family,uint32_t identifier,size_t offset,int more,const uint8_t *payload,size_t length,uint64_t now,MLUDPPacketReceive receive,void *ctx){
    struct MLFragment *slot=NULL,*vacant=NULL;
    for(unsigned i=0;i<ML_SLOTS;i++){
        struct MLFragment *f=&s->fragments[i];if(f->used && now-f->created>15000){f->used=0;s->invalid++;}
        if(!f->used && !vacant)vacant=f;
        if(f->used && f->family==family && f->identifier==identifier && !memcmp(f->source,source,family) && !memcmp(f->destination,destination,family))slot=f;
    }
    if(!length || offset>ML_MAX || length>ML_MAX-offset || (more && (length&7))){if(slot)slot->used=0;s->invalid++;return 1;}
    if(!slot){slot=vacant;if(!slot){s->invalid++;return 1;}memset(slot,0,sizeof *slot);slot->used=1;slot->family=family;slot->identifier=identifier;slot->created=now;memcpy(slot->source,source,family);memcpy(slot->destination,destination,family);}
    if((slot->final && offset+length>slot->total) || (!more && slot->final) || (!more && slot->extent>offset+length)){slot->used=0;s->invalid++;return 1;}
    for(size_t i=offset;i<offset+length;i++)if(slot->present[i/8]&(1<<(i&7))){slot->used=0;s->invalid++;return 1;}
    memcpy(slot->bytes+offset,payload,length);for(size_t i=offset;i<offset+length;i++)slot->present[i/8]|=1<<(i&7);slot->received+=length;if(offset+length>slot->extent)slot->extent=offset+length;
    if(!more){slot->final=1;slot->total=offset+length;}
    if(slot->final && slot->received==slot->total){slot->used=0;return deliver(s,source,destination,family,slot->bytes,slot->total,receive,ctx);}return 1;
}
int MLUDPPacketsInput(MLUDPPackets *s,const uint8_t *frame,size_t length,uint64_t now,MLUDPPacketReceive receive,void *ctx){
    if(!s || !frame || length<5)return 0;
    const uint8_t *p=frame+4;size_t n=length-4;
    if(get32(frame)==2 && p[0]>>4==4){
        if(n<20 || p[9]!=17)return 0;s->input++;
        size_t header=(p[0]&15)*4;if(header<20 || header>n || get16(p+2)!=n || n>ML_MTU || digest(sum(p,header,0))!=0){s->invalid++;return 1;}
        // Source-route IP options cannot preserve the immutable route decision.
        for(size_t i=20;i<header;){uint8_t option=p[i];if(!option)break;if(option==1){i++;continue;}if(i+2>header || p[i+1]<2 || p[i+1]>header-i || option==131 || option==137){s->invalid++;return 1;}i+=p[i+1];}
        uint16_t flags=get16(p+6);if(flags&0x8000){s->invalid++;return 1;}
        if(flags&0x3fff)return fragment(s,p+12,p+16,4,get16(p+4),(flags&8191)*8,flags&8192,p+header,n-header,now,receive,ctx);
        return deliver(s,p+12,p+16,4,p+header,n-header,receive,ctx);
    }
    if(get32(frame)==30 && p[0]>>4==6){
        if(n<40)return 0;uint8_t next=p[6];size_t cursor=40;
        for(unsigned ext=0;ext<8 && (next==0 || next==43 || next==60);ext++){
            if(cursor+2>n){s->input++;s->invalid++;return 1;}size_t bytes=((size_t)p[cursor+1]+1)*8;
            if(bytes>n-cursor || (next==43 && p[cursor+3])){s->input++;s->invalid++;return 1;}next=p[cursor];cursor+=bytes;
        }
        if(next!=17 && next!=44)return 0;s->input++;
        if(n>ML_MTU || get16(p+4)!=n-40){s->invalid++;return 1;}
        if(next==44){
            if(cursor+8>n || p[cursor]!=17 || p[cursor+1] || (get16(p+cursor+2)&6)){s->invalid++;return 1;}
            uint16_t value=get16(p+cursor+2);return fragment(s,p+8,p+24,16,get32(p+cursor+4),value&65528,value&1,p+cursor+8,n-cursor-8,now,receive,ctx);
        }
        return deliver(s,p+8,p+24,16,p+cursor,n-cursor,receive,ctx);
    }
    return 0;
}
static void enqueue(MLUDPPackets *s,const uint8_t *packet,size_t length,unsigned family,uint64_t now){
    struct MLFrame *f=&s->queue[(s->head+s->count)%ML_QUEUE];put32(f->bytes,family==4?2:30);memcpy(f->bytes+4,packet,length);f->length=length+4;f->created=now;s->count++;
}
int MLUDPPacketsReply(MLUDPPackets *s,const tun_flow_key_t *key,const uint8_t *payload,size_t length,uint64_t now){
    if(!s || !key || (key->address_len!=4 && key->address_len!=16) || key->protocol!=TUN_FLOW_UDP || length>65507 || (!payload && length))return -1;
    unsigned family=key->address_len;size_t total=length+8,maximum=family==4?1480:1448;
    if(total<=ML_MTU-(family==4?20:40))maximum=total;
    size_t frames=(total+maximum-1)/maximum;if(frames>ML_QUEUE-s->count){s->invalid++;return -1;}
    uint8_t *datagram=malloc(total);if(!datagram)return -1;
    put16(datagram,key->destination_port);put16(datagram+2,key->source_port);put16(datagram+4,total);put16(datagram+6,0);if(length)memcpy(datagram+8,payload,length);
    uint16_t checksum=digest(sum(datagram,total,pseudo(key->destination,key->source,family,total)));put16(datagram+6,checksum?checksum:65535);
    uint32_t identifier=++s->identifier;uint8_t packet[ML_MTU];
    for(size_t offset=0;offset<total;){size_t part=total-offset;if(part>maximum)part=maximum;int more=offset+part<total;
        memset(packet,0,sizeof packet);size_t header;
        if(family==4){header=20;packet[0]=0x45;put16(packet+2,header+part);put16(packet+4,identifier);put16(packet+6,(uint16_t)(offset/8)|(more?8192:0));packet[8]=64;packet[9]=17;memcpy(packet+12,key->destination,4);memcpy(packet+16,key->source,4);put16(packet+10,digest(sum(packet,20,0)));}
        else{header=frames>1?48:40;packet[0]=0x60;put16(packet+4,header-40+part);packet[6]=frames>1?44:17;packet[7]=64;memcpy(packet+8,key->destination,16);memcpy(packet+24,key->source,16);if(frames>1){packet[40]=17;put16(packet+42,(uint16_t)offset|(more?1:0));put32(packet+44,identifier);}}
        memcpy(packet+header,datagram+offset,part);enqueue(s,packet,header+part,family,now);offset+=part;
    }
    free(datagram);return 0;
}
void MLUDPPacketsDrain(MLUDPPackets *s,uint64_t now,MLUDPPacketWrite writeFrame,void *ctx){
    if(!s)return;for(unsigned i=0;i<64 && s->count;i++){
        struct MLFrame *f=&s->queue[s->head];int result=now-f->created>2000?-1:writeFrame(ctx,f->bytes,f->length);
        if(result==0)break;if(result<0)s->invalid++;else s->output++;s->head=(s->head+1)%ML_QUEUE;s->count--;
    }
}
size_t MLUDPPacketsPending(const MLUDPPackets *s){return s?s->count:0;}
void MLUDPPacketsCounts(const MLUDPPackets *s,uint64_t *input,uint64_t *output,uint64_t *invalid){*input=s?s->input:0;*output=s?s->output:0;*invalid=s?s->invalid:0;}
