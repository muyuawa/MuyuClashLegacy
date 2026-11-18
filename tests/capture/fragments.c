#include "MLUDPPackets.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct Harness { unsigned count,delivered; size_t sizes[128],expectedLength; uint8_t frames[128][1504];const uint8_t *expected; };
static int save(void *ctx,const uint8_t *frame,size_t length){struct Harness *h=ctx;assert(h->count<128);memcpy(h->frames[h->count],frame,length);h->sizes[h->count++]=length;return 1;}
static int receive(void *ctx,const tun_flow_key_t *key,const uint8_t *data,size_t length){struct Harness *h=ctx;assert(key->source_port==443 && key->destination_port==40001);assert(length==h->expectedLength && !memcmp(data,h->expected,length));h->delivered++;return 0;}
static tun_flow_key_t tuple(unsigned family){tun_flow_key_t k;memset(&k,0,sizeof k);k.address_len=family;k.protocol=TUN_FLOW_UDP;k.source_port=40001;k.destination_port=443;if(family==4){k.source[0]=10;k.source[3]=2;k.destination[0]=192;k.destination[1]=0;k.destination[2]=2;k.destination[3]=1;}else{k.source[0]=0xfd;k.source[1]=1;k.source[15]=2;k.destination[0]=0xfd;k.destination[1]=2;k.destination[15]=1;}return k;}
int main(void){
    uint8_t *payload=malloc(65507);for(size_t i=0;i<65507;i++)payload[i]=(uint8_t)(i*17+31);
    for(unsigned family=4;family<=16;family+=12)for(unsigned test=0;test<5;test++){
        size_t lengths[]={0,1450,4096,8192,65507};struct Harness h={0};h.expected=payload;h.expectedLength=lengths[test];
        MLUDPPackets *out=MLUDPPacketsCreate(),*in=MLUDPPacketsCreate();tun_flow_key_t k=tuple(family);
        assert(!MLUDPPacketsReply(out,&k,payload,h.expectedLength,1000));MLUDPPacketsDrain(out,1000,save,&h);assert(h.count>0 && !MLUDPPacketsPending(out));
        for(unsigned i=h.count;i>0;i--)assert(MLUDPPacketsInput(in,h.frames[i-1],h.sizes[i-1],1000,receive,&h)==1);
        assert(h.delivered==1);
        if(h.count>1){h.delivered=0;MLUDPPacketsInput(in,h.frames[0],h.sizes[0],1000,receive,&h);MLUDPPacketsInput(in,h.frames[0],h.sizes[0],1000,receive,&h);
            for(unsigned i=1;i<h.count;i++)MLUDPPacketsInput(in,h.frames[i],h.sizes[i],1000,receive,&h);assert(!h.delivered);
            uint64_t a,b,c;MLUDPPacketsCounts(in,&a,&b,&c);assert(c>=1);
        }
        MLUDPPacketsDestroy(out);MLUDPPacketsDestroy(in);
    }
    {MLUDPPackets *out=MLUDPPacketsCreate(),*in=MLUDPPacketsCreate();tun_flow_key_t k=tuple(4);struct Harness h={0};h.expected=payload;h.expectedLength=4096;
        assert(!MLUDPPacketsReply(out,&k,payload,4096,1000));MLUDPPacketsDrain(out,1000,save,&h);
        MLUDPPacketsInput(in,h.frames[0],h.sizes[0],1000,receive,&h);for(unsigned i=1;i<h.count;i++)MLUDPPacketsInput(in,h.frames[i],h.sizes[i],20000,receive,&h);assert(!h.delivered);
        MLUDPPacketsDestroy(out);MLUDPPacketsDestroy(in);}
    free(payload);puts("PASS IPv4/IPv6 UDP fragmentation through 65507 bytes, reordering, overlap rejection and timeout");return 0;
}
