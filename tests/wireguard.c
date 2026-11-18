#include "../protocols/MLWireGuard.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int readable(MLWGSession *s,int write){struct pollfd p={MLWGFD(s),write?POLLOUT:POLLIN,0};return poll(&p,1,5000)>0;}
int main(int argc,const char **argv){
    alarm(40);if(argc!=4)return 64;FILE *file=fopen(argv[1],"rb");if(!file)return 1;char profile[65536];size_t n=fread(profile,1,sizeof profile-1,file);profile[n]=0;fclose(file);
    awg_config_t *cfg=calloc(1,sizeof *cfg);char reason[256];if(MLWGParseProfile(profile,cfg,reason,sizeof reason)){fprintf(stderr,"profile %s\n",reason);return 2;}
    vless_dest_t target={.port=20080};target.atyp=strchr(argv[2],':')?VLESS_ADDR_IPV6:VLESS_ADDR_IPV4;
    if(inet_pton(target.atyp==VLESS_ADDR_IPV4?AF_INET:AF_INET6,argv[2],target.host_addr)!=1)return 3;
    MLWGSession *s=MLWGOpen(cfg,&target,0,5000);if(!strcmp(argv[3],"reject")){if(s){MLWGClose(s);return 4;}puts("PASS rejected WireGuard handshake");free(cfg);return 0;}
    if(!s){perror("WG open");return 5;}uint8_t data[262144],reply[1500];for(size_t i=0;i<sizeof data;i++)data[i]=i%251;size_t sent=0,got=0;
    while(got<sizeof data){int progress=0;if(sent<sizeof data){n=sizeof data-sent;if(n>4096)n=4096;ssize_t r=MLWGWrite(s,data+sent,n);if(r>0){sent+=r;progress=1;}else if(errno!=EAGAIN){perror("WG write");return 6;}}
        for(unsigned k=0;k<16&&got<sizeof data;k++){ssize_t r=MLWGRead(s,reply,sizeof reply);if(r<0&&errno==EAGAIN)break;if(r<=0||r>sizeof data-got||memcmp(reply,data+got,r)){fprintf(stderr,"WG mismatch %ld at %lu\n",(long)r,(unsigned long)got);return 7;}got+=r;progress=1;}
        if(!progress&&!readable(s,sent<sizeof data)){fprintf(stderr,"WG TCP timeout sent=%lu got=%lu\n",(unsigned long)sent,(unsigned long)got);return 8;}
    }
    MLWGShutdown(s);for(;;){ssize_t r=MLWGRead(s,reply,sizeof reply);if(!r)break;if(r<0&&errno==EAGAIN&&readable(s,0))continue;perror("WG EOF");return 9;}MLWGClose(s);printf("PASS WireGuard TCP %lu bytes and EOF\n",(unsigned long)got);fflush(stdout);
    target.port=20081;s=MLWGOpen(cfg,&target,1,5000);if(!s){perror("WG UDP open");return 10;}uint8_t upload[1501],download[1501];unsigned sizes[]={1,1400,1500};
    for(unsigned k=0;k<15;k++){if(k==7&&!strcmp(argv[3],"renew"))sleep(4);size_t size=sizes[k%3];for(size_t i=0;i<size;i++)upload[i]=(i+k)%251;
        if(MLWGWrite(s,upload,size)!=size||!readable(s,0)){perror("WG UDP");return 11;}ssize_t r=MLWGRead(s,download,sizeof download);if(r!=size||memcmp(upload,download,size)){fprintf(stderr,"WG UDP mismatch k=%u got=%ld\n",k,(long)r);return 12;}
    }
    if(MLWGWrite(s,upload,1501)!=-1||errno!=EMSGSIZE)return 13;MLWGClose(s);free(cfg);puts("PASS WireGuard UDP15 with fragmentation and replay rejection");return 0;
}
