#import <Foundation/Foundation.h>
#include "../protocols/MLAnyTLS.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef struct { unsigned short port;const char *ca;unsigned calls; } Factory;
static MLStream *wire(void *context,unsigned timeout){Factory *f=context;f->calls++;MLStream *plain=MLStreamOpen(NULL,"127.0.0.1",f->port,timeout);if(!plain)return NULL;MLStream *tls=MLStreamWrapTLS(plain,"localhost",f->ca,timeout);if(!tls)MLStreamClose(plain);return tls;}
static int transfer(MLAnyTLS *s){uint8_t data[65536],reply[997];for(size_t i=0;i<sizeof data;i++)data[i]=i%251;size_t sent=0,got=0;
    while(got<sizeof data){int progress=0;if(sent<sizeof data){ssize_t n=MLAnyTLSWrite(s,data+sent,sizeof data-sent);if(n>0){sent+=n;progress=1;}else if(n>=0||errno!=EAGAIN)return -1;}
        for(unsigned i=0;i<32&&got<sizeof data;i++){ssize_t n=MLAnyTLSRead(s,reply,sizeof reply);if(n<0&&errno==EAGAIN)break;if(n<=0||n>sizeof data-got||memcmp(reply,data+got,n))return -1;got+=n;progress=1;}
        if(!progress){struct pollfd fd={MLAnyTLSFD(s),POLLIN|(sent<sizeof data?POLLOUT:0),0};if(poll(&fd,1,5000)<=0)return -1;}}
    return 0;
}
int main(int argc,const char **argv){@autoreleasepool{
    alarm(55);if(argc!=5)return 64;Factory f={atoi(argv[1]),argv[3],0};vless_dest_t dest={.atyp=VLESS_ADDR_IPV4,.port=atoi(argv[2])};inet_pton(AF_INET,"127.0.0.1",dest.host_addr);
    MLAnyTLS *a=MLAnyTLSOpen("fixture","fixture-secret",&dest,1,1,1,8000,wire,&f);if(!a){perror("a open");return 1;}if(transfer(a))return 2;
    char md5[33];MLAnyTLSPaddingMD5(a,md5);if(strcmp(md5,argv[4])){fprintf(stderr,"padding md5 %s != %s\n",md5,argv[4]);return 3;}uint64_t first=MLAnyTLSSequence(a);MLAnyTLSClose(a);
    MLAnyTLS *b=MLAnyTLSOpen("fixture","fixture-secret",&dest,1,1,1,8000,wire,&f);if(!b||MLAnyTLSSequence(b)!=first||f.calls!=1||transfer(b))return 4;
    MLAnyTLS *c=MLAnyTLSOpen("fixture","fixture-secret",&dest,1,1,1,8000,wire,&f);if(!c||MLAnyTLSSequence(c)<=first||f.calls!=2||transfer(c))return 5;MLAnyTLSSessionPaddingMD5(c,md5);if(strcmp(md5,argv[4]))return 12;uint64_t latest=MLAnyTLSSequence(c);MLAnyTLSClose(c);MLAnyTLSClose(b);
    MLAnyTLS *d=MLAnyTLSOpen("fixture","fixture-secret",&dest,1,1,1,8000,wire,&f);if(!d||MLAnyTLSSequence(d)!=latest||f.calls!=2||transfer(d))return 6;MLAnyTLSShutdown(d);
    uint8_t byte;for(;;){ssize_t n=MLAnyTLSRead(d,&byte,1);if(!n)break;if(n<0&&errno==EAGAIN){struct pollfd fd={MLAnyTLSFD(d),POLLIN,0};if(poll(&fd,1,5000)>0)continue;}return 7;}MLAnyTLSClose(d);
    sleep(3);MLAnyTLS *e=MLAnyTLSOpen("fixture","fixture-secret",&dest,1,1,1,8000,wire,&f);if(!e||MLAnyTLSSequence(e)!=latest||f.calls!=2||transfer(e))return 8;MLAnyTLSClose(e);
    MLAnyTLS *expired=MLAnyTLSOpen("expire","fixture-secret",&dest,1,1,0,8000,wire,&f);if(!expired||transfer(expired))return 9;uint64_t expiredSequence=MLAnyTLSSequence(expired);MLAnyTLSClose(expired);sleep(3);
    expired=MLAnyTLSOpen("expire","fixture-secret",&dest,1,1,0,8000,wire,&f);if(!expired||MLAnyTLSSequence(expired)<=expiredSequence||f.calls!=4||transfer(expired))return 10;MLAnyTLSClose(expired);
    MLAnyTLS *bad=MLAnyTLSOpen("bad-password","wrong",&dest,1,1,0,3000,wire,&f);if(bad){MLAnyTLSClose(bad);return 11;}
    printf("PASS AnyTLS 7 transfers, latest idle reuse, idle expiration/retention, padding update, FIN, auth rejection; TLS sessions=%u\n",f.calls);return 0;
}}
