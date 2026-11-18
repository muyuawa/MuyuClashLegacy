#include "MLDNSDoQ.h"
#include "../transport/MLNetworkBinding.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "hy2_engine.h"
static int ml_doq_socket(int family,int type,int protocol){
    int fd=socket(family,type,protocol);
    if(fd>=0&&(family==AF_INET||family==AF_INET6)&&MLNetworkBindSocket(fd,family)){
        int saved=errno;close(fd);errno=saved;return -1;
    }
    return fd;
}
#define socket ml_doq_socket
#define hy2_engine_start ml_doq_engine_start
#define hy2_engine_dial ml_doq_engine_dial
#define hy2_engine_cancel ml_doq_engine_cancel
#define hy2_engine_stop ml_doq_engine_stop
#define transport_hy2 ml_doq_transport
#include "transport_doq_muyu.c"
#undef socket
#undef hy2_engine_start
#undef hy2_engine_dial
#undef hy2_engine_cancel
#undef hy2_engine_stop
#undef transport_hy2

static int doqWait(int fd,short events,uint64_t deadline){
    for(;;){uint64_t now=senko_now_ms();if(now>=deadline){errno=ETIMEDOUT;return -1;}
        struct pollfd p={fd,events,0};int result=poll(&p,1,(int)(deadline-now));
        if(result>0)return 0;if(result==0){errno=ETIMEDOUT;return -1;}if(errno!=EINTR)return -1;
    }
}
static int doqRead(void *stream,int fd,void *data,size_t size,uint64_t deadline){
    size_t used=0;while(used<size){int n=ml_doq_transport.read(stream,(uint8_t *)data+used,(int)(size-used));
        if(n>0){used+=n;continue;}if(n==TRANSPORT_WANT_READ){if(doqWait(fd,POLLIN,deadline))return -1;continue;}
        errno=n==TRANSPORT_EOF||n==0?EPROTO:ECONNRESET;return -1;
    }return 0;
}
ssize_t MLDNSDoQQuery(const char *host,uint16_t port,const char *serverName,const char *caFile,
                     const void *query,size_t queryLength,void *response,size_t responseCapacity,
                     unsigned timeoutMS,char *error,size_t errorCapacity){
    char reason[400]={0};if(error&&errorCapacity)error[0]=0;
    if(!host||!*host||!port||!caFile||!*caFile||!query||queryLength<12||queryLength>65535||!response||responseCapacity<12||
       timeoutMS<100||timeoutMS>60000||((const uint8_t *)query)[2]&0x80){errno=EINVAL;goto refused;}
    uint64_t deadline=senko_now_ms()+timeoutMS;uint8_t addresses[16][16]={{0}},lengths[16]={0};size_t count=0;
    struct addrinfo hints={0},*resolved=NULL;hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_DGRAM;
    if(MLNetworkResolveBootstrapHost(host,NULL,&hints,&resolved)){errno=EHOSTUNREACH;goto refused;}
    for(struct addrinfo *a=resolved;a&&count<16;a=a->ai_next){
        if(a->ai_family==AF_INET){memcpy(addresses[count],&((struct sockaddr_in *)a->ai_addr)->sin_addr,4);lengths[count++]=4;}
        else if(a->ai_family==AF_INET6){memcpy(addresses[count],&((struct sockaddr_in6 *)a->ai_addr)->sin6_addr,16);lengths[count++]=16;}
    }freeaddrinfo(resolved);if(!count){errno=EHOSTUNREACH;goto refused;}
    uint64_t now=senko_now_ms();if(now+50>=deadline){errno=ETIMEDOUT;goto refused;}
    hy2_engine_config_t config={.addresses=addresses,.address_lens=lengths,.address_count=count,.port=port,
        .sni=serverName?serverName:"",.peer_host=host,.auth="",.ca_file=caFile,.connect_timeout_ms=(int)(deadline-now)-50};
    hy2_engine_t *engine=ml_doq_engine_start(&config,reason,sizeof reason);if(!engine){errno=EACCES;goto refused;}
    int fd=ml_doq_engine_dial(engine,reason,sizeof reason);void *stream=NULL;uint8_t *request=NULL;ssize_t result=-1;
    if(fd<0){errno=EACCES;goto done;}stream=ml_doq_transport.open(fd,NULL);if(!stream){errno=EIO;goto done;}
    request=malloc(queryLength+2);if(!request)goto done;request[0]=queryLength>>8;request[1]=queryLength;
    memcpy(request+2,query,queryLength);request[2]=request[3]=0;
    size_t sent=0;while(sent<queryLength+2){int n=ml_doq_transport.write(stream,request+sent,(int)(queryLength+2-sent));
        if(n>0){sent+=n;continue;}if(n==TRANSPORT_WANT_WRITE){if(doqWait(fd,POLLOUT,deadline))goto done;continue;}
        errno=ECONNRESET;goto done;
    }
    if(shutdown(fd,SHUT_WR))goto done;
    uint8_t size[2];if(doqRead(stream,fd,size,2,deadline))goto done;size_t answerLength=(size_t)size[0]<<8|size[1];
    if(answerLength<12){errno=EPROTO;goto done;}if(answerLength>responseCapacity){errno=EMSGSIZE;goto done;}
    if(doqRead(stream,fd,response,answerLength,deadline))goto done;
    const uint8_t *answer=response;if(answer[0]||answer[1]||!(answer[2]&0x80)){errno=EPROTO;goto done;}
    for(;;){uint8_t extra;int n=ml_doq_transport.read(stream,&extra,1);
        if(n==TRANSPORT_EOF||n==0){result=answerLength;break;}
        if(n==TRANSPORT_WANT_READ){if(doqWait(fd,POLLIN,deadline))goto done;continue;}
        errno=n>0?EPROTO:ECONNRESET;goto done;
    }
done:{int saved=errno;free(request);if(stream)ml_doq_transport.close(stream);if(fd>=0)close(fd);ml_doq_engine_stop(engine);
    errno=saved;if(result>=0)return result;}
refused:
    if(error&&errorCapacity)snprintf(error,errorCapacity,"%s",reason[0]?reason:strerror(errno));return -1;
}
