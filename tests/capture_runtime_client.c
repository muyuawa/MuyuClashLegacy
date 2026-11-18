#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
// Runs ordinary application sockets: no interface binding or proxy awareness.
int main(int argc,char **argv) {
    if(argc!=4)return 64;
    int dns=!strcmp(argv[1],"dns"),udp=!strcmp(argv[1],"udp")||dns,system=!strcmp(argv[1],"system-tcp");
    struct addrinfo hints={0},*addresses=NULL;hints.ai_socktype=udp?SOCK_DGRAM:SOCK_STREAM;hints.ai_flags=system?0:AI_NUMERICHOST;
    alarm(25);
    int resolved=getaddrinfo(argv[2],argv[3],&hints,&addresses);
    if(resolved){fprintf(stderr,"application getaddrinfo: %s\n",gai_strerror(resolved));return 65;}
    if(system) {
        for(struct addrinfo *item=addresses;item;item=item->ai_next) {
            char literal[INET6_ADDRSTRLEN];const void *bytes=NULL;int fake=0;
            if(item->ai_family==AF_INET){const struct in_addr *ip=&((struct sockaddr_in *)item->ai_addr)->sin_addr;bytes=ip;fake=(ntohl(ip->s_addr)&0xffff0000)==0xc6120000;}
            else if(item->ai_family==AF_INET6){const struct in6_addr *ip=&((struct sockaddr_in6 *)item->ai_addr)->sin6_addr;struct in6_addr base;inet_pton(AF_INET6,"fd00:5e4b:1::",&base);bytes=ip;fake=!memcmp(ip,&base,14);}
            if(!bytes||!fake){fputs("system resolver did not return retained Fake-IP\n",stderr);freeaddrinfo(addresses);return 66;}
            inet_ntop(item->ai_family,bytes,literal,sizeof(literal));printf("system resolver %s -> %s\n",argv[2],literal);fflush(stdout);
        }
    }
    int fd=socket(addresses->ai_family,hints.ai_socktype,0);
    struct timeval timeout={8,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    alarm(25);fcntl(fd,F_SETFL,O_NONBLOCK);
    int rc=connect(fd,addresses->ai_addr,addresses->ai_addrlen);freeaddrinfo(addresses);
    if(rc&&errno==EINPROGRESS) {
        struct pollfd event={fd,POLLOUT,0};
        if(poll(&event,1,6000)<=0){errno=ETIMEDOUT;perror("application connect deadline");return 1;}
        int error=0;socklen_t size=sizeof(error);if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)||error){errno=error;perror("application connect");return 1;}
        rc=0;
    }
    if(rc){perror("application connect");return 1;}
    fcntl(fd,F_SETFL,0);
    unsigned char sent[35000],received[35000];for(size_t i=0;i<sizeof(sent);i++)sent[i]=(unsigned char)(i*73+11);
    if(dns) {
        unsigned char query[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,7,'c','a','p','t','u','r','e',4,'t','e','s','t',0,0,1,0,1};
        if(send(fd,query,sizeof(query),0)!=sizeof(query))return 8;
        ssize_t n=recv(fd,received,sizeof(received),0);
        if(n<12||received[0]!=0x12||received[1]!=0x34||!(received[2]&128)||(received[3]&15)||received[7]!=1){fprintf(stderr,"DNS bytes=%ld rcode=%u answers=%u errno=%d\n",(long)n,n>=12?received[3]&15:255,n>=12?received[7]:0,errno);return 9;}
    } else if(udp) {
        size_t lengths[]={1,1400,1500};
        for(unsigned i=0;i<3;i++) {
            if(send(fd,sent,lengths[i],0)!=(ssize_t)lengths[i]){perror("UDP send");return 2;}
            ssize_t n=recv(fd,received,sizeof(received),0);
            if(n!=(ssize_t)lengths[i]||memcmp(sent,received,lengths[i])){perror("UDP echo");return 3;}
        }
    } else {
        size_t offset=0;
        while(offset<sizeof(sent)){ssize_t n=send(fd,sent+offset,sizeof(sent)-offset,0);if(n<=0)return 4;offset+=(size_t)n;}
        shutdown(fd,SHUT_WR);offset=0;
        while(offset<sizeof(received)){ssize_t n=recv(fd,received+offset,sizeof(received)-offset,0);if(n<=0){perror("TCP echo");return 5;}offset+=(size_t)n;}
        if(memcmp(sent,received,sizeof(sent)))return 6;
        unsigned char extra;ssize_t eof=recv(fd,&extra,1,0);if(eof!=0){fprintf(stderr,"TCP EOF result=%ld errno=%d\n",(long)eof,errno);return 7;}
    }
    close(fd);puts(dns?"PASS captured application DNS":udp?"PASS application UDP packet boundaries":"PASS application TCP 35000 bytes and half-close");return 0;
}
