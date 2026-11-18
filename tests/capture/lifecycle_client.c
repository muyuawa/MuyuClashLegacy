// Ordinary, unbound sockets kept alive for PROCESS and crash integration.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int exact(int fd,unsigned char *bytes,size_t length,int writing){
    while(length){ssize_t n=writing?send(fd,bytes,length,0):recv(fd,bytes,length,0);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;bytes+=n;length-=n;}return 0;
}
static void endpoint(const struct sockaddr_storage *a,char *literal,size_t size,unsigned *port){
    if(a->ss_family==AF_INET){const struct sockaddr_in *v=(const struct sockaddr_in *)a;inet_ntop(AF_INET,&v->sin_addr,literal,size);*port=ntohs(v->sin_port);}
    else{const struct sockaddr_in6 *v=(const struct sockaddr_in6 *)a;inet_ntop(AF_INET6,&v->sin6_addr,literal,size);*port=ntohs(v->sin6_port);}
}
int main(int argc,char **argv){
    if(argc!=4&&argc!=5)return 64;
    int udp=!strcmp(argv[1],"UDP"),probe=argc==5&&!strcmp(argv[4],"probe"),resolve4=!strcmp(argv[1],"RESOLVE4"),resolve6=!strcmp(argv[1],"RESOLVE6");
    if(!udp&&!resolve4&&!resolve6&&strcmp(argv[1],"TCP"))return 64;
    signal(SIGPIPE,SIG_IGN);alarm(90);
    struct addrinfo hints={0},*addresses=NULL;hints.ai_socktype=udp?SOCK_DGRAM:SOCK_STREAM;hints.ai_flags=resolve4||resolve6?0:AI_NUMERICHOST;
    hints.ai_family=resolve4?AF_INET:(resolve6?AF_INET6:AF_UNSPEC);
    int resolved=getaddrinfo(argv[2],argv[3],&hints,&addresses);
    if(resolved){fprintf(stderr,"getaddrinfo: %s\n",gai_strerror(resolved));return 65;}
    if(resolve4||resolve6){
        printf("{\"event\":\"resolved\",\"addresses\":[");unsigned count=0;
        for(struct addrinfo *a=addresses;a;a=a->ai_next){struct sockaddr_storage storage;memset(&storage,0,sizeof storage);memcpy(&storage,a->ai_addr,a->ai_addrlen);
            char literal[INET6_ADDRSTRLEN];unsigned port;endpoint(&storage,literal,sizeof literal,&port);printf("%s\"%s\"",count++?",":"",literal);}
        puts("]}");fflush(stdout);freeaddrinfo(addresses);return count?0:65;
    }
    int fd=socket(addresses->ai_family,hints.ai_socktype,0);if(fd<0){freeaddrinfo(addresses);return 66;}
    fcntl(fd,F_SETFL,O_NONBLOCK);int connected=connect(fd,addresses->ai_addr,addresses->ai_addrlen),error=errno;freeaddrinfo(addresses);
    if(connected&&error==EINPROGRESS){
        struct pollfd event={fd,POLLOUT,0};int ready=poll(&event,1,probe?1500:6000);socklen_t size=sizeof(error);
        error=ready>0?0:ETIMEDOUT;if(ready>0&&getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size))error=errno;connected=error?-1:0;
    }
    if(connected){printf("{\"event\":\"connect-failed\",\"errno\":%d,\"connected\":false}\n",error);fflush(stdout);close(fd);return 2;}
    fcntl(fd,F_SETFL,0);struct timeval timeout={3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout);setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof timeout);
    struct sockaddr_storage source,destination;socklen_t a=sizeof source,b=sizeof destination;
    if(getsockname(fd,(struct sockaddr *)&source,&a)||getpeername(fd,(struct sockaddr *)&destination,&b)){close(fd);return 3;}
    char src[INET6_ADDRSTRLEN],dst[INET6_ADDRSTRLEN];unsigned sport,dport;endpoint(&source,src,sizeof src,&sport);endpoint(&destination,dst,sizeof dst,&dport);
    printf("{\"event\":\"connected\",\"connected\":true,\"pid\":%d,\"source\":\"%s\",\"sourcePort\":%u,\"destination\":\"%s\",\"destinationPort\":%u,\"network\":\"%s\"}\n",getpid(),src,sport,dst,dport,udp?"UDP":"TCP");fflush(stdout);
    if(probe){close(fd);return 0;}
    unsigned char sent[35000],received[35000];for(size_t i=0;i<sizeof sent;i++)sent[i]=(unsigned char)(i*73+11);
    char command[32];while(fgets(command,sizeof command,stdin)){
        if(!strcmp(command,"echo\n")){
            if(udp){size_t lengths[]={1,1400,1500};for(unsigned i=0;i<3;i++){
                if(send(fd,sent,lengths[i],0)!=(ssize_t)lengths[i]||recv(fd,received,sizeof received,0)!=(ssize_t)lengths[i]||memcmp(sent,received,lengths[i])){close(fd);return 4;}
            }}else if(exact(fd,sent,sizeof sent,1)||exact(fd,received,sizeof received,0)||memcmp(sent,received,sizeof sent)){close(fd);return 5;}
            puts(udp?"{\"event\":\"echo\",\"packets\":3,\"bytes\":2901}":"{\"event\":\"echo\",\"bytes\":35000}");fflush(stdout);
        }else if(!strcmp(command,"fin\n")){
            if(!udp){shutdown(fd,SHUT_WR);if(recv(fd,received,1,0)!=0){close(fd);return 6;}}
            puts("{\"event\":\"finished\"}");fflush(stdout);close(fd);return 0;
        }else{close(fd);return 67;}
    }
    close(fd);return 0;
}
