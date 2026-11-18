#include "../protocols/MLSS2022.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int response(MLSS2022 *s,int fd,uint8_t *wire,size_t *length){
    uint8_t upload[2048];ssize_t n=MLSS2022UDPEncode(s,(const uint8_t *)"security",8,upload,sizeof upload);if(n<0||send(fd,upload,n,0)!=n)return -1;
    /* A response reflected in the request direction must never authenticate. */
    uint8_t data[32];if(MLSS2022UDPDecode(s,upload,n,data,sizeof data)!=-1||errno!=EACCES)return -1;
    n=recv(fd,wire,4096,0);if(n<=0)return -1;*length=n;return 0;
}
int main(int argc,const char **argv){
    alarm(15);if(argc!=5)return 64;vless_dest_t dest={.atyp=VLESS_ADDR_IPV4,.port=atoi(argv[4])};inet_pton(AF_INET,"127.0.0.1",dest.host_addr);
    MLSS2022 *s=MLSS2022Open(argv[1],argv[2],&dest),*other=MLSS2022Open(argv[1],argv[2],&dest);if(!s||!other)return 1;
    int fd=socket(AF_INET,SOCK_DGRAM,0);struct sockaddr_in server={.sin_family=AF_INET,.sin_port=htons(atoi(argv[3]))};inet_pton(AF_INET,"127.0.0.1",&server.sin_addr);if(connect(fd,(struct sockaddr *)&server,sizeof server))return 2;
    uint8_t wire[4096],bad[4096],data[32];size_t n;
    if(response(s,fd,wire,&n))return 3;memcpy(bad,wire,n);bad[n-1]^=1;
    if(MLSS2022UDPDecode(s,bad,n,data,sizeof data)!=-1||errno!=EACCES)return 4;
    if(MLSS2022UDPDecode(other,wire,n,data,sizeof data)!=-1||errno!=EACCES)return 5;
    if(MLSS2022UDPDecode(s,wire,n,data,sizeof data)!=8||memcmp(data,"security",8))return 6;
    if(MLSS2022UDPDecode(s,wire,n,data,sizeof data)!=-1||errno!=EACCES)return 7;
    if(response(s,fd,wire,&n))return 8;
    if(MLSS2022UDPDecode(s,wire,n,data,7)!=-1||errno!=EMSGSIZE)return 9;
    if(MLSS2022UDPDecode(s,wire,n,data,sizeof data)!=-1||errno!=EACCES)return 10;
    close(fd);MLSS2022Close(s);MLSS2022Close(other);puts("PASS SS2022 tampering, reflection, association, replay, and capacity rejection");return 0;
}
