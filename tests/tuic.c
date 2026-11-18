#include "../protocols/MLTUICEngine.h"
#include <arpa/inet.h>
#include <errno.h>
#include <ngtcp2/ngtcp2.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int waitFD(int fd,int write){struct pollfd p={fd,write?POLLOUT:POLLIN,0};return poll(&p,1,5000)>0;}
static int writeAll(void *handle,int fd,const uint8_t *data,size_t n){size_t sent=0;while(sent<n){int r=ml_tuic_transport.write(handle,data+sent,n-sent);if(r>0)sent+=r;else if(r==TRANSPORT_WANT_WRITE&&waitFD(fd,1))continue;else return -1;}return 0;}
int main(int argc,const char **argv){
    alarm(40);if(argc!=7&&argc!=8)return 64;uint8_t address[2][16]={{127,0,0,1}},lens[]={4,4};MLTUICConfig c={0};
    c.quic=(hy2_engine_config_t){.addresses=address,.address_lens=lens,.address_count=1,.port=atoi(argv[1]),.sni="localhost",.peer_host="127.0.0.1",.auth="fixture-secret",.ca_file=argv[4],.connect_timeout_ms=6000};
    for(unsigned i=0;i<16;i++)c.uuid[i]=i*17;c.alpn[0]=2;c.alpn[1]='h';c.alpn[2]='3';c.alpnLength=3;c.congestion=NGTCP2_CC_ALGO_BBR;c.heartbeatMS=1000;
    int reject=strncmp(argv[6],"trusted",7)!=0;if(!strcmp(argv[6],"wrong-password"))c.quic.auth="bad";if(!strcmp(argv[6],"wrong-sni"))c.quic.sni="wrong.invalid";
    if(!strcmp(argv[6],"trusted-nosni"))c.disableSNI=1;
    if(!strcmp(argv[6],"trusted-size"))c.maxUDPPayload=1200;
    if(!strcmp(argv[6],"trusted-fallback")){memset(address[0],0,16);address[0][15]=1;address[1][0]=127;address[1][3]=1;lens[0]=16;c.quic.address_count=2;c.quic.connect_timeout_ms=1200;}
    char error[400];hy2_engine_t *e=MLTUICStart(&c,error,sizeof error);if(!e){fprintf(stderr,"start %s\n",error);return reject?0:1;}
    int fd=MLTUICDial(e,error,sizeof error);if(fd<0){fprintf(stderr,"dial %s\n",error);MLTUICStop(e);return reject?0:2;}void *handle=ml_tuic_transport.open(fd,NULL);if(!handle)return 3;
    vless_dest_t target={.port=atoi(argv[2])};const char *host=argc==8?argv[7]:"127.0.0.1";
    if(inet_pton(AF_INET,host,target.host_addr)==1)target.atyp=VLESS_ADDR_IPV4;else if(inet_pton(AF_INET6,host,target.host_addr)==1)target.atyp=VLESS_ADDR_IPV6;else{target.atyp=VLESS_ADDR_DOMAIN;snprintf(target.domain,sizeof target.domain,"%s",host);}
    uint8_t request[300]={5,1};size_t requestLength=2+MLTUICAddress(&target,request+2,sizeof request-2);
    uint8_t data[35000],reply[997];for(size_t i=0;i<sizeof data;i++)data[i]=i%251;
    if(writeAll(handle,fd,request,requestLength)||writeAll(handle,fd,data,sizeof data)){ml_tuic_transport.close(handle);close(fd);MLTUICStop(e);return reject?0:4;}
    size_t got=0;while(got<sizeof data){int n=ml_tuic_transport.read(handle,reply,sizeof reply);if(n==TRANSPORT_WANT_READ&&waitFD(fd,0))continue;if(n<=0){ml_tuic_transport.close(handle);close(fd);MLTUICStop(e);return reject?0:5;}if(reject)return 6;if(n>sizeof data-got||memcmp(reply,data+got,n))return 7;got+=n;}
    shutdown(fd,SHUT_WR);for(;;){int n=ml_tuic_transport.read(handle,reply,sizeof reply);if(n==TRANSPORT_EOF||n==0)break;if(n==TRANSPORT_WANT_READ&&waitFD(fd,0))continue;fprintf(stderr,"TCP EOF failure %d\n",n);return 8;}
    ml_tuic_transport.close(handle);close(fd);printf("TCP bytes=%lu EOF\n",(unsigned long)got);fflush(stdout);
    target.port=atoi(argv[3]);MLTUICUDP *udp=MLTUICUDPOpen(e,&target,!strcmp(argv[5],"quic"));if(!udp){perror("UDP open");return 9;}
    uint8_t upload[1501],download[1501];unsigned sizes[]={1,1400,1500};if(c.maxUDPPayload){sizes[1]=1199;sizes[2]=1200;}
    for(unsigned k=0;k<15;k++){if(k==2&&!strcmp(argv[6],"trusted-heartbeat"))sleep(11);size_t n=sizes[k%3];for(size_t i=0;i<n;i++)upload[i]=(i+k)%251;if(MLTUICUDPSend(udp,upload,n)!=n){perror("UDP send");return 10;}if(!waitFD(MLTUICUDPFD(udp),0)){fprintf(stderr,"UDP timeout k=%u\n",k);return 11;}ssize_t r=MLTUICUDPReceive(udp,download,sizeof download);if(r!=n||memcmp(upload,download,n)){fprintf(stderr,"UDP mismatch k=%u got=%ld\n",k,(long)r);return 12;}}
    if(MLTUICUDPSend(udp,upload,c.maxUDPPayload?1201:1501)!=-1||errno!=EMSGSIZE)return 13;MLTUICUDPClose(udp);MLTUICStop(e);puts("PASS TUIC 15 UDP datagrams and size limit");return 0;
}
