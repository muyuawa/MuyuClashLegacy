#include "../protocols/MLDNSDoQ.h"
#include "../transport/MLNetworkBinding.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static size_t threeAddresses(const char *host,char addresses[][46],size_t cap,void *unused){(void)host;(void)unused;if(cap<3)return 0;strcpy(addresses[0],"::1");strcpy(addresses[1],"127.0.0.2");strcpy(addresses[2],"127.0.0.1");return 3;}
int main(int argc,const char **argv){
    alarm(12);if(argc!=6)return 64;const char *mode=argv[4];uint8_t query[128]={0xbe,0xef,1,0,0,1};
    size_t n=strlen(mode);if(n>63)return 64;query[12]=n;memcpy(query+13,mode,n);query[13+n]=0;query[14+n]=0;query[15+n]=1;query[16+n]=0;query[17+n]=1;
    uint8_t response[512];char error[400];size_t cap=!strcmp(mode,"small")?12:sizeof response;
    const char *name=strcmp(mode,"wrong-sni")?"localhost":"wrong.invalid";
    if(!strcmp(mode,"fallback-three"))MLNetworkSetBootstrapResolver(threeAddresses,NULL);
    ssize_t result=MLDNSDoQQuery(!strcmp(mode,"fallback-three")?"fixture.invalid":!strcmp(argv[3],"unused")?"127.0.0.1":argv[3],atoi(argv[1]),name,argv[2],query,n+18,response,cap,1200,error,sizeof error);
    if(strcmp(argv[5],"accept")){if(result>=0){fprintf(stderr,"unexpected acceptance %s\n",mode);return 1;}printf("rejected %s errno=%d %s\n",mode,errno,error);return 0;}
    if(result!=n+18||response[0]||response[1]||response[2]!=0x81||memcmp(response+12,query+12,n+6)){fprintf(stderr,"DoQ failure %ld %s\n",(long)result,error);return 2;}
    puts("PASS RFC9250 framed DNS response and FIN");return 0;
}
