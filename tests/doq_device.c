#include "../protocols/MLDNSDoQ.h"
#include "../transport/MLNetworkBinding.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc,const char **argv){
    alarm(20);if(argc<5||argc>6)return 64;if(argc==6)MLNetworkSetInterfaceIndex(atoi(argv[5]));
    const unsigned char query[]={0xbe,0xef,1,0,0,1,0,0,0,0,0,0,7,'f','i','x','t','u','r','e',0,0,1,0,1};
    unsigned char response[512];char error[512];ssize_t n=MLDNSDoQQuery(argv[1],atoi(argv[2]),argv[4],argv[3],query,sizeof query,response,sizeof response,5000,error,sizeof error);
    if(n!=sizeof query||response[0]||response[1]||response[2]!=0x81||memcmp(response+3,query+3,sizeof query-3)){fprintf(stderr,"DoQ query failed errno=%d %s\n",errno,error);return 1;}
    puts("PASS DoQ framed zero-ID query and response FIN");return 0;
}
