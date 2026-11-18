#import <Foundation/Foundation.h>
#include "../protocols/MLStream.h"
#include "../transport/MLNetworkBinding.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc,const char **argv){@autoreleasepool{
    alarm(65);if(argc<4||argc>5)return 64;
    if(argc==5)MLNetworkSetInterfaceIndex(atoi(argv[4]));
    NSString *node=[NSString stringWithContentsOfFile:[NSString stringWithUTF8String:argv[1]] encoding:NSUTF8StringEncoding error:NULL];
    MLDatagram *s=MLDatagramOpen(node.UTF8String,argv[2],atoi(argv[3]),10000);if(!s){perror("open UDP");return 2;}
    uint8_t data[1501],reply[1501];unsigned sizes[]={1,1400,1500};
    for(unsigned k=0;k<15;k++){
        size_t n=sizes[k%3];for(size_t i=0;i<n;i++)data[i]=(i+k)%251;
        if(MLDatagramWrite(s,data,n)!=n){perror("write UDP");return 3;}
        struct pollfd fd={MLDatagramFD(s),POLLIN,0};if(poll(&fd,1,3500)<=0){fprintf(stderr,"UDP timeout packet=%u\n",k);return 4;}
        ssize_t got=MLDatagramRead(s,reply,sizeof reply);if(got<0){perror("read UDP");return 5;}
        if(got!=n||memcmp(data,reply,n)){fprintf(stderr,"UDP mismatch %ld != %lu\n",(long)got,(unsigned long)n);return 6;}
        printf("packet=%u bytes=%lu\n",k,(unsigned long)n);fflush(stdout);
    }
    MLDatagramClose(s);puts("PASS UDP 15 datagrams");return 0;
}}
