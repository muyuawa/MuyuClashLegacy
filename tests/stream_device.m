#import <Foundation/Foundation.h>
#include "../protocols/MLStream.h"
#include "../transport/MLNetworkBinding.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int waitStream(MLStream *s,int read,int write){
    if(read&&MLStreamPendingRead(s))return MLStreamPump(s)==0;
    struct pollfd fd={MLStreamFD(s),MLStreamEvents(s,read,write),0};return poll(&fd,1,8000)>0&&MLStreamPump(s)==0;
}
int main(int argc,const char **argv){@autoreleasepool{
    alarm(45);if(argc<4||argc>5)return 64;if(argc==5)MLNetworkSetInterfaceIndex(atoi(argv[4]));
    NSString *node=[NSString stringWithContentsOfFile:[NSString stringWithUTF8String:argv[1]] encoding:NSUTF8StringEncoding error:NULL];
    MLStream *s=MLStreamOpen(node.UTF8String,argv[2],atoi(argv[3]),10000);if(!s){perror("open TCP");return 2;}
    uint8_t data[35000],reply[997];for(size_t i=0;i<sizeof data;i++)data[i]=i%251;size_t sent=0,got=0;
    while(got<sizeof data){
        int progress=0;if(sent<sizeof data){ssize_t n=MLStreamWrite(s,data+sent,sizeof data-sent);if(n>0){sent+=n;progress=1;}else if(n>=0||errno!=EAGAIN){perror("write TCP");return 3;}}
        for(unsigned i=0;i<32&&got<sizeof data;i++){ssize_t n=MLStreamRead(s,reply,sizeof reply);if(n<0&&errno==EAGAIN)break;if(n<=0){perror("read TCP");return 4;}if(n>sizeof data-got||memcmp(reply,data+got,n))return 5;got+=n;progress=1;}
        if(!progress&&!waitStream(s,1,sent<sizeof data)){perror("TCP poll");return 6;}
    }
    printf("roundtrip_bytes=%lu\n",(unsigned long)got);fflush(stdout);MLStreamShutdownWrite(s);
    while(MLStreamWritePending(s))if(!waitStream(s,0,1))return 7;
    for(;;){ssize_t n=MLStreamRead(s,reply,sizeof reply);if(n==0)break;if(n<0&&errno==EAGAIN){if(waitStream(s,1,0))continue;fprintf(stderr,"EOF timeout after complete roundtrip\n");return 8;}perror("read EOF");return 9;}
    MLStreamClose(s);puts("PASS TCP 35000 bytes and EOF");return 0;
}}
