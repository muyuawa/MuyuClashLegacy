#import <Foundation/Foundation.h>
#include "../protocols/MLWireGuard.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc,const char **argv){@autoreleasepool{
    alarm(15);if(argc!=3)return 64;NSString *json=[NSString stringWithContentsOfFile:[NSString stringWithUTF8String:argv[1]] encoding:NSUTF8StringEncoding error:NULL];
    NSMutableDictionary *node=[[NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:NULL] mutableCopy];
    if(MLWGValidateNode(node)){fprintf(stderr,"validation %s\n",MLWGValidateNode(node).UTF8String);return 1;}
    for(id key in @[@"ip",@"private-key",@"mtu",@"remote-dns-resolve",@"dns"]){id before=node[key];node[key]=@"invalid-value";assert(MLWGValidateNode(node)!=nil);if(before)node[key]=before;else[node removeObjectForKey:key];}
    if(!strcmp(argv[2],"validate")){puts("PASS WG JSON options and rejection");return 0;}
    MLWGSession *s=MLWGOpenJSON(json.UTF8String,"echo.fixture",20080,0,5000);if(!s){perror("open remoteDNS WG");return 2;}
    if(MLWGWrite(s,"test",4)!=4)return 3;char reply[4];size_t got=0;while(got<4){ssize_t n=MLWGRead(s,reply+got,4-got);if(n>0)got+=n;else if(n<0&&errno==EAGAIN){struct pollfd fd={MLWGFD(s),POLLIN,0};if(poll(&fd,1,5000)<=0)return 4;}else return 5;}
    if(memcmp(reply,"test",4))return 6;MLWGClose(s);puts("PASS WG JSON multi-peer selection and remote DNS through tunnel");return 0;
}}
