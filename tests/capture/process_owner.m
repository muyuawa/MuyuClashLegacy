#import "MLProcessOwner.h"
#include "MLProcessOwnerABI.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
static struct MLProcessSocketFD sockets[3];static unsigned count,infoCalls;static BOOL change,denied,badABI,slow;
static void initialize(unsigned family,unsigned protocol,BOOL connected){
    memset(sockets,0,sizeof sockets);count=1;infoCalls=0;change=denied=badABI=slow=NO;
    struct MLProcessSocketFD *s=&sockets[0];s->socket=1000;s->type=protocol==6?SOCK_STREAM:SOCK_DGRAM;s->protocol=protocol;s->family=family==4?AF_INET:AF_INET6;s->kind=protocol==6?2:1;
    uint8_t *in=(uint8_t *)s->transport;int32_t local=htons(40001),remote=connected?htons(443):0;memcpy(in,&remote,4);memcpy(in+4,&local,4);uint64_t generation=5;memcpy(in+8,&generation,8);in[24]=family==4?1:2;
    if(family==4){inet_pton(AF_INET,"10.0.0.2",in+60);if(connected)inet_pton(AF_INET,"192.0.2.1",in+44);}else{inet_pton(AF_INET6,"fd00:42::2",in+48);if(connected)inet_pton(AF_INET6,"2001:db8::1",in+32);}
}
static int information(int call,int pid,int flavor,uint64_t arg,void *buffer,int size){
    if(slow && call==2)usleep(20000);
    if(call==1){assert(size>=12);int *pids=buffer;for(unsigned i=0;i<count;i++)pids[i]=101+i;return count*4;}
    if(call==2 && flavor==1){if(denied && pid==102){errno=EACCES;return -1;}if(!buffer)return 8;assert(size>=8);struct MLProcessFD *fd=buffer;fd->descriptor=7;fd->type=2;return 8;}
    if(call==3){assert(arg==7 && size==792);unsigned index=pid-101;assert(index<count);memcpy(buffer,&sockets[index],792);infoCalls++;return badABI?791:792;}
    if(call==2 && flavor==11){snprintf(buffer,size,"/Applications/App%d.app/Executable%d",pid,pid);if(change){uint64_t generation=100;memcpy((uint8_t *)sockets[pid-101].transport+8,&generation,8);}return 0;}
    assert(0);return -1;
}
static NSDictionary *lookup(unsigned family,NSString *network){MLProcessOwner *owner=[[MLProcessOwner alloc]initWithInformationFunction:information budgetMilliseconds:10];return [owner lookupSource:family==4?@"10.0.0.2":@"fd00:42::2" sourcePort:40001 destination:family==4?@"192.0.2.1":@"2001:db8::1" destinationPort:443 network:network];}
int main(void){@autoreleasepool{
    initialize(4,6,YES);sockets[1]=sockets[0];sockets[1].socket=1001;inet_pton(AF_INET,"192.0.2.2",(uint8_t *)sockets[1].transport+44);count=2;
    NSDictionary *r=lookup(4,@"TCP");assert([r[@"verified"] boolValue] && [r[@"pid"] isEqual:@101] && [r[@"processName"] isEqual:@"Executable101"] && [r[@"processPath"] hasSuffix:@"/Executable101"]);
    initialize(16,6,YES);assert([lookup(16,@"TCP")[@"verified"] boolValue]);
    initialize(4,17,NO);memset((uint8_t *)sockets[0].transport+60,0,4);assert([lookup(4,@"UDP")[@"verified"] boolValue]);
    initialize(4,17,NO);sockets[1]=sockets[0];sockets[1].socket=1001;count=2;assert([lookup(4,@"UDP")[@"reason"] isEqual:@"ambiguous"]);
    initialize(4,17,YES);sockets[1]=sockets[0];sockets[1].socket=1001;inet_pton(AF_INET,"192.0.2.2",(uint8_t *)sockets[1].transport+44);count=2;assert([lookup(4,@"UDP")[@"reason"] isEqual:@"ambiguous"]);
    initialize(4,6,YES);sockets[1]=sockets[0];count=2;assert([lookup(4,@"TCP")[@"reason"] isEqual:@"ambiguous"]);
    initialize(4,6,YES);change=YES;assert([lookup(4,@"TCP")[@"reason"] isEqual:@"socket-changed"]);
    initialize(4,6,YES);sockets[1]=sockets[0];count=2;denied=YES;assert([lookup(4,@"TCP")[@"reason"] isEqual:@"incomplete-scan"]);
    initialize(4,6,YES);badABI=YES;assert([lookup(4,@"TCP")[@"reason"] isEqual:@"incomplete-scan"]);
    initialize(4,6,YES);slow=YES;assert([lookup(4,@"TCP")[@"reason"] isEqual:@"incomplete-scan"]);
    puts("PASS process owner full tuples, IPv6, wildcard UDP uniqueness, ambiguity, FD generation, ABI/permission errors and scan budget");return 0;
}}
