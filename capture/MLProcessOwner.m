#import "MLProcessOwner.h"
#include "MLProcessOwnerABI.h"
#include "core/senko_time.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>

enum { MLOwnerPIDs=1024,MLOwnerFDBytes=65536,MLOwnerRows=4096 };
struct MLOwnerRow {
    int pid,fd;uint64_t socket,generation;
    uint8_t protocol,family,local[16],remote[16];uint16_t localPort,remotePort;
};
static BOOL MLZeros(const uint8_t *p,unsigned length){uint8_t value=0;for(unsigned i=0;i<length;i++)value|=p[i];return !value;}
static void MLNormalize(uint8_t *p,unsigned family){if(family==16 && p[0]==0xfe && (p[1]&0xc0)==0x80)p[2]=p[3]=0;}
static BOOL MLRow(struct MLProcessSocketFD *info,int pid,int fd,struct MLOwnerRow *row){
    if((info->protocol!=6 && info->protocol!=17) || (info->kind!=1 && info->kind!=2) ||
        (info->family!=AF_INET && info->family!=AF_INET6) || (info->protocol==6 && info->type!=SOCK_STREAM) || (info->protocol==17 && info->type!=SOCK_DGRAM))return NO;
    const uint8_t *in=(const uint8_t *)info->transport;int32_t localPort,remotePort;memcpy(&localPort,in+4,4);memcpy(&remotePort,in,4);
    if(localPort<=0 || localPort>65535 || remotePort<0 || remotePort>65535)return NO;
    memset(row,0,sizeof *row);row->pid=pid;row->fd=fd;row->socket=info->socket;memcpy(&row->generation,in+8,8);
    row->protocol=info->protocol;row->localPort=ntohs((uint16_t)localPort);row->remotePort=ntohs((uint16_t)remotePort);
    if(in[24]&1){row->family=4;memcpy(row->local,in+60,4);memcpy(row->remote,in+44,4);}
    else if(in[24]&2){row->family=16;memcpy(row->local,in+48,16);memcpy(row->remote,in+32,16);}
    else return NO;
    MLNormalize(row->local,row->family);MLNormalize(row->remote,row->family);return YES;
}
static BOOL MLMatches(const struct MLOwnerRow *row,const struct MLOwnerRow *key){
    if(row->protocol!=key->protocol || row->family!=key->family || row->localPort!=key->localPort)return NO;
    if(!MLZeros(row->local,row->family) && memcmp(row->local,key->local,row->family))return NO;
    if(row->protocol==6 || (row->remotePort && !MLZeros(row->remote,row->family)))
        return row->remotePort==key->remotePort && !memcmp(row->remote,key->remote,row->family);
    return YES; // unconnected UDP: uniqueness must still be established
}
static BOOL MLLocalMatches(const struct MLOwnerRow *row,const struct MLOwnerRow *key){
    return row->protocol==key->protocol && row->family==key->family && row->localPort==key->localPort &&
        (MLZeros(row->local,row->family) || !memcmp(row->local,key->local,row->family));
}
static NSDictionary *MLUnknown(NSString *reason){return @{@"verified":@NO,@"reason":reason};}
@implementation MLProcessOwner {
    MLProcessInformation _information;
    struct MLOwnerRow *_rows;
    size_t _count;
    unsigned _budget;
    uint64_t _scannedAt,_scans,_lookups,_matched,_ambiguous,_errors;
    BOOL _incomplete;
}
- (id)init {return [self initWithBudgetMilliseconds:75];}
- (id)initWithBudgetMilliseconds:(unsigned)milliseconds {return [self initWithInformationFunction:NULL budgetMilliseconds:milliseconds];}
- (id)initWithInformationFunction:(MLProcessInformation)information budgetMilliseconds:(unsigned)milliseconds {
    if((self=[super init])){
        _information=information;if(!_information){void *symbol=dlsym(RTLD_DEFAULT,"__proc_info");if(symbol)memcpy(&_information,&symbol,sizeof _information);}
        _budget=MIN(150,MAX(10,milliseconds));_rows=calloc(MLOwnerRows,sizeof *_rows);if(!_rows)return nil;
    }
    return self;
}
- (void)dealloc {free(_rows);}
- (void)scan {
    uint64_t now=(uint64_t)senko_now_ms(),deadline=now+_budget;_scannedAt=now;_scans++;_count=0;_incomplete=NO;
    int *pids=calloc(MLOwnerPIDs,sizeof(int));struct MLProcessFD *descriptors=malloc(MLOwnerFDBytes);
    if(!pids || !descriptors){free(pids);free(descriptors);_incomplete=YES;return;}
    int listed=_information(1,1,0,0,pids,MLOwnerPIDs*sizeof(int));
    if(listed<=0 || listed>MLOwnerPIDs*(int)sizeof(int) || listed%(int)sizeof(int)){_errors++;_incomplete=YES;goto done;}
    if(listed==MLOwnerPIDs*(int)sizeof(int))_incomplete=YES;
    for(int index=0;index<listed/(int)sizeof(int);index++){
        int pid=pids[index];if(pid<=0)continue;
        if((uint64_t)senko_now_ms()>deadline){_incomplete=YES;break;}
        errno=0;int need=_information(2,pid,1,0,NULL,0);
        if(need<0){if(errno!=ESRCH){_errors++;_incomplete=YES;}continue;}
        if(!need)continue;if(need>MLOwnerFDBytes){need=MLOwnerFDBytes;_incomplete=YES;}
        int got=_information(2,pid,1,0,descriptors,need);
        if(got<0){if(errno!=ESRCH){_errors++;_incomplete=YES;}continue;}
        if(got>need || got%(int)sizeof(*descriptors)){_errors++;_incomplete=YES;continue;}
        for(int f=0;f<got/(int)sizeof(*descriptors);f++){
            if((uint64_t)senko_now_ms()>deadline || _count==MLOwnerRows){_incomplete=YES;goto done;}
            if(descriptors[f].type!=2 || descriptors[f].descriptor<0)continue;
            struct MLProcessSocketFD info;memset(&info,0,sizeof info);errno=0;
            int bytes=_information(3,pid,3,(uint64_t)(uint32_t)descriptors[f].descriptor,&info,sizeof info);
            if(bytes!=(int)sizeof info){if(bytes>=0 || (errno!=ESRCH && errno!=EBADF)){_errors++;_incomplete=YES;}continue;}
            if(MLRow(&info,pid,descriptors[f].descriptor,&_rows[_count]))_count++;
        }
    }
done:free(pids);free(descriptors);
}
- (NSDictionary *)lookupSource:(NSString *)source sourcePort:(uint16_t)sourcePort destination:(NSString *)destination destinationPort:(uint16_t)destinationPort network:(NSString *)network {
    @synchronized(self){
        _lookups++;if(!_information)return MLUnknown(@"unavailable");
        struct MLOwnerRow key;memset(&key,0,sizeof key);key.localPort=sourcePort;key.remotePort=destinationPort;
        key.protocol=[network isEqual:@"TCP"]?6:([network isEqual:@"UDP"]?17:0);
        if(!key.protocol || !sourcePort || !destinationPort || ![source isKindOfClass:[NSString class]] || ![destination isKindOfClass:[NSString class]] || source.length>64 || destination.length>64)return MLUnknown(@"invalid-tuple");
        if(inet_pton(AF_INET,source.UTF8String,key.local)==1 && inet_pton(AF_INET,destination.UTF8String,key.remote)==1)key.family=4;
        else if(inet_pton(AF_INET6,source.UTF8String,key.local)==1 && inet_pton(AF_INET6,destination.UTF8String,key.remote)==1)key.family=16;
        else return MLUnknown(@"invalid-tuple");MLNormalize(key.local,key.family);MLNormalize(key.remote,key.family);
        uint64_t now=(uint64_t)senko_now_ms();BOOL refreshed=!_scans || key.protocol==17 || now<_scannedAt || now-_scannedAt>=250;
        if(refreshed)[self scan];
        if(_incomplete)return MLUnknown(@"incomplete-scan");
again:;
        struct MLOwnerRow selected,localOwner;BOOL found=NO,localFound=NO;
        for(size_t i=0;i<_count;i++){
            if(key.protocol==17?!MLLocalMatches(&_rows[i],&key):!MLMatches(&_rows[i],&key))continue;
            struct MLProcessSocketFD info;memset(&info,0,sizeof info);
            if(_information(3,_rows[i].pid,3,(uint64_t)(uint32_t)_rows[i].fd,&info,sizeof info)!=(int)sizeof info)continue;
            struct MLOwnerRow live;if(!MLRow(&info,_rows[i].pid,_rows[i].fd,&live) || live.socket!=_rows[i].socket || live.generation!=_rows[i].generation || !MLLocalMatches(&live,&key))continue;
            if(key.protocol==17){
                if(localFound && (localOwner.pid!=live.pid || localOwner.socket!=live.socket)){_ambiguous++;return MLUnknown(@"ambiguous");}
                localOwner=live;localFound=YES;
            }
            if(!MLMatches(&live,&key))continue;
            if(found && (selected.pid!=live.pid || selected.socket!=live.socket)){_ambiguous++;return MLUnknown(@"ambiguous");}
            selected=live;found=YES;
        }
        if(!found && !refreshed){[self scan];refreshed=YES;if(_incomplete)return MLUnknown(@"incomplete-scan");goto again;}
        if(!found)return MLUnknown(@"no-match");
        char path[4096]={0};int size=_information(2,selected.pid,11,0,path,sizeof path);
        if(size<0 || !path[0] || !memchr(path,0,sizeof path))return MLUnknown(@"process-path-unavailable");
        NSString *text=[NSString stringWithUTF8String:path];if(![text hasPrefix:@"/"] || !text.lastPathComponent.length)return MLUnknown(@"process-path-unavailable");
        struct MLProcessSocketFD again;memset(&again,0,sizeof again);struct MLOwnerRow live;
        if(_information(3,selected.pid,3,(uint64_t)(uint32_t)selected.fd,&again,sizeof again)!=(int)sizeof again || !MLRow(&again,selected.pid,selected.fd,&live) ||
            live.socket!=selected.socket || live.generation!=selected.generation || !MLMatches(&live,&key))return MLUnknown(@"socket-changed");
        _matched++;return @{@"verified":@YES,@"pid":@(selected.pid),@"processName":text.lastPathComponent,@"processPath":text,@"source":@"kernel-proc-info"};
    }
}
- (NSDictionary *)status {@synchronized(self){return @{@"available":@(_information!=NULL),@"scans":@(_scans),@"sockets":@(_count),@"lookups":@(_lookups),@"matched":@(_matched),@"ambiguous":@(_ambiguous),@"errors":@(_errors),@"incomplete":@(_incomplete),@"budgetMilliseconds":@(_budget),@"snapshotMaxAgeMilliseconds":@250};}}
@end
