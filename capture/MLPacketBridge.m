#import "MLPacketBridge.h"
#import "MLStream.h"
#include "MLUDPPackets.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <dispatch/dispatch.h>
#include "tun_loop.h"
#include "core/senko_time.h"

enum { MLPacketTCPMax=24, MLPacketUDPMax=64, MLPacketUDPQueueMax=4, MLPacketUDPBytesMax=65507 };
static BOOL MLPacketError(NSError **error,NSString *message,int code) {
    if (error) *error=[NSError errorWithDomain:@"E_PACKET_BRIDGE" code:code userInfo:@{NSLocalizedDescriptionKey:message}];
    return NO;
}
static NSString *MLAddress(const uint8_t *bytes,uint8_t length) {
    char text[INET6_ADDRSTRLEN];
    return inet_ntop(length==4?AF_INET:AF_INET6,bytes,text,sizeof text)?[NSString stringWithUTF8String:text]:nil;
}
static BOOL MLAgain(void) { return errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK; }
static NSDictionary *MLMetadata(NSDictionary *input) {
    NSMutableDictionary *result=[NSMutableDictionary dictionary];
    for (NSString *key in @[@"actual",@"node",@"proxy",@"group",@"protocol",@"rule",@"configID",@"routingToken",@"host",@"processName",@"processPath"])
        if ([input[key] isKindOfClass:[NSString class]] && [input[key] length]<=1024) result[key]=input[key];
    return result;
}

@interface MLPacketFlow : NSObject {
@public
    tun_flow_key_t tuple;
    MLStream *stream;
    uint8_t buffer[16384];
    size_t offset, remaining;
}
@property(nonatomic) uint64_t identifier, created, activity, upload, download;
@property(nonatomic) NSTimeInterval startedAt;
@property(nonatomic,copy) NSString *name, *destination, *source;
@property(nonatomic,strong) NSDictionary *route, *metadata;
@property(nonatomic,strong) id<MLPacketDatagram> datagram;
@property(nonatomic,strong) NSMutableArray *datagrams;
@property(nonatomic,strong) NSMutableData *dnsInput;
@property(nonatomic,strong) NSData *dnsResult;
@property(atomic) BOOL dns, opening, dialFinished, accepted, opened, closed, cancelled, localEOF, remoteEOF, remoteFin, stackClosing, dnsBusy, dnsFinished;
@end
@implementation MLPacketFlow
@end

@interface MLPacketBridge ()
- (void)flowEvent:(tun_stack_flow_event_t)event identifier:(uint64_t)identifier key:(const tun_flow_key_t *)key;
- (int)udp:(const tun_flow_key_t *)key bytes:(const uint8_t *)bytes length:(size_t)length;
- (int)ownerStarted:(tun_stack_t *)stack;
- (void)prepareRead:(fd_set *)readable write:(fd_set *)writable highest:(int *)highest wait:(uint32_t *)wait;
- (void)dispatchRead:(const fd_set *)readable write:(const fd_set *)writable;
- (void)ownerStopped;
- (void)becameReady;
- (void)run;
- (int)filterFrame:(uint8_t *)frame length:(size_t)length;
- (int)writeUDPFrame:(const uint8_t *)frame length:(size_t)length;
@end
static int MLFilter(void *ctx,uint8_t *frame,size_t length) { return [(__bridge MLPacketBridge *)ctx filterFrame:frame length:length]; }
static int MLWriteUDPFrame(void *ctx,const uint8_t *frame,size_t length) { return [(__bridge MLPacketBridge *)ctx writeUDPFrame:frame length:length]; }
static void MLFlowEvent(void *ctx,tun_stack_flow_event_t event,uint64_t identifier,const tun_flow_key_t *key) {
    [(__bridge MLPacketBridge *)ctx flowEvent:event identifier:identifier key:key];
}
static int MLUDP(void *ctx,const tun_flow_key_t *key,const uint8_t *bytes,size_t length) {
    return [(__bridge MLPacketBridge *)ctx udp:key bytes:bytes length:length];
}
static int MLOwnerStart(void *ctx,tun_stack_t *stack,char *error,size_t cap) {
    int code=[(__bridge MLPacketBridge *)ctx ownerStarted:stack];
    if (code && error && cap) snprintf(error,cap,"packet flow owner could not start"); return code;
}
static void MLOwnerPrepare(void *ctx,fd_set *readable,fd_set *writable,int *highest,uint32_t *wait) {
    [(__bridge MLPacketBridge *)ctx prepareRead:readable write:writable highest:highest wait:wait];
}
static void MLOwnerDispatch(void *ctx,const fd_set *readable,const fd_set *writable) {
    [(__bridge MLPacketBridge *)ctx dispatchRead:readable write:writable];
}
static void MLOwnerStop(void *ctx) { [(__bridge MLPacketBridge *)ctx ownerStopped]; }
static void MLReady(void *ctx) { [(__bridge MLPacketBridge *)ctx becameReady]; }
static void *MLRunThread(void *ctx) { @autoreleasepool { MLPacketBridge *bridge=CFBridgingRelease(ctx); [bridge run]; } return NULL; }

@implementation MLPacketBridge {
    MLPacketRouteHandler _route;
    MLPacketDatagramFactory _datagram;
    MLPacketDNSHandler _dns;
    MLPacketAddressHandler _retainAddress, _releaseAddress;
    utun_device_t _device;
    tun_loop_t *_loop;
    tun_stack_t *_stack;
    MLUDPPackets *_packets;
    pthread_t _thread;
    BOOL _threadStarted, _joined, _ready, _running, _stopping;
    NSCondition *_condition;
    NSMutableDictionary *_tcp, *_udp;
    NSDictionary *_snapshot;
    NSDictionary *_lastConnection;
    NSArray *_rows;
    NSString *_problem;
    uint64_t _generation, _upload, _download, _started, _droppedUDP, _failedTCP, _dnsFailures;
    uint64_t _ipv4Frames,_ipv6Frames,_tcpFINFrames,_localEOFs,_remoteEOFs,_tcpFinSent,_tcpFinRetries;
    dispatch_group_t _workers;
    dispatch_semaphore_t _capacity;
}
- (id)initWithFileDescriptor:(int)fd interfaceName:(NSString *)name route:(MLPacketRouteHandler)route
    datagram:(MLPacketDatagramFactory)datagram dns:(MLPacketDNSHandler)dns
    retainAddress:(MLPacketAddressHandler)retainAddress releaseAddress:(MLPacketAddressHandler)releaseAddress {
    if ((self=[super init])) {
        utun_device_init(&_device);
        int copy=fcntl(fd,F_DUPFD,3);
        if (copy<0 || copy>=FD_SETSIZE || !name.length || name.length>=16 ||
            utun_device_adopt(&_device,copy,name.UTF8String)!=UTUN_DEVICE_OK) {
            if (copy>=0) close(copy); return nil;
        }
        fcntl(copy,F_SETFD,FD_CLOEXEC);
        _route=[route copy]; _datagram=[datagram copy]; _dns=[dns copy];
        _retainAddress=[retainAddress copy]; _releaseAddress=[releaseAddress copy];
        _condition=[NSCondition new]; _tcp=[NSMutableDictionary dictionary]; _udp=[NSMutableDictionary dictionary];
        _workers=dispatch_group_create(); _capacity=dispatch_semaphore_create(3);
        _generation=(uint64_t)senko_now_ms() ?: 1; _snapshot=@{}; _rows=@[];
    }
    return self;
}
- (void)dealloc { [self stop]; if (_loop) { tun_loop_destroy(_loop); free(_loop); } else utun_device_close(&_device); MLUDPPacketsDestroy(_packets); }
- (void)wake {
    if (_loop) { tun_loop_command_t command={TUN_LOOP_CMD_OWNER,_generation,0}; tun_loop_post(_loop,&command); }
}
- (BOOL)start:(NSError **)error {
    if (_threadStarted) return MLPacketError(error,@"数据通路已经启动",EALREADY);
    if (!_route || !_datagram || !_dns) return MLPacketError(error,@"完整 TCP/UDP/DNS 处理器尚未接入",ENOTSUP);
    _loop=calloc(1,tun_loop_size()); if (!_loop) return MLPacketError(error,@"数据通路内存不足",ENOMEM);
    _packets=MLUDPPacketsCreate(); if(!_packets)return MLPacketError(error,@"UDP 分片缓冲内存不足",ENOMEM);
    tun_loop_config_t config; memset(&config,0,sizeof config);
    config.generation=_generation; config.stack.mtu=1500; config.stack.have_ipv4=config.stack.have_ipv6=1;
    strlcpy(config.stack.ifname,_device.ifname,sizeof config.stack.ifname);
    inet_pton(AF_INET,"198.18.0.1",config.stack.address4);
    inet_pton(AF_INET,"198.18.0.2",config.stack.synthetic4);
    memset(config.stack.netmask4,0xff,sizeof config.stack.netmask4);
    inet_pton(AF_INET6,"fd00:5e4b::1",config.stack.address6);
    inet_pton(AF_INET6,"fd00:5e4b::2",config.stack.synthetic6);
    config.stack.flow_event=MLFlowEvent; config.stack.flow_ctx=(__bridge void *)self;
    config.stack.udp_packet=MLUDP; config.stack.udp_ctx=(__bridge void *)self;
    config.hooks=(tun_loop_hooks_t){MLOwnerStart,MLOwnerPrepare,MLOwnerDispatch,MLOwnerStop,(__bridge void *)self};
    config.on_ready=MLReady; config.ready_ctx=(__bridge void *)self;
    config.frame_filter=MLFilter;config.filter_ctx=(__bridge void *)self;
    if (tun_loop_init(_loop,&config,&_device)!=TUN_LOOP_OK) return MLPacketError(error,@"utun 数据通路初始化失败",EIO);
    void *retained=(__bridge_retained void *)self;
    int code=pthread_create(&_thread,NULL,MLRunThread,retained);
    if (code) { CFBridgingRelease(retained); return MLPacketError(error,@"数据通路线程创建失败",code); }
    _threadStarted=YES;
    [_condition lock];
    NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:8];
    while (!_ready && !__atomic_load_n(&_stopping,__ATOMIC_ACQUIRE)) if (![_condition waitUntilDate:deadline]) break;
    BOOL ready=_ready && _running; [_condition unlock];
    if (!ready) { [self stop]; return MLPacketError(error,_problem ?: @"完整数据通路未能就绪",EIO); }
    return YES;
}
- (void)stop {
    [_condition lock]; __atomic_store_n(&_stopping,YES,__ATOMIC_RELEASE); [_condition broadcast]; [_condition unlock];
    if (_loop) tun_loop_request_stop(_loop);
    if (_threadStarted && !_joined && !pthread_equal(pthread_self(),_thread)) { pthread_join(_thread,NULL); _joined=YES; }
    if (!_threadStarted) utun_device_close(&_device);
}
- (BOOL)running { [_condition lock]; BOOL active=_running && !__atomic_load_n(&_stopping,__ATOMIC_ACQUIRE); [_condition unlock]; return active; }
- (NSDictionary *)readiness { BOOL active=self.running; return @{@"ready":@(active),@"tcp":@(active),@"udp":@(active),@"ipv6":@(active),@"dns":@(active)}; }
- (NSDictionary *)statistics { @synchronized(self) { return _snapshot; } }
- (NSArray *)connections { @synchronized(self) { return _rows; } }
- (NSDictionary *)lastConnection { @synchronized(self) { return _lastConnection; } }
- (BOOL)closeConnection:(NSString *)identifier {
    @synchronized(self) {
        for (MLPacketFlow *flow in [_tcp.allValues arrayByAddingObjectsFromArray:_udp.allValues]) {
            if ([flow.name isEqual:identifier]) { flow.cancelled=YES; [self wake]; return YES; }
        }
    }
    return NO;
}
- (int)ownerStarted:(tun_stack_t *)stack { _stack=stack; _started=(uint64_t)senko_now_ms(); return 0; }
- (int)filterFrame:(uint8_t *)frame length:(size_t)length {
    if(length>=24 && frame[0]==0 && frame[1]==0 && frame[2]==0 && frame[3]==AF_INET){
        _ipv4Frames++;size_t header=(frame[4]&15)*4;
        if(frame[13]==6 && header>=20 && length>=4+header+20 && (frame[4+header+13]&1))_tcpFINFrames++;
    }else if(length>=44 && frame[0]==0 && frame[1]==0 && frame[2]==0 && frame[3]==AF_INET6){
        _ipv6Frames++;if(frame[10]==6 && length>=64 && (frame[57]&1))_tcpFINFrames++;
    }
    return MLUDPPacketsInput(_packets,frame,length,(uint64_t)senko_now_ms(),MLUDP,(__bridge void *)self);
}
- (int)writeUDPFrame:(const uint8_t *)frame length:(size_t)length {
    utun_device_status_t result=tun_loop_write_frame(_loop,frame,length);
    return result==UTUN_DEVICE_OK?1:(result==UTUN_DEVICE_AGAIN?0:-1);
}
- (void)becameReady { [_condition lock]; _ready=_running=YES; [_condition broadcast]; [_condition unlock]; }
- (void)run {
    tun_loop_result_t result; tun_loop_run(_loop,&result);
    // Workers borrow this bridge and their flow; cancellation prevents a late
    // dial result from touching the stopped stack or the following generation.
    dispatch_group_wait(_workers,DISPATCH_TIME_FOREVER);
    [_condition lock]; _running=NO; __atomic_store_n(&_stopping,YES,__ATOMIC_RELEASE);
    _problem=[NSString stringWithUTF8String:result.message]; [_condition broadcast]; [_condition unlock];
}
- (MLPacketFlow *)newFlow:(const tun_flow_key_t *)key identifier:(uint64_t)identifier name:(NSString *)name {
    MLPacketFlow *flow=[MLPacketFlow new]; flow->tuple=*key; flow.identifier=identifier; flow.name=name;
    flow.created=flow.activity=(uint64_t)senko_now_ms();
    flow.startedAt=[[NSDate date] timeIntervalSince1970];
    flow.destination=MLAddress(key->destination,key->address_len); flow.source=MLAddress(key->source,key->address_len);
    flow.dns=key->destination_port==53; flow.opening=YES;
    flow.datagrams=[NSMutableArray array]; flow.dnsInput=[NSMutableData data];
    if (_retainAddress) _retainAddress(flow.destination);
    return flow;
}
- (NSDictionary *)routeFlow:(MLPacketFlow *)flow {
    NSDictionary *route=_route(flow.destination,flow.source,flow->tuple.source_port,flow->tuple.destination_port,
        flow->tuple.protocol==TUN_FLOW_TCP?@"TCP":@"UDP");
    if (![route isKindOfClass:[NSDictionary class]] || [route[@"reject"] boolValue]) return nil;
    NSString *host=route[@"host"] ?: flow.destination;
    if (![host isKindOfClass:[NSString class]] || !host.length || host.length>253 ||
        [host lengthOfBytesUsingEncoding:NSUTF8StringEncoding]!=strlen(host.UTF8String)) return nil;
    NSMutableDictionary *result=[route mutableCopy]; result[@"host"]=host;
    if (result[@"nodeJSON"] && ![result[@"nodeJSON"] isKindOfClass:[NSString class]]) return nil;
    if (result[@"chainJSON"] && ![result[@"chainJSON"] isKindOfClass:[NSString class]]) return nil;
    return result;
}
- (void)dial:(MLPacketFlow *)flow {
    dispatch_group_async(_workers,dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{ @autoreleasepool {
        dispatch_semaphore_wait(self->_capacity,DISPATCH_TIME_FOREVER);
        BOOL cancelled; @synchronized(self) { cancelled=flow.closed || flow.cancelled || __atomic_load_n(&self->_stopping,__ATOMIC_ACQUIRE); }
        NSDictionary *route=cancelled?nil:[self routeFlow:flow];
        MLStream *stream=NULL; id<MLPacketDatagram> datagram=nil;
        if (route && !flow.dns) {
            if (flow->tuple.protocol==TUN_FLOW_TCP) {
                if(route[@"chainJSON"])stream=MLStreamOpenChain([route[@"chainJSON"] UTF8String],[route[@"host"] UTF8String],flow->tuple.destination_port,8000);
                else stream=MLStreamOpen([route[@"nodeJSON"] UTF8String],[route[@"host"] UTF8String],flow->tuple.destination_port,8000);
            }
            else datagram=self->_datagram(route,flow->tuple.destination_port,NULL);
        }
        @synchronized(self) {
            if (flow.closed || flow.cancelled || __atomic_load_n(&self->_stopping,__ATOMIC_ACQUIRE)) { if (stream) MLStreamClose(stream); [datagram close]; }
            else {
                flow.route=route; flow.metadata=MLMetadata(route[@"metadata"]);
                flow->stream=stream; flow.datagram=datagram; flow.dialFinished=YES;
                if (!flow.dns && (stream || datagram) && flow.startedAt>=[self->_lastConnection[@"startedAt"] doubleValue]) {
                    NSMutableDictionary *last=[NSMutableDictionary dictionary];
                    for (NSString *key in @[@"actual",@"group",@"protocol",@"configID",@"routingToken"])
                        if (flow.metadata[key]) last[key]=flow.metadata[key];
                    last[@"startedAt"]=@(flow.startedAt);
                    self->_lastConnection=[last copy];
                }
            }
        }
        dispatch_semaphore_signal(self->_capacity); [self wake];
    }});
}
- (void)finish:(MLPacketFlow *)flow {
    if (!flow || flow.closed) return;
    @synchronized(self) { flow.closed=YES; flow.cancelled=YES;
        if (flow->tuple.protocol==TUN_FLOW_TCP) [_tcp removeObjectForKey:@(flow.identifier)];
        else [_udp removeObjectForKey:[NSData dataWithBytes:&flow->tuple length:sizeof flow->tuple]];
        if (flow->stream) { MLStreamClose(flow->stream); flow->stream=NULL; }
        [flow.datagram close]; flow.datagram=nil;
    }
    if (_releaseAddress) _releaseAddress(flow.destination);
}
- (void)flowEvent:(tun_stack_flow_event_t)event identifier:(uint64_t)identifier key:(const tun_flow_key_t *)key {
    MLPacketFlow *flow; @synchronized(self) { flow=_tcp[@(identifier)]; }
    if (event==TUN_STACK_FLOW_REQUESTED) {
        if (_tcp.count>=MLPacketTCPMax) { _failedTCP++; tun_stack_flow_reject(_stack,identifier); return; }
        flow=[self newFlow:key identifier:identifier name:[NSString stringWithFormat:@"capture-tcp-%llu",(unsigned long long)identifier]];
        @synchronized(self) { _tcp[@(identifier)]=flow; } [self dial:flow];
    } else if (event==TUN_STACK_FLOW_OPEN) flow.opened=YES;
    else if (event==TUN_STACK_FLOW_CLOSED) [self finish:flow];
}
- (int)udp:(const tun_flow_key_t *)key bytes:(const uint8_t *)bytes length:(size_t)length {
    if (length>MLPacketUDPBytesMax) { _droppedUDP++; return -1; }
    NSData *identifier=[NSData dataWithBytes:key length:sizeof *key];
    MLPacketFlow *flow; @synchronized(self) { flow=_udp[identifier]; }
    if (!flow) {
        if (_udp.count>=MLPacketUDPMax) { _droppedUDP++; return -1; }
        flow=[self newFlow:key identifier:0 name:[NSString stringWithFormat:@"capture-udp-%@",[[NSProcessInfo processInfo] globallyUniqueString]]];
        @synchronized(self) { _udp[identifier]=flow; } [self dial:flow];
    }
    size_t queued=0; for (NSData *packet in flow.datagrams) queued+=packet.length;
    if (flow.datagrams.count>=MLPacketUDPQueueMax || queued+length>MLPacketUDPBytesMax) { _droppedUDP++; return -1; }
    [flow.datagrams addObject:[NSData dataWithBytes:bytes length:length]]; flow.activity=(uint64_t)senko_now_ms(); return 0;
}
- (void)dnsQuery:(NSData *)query flow:(MLPacketFlow *)flow {
    flow.dnsBusy=YES; flow.dnsFinished=NO; flow.dnsResult=nil;
    dispatch_group_async(_workers,dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{ @autoreleasepool {
        dispatch_semaphore_wait(self->_capacity,DISPATCH_TIME_FOREVER);
        BOOL cancelled; @synchronized(self) { cancelled=flow.closed || flow.cancelled || __atomic_load_n(&self->_stopping,__ATOMIC_ACQUIRE); }
        NSData *answer=!cancelled?self->_dns(query):nil;
        if (answer.length>4096) answer=nil;
        @synchronized(self) { if (!flow.closed && !flow.cancelled && !__atomic_load_n(&self->_stopping,__ATOMIC_ACQUIRE)) { flow.dnsResult=answer; flow.dnsFinished=YES; } }
        dispatch_semaphore_signal(self->_capacity); [self wake];
    }});
}
- (void)tcpDNS:(MLPacketFlow *)flow {
    if (flow.dnsBusy && flow.dnsFinished) {
        flow.dnsBusy=NO; flow.dnsFinished=NO;
        NSData *answer=flow.dnsResult; flow.dnsResult=nil;
        if (!answer.length) { _dnsFailures++; tun_stack_flow_abort(_stack,flow.identifier); return; }
        uint16_t prefix=htons((uint16_t)answer.length); memcpy(flow->buffer,&prefix,2);
        memcpy(flow->buffer+2,answer.bytes,answer.length); flow->offset=0; flow->remaining=answer.length+2;
    }
    if (flow->remaining) {
        size_t accepted=0;
        tun_stack_status_t sent=tun_stack_flow_write(_stack,flow.identifier,flow->buffer+flow->offset,flow->remaining,&accepted);
        if (sent<0) { tun_stack_flow_abort(_stack,flow.identifier); return; }
        flow->offset+=accepted; flow->remaining-=accepted; flow.download+=accepted; _download+=accepted;
        if (accepted) flow.activity=(uint64_t)senko_now_ms();
    }
    if (flow.dnsBusy || flow->remaining) return;
    const uint8_t *data; size_t length; int eof;
    if (tun_stack_flow_peek(_stack,flow.identifier,&data,&length,&eof)!=TUN_STACK_OK) return;
    if (length) {
        size_t take=MIN(length,4098-flow.dnsInput.length);
        if (!take) { tun_stack_flow_abort(_stack,flow.identifier); return; }
        [flow.dnsInput appendBytes:data length:take]; tun_stack_flow_consume(_stack,flow.identifier,take);
        flow.upload+=take; _upload+=take; flow.activity=(uint64_t)senko_now_ms();
    }
    if (flow.dnsInput.length>=2) {
        const uint8_t *bytes=flow.dnsInput.bytes; size_t size=((size_t)bytes[0]<<8)|bytes[1];
        if (size<12 || size>4096) { tun_stack_flow_abort(_stack,flow.identifier); return; }
        if (flow.dnsInput.length>=size+2) {
            NSData *query=[NSData dataWithBytes:bytes+2 length:size];
            [flow.dnsInput replaceBytesInRange:NSMakeRange(0,size+2) withBytes:NULL length:0];
            [self dnsQuery:query flow:flow]; return;
        }
    }
    if (eof) {
        if (flow.dnsInput.length) { tun_stack_flow_abort(_stack,flow.identifier); return; }
        // FIN needs its own lwIP send segment. A full queue may temporarily
        // refuse it; wait for ACKs rather than closing into tcp_abort/RST.
        if(tun_stack_flow_shutdown(_stack,flow.identifier)==TUN_STACK_OK){tun_stack_flow_close(_stack,flow.identifier);flow.stackClosing=YES;}
    }
}
- (void)relayTCP:(MLPacketFlow *)flow {
    if (flow.closed || flow.stackClosing) return;
    if (flow.cancelled || (uint64_t)senko_now_ms()-flow.activity>300000) {
        if (flow.accepted) tun_stack_flow_abort(_stack,flow.identifier); else tun_stack_flow_reject(_stack,flow.identifier); return;
    }
    BOOL finished; @synchronized(self) { finished=flow.dialFinished; }
    if (!finished) return;
    if (!flow.accepted) {
        if (!flow.route || (!flow.dns && !flow->stream)) { _failedTCP++; tun_stack_flow_reject(_stack,flow.identifier); return; }
        flow.accepted=YES; flow.opening=NO;
        if (tun_stack_flow_accept(_stack,flow.identifier)!=TUN_STACK_OK) { [self finish:flow]; return; }
    }
    if (!flow.opened) return;
    if (flow.dns) { [self tcpDNS:flow]; return; }
    const uint8_t *data; size_t length; int eof;
    if (!flow.localEOF && tun_stack_flow_peek(_stack,flow.identifier,&data,&length,&eof)==TUN_STACK_OK) {
        if (length) {
            ssize_t n=MLStreamWrite(flow->stream,data,length);
            if (n>0) { tun_stack_flow_consume(_stack,flow.identifier,n); flow.upload+=n; _upload+=n; flow.activity=(uint64_t)senko_now_ms(); }
            else if (!n || !MLAgain()) { tun_stack_flow_abort(_stack,flow.identifier); return; }
        }
        if (eof) { flow.localEOF=YES;_localEOFs++; MLStreamShutdownWrite(flow->stream); }
    }
    if (!flow.remoteEOF && !flow->remaining && tun_stack_flow_writable(_stack,flow.identifier)) {
        ssize_t n=MLStreamRead(flow->stream,flow->buffer,MIN(sizeof flow->buffer,tun_stack_flow_writable(_stack,flow.identifier)));
        if (n>0) { flow->offset=0; flow->remaining=n; }
        else if (!n) {flow.remoteEOF=YES;_remoteEOFs++;}
        else if (!MLAgain()) { tun_stack_flow_abort(_stack,flow.identifier); return; }
    }
    if (flow->remaining) {
        size_t accepted=0;
        if (tun_stack_flow_write(_stack,flow.identifier,flow->buffer+flow->offset,flow->remaining,&accepted)<0) { tun_stack_flow_abort(_stack,flow.identifier); return; }
        flow->offset+=accepted; flow->remaining-=accepted; flow.download+=accepted; _download+=accepted;
        if (accepted) flow.activity=(uint64_t)senko_now_ms();
    }
    if (MLStreamPump(flow->stream)<0) { tun_stack_flow_abort(_stack,flow.identifier); return; }
    if (flow.remoteEOF && !flow->remaining && !flow.remoteFin){
        if(tun_stack_flow_shutdown(_stack,flow.identifier)==TUN_STACK_OK){flow.remoteFin=YES;_tcpFinSent++;}
        else _tcpFinRetries++;
    }
    if (flow.localEOF && flow.remoteFin && !MLStreamWritePending(flow->stream)) { tun_stack_flow_close(_stack,flow.identifier); flow.stackClosing=YES; }
}
- (void)relayUDP:(MLPacketFlow *)flow {
    if (flow.closed) return;
    if (flow.cancelled || (uint64_t)senko_now_ms()-flow.activity>(flow.dns?10000:60000)) { [self finish:flow]; return; }
    BOOL finished; @synchronized(self) { finished=flow.dialFinished; }
    if (!finished) return;
    if (flow.opening) {
        if (!flow.route || (!flow.dns && !flow.datagram)) { _droppedUDP+=flow.datagrams.count; [self finish:flow]; return; }
        flow.opening=NO; flow.opened=YES;
    }
    if (flow.dns) {
        if (flow.dnsBusy && flow.dnsFinished) {
            flow.dnsBusy=NO; flow.dnsFinished=NO; NSData *answer=flow.dnsResult; flow.dnsResult=nil;
            if (answer && MLUDPPacketsReply(_packets,&flow->tuple,answer.bytes,answer.length,(uint64_t)senko_now_ms())>=0) { flow.download+=answer.length; _download+=answer.length; flow.activity=(uint64_t)senko_now_ms(); }
            else _dnsFailures++;
        }
        if (!flow.dnsBusy && flow.datagrams.count) {
            NSData *query=flow.datagrams[0]; [flow.datagrams removeObjectAtIndex:0]; flow.upload+=query.length; _upload+=query.length;
            [self dnsQuery:query flow:flow];
        }
        return;
    }
    while (flow.datagrams.count) {
        NSData *packet=flow.datagrams[0]; NSError *error=nil;
        if (![flow.datagram sendData:packet error:&error]) {
            if (!error || error.code==EAGAIN || error.code==EWOULDBLOCK || error.code==EINTR) break;
            _droppedUDP+=flow.datagrams.count; [self finish:flow]; return;
        }
        flow.upload+=packet.length; _upload+=packet.length; [flow.datagrams removeObjectAtIndex:0]; flow.activity=(uint64_t)senko_now_ms();
    }
    for (unsigned i=0;i<16;i++) {
        NSError *error=nil; NSData *packet=[flow.datagram receiveData:&error];
        if (!packet) {
            if (error && error.code!=EAGAIN && error.code!=EWOULDBLOCK && error.code!=EINTR) [self finish:flow];
            break;
        }
        if (packet.length>MLPacketUDPBytesMax || MLUDPPacketsReply(_packets,&flow->tuple,packet.bytes,packet.length,(uint64_t)senko_now_ms())<0) { _droppedUDP++; continue; }
        flow.download+=packet.length; _download+=packet.length; flow.activity=(uint64_t)senko_now_ms();
    }
}
- (void)prepareRead:(fd_set *)readable write:(fd_set *)writable highest:(int *)highest wait:(uint32_t *)wait {
    NSArray *flows; @synchronized(self) { flows=[_tcp.allValues arrayByAddingObjectsFromArray:_udp.allValues]; }
    if (flows.count && *wait>100) *wait=100;
    if(MLUDPPacketsPending(_packets) && *wait>10)*wait=10;
    for (MLPacketFlow *flow in flows) {
        if (flow.closed || flow.dns || !flow.opened || flow.stackClosing) continue;
        int fd=-1; short events=0;
        if (flow->tuple.protocol==TUN_FLOW_TCP && flow->stream) {
            fd=MLStreamFD(flow->stream);
            const uint8_t *pending; size_t pendingLength=0; int eof=0;
            if (!flow.localEOF) tun_stack_flow_peek(_stack,flow.identifier,&pending,&pendingLength,&eof);
            events=MLStreamEvents(flow->stream,!flow.remoteEOF && !flow->remaining && tun_stack_flow_writable(_stack,flow.identifier)>0,pendingLength>0 || MLStreamWritePending(flow->stream));
            if (tun_stack_flow_writable(_stack,flow.identifier) && !flow->remaining && MLStreamPendingRead(flow->stream)) *wait=0;
        } else if (flow.datagram) { fd=flow.datagram.fileDescriptor; events=[flow.datagram eventsForRead:YES write:flow.datagrams.count>0]; }
        if (fd<0 || fd>=FD_SETSIZE) continue;
        if (events&POLLIN) FD_SET(fd,readable);
        if (events&POLLOUT) FD_SET(fd,writable);
        if (events && fd>*highest) *highest=fd;
    }
}
- (void)snapshot {
    const tun_stack_stats_t *stats=tun_stack_stats(_stack); uint64_t now=(uint64_t)senko_now_ms();
    NSMutableArray *rows=[NSMutableArray array];
    for (MLPacketFlow *flow in [_tcp.allValues arrayByAddingObjectsFromArray:_udp.allValues]) {
        if (flow.closed || !flow.route) continue;
        NSMutableDictionary *row=[flow.metadata mutableCopy] ?: [NSMutableDictionary dictionary];
        [row addEntriesFromDictionary:@{@"id":flow.name,@"source":flow.source ?: @"",@"sourcePort":@(flow->tuple.source_port),
            @"host":flow.metadata[@"host"] ?: flow.route[@"host"] ?: flow.destination,@"target":flow.destination,@"targetPort":@(flow->tuple.destination_port),@"startedAt":@(flow.startedAt),
            @"destination":[NSString stringWithFormat:@"%@:%u",flow.destination,(unsigned)flow->tuple.destination_port],
            @"network":flow->tuple.protocol==TUN_FLOW_TCP?@"TCP":@"UDP",@"uploadBytes":@(flow.upload),@"downloadBytes":@(flow.download),
            @"duration":@((now-flow.created)/1000.0),@"capture":@"utun"}];
        if(flow->tuple.protocol==TUN_FLOW_TCP)[row addEntriesFromDictionary:@{@"localEOF":@(flow.localEOF),@"remoteEOF":@(flow.remoteEOF),@"remoteFin":@(flow.remoteFin),@"upstreamWritePending":@(flow->stream && MLStreamWritePending(flow->stream))}];
        [rows addObject:row];
    }
    uint64_t udpIn,udpOut,udpInvalid;MLUDPPacketsCounts(_packets,&udpIn,&udpOut,&udpInvalid);
    @synchronized(self) {
        _rows=[rows copy];
        _snapshot=@{@"uploadBytes":@(_upload),@"downloadBytes":@(_download),@"connections":@(_tcp.count+_udp.count),
            @"tcpConnections":@(_tcp.count),@"udpSessions":@(_udp.count),@"duration":@((now-_started)/1000),
            @"tcpFailures":@(_failedTCP),@"udpDropped":@(_droppedUDP),@"dnsFailures":@(_dnsFailures),
            @"ipv4Frames":@(_ipv4Frames),@"ipv6Frames":@(_ipv6Frames),@"tcpFINFrames":@(_tcpFINFrames),@"localEOFs":@(_localEOFs),@"remoteEOFs":@(_remoteEOFs),@"tcpFinSent":@(_tcpFinSent),@"tcpFinRetries":@(_tcpFinRetries),
            @"framesIn":@(stats->frames_in+udpIn),@"framesOut":@(stats->frames_out+udpOut),@"invalidFrames":@(stats->dropped_frame+stats->dropped_capture+udpInvalid),
            @"queuePackets":@(stats->queue_packets),@"queueBytes":@(stats->queue_bytes)};
    }
}
- (void)dispatchRead:(const fd_set *)readable write:(const fd_set *)writable {
    (void)readable; (void)writable;
    @autoreleasepool {
        NSArray *tcp,*udp; @synchronized(self) { tcp=[_tcp.allValues copy]; udp=[_udp.allValues copy]; }
        for (MLPacketFlow *flow in tcp) [self relayTCP:flow];
        for (MLPacketFlow *flow in udp) [self relayUDP:flow];
        MLUDPPacketsDrain(_packets,(uint64_t)senko_now_ms(),MLWriteUDPFrame,(__bridge void *)self);
        [self snapshot];
    }
}
- (void)ownerStopped {
    @autoreleasepool {
        NSArray *flows; @synchronized(self) { __atomic_store_n(&_stopping,YES,__ATOMIC_RELEASE); flows=[_tcp.allValues arrayByAddingObjectsFromArray:_udp.allValues]; }
        for (MLPacketFlow *flow in flows) [self finish:flow];
        [self snapshot];
    }
}
@end
