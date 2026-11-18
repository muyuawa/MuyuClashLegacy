#import "MLCoreDatagram.h"
#import "MLStream.h"
#include <errno.h>

@interface MLCoreDatagram : NSObject <MLPacketDatagram>
- (id)initWithSession:(MLDatagram *)session;
@end
@implementation MLCoreDatagram { MLDatagram *_session; }
- (id)initWithSession:(MLDatagram *)session { if ((self=[super init])) _session=session; return self; }
- (void)dealloc { [self close]; }
- (int)fileDescriptor { return _session?MLDatagramFD(_session):-1; }
- (void)close { if (_session) MLDatagramClose(_session); _session=NULL; }
- (short)eventsForRead:(BOOL)read write:(BOOL)write { return (read?POLLIN:0)|(write?POLLOUT:0); }
- (BOOL)sendData:(NSData *)data error:(NSError **)error {
    ssize_t n=_session?MLDatagramWrite(_session,data.bytes,data.length):-1;
    if (n==(ssize_t)data.length) return YES;
    int code=_session?errno:EBADF;
    if(error)*error=[NSError errorWithDomain:NSPOSIXErrorDomain code:code userInfo:nil];
    return NO;
}
- (NSData *)receiveData:(NSError **)error {
    uint8_t bytes[65535]; ssize_t n=_session?MLDatagramRead(_session,bytes,sizeof(bytes)):-1;
    if(n>=0) return [NSData dataWithBytes:bytes length:(NSUInteger)n];
    int code=_session?errno:EBADF;
    if(code!=EAGAIN&&code!=EWOULDBLOCK&&error)*error=[NSError errorWithDomain:NSPOSIXErrorDomain code:code userInfo:nil];
    return nil;
}
@end
id<MLPacketDatagram> MLCoreOpenDatagram(NSDictionary *route,uint16_t port,NSError **error) {
    if(route[@"chainJSON"]) {
        if(error)*error=[NSError errorWithDomain:NSPOSIXErrorDomain code:ENOTSUP userInfo:nil];
        return nil;
    }
    MLDatagram *session=MLDatagramOpen([route[@"nodeJSON"] UTF8String],[route[@"host"] UTF8String],port,8000);
    if(!session) { if(error)*error=[NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil]; return nil; }
    return [[MLCoreDatagram alloc]initWithSession:session];
}
