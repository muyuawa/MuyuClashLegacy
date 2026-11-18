#import "MLCoreProcess.h"
#import "MLIPC.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static BOOL MLCoreError(NSError **error, NSString *code, NSString *message) {
    if (error) *error = [NSError errorWithDomain:code code:1 userInfo:@{NSLocalizedDescriptionKey:message}];
    return NO;
}
static int MLDuplicate(int fd) {
    int copy=fcntl(fd,F_DUPFD,10);
    if(copy>=0 && fcntl(copy,F_SETFD,FD_CLOEXEC)) { close(copy);return -1; }
    return copy;
}

@implementation MLCoreProcess {
    int _control;
}
- (id)init {
    if ((self = [super init])) _control = -1;
    return self;
}
- (void)dealloc { [self stop]; }

- (BOOL)start:(NSString *)executable port:(NSUInteger)port error:(NSError **)error {
    return [self start:executable port:port captureFD:-1 lifetimeFD:-1 outboundInterface:0 interfaceName:nil error:error];
}
- (BOOL)start:(NSString *)executable port:(NSUInteger)port captureFD:(int)captureFD
    lifetimeFD:(int)lifetimeFD outboundInterface:(unsigned)index interfaceName:(NSString *)name error:(NSError **)error {
    if (_pid) return YES;
    int sockets[2];
    if (socketpair(AF_UNIX,SOCK_STREAM,0,sockets) != 0)
        return MLCoreError(error,@"E_CORE_SPAWN",@"无法创建核心控制通道");
    MLIPCSetTimeout(sockets[0],5);
    MLIPCSetTimeout(sockets[1],5);
    if (sockets[1] < 10) {
        int fd = MLDuplicate(sockets[1]);
        close(sockets[1]);
        if (fd < 0) { close(sockets[0]); return MLCoreError(error,@"E_CORE_SPAWN",@"无法配置核心控制通道"); }
        sockets[1] = fd;
        MLIPCSetTimeout(fd,5);
    }
    posix_spawn_file_actions_t actions;
    int borrowed[2]={-1,-1};
    if(captureFD>=0) {
        borrowed[0]=MLDuplicate(captureFD);
        borrowed[1]=MLDuplicate(lifetimeFD);
        if(borrowed[0]<0||borrowed[1]<0||!index||!name.length) {
            if(borrowed[0]>=0)close(borrowed[0]); if(borrowed[1]>=0)close(borrowed[1]);
            close(sockets[0]);close(sockets[1]);
            return MLCoreError(error,@"E_CORE_SPAWN",@"无法传递接管描述符");
        }
    }
    int code = posix_spawn_file_actions_init(&actions);
    if (code) {
        if(borrowed[0]>=0)close(borrowed[0]); if(borrowed[1]>=0)close(borrowed[1]);
        close(sockets[0]); close(sockets[1]);
        return MLCoreError(error,@"E_CORE_SPAWN",@"无法配置核心进程");
    }
    code = posix_spawn_file_actions_addclose(&actions,sockets[0]);
    if (!code) code = posix_spawn_file_actions_adddup2(&actions,sockets[1],STDIN_FILENO);
    if (!code) code = posix_spawn_file_actions_addclose(&actions,sockets[1]);
    for(int i=0;i<2&&!code;i++) if(borrowed[i]>=0) {
        code=posix_spawn_file_actions_adddup2(&actions,borrowed[i],3+i);
        if(!code)code=posix_spawn_file_actions_addclose(&actions,borrowed[i]);
    }
    char number[16];
    snprintf(number,sizeof(number),"%lu",(unsigned long)port);
    const char *path = executable.fileSystemRepresentation;
    char interfaceNumber[16]; snprintf(interfaceNumber,sizeof(interfaceNumber),"%u",index);
    char *args[] = {(char *)path,(char *)"--supervised",number,
        captureFD>=0?(char *)"--capture-fd":NULL,(char *)"3",(char *)"--capture-lifetime-fd",(char *)"4",
        (char *)"--outbound-if",interfaceNumber,(char *)"--capture-name",(char *)name.UTF8String,NULL};
    char *env[] = {(char *)"PATH=/usr/bin:/bin:/usr/sbin:/sbin",NULL};
    pid_t child = 0;
    if (!code && path) code = posix_spawn(&child,path,&actions,NULL,args,env);
    else if (!code) code = EINVAL;
    posix_spawn_file_actions_destroy(&actions);
    close(sockets[1]);
    if(borrowed[0]>=0)close(borrowed[0]); if(borrowed[1]>=0)close(borrowed[1]);
    if (code) { close(sockets[0]); return MLCoreError(error,@"E_CORE_SPAWN",@"无法启动本机核心"); }
    _pid = child; _control = sockets[0];
    NSDictionary *ready = MLIPCReadFrame(_control,NULL);
    id value = ready[@"port"];
    if (![ready[@"version"] isEqual:@1] || ![value isKindOfClass:[NSNumber class]] ||
        [value integerValue] <= 0 || [value integerValue] > 65535) {
        [self stop];
        return MLCoreError(error,@"E_CORE_LISTENER",ready[@"error"] ?: @"本机核心未能就绪");
    }
    _port = [value unsignedIntegerValue];
    return YES;
}

- (BOOL)running {
    if (!_pid) return NO;
    pid_t result;
    do { result = waitpid(_pid,NULL,WNOHANG); } while (result < 0 && errno == EINTR);
    if (result == 0) return YES;
    if (result == _pid || (result < 0 && errno == ECHILD)) {
        close(_control);
        _control = -1; _pid = 0; _port = 0;
    }
    return NO;
}

- (NSDictionary *)request:(NSString *)method params:(NSDictionary *)params error:(NSError **)error {
    if (![self running]) {
        MLCoreError(error,@"E_CORE_NOT_RUNNING",@"本机核心未运行");
        return nil;
    }
    NSString *identifier = [[NSProcessInfo processInfo] globallyUniqueString];
    NSDictionary *packet = @{@"version":@1,@"id":identifier,@"method":method,@"params":params ?: @{}};
    NSDictionary *reply = MLIPCWriteFrame(_control,packet,error) ? MLIPCReadFrame(_control,error) : nil;
    if (![reply[@"id"] isEqual:identifier] || ![reply[@"version"] isEqual:@1]) {
        // A timed-out request leaves stream framing ambiguous.
        [self stop];
        MLCoreError(error,@"E_CORE_IPC",@"本机核心控制通道中断");
        return nil;
    }
    if (![reply[@"result"] isKindOfClass:[NSDictionary class]]) {
        NSDictionary *reason = reply[@"error"];
        MLCoreError(error,reason[@"code"] ?: @"E_CORE_REQUEST",reason[@"message"] ?: @"本机核心拒绝请求");
        return nil;
    }
    return reply[@"result"];
}

- (void)stop {
    if (_control >= 0) close(_control);
    _control = -1; _port = 0;
    if (!_pid) return;
    pid_t result = 0;
    for (int attempt = 0; attempt < 30; ++attempt) {
        result = waitpid(_pid,NULL,WNOHANG);
        if (result > 0 || (result < 0 && errno != EINTR)) break;
        usleep(10000);
    }
    if (!result || (result < 0 && errno == EINTR)) {
        kill(_pid,SIGKILL);
        do { result = waitpid(_pid,NULL,0); } while (result < 0 && errno == EINTR);
    }
    _pid = 0;
}
@end
