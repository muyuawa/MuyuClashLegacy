#import "MLIPC.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#include <mach/mach_time.h>

NSString * const MLControlSocket = @"/var/run/muyuclash/control.sock";
static const NSUInteger MLMaximumFrame = 1024 * 1024;

static void MLError(NSError **error, NSInteger code, NSString *message) {
    if (error) *error = [NSError errorWithDomain:@"MuyuClash.IPC" code:code
                                      userInfo:@{NSLocalizedDescriptionKey:message}];
}
static double MLClock(void) {
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    return (double)mach_absolute_time() * timebase.numer / timebase.denom / 1e9;
}
void MLIPCSetTimeout(int fd, unsigned seconds) {
    struct timeval timeout = {(time_t)seconds, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}
static BOOL MLTransfer(int fd, void *bytes, size_t count, BOOL writing, double deadline, NSError **error) {
    size_t offset = 0;
    while (offset < count) {
        int remaining = (int)((deadline - MLClock()) * 1000);
        if (remaining <= 0) { MLError(error, ETIMEDOUT, @"本地服务请求超时"); return NO; }
        struct pollfd pollfd = {fd, writing ? POLLOUT : POLLIN, 0};
        int ready = poll(&pollfd, 1, remaining);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) { MLError(error, ready == 0 ? ETIMEDOUT : errno, @"本地通信等待失败"); return NO; }
        ssize_t transferred = writing ? send(fd, (char *)bytes + offset, count - offset, MSG_DONTWAIT)
                                      : recv(fd, (char *)bytes + offset, count - offset, MSG_DONTWAIT);
        if (transferred < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (transferred <= 0) { MLError(error, transferred == 0 ? ECONNRESET : errno, @"本地通信中断"); return NO; }
        offset += (size_t)transferred;
    }
    return YES;
}
BOOL MLIPCWriteFrame(int fd, NSDictionary *message, NSError **error) {
    if (![message isKindOfClass:[NSDictionary class]] || ![NSJSONSerialization isValidJSONObject:message]) {
        MLError(error, EINVAL, @"无效的 IPC 对象"); return NO;
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:message options:0 error:error];
    if (!data || data.length == 0 || data.length > MLMaximumFrame) {
        MLError(error, EMSGSIZE, @"IPC 消息超出 1 MiB 限制"); return NO;
    }
    uint32_t length = htonl((uint32_t)data.length);
    double deadline = MLClock() + 5;
    return MLTransfer(fd, &length, sizeof(length), YES, deadline, error) &&
           MLTransfer(fd, (void *)data.bytes, data.length, YES, deadline, error);
}
BOOL MLIPCWriteReply(int fd, NSDictionary *request, NSDictionary *response) {
    NSError *error = nil;
    if (MLIPCWriteFrame(fd, response, &error)) return YES;
    // Oversize is detected before any frame byte is sent. After a partial I/O
    // failure, close the stream instead of attempting a second corrupt frame.
    if ([error.domain isEqual:@"MuyuClash.IPC"] && error.code == EMSGSIZE)
        return MLIPCWriteFrame(fd, MLIPCResponse(request,nil,@"E_RESPONSE_SIZE",@"结果超出本地通信大小限制，请缩小查询范围"), NULL);
    return NO;
}
NSDictionary *MLIPCReadFrame(int fd, NSError **error) {
    uint32_t length = 0;
    double deadline = MLClock() + 5;
    if (!MLTransfer(fd, &length, sizeof(length), NO, deadline, error)) return nil;
    length = ntohl(length);
    if (length == 0 || length > MLMaximumFrame) { MLError(error, EMSGSIZE, @"无效的 IPC 消息长度"); return nil; }
    NSMutableData *data = [NSMutableData dataWithLength:length];
    if (!MLTransfer(fd, data.mutableBytes, length, NO, deadline, error)) return nil;
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:error];
    if (![object isKindOfClass:[NSDictionary class]]) { MLError(error, EINVAL, @"IPC 消息必须为对象"); return nil; }
    return object;
}
BOOL MLIPCValidRequest(NSDictionary *request) {
    if (![request isKindOfClass:[NSDictionary class]]) return NO;
    id version = request[@"version"], identifier = request[@"id"], method = request[@"method"];
    return [version isKindOfClass:[NSNumber class]] && [version doubleValue] == 1.0 &&
           [identifier isKindOfClass:[NSString class]] && [identifier length] > 0 && [identifier length] <= 128 &&
           [method isKindOfClass:[NSString class]] && [method length] > 0 && [method length] <= 128 &&
           [request[@"params"] isKindOfClass:[NSDictionary class]];
}
NSDictionary *MLIPCResponse(NSDictionary *request, NSDictionary *result, NSString *code, NSString *message) {
    id identifier = [request[@"id"] isKindOfClass:[NSString class]] ? request[@"id"] : @"invalid";
    if (code) return @{@"version":@1,@"id":identifier,@"error":@{@"code":code,@"message":message ?: @"请求失败"}};
    return @{@"version":@1,@"id":identifier,@"result":result ?: @{}};
}
BOOL MLIPCPeerAllowed(int fd, uid_t owner) {
    uid_t uid = (uid_t)-1; gid_t gid = (gid_t)-1;
    return getpeereid(fd, &uid, &gid) == 0 && uid == owner;
}
NSDictionary *MLIPCRequest(NSString *socketPath, NSString *method, NSDictionary *params, NSError **error) {
    return MLIPCRequestWithOwner(socketPath,[socketPath isEqual:MLControlSocket]?0:getuid(),method,params,error);
}
NSDictionary *MLIPCRequestWithOwner(NSString *socketPath, uid_t expectedUID, NSString *method, NSDictionary *params, NSError **error) {
    struct sockaddr_un address; memset(&address, 0, sizeof(address));
    NSData *path = [socketPath dataUsingEncoding:NSUTF8StringEncoding];
    if (!path || path.length == 0 || path.length >= sizeof(address.sun_path) || [socketPath rangeOfString:@"\0"].location != NSNotFound) {
        MLError(error, EINVAL, @"本地服务路径无效"); return nil;
    }
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path.bytes, path.length);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { MLError(error, errno, @"无法创建本地通信"); return nil; }
    MLIPCSetTimeout(fd, 5);
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int connected = connect(fd, (struct sockaddr *)&address, sizeof(address));
    if (connected < 0 && errno == EINPROGRESS) {
        struct pollfd pollfd = {fd, POLLOUT, 0};
        if (poll(&pollfd, 1, 5000) > 0) {
            int code = 0; socklen_t len = sizeof(code);
            connected = getsockopt(fd, SOL_SOCKET, SO_ERROR, &code, &len) == 0 && code == 0 ? 0 : -1;
        }
    }
    if (connected < 0) { close(fd); MLError(error, ENOTCONN, @"后台服务未连接，请检查安装及 launchd 状态"); return nil; }
    if (!MLIPCPeerAllowed(fd, expectedUID)) { close(fd); MLError(error, EACCES, @"后台服务身份校验失败"); return nil; }
    NSString *identifier = [[NSProcessInfo processInfo] globallyUniqueString];
    NSDictionary *request = @{@"version":@1,@"id":identifier,@"method":method ?: @"",@"params":params ?: @{}};
    NSDictionary *reply = nil;
    if (MLIPCValidRequest(request) && MLIPCWriteFrame(fd, request, error)) reply = MLIPCReadFrame(fd, error);
    close(fd);
    if (!reply) return nil;
    if (![reply[@"version"] isEqual:@1] || ![reply[@"id"] isEqual:identifier]) { MLError(error, EPROTO, @"后台应答版本或请求 ID 不匹配"); return nil; }
    id failure = reply[@"error"];
    if ([failure isKindOfClass:[NSDictionary class]]) {
        NSString *message = [failure[@"message"] isKindOfClass:[NSString class]] ? failure[@"message"] : @"后台请求失败";
        if (error) *error = [NSError errorWithDomain:@"MuyuClash.Service" code:1 userInfo:@{NSLocalizedDescriptionKey:message,@"serviceCode":failure[@"code"] ?: @"E_UNKNOWN"}];
        return nil;
    }
    if (![reply[@"result"] isKindOfClass:[NSDictionary class]]) { MLError(error, EPROTO, @"后台应答缺少结果"); return nil; }
    return reply[@"result"];
}
