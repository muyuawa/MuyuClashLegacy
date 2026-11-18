#import <Foundation/Foundation.h>
#import "MLService.h"
#import "MLIPC.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <dispatch/dispatch.h>

static volatile sig_atomic_t MLStopping = 0;
static void MLStopSignal(int signalNumber) { (void)signalNumber; MLStopping = 1; }

int main(int argc, const char *argv[]) { @autoreleasepool {
    umask(0077);
    NSString *socketPath = MLControlSocket;
    NSString *statePath = @"/private/var/lib/muyuclash";
    NSString *caPath = @"/usr/share/muyuclash/cacert.pem";
    BOOL development = NO;
    for (int index = 1; index < argc; index++) {
        NSString *arg = [NSString stringWithUTF8String:argv[index]];
        if ([arg isEqual:@"--development"]) development = YES;
        else if (index + 1 < argc && [arg isEqual:@"--socket"]) socketPath = [NSString stringWithUTF8String:argv[++index]];
        else if (index + 1 < argc && [arg isEqual:@"--state-dir"]) statePath = [NSString stringWithUTF8String:argv[++index]];
        else if (index + 1 < argc && [arg isEqual:@"--ca"]) caPath = [NSString stringWithUTF8String:argv[++index]];
        else { fputs("usage: muyu-supervisor [--development --socket PATH --state-dir PATH] [--ca PATH]\n",stderr); return 64; }
    }
    if (!development && (geteuid() != 0 || ![socketPath isEqual:MLControlSocket] || ![statePath isEqual:@"/private/var/lib/muyuclash"])) {
        fputs("Production service requires root and fixed app-owned paths.\n",stderr); return 77;
    }
    if (development && ([socketPath isEqual:MLControlSocket] || [statePath isEqual:@"/private/var/lib/muyuclash"])) {
        fputs("Development service requires explicit isolated socket and state paths.\n",stderr); return 64;
    }
    NSString *socketParent = socketPath.stringByDeletingLastPathComponent;
    if (!development && mkdir(socketParent.fileSystemRepresentation,0750) < 0 && errno != EEXIST) { perror("socket directory"); return 73; }
    struct stat parentStatus;
    if (lstat(socketParent.fileSystemRepresentation,&parentStatus) != 0 || !S_ISDIR(parentStatus.st_mode) ||
        parentStatus.st_uid != geteuid() || (parentStatus.st_mode & 0022)) {
        fputs("Socket directory is not privately owned.\n",stderr); return 77;
    }
    uid_t mobileUID = getuid(); gid_t mobileGID = getgid();
    BOOL privilegedDevelopment=NO;
    if(development&&geteuid()==0) {struct passwd *mobile=getpwnam("mobile");if(mobile){mobileUID=mobile->pw_uid;mobileGID=mobile->pw_gid;privilegedDevelopment=YES;}}
    if (!development) {
        struct passwd *mobile = getpwnam("mobile");
        if (!mobile) { fputs("mobile account not found.\n",stderr); return 77; }
        mobileUID = mobile->pw_uid; mobileGID = mobile->pw_gid;
        if (chown(socketParent.fileSystemRepresentation,0,mobileGID) || chmod(socketParent.fileSystemRepresentation,0750)) { perror("socket permissions"); return 77; }
    }
    NSError *error = nil;
    MLService *service = [[MLService alloc] initWithDirectory:statePath caPath:caPath error:&error];
    if (!service) { fputs("Private configuration storage could not be opened.\n",stderr); return 73; }
    NSString *lockPath = [statePath stringByAppendingPathComponent:@"supervisor.lock"];
    int lockFD = open(lockPath.fileSystemRepresentation,O_RDWR|O_CREAT|O_NOFOLLOW,0600);
    struct stat lockStatus;
    if (lockFD < 0 || fstat(lockFD,&lockStatus) || !S_ISREG(lockStatus.st_mode) || lockStatus.st_nlink != 1 || lockStatus.st_uid != geteuid() || flock(lockFD,LOCK_EX|LOCK_NB)) {
        fputs("Supervisor already running or lock is unsafe.\n",stderr); if (lockFD >= 0) close(lockFD); return 75;
    }
    fcntl(lockFD,F_SETFD,FD_CLOEXEC);
    service.corePort = development ? 0 : 7891;
    service.controlSocket=socketPath;
    NSString *binary = [[[NSProcessInfo processInfo] arguments] objectAtIndex:0];
    service.coreExecutable = development ? [binary.stringByDeletingLastPathComponent stringByAppendingPathComponent:@"muyu-core"]
                                         : @"/usr/libexec/muyuclash/muyu-core";
    struct sockaddr_un address; memset(&address,0,sizeof(address)); address.sun_family = AF_UNIX;
    NSData *path = [socketPath dataUsingEncoding:NSUTF8StringEncoding];
    if (!path.length || path.length >= sizeof(address.sun_path)) { close(lockFD); return 64; }
    memcpy(address.sun_path,path.bytes,path.length);
    struct stat old;
    if (lstat(address.sun_path,&old) == 0) {
        if (!S_ISSOCK(old.st_mode) || old.st_uid != geteuid()) { fputs("Refusing to replace a non-owned socket.\n",stderr); close(lockFD); return 77; }
        if (unlink(address.sun_path)) { close(lockFD); return 73; }
    }
    int listener = socket(AF_UNIX,SOCK_STREAM,0);
    if (listener < 0 || bind(listener,(struct sockaddr *)&address,sizeof(address)) ||
        chmod(address.sun_path,development&&!privilegedDevelopment ? 0600 : 0660) ||
        ((!development||privilegedDevelopment) && chown(address.sun_path,0,mobileGID)) || listen(listener,16)) {
        perror("control socket"); if (listener >= 0) close(listener); unlink(address.sun_path); close(lockFD); return 71;
    }
    fcntl(listener,F_SETFD,FD_CLOEXEC);
    signal(SIGTERM,MLStopSignal); signal(SIGINT,MLStopSignal); signal(SIGPIPE,SIG_IGN);
    dispatch_semaphore_t capacity = dispatch_semaphore_create(4);
    dispatch_group_t workers = dispatch_group_create();
    dispatch_queue_t maintenance = dispatch_queue_create("org.muyu.clash.supervisor",NULL);
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,maintenance);
    dispatch_source_set_timer(timer,dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC),NSEC_PER_SEC,NSEC_PER_SEC/10);
    dispatch_source_set_event_handler(timer,^{ [service tick]; });
    dispatch_resume(timer);
    [service controlListenerReady];
    while (!MLStopping) { @autoreleasepool {
        struct pollfd pollfd = {listener,POLLIN,0};
        int ready = poll(&pollfd,1,250);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) break;
        if (ready == 0) continue;
        int fd = accept(listener,NULL,NULL);
        if (fd < 0) continue;
        MLIPCSetTimeout(fd,5);
        if (!(MLIPCPeerAllowed(fd,mobileUID) || (geteuid()==0 && MLIPCPeerAllowed(fd,0))) || dispatch_semaphore_wait(capacity,DISPATCH_TIME_NOW) != 0) { close(fd); continue; }
        dispatch_group_async(workers,dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{ @autoreleasepool {
            NSError *requestError = nil;
            NSDictionary *request = MLIPCReadFrame(fd,&requestError);
            if (request) {
                NSDictionary *response;
                if (!MLIPCValidRequest(request)) response = MLIPCResponse(request,nil,@"E_REQUEST",@"请求版本、ID、方法或参数不合法");
                else {
                    NSDictionary *result = [service handleMethod:request[@"method"] params:request[@"params"] error:&requestError];
                    response = MLIPCResponse(request,result,result ? nil : (requestError.domain ?: @"E_INTERNAL"),requestError.localizedDescription);
                }
                MLIPCWriteReply(fd,request,response);
            }
            close(fd); dispatch_semaphore_signal(capacity);
        }});
    }}
    dispatch_source_cancel(timer);
    dispatch_sync(maintenance,^{});
    close(listener);
    dispatch_group_wait(workers,DISPATCH_TIME_FOREVER);
    [service shutdown];
    unlink(address.sun_path); close(lockFD);
    return 0;
}}
