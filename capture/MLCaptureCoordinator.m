#import "MLCaptureInternal.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <spawn.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
extern char **environ;
#include <unistd.h>

static BOOL MLFailure(NSError **error, NSString *message, int code) {
    if (error) *error = [NSError errorWithDomain:@"E_CAPTURE" code:code ?: EIO userInfo:@{NSLocalizedDescriptionKey:message}];
    return NO;
}
static BOOL MLUnsigned(id value, unsigned *number) {
    if (![value isKindOfClass:[NSNumber class]] || CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID()) return NO;
    double d = [value doubleValue];
    if (d < 1 || d > UINT16_MAX || d != floor(d)) return NO;
    *number = (unsigned)d;
    return YES;
}
static BOOL MLName(NSString *name) {
    return [name isKindOfClass:[NSString class]] && name.length < 16 &&
        [name rangeOfString:@"^utun[0-9]+$" options:NSRegularExpressionSearch].location != NSNotFound;
}
static NSArray *MLDestinations(void) { return @[@"0.0.0.0", @"128.0.0.0", @"::", @"8000::"]; }
static NSArray *MLPhysicalDefaults(NSDictionary *path) {
    if(![path isKindOfClass:[NSDictionary class]])return @[];
    NSString *name=path[@"interface"];unsigned index;
    if(![name isKindOfClass:[NSString class]] || !name.length || name.length>=16 ||
        [name hasPrefix:@"utun"] || [name hasPrefix:@"lo"] || [name hasPrefix:@"ipsec"] ||
        [name hasPrefix:@"ppp"] || !MLUnsigned(path[@"interfaceIndex"],&index))return @[];
    NSMutableArray *routes=[NSMutableArray array];
    for(NSString *key in @[@"gateway4",@"gateway6"]){
        NSString *gateway=path[key];BOOL v6=[key isEqual:@"gateway6"];uint8_t address[16];
        if(v6 && ![path[@"haveIPv6Path"] boolValue])continue;
        if(![gateway isKindOfClass:[NSString class]] || inet_pton(v6?AF_INET6:AF_INET,gateway.UTF8String,address)!=1)continue;
        [routes addObject:@{@"destination":v6?@"::":@"0.0.0.0",@"prefix":@0,
            @"interface":name,@"interfaceIndex":@(index),@"gatewayIsLink":@NO,@"gateway":gateway,@"scoped":@YES}];
    }
    return routes;
}
static BOOL MLSameRoute(NSDictionary *a, NSDictionary *b) {
    BOOL same=a && b && [a[@"destination"] isEqual:b[@"destination"]] &&
        [a[@"prefix"] isEqual:b[@"prefix"]] && [a[@"interfaceIndex"] isEqual:b[@"interfaceIndex"]] &&
        [a[@"interface"] isEqual:b[@"interface"]] && [a[@"scoped"] boolValue]==[b[@"scoped"] boolValue] &&
        [a[@"gatewayIsLink"] boolValue]==[b[@"gatewayIsLink"] boolValue];
    return same && ([b[@"gatewayIsLink"] boolValue] || [a[@"gateway"] isEqual:b[@"gateway"]]);
}
static int MLDirectory(NSString *directory, NSError **error) {
    int fd = open(directory.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd,&st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0077)) {
        if (fd >= 0) close(fd);
        MLFailure(error,@"接管状态目录必须由当前服务独占，权限为 0700",EPERM);
        return -1;
    }
    return fd;
}
static BOOL MLWrite(NSString *directory, int directoryFD, NSDictionary *journal, NSError **error) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:journal options:0 error:error];
    if (!data || data.length > 32768) return MLFailure(error,@"接管恢复记录超出限制",EFBIG);
    NSString *tmpName = [NSString stringWithFormat:@"capture-%@.new",[[NSProcessInfo processInfo] globallyUniqueString]];
    NSString *tmp = [directory stringByAppendingPathComponent:tmpName];
    int fd = open(tmp.fileSystemRepresentation,O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,0600);
    if (fd < 0) return MLFailure(error,@"无法在修改网络前保存恢复记录",errno);
    size_t offset = 0; BOOL success = YES;
    while (offset < data.length) {
        ssize_t n = write(fd,(const char *)data.bytes + offset,data.length - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { success = NO; break; }
        offset += (size_t)n;
    }
    if (success) success = fsync(fd) == 0;
    int saved = errno;
    if (close(fd)) { success = NO; saved = errno; }
    NSString *path = [directory stringByAppendingPathComponent:@"capture.json"];
    struct stat previous;
    if (success && lstat(path.fileSystemRepresentation,&previous) == 0 &&
        (!S_ISREG(previous.st_mode) || previous.st_uid != geteuid() || previous.st_nlink != 1)) {
        success = NO; saved = EPERM;
    }
    if (success && rename(tmp.fileSystemRepresentation,path.fileSystemRepresentation)) { success = NO; saved = errno; }
    if (success && fsync(directoryFD)) { success = NO; saved = errno; }
    if (!success) { unlink(tmp.fileSystemRepresentation); return MLFailure(error,@"网络恢复记录未能安全落盘",saved); }
    return YES;
}
static NSDictionary *MLRead(NSString *directory, NSError **error, BOOL *missing) {
    *missing = NO;
    NSString *path = [directory stringByAppendingPathComponent:@"capture.json"];
    int fd = open(path.fileSystemRepresentation,O_RDONLY | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT) { *missing = YES; return nil; }
    struct stat st;
    if (fd < 0 || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 ||
        (st.st_mode & 0077) || st.st_size <= 0 || st.st_size > 32768) {
        if (fd >= 0) close(fd);
        MLFailure(error,@"拒绝读取不安全或损坏的网络恢复记录",EPERM); return nil;
    }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)st.st_size];
    size_t offset = 0;
    while (offset < data.length) {
        ssize_t n = read(fd,(char *)data.mutableBytes + offset,data.length - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        offset += n;
    }
    close(fd);
    id journal = offset == data.length ? [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:NULL] : nil;
    unsigned index;
    BOOL valid = [journal isKindOfClass:[NSDictionary class]] && [@[@1,@2] containsObject:journal[@"format"]] &&
        MLName(journal[@"interface"]) && MLUnsigned(journal[@"interfaceIndex"],&index) &&
        [journal[@"nonce"] isKindOfClass:[NSString class]] && [journal[@"nonce"] length] <= 128 &&
        [journal[@"nonce"] length] > 0 && [journal[@"routes"] isKindOfClass:[NSArray class]] && [journal[@"routes"] count] <= ([journal[@"format"] isEqual:@2]?6:4);
    NSMutableSet *seen = [NSMutableSet set];
    if (valid) for (id row in journal[@"routes"]) {
        if(![row isKindOfClass:[NSDictionary class]]){valid=NO;break;}
        BOOL split=[MLDestinations() containsObject:row[@"destination"]] && [row[@"prefix"] isEqual:@1] &&
            [row[@"interface"] isEqual:journal[@"interface"]] && [row[@"interfaceIndex"] isEqual:journal[@"interfaceIndex"]] &&
            [row[@"gatewayIsLink"] isEqual:@YES] && ![row[@"scoped"] boolValue];
        BOOL physical=NO;
        if([journal[@"format"] isEqual:@2])for(NSDictionary *candidate in MLPhysicalDefaults(journal[@"physicalPath"]))
            if(MLSameRoute(row,candidate)){physical=YES;break;}
        NSString *key=[NSString stringWithFormat:@"%@/%@/%@",row[@"destination"],row[@"prefix"],row[@"interfaceIndex"]];
        if((!split && !physical) || ![@[@"pending",@"applied"] containsObject:row[@"state"]] || [seen containsObject:key]){valid=NO;break;}
        [seen addObject:key];
    }
    if (!valid) { MLFailure(error,@"接管恢复记录校验失败；未触碰系统网络",EINVAL); return nil; }
    return journal;
}
static BOOL MLRecoverJournal(NSString *directory, int dirFD, NSDictionary *journal, id<MLCaptureBackend> backend, NSError **error) {
    NSError *first = nil;
    [backend withdrawDNS:journal[@"nonce"] error:&first];
    for (NSDictionary *route in [journal[@"routes"] reverseObjectEnumerator]) {
        unsigned index=[route[@"interfaceIndex"] unsignedIntValue];
        if([backend indexForInterface:route[@"interface"]]!=index)continue;
        NSError *operation = nil;
        NSDictionary *actual = [backend routeForDestination:route[@"destination"] prefix:[route[@"prefix"] unsignedIntValue] interfaceIndex:index error:&operation];
        if (operation) { if (!first) first = operation; continue; }
        if (!MLSameRoute(actual,route)) continue; // another owner replaced it
        if (![backend deleteRoute:route error:&operation] && !first) first = operation;
    }
    if (first) { if (error) *error = first; return NO; }
    NSString *path = [directory stringByAppendingPathComponent:@"capture.json"];
    if (unlink(path.fileSystemRepresentation) && errno != ENOENT) return MLFailure(error,@"网络已恢复，但恢复记录清理失败",errno);
    if (fsync(dirFD)) return MLFailure(error,@"网络恢复记录未能同步",errno);
    return YES;
}
static BOOL MLGuardianCommand(int fd, char command, int passed, NSError **error) {
    char ancillary[64]; struct iovec iov={&command,1};
    struct msghdr message; memset(&message,0,sizeof message); message.msg_iov=&iov; message.msg_iovlen=1;
    if (passed>=0) {
        memset(ancillary,0,sizeof ancillary); message.msg_control=ancillary; message.msg_controllen=CMSG_SPACE(sizeof(int));
        struct cmsghdr *rights=CMSG_FIRSTHDR(&message); rights->cmsg_level=SOL_SOCKET; rights->cmsg_type=SCM_RIGHTS;
        rights->cmsg_len=CMSG_LEN(sizeof(int)); memcpy(CMSG_DATA(rights),&passed,sizeof passed);
    }
    ssize_t sent; do { sent=sendmsg(fd,&message,0); } while(sent<0 && errno==EINTR);
    struct pollfd event={fd,POLLIN,0}; char reply=1;
    if (sent!=1 || poll(&event,1,4000)<=0 || read(fd,&reply,1)!=1 || reply)
        return MLFailure(error,@"独立网络守护进程未能确认操作",EIO);
    return YES;
}
static int MLGuardianConnect(NSString *directory,NSError **error) {
    NSString *path=[directory stringByAppendingPathComponent:@"guardian.sock"];struct stat st;
    if(lstat(path.fileSystemRepresentation,&st) || !S_ISSOCK(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&0077)){
        MLFailure(error,@"独立网络守护通道不可用或权限不安全",EPERM);return -1;
    }
    struct sockaddr_un address;memset(&address,0,sizeof address);address.sun_family=AF_UNIX;
    if([path lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>=sizeof address.sun_path){MLFailure(error,@"网络守护通道路径过长",ENAMETOOLONG);return -1;}
    strlcpy(address.sun_path,path.fileSystemRepresentation,sizeof address.sun_path);
    int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return -1;fcntl(fd,F_SETFD,FD_CLOEXEC);
    if(connect(fd,(struct sockaddr *)&address,sizeof address)){close(fd);return -1;}
    return fd;
}
static BOOL MLGuardianAdopt(NSString *directory,int *control,int *device,int *lease,pid_t *pid,NSError **error) {
    // Core is allowed to finish bounded shutdown before handing its interface
    // to another owner. An alive Supervisor is never replaced by this API.
    for(unsigned attempt=0;attempt<40;attempt++){
        int fd=MLGuardianConnect(directory,error);if(fd<0)return NO;
        char command='A';struct pollfd event={fd,POLLIN,0};uint8_t reply[5]={1};char ancillary[128];
        struct iovec iov={reply,sizeof reply};struct msghdr message;memset(&message,0,sizeof message);
        message.msg_iov=&iov;message.msg_iovlen=1;message.msg_control=ancillary;message.msg_controllen=sizeof ancillary;
        ssize_t n=-1;if(write(fd,&command,1)==1 && poll(&event,1,1000)>0)n=recvmsg(fd,&message,0);
        int received[2]={-1,-1};unsigned count=0;
        for(struct cmsghdr *rights=n>0?CMSG_FIRSTHDR(&message):NULL;rights;rights=CMSG_NXTHDR(&message,rights)){
            if(rights->cmsg_level!=SOL_SOCKET || rights->cmsg_type!=SCM_RIGHTS || rights->cmsg_len<CMSG_LEN(0))continue;
            size_t bytes=rights->cmsg_len-CMSG_LEN(0);
            for(size_t offset=0;offset+sizeof(int)<=bytes;offset+=sizeof(int)){
                int passed;memcpy(&passed,(char *)CMSG_DATA(rights)+offset,sizeof passed);
                if(count<2)received[count++]=passed;else close(passed);
            }
        }
        BOOL valid=n==sizeof reply && !reply[0] && count==2 && !(message.msg_flags&MSG_CTRUNC);
        if(valid){
            int type;socklen_t size=sizeof type;struct stat lock,path;
            NSString *lockPath=[directory stringByAppendingPathComponent:@"capture.lock"];
            valid=!getsockopt(received[0],SOL_SOCKET,SO_TYPE,&type,&size) && type==SOCK_DGRAM &&
                !fstat(received[1],&lock) && !lstat(lockPath.fileSystemRepresentation,&path) && S_ISREG(lock.st_mode) &&
                lock.st_uid==geteuid() && !(lock.st_mode&0077) && lock.st_nlink==1 && lock.st_dev==path.st_dev && lock.st_ino==path.st_ino;
        }
        if(valid){
            uint32_t value;memcpy(&value,reply+1,4);*pid=(pid_t)ntohl(value);
            fcntl(received[0],F_SETFD,FD_CLOEXEC);fcntl(received[1],F_SETFD,FD_CLOEXEC);
            *control=fd;*device=received[0];*lease=received[1];if(error)*error=nil;return YES;
        }
        for(unsigned i=0;i<count;i++)close(received[i]);close(fd);
        if(n==1 && reply[0]){usleep(250000);continue;}
        return MLFailure(error,@"独立网络守护状态接回失败",EPROTO);
    }
    return MLFailure(error,@"旧核心或 Supervisor 仍在运行，未接回系统流量",EBUSY);
}
BOOL MLCaptureEmergencyRecover(NSString *directory, NSError **error) {
    int dir=MLDirectory(directory,error); if(dir<0)return NO; close(dir);
    NSString *path=[directory stringByAppendingPathComponent:@"guardian.sock"]; struct stat st;
    if(lstat(path.fileSystemRepresentation,&st)) return errno==ENOENT?MLCaptureRecover(directory,error):MLFailure(error,@"无法检查网络守护通道",errno);
    if(!S_ISSOCK(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&0077))return MLFailure(error,@"网络守护通道权限不安全",EPERM);
    struct sockaddr_un address; memset(&address,0,sizeof address); address.sun_family=AF_UNIX;
    if(path.length>=sizeof address.sun_path)return MLFailure(error,@"网络守护通道路径过长",ENAMETOOLONG);
    strlcpy(address.sun_path,path.fileSystemRepresentation,sizeof address.sun_path);
    int fd=socket(AF_UNIX,SOCK_STREAM,0); if(fd<0)return MLFailure(error,@"无法打开网络守护通道",errno);
    BOOL connected=connect(fd,(struct sockaddr *)&address,sizeof address)==0;
    BOOL result=connected && MLGuardianCommand(fd,'E',-1,error); int saved=errno; close(fd);
    if(!connected)return saved==ECONNREFUSED?MLCaptureRecover(directory,error):MLFailure(error,@"无法连接网络守护进程",saved);
    return result;
}
int MLCaptureGuardianRun(NSString *directory,int control,int device,int lifetime,int lease,id<MLCaptureBackend> backend) {
    signal(SIGPIPE,SIG_IGN); int dir=MLDirectory(directory,NULL); if(dir<0)return 77;
    BOOL missing; NSDictionary *initial=MLRead(directory,NULL,&missing); if(!initial)return 65;
    NSString *nonce=initial[@"nonce"],*interface=initial[@"interface"];
    NSString *path=[directory stringByAppendingPathComponent:@"guardian.sock"];
    struct sockaddr_un address; memset(&address,0,sizeof address); address.sun_family=AF_UNIX;
    if(path.length>=sizeof address.sun_path)return 65;
    strlcpy(address.sun_path,path.fileSystemRepresentation,sizeof address.sun_path);
    struct stat old; if(!lstat(path.fileSystemRepresentation,&old)) {
        if(!S_ISSOCK(old.st_mode) || old.st_uid!=geteuid() || (old.st_mode&0077))return 77;
        unlink(path.fileSystemRepresentation);
    }
    int listener=socket(AF_UNIX,SOCK_STREAM,0); if(listener<0)return 71;
    mode_t mask=umask(0077); int bound=bind(listener,(struct sockaddr *)&address,sizeof address); umask(mask);
    if(bound || chmod(path.fileSystemRepresentation,0600) || listen(listener,2)) { close(listener); return 71; }
    fcntl(listener,F_SETFD,FD_CLOEXEC); fcntl(device,F_SETFL,fcntl(device,F_GETFL,0)|O_NONBLOCK);
    BOOL parentAlive=YES,coreAlive=YES,strict=[initial[@"strictBlock"] boolValue],finished=NO;
    char acknowledgement=0; if(write(control,&acknowledgement,1)!=1)finished=YES;
    uint64_t retryAt=0; int result=0;
    while(!finished) { @autoreleasepool {
        struct pollfd events[]={{parentAlive?control:-1,POLLIN,0},{coreAlive?lifetime:-1,POLLIN,0},
            {listener,POLLIN,0},{!parentAlive && !coreAlive && strict?device:-1,POLLIN,0}};
        int ready=poll(events,4,250); if(ready<0 && errno==EINTR)continue; if(ready<0){result=71;break;}
        if(events[1].revents) { char byte; ssize_t n=read(lifetime,&byte,1); if(n==0){coreAlive=NO;close(lifetime);lifetime=-1;} }
        if(events[0].revents) {
            char command=0,ancillary[64]; struct iovec iov={&command,1};
            struct msghdr message; memset(&message,0,sizeof message); message.msg_iov=&iov;message.msg_iovlen=1;
            message.msg_control=ancillary;message.msg_controllen=sizeof ancillary;
            ssize_t n=recvmsg(control,&message,0);
            if(n==0 || (n<0 && errno!=EINTR && errno!=EAGAIN)){parentAlive=NO;close(control);control=-1;}
            else if(n==1){
                int passed=-1; for(struct cmsghdr *rights=CMSG_FIRSTHDR(&message);rights;rights=CMSG_NXTHDR(&message,rights))
                    if(rights->cmsg_level==SOL_SOCKET && rights->cmsg_type==SCM_RIGHTS && rights->cmsg_len==CMSG_LEN(sizeof(int)))memcpy(&passed,CMSG_DATA(rights),sizeof passed);
                BOOL accepted=YES;
                if(command=='S')strict=YES;
                else if(command=='R')strict=NO;
                else if(command=='N' && passed>=0){if(lifetime>=0)close(lifetime);lifetime=passed;passed=-1;coreAlive=YES;}
                else if(command=='Q'){BOOL absent;MLRead(directory,NULL,&absent);accepted=absent;if(accepted)finished=YES;}
                else if(command!='H')accepted=NO;
                if(passed>=0)close(passed);char reply=accepted?0:1;write(control,&reply,1);
            }
        }
        if(events[2].revents&POLLIN) {
            int client=accept(listener,NULL,NULL);
            if(client>=0){struct pollfd event={client,POLLIN,0};char command=0,reply=1;
                if(poll(&event,1,1000)>0 && read(client,&command,1)==1){
                    if(command=='E' && !parentAlive){
                        NSDictionary *journal=MLRead(directory,NULL,&missing);
                        if(missing || (journal && [journal[@"nonce"] isEqual:nonce] && MLRecoverJournal(directory,dir,journal,backend,NULL))){reply=0;finished=YES;}
                    }else if(command=='A' && !parentAlive && !coreAlive){
                        uint8_t payload[5]={0};uint32_t pid=htonl((uint32_t)getpid());memcpy(payload+1,&pid,4);
                        struct iovec iov={payload,sizeof payload};char ancillary[64];struct msghdr message;memset(&message,0,sizeof message);
                        memset(ancillary,0,sizeof ancillary);message.msg_iov=&iov;message.msg_iovlen=1;message.msg_control=ancillary;message.msg_controllen=CMSG_SPACE(sizeof(int)*2);
                        struct cmsghdr *rights=CMSG_FIRSTHDR(&message);rights->cmsg_level=SOL_SOCKET;rights->cmsg_type=SCM_RIGHTS;rights->cmsg_len=CMSG_LEN(sizeof(int)*2);
                        int descriptors[]={device,lease};memcpy(CMSG_DATA(rights),descriptors,sizeof descriptors);
                        if(sendmsg(client,&message,0)==sizeof payload){control=client;parentAlive=YES;client=-1;}
                    }
                }
                if(client>=0){write(client,&reply,1);close(client);}
            }
        }
        if(!parentAlive && !finished){
            NSDictionary *journal=MLRead(directory,NULL,&missing);
            if(missing){finished=YES;continue;}
            if(!journal || ![journal[@"nonce"] isEqual:nonce]){result=65;strict=YES;}
            else if(!strict || ![@[@"active",@"blocking"] containsObject:journal[@"state"]]){
                if(MLRecoverJournal(directory,dir,journal,backend,NULL))finished=YES;
            }else if(!coreAlive && (uint64_t)time(NULL)>=retryAt){
                // configd automatically withdrew the dead Supervisor's DNS.
                // Re-publish it only after removing records with our nonce.
                [backend withdrawDNS:nonce error:NULL]; [backend publishDNS:interface nonce:nonce error:NULL];retryAt=(uint64_t)time(NULL)+5;
            }
        }
        if(events[3].revents&POLLIN){uint8_t discard[2048];for(unsigned i=0;i<64;i++)if(read(device,discard,sizeof discard)<=0)break;}
    }}
    close(listener);unlink(path.fileSystemRepresentation);close(device);if(control>=0)close(control);if(lifetime>=0)close(lifetime);close(lease);close(dir);return result;
}
BOOL MLCaptureRecoverWithBackend(NSString *directory, id<MLCaptureBackend> backend, NSError **error) {
    int dirFD = MLDirectory(directory,error); if (dirFD < 0) return NO;
    NSString *lock = [directory stringByAppendingPathComponent:@"capture.lock"];
    int lockFD = open(lock.fileSystemRepresentation,O_RDWR|O_CREAT|O_NOFOLLOW,0600);
    struct stat st;
    if (lockFD < 0 || fstat(lockFD,&st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 ||
        flock(lockFD,LOCK_EX|LOCK_NB)) {
        if (lockFD >= 0) close(lockFD); close(dirFD);
        return MLFailure(error,@"接管事务正在运行或锁文件不安全",EBUSY);
    }
    BOOL missing; NSDictionary *journal = MLRead(directory,error,&missing);
    BOOL result = missing || (journal && MLRecoverJournal(directory,dirFD,journal,backend,error));
    close(lockFD); close(dirFD); return result;
}
BOOL MLCaptureRecover(NSString *directory, NSError **error) {
    return MLCaptureRecoverWithBackend(directory,MLCaptureSystemBackend(),error);
}

@implementation MLCaptureCoordinator {
    NSString *_directory;
    id<MLCaptureBackend> _backend;
    NSMutableDictionary *_journal;
    int _dirFD, _lockFD, _fileDescriptor, _guardianFD, _coreLifetimeDescriptor;
    pid_t _guardianPID;
    BOOL _resumedGuardian;
    BOOL _reuseRoutes;
    unsigned _interfaceIndex, _outboundInterfaceIndex;
    NSString *_interfaceName, *_state, *_problem;
    NSDictionary *_lastPathCheck;
}
@synthesize fileDescriptor = _fileDescriptor, interfaceIndex = _interfaceIndex;
@synthesize outboundInterfaceIndex = _outboundInterfaceIndex, interfaceName = _interfaceName;
@synthesize coreLifetimeDescriptor = _coreLifetimeDescriptor;
@synthesize resumedGuardian = _resumedGuardian;
- (id)initWithStateDirectory:(NSString *)directory error:(NSError **)error {
    return [self initWithStateDirectory:directory backend:MLCaptureSystemBackend() error:error];
}
- (id)initWithStateDirectory:(NSString *)directory backend:(id<MLCaptureBackend>)backend error:(NSError **)error {
    if ((self = [super init])) {
        _dirFD = _lockFD = _fileDescriptor = _guardianFD = _coreLifetimeDescriptor = -1; _state = @"STOPPED";
        _directory = [directory copy]; _backend = backend;
        NSError *recovery=nil;
        if (!MLCaptureRecoverWithBackend(directory,backend,&recovery)) {
            if(recovery.code!=EBUSY || !MLGuardianAdopt(directory,&_guardianFD,&_fileDescriptor,&_lockFD,&_guardianPID,error)){
                if(error && !*error)*error=recovery;return nil;
            }
            _dirFD=MLDirectory(directory,error);if(_dirFD<0)return nil;
            BOOL missing;NSDictionary *existing=MLRead(directory,error,&missing);
            unsigned index;
            if(!existing || !MLUnsigned(existing[@"interfaceIndex"],&index) || [_backend indexForInterface:existing[@"interface"]]!=index){MLFailure(error,@"守护接口与恢复记录的身份不一致",ESTALE);return nil;}
            _journal=[existing mutableCopy];NSMutableArray *rows=[NSMutableArray array];for(NSDictionary *route in existing[@"routes"])[rows addObject:[route mutableCopy]];_journal[@"routes"]=rows;
            _interfaceIndex=index;_interfaceName=[existing[@"interface"] copy];_outboundInterfaceIndex=[existing[@"outboundInterfaceIndex"] unsignedIntValue];
            _resumedGuardian=YES;_state=@"PREPARED";if(error)*error=nil;return self;
        }
        _dirFD = MLDirectory(directory,error); if (_dirFD < 0) return nil;
        NSString *lock = [directory stringByAppendingPathComponent:@"capture.lock"];
        _lockFD = open(lock.fileSystemRepresentation,O_RDWR|O_CREAT|O_NOFOLLOW,0600);
        if (_lockFD < 0 || flock(_lockFD,LOCK_EX|LOCK_NB)) { MLFailure(error,@"另一个接管协调器正在运行",EBUSY); return nil; }
        fcntl(_lockFD,F_SETFD,FD_CLOEXEC);
    }
    return self;
}
- (void)dealloc {
    [self restore:NULL];
    if (_guardianFD >= 0) close(_guardianFD);
    if (_coreLifetimeDescriptor >= 0) close(_coreLifetimeDescriptor);
    if (_resumedGuardian && _fileDescriptor >= 0) close(_fileDescriptor);
    if (_lockFD >= 0) close(_lockFD);
    if (_dirFD >= 0) close(_dirFD);
}
- (BOOL)startGuardianWithExecutable:(NSString *)executable strictBlock:(BOOL)strict error:(NSError **)error {
    @synchronized(self) {
        if(_guardianFD>=0 && [_state isEqual:@"PREPARED"]){
            if(_coreLifetimeDescriptor<0 && ![self prepareCoreLifetime:error])return NO;
            return [self setStrictBlock:strict error:error];
        }
        if(!_journal || ![_state isEqual:@"PREPARED"] || _guardianFD>=0)return MLFailure(error,@"守护进程只能在准备好的接管事务中启动",EINVAL);
        struct stat st;
        if(lstat(executable.fileSystemRepresentation,&st) || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&0022) || !(st.st_mode&0111))
            return MLFailure(error,@"网络守护程序必须是服务所有者提供的安全可执行文件",EPERM);
        _journal[@"strictBlock"]=@(strict);if(!MLWrite(_directory,_dirFD,_journal,error))return NO;
        int channel[2]={-1,-1},life[2]={-1,-1};
        if(socketpair(AF_UNIX,SOCK_STREAM,0,channel) || pipe(life)) {
            if(channel[0]>=0)close(channel[0]);if(channel[1]>=0)close(channel[1]);return MLFailure(error,@"无法创建网络守护通道",errno);
        }
        for(unsigned i=0;i<2;i++){fcntl(channel[i],F_SETFD,FD_CLOEXEC);fcntl(life[i],F_SETFD,FD_CLOEXEC);}
        int original[]={channel[1],_fileDescriptor,life[0],_lockFD},copies[4]={-1,-1,-1,-1};
        posix_spawn_file_actions_t actions;posix_spawn_file_actions_init(&actions);int code=0;
        for(unsigned i=0;i<4;i++) {
            copies[i]=fcntl(original[i],F_DUPFD,16);
            if(copies[i]<0){code=errno;break;}
            fcntl(copies[i],F_SETFD,FD_CLOEXEC);
            posix_spawn_file_actions_adddup2(&actions,copies[i],3+i);posix_spawn_file_actions_addclose(&actions,copies[i]);
        }
        const char *arguments[]={executable.fileSystemRepresentation,"--guardian",_directory.fileSystemRepresentation,NULL};
        if(!code)code=posix_spawn(&_guardianPID,executable.fileSystemRepresentation,&actions,NULL,(char *const *)arguments,environ);
        posix_spawn_file_actions_destroy(&actions);for(unsigned i=0;i<4;i++)if(copies[i]>=0)close(copies[i]);
        close(channel[1]);close(life[0]);
        if(code){close(channel[0]);close(life[1]);_guardianPID=0;return MLFailure(error,@"独立网络守护进程未能启动",code);}
        struct pollfd event={channel[0],POLLIN,0};char reply=1;
        if(poll(&event,1,4000)<=0 || read(channel[0],&reply,1)!=1 || reply){
            close(channel[0]);close(life[1]);kill(_guardianPID,SIGTERM);waitpid(_guardianPID,NULL,0);_guardianPID=0;
            return MLFailure(error,@"独立网络守护进程未能准备好",EIO);
        }
        _guardianFD=channel[0];_coreLifetimeDescriptor=life[1];return YES;
    }
}
- (void)coreDidStart { @synchronized(self) { if(_coreLifetimeDescriptor>=0){close(_coreLifetimeDescriptor);_coreLifetimeDescriptor=-1;} } }
- (BOOL)prepareCoreLifetime:(NSError **)error {
    @synchronized(self) {
        if(_guardianFD<0 || _coreLifetimeDescriptor>=0)return MLFailure(error,@"守护进程尚未准备或上一个核心生存通道仍由 Supervisor 持有",EINVAL);
        int life[2];if(pipe(life))return MLFailure(error,@"无法创建核心生存通道",errno);
        fcntl(life[0],F_SETFD,FD_CLOEXEC);fcntl(life[1],F_SETFD,FD_CLOEXEC);
        BOOL result=MLGuardianCommand(_guardianFD,'N',life[0],error);close(life[0]);
        if(result)_coreLifetimeDescriptor=life[1];else close(life[1]);return result;
    }
}
- (BOOL)setStrictBlock:(BOOL)strict error:(NSError **)error {
    @synchronized(self) {
        if(!_journal || _guardianFD<0)return MLFailure(error,@"独立网络守护进程尚未可用",ENOTSUP);
        // Guardian confirmation precedes changing the persisted policy.
        if(!MLGuardianCommand(_guardianFD,strict?'S':'R',-1,error))return NO;
        _journal[@"strictBlock"]=@(strict);return MLWrite(_directory,_dirFD,_journal,error);
    }
}
- (BOOL)checkPhysicalPathChanged:(BOOL *)changed error:(NSError **)error {
    @synchronized(self) {
        if(changed)*changed=NO;if(!_journal)return YES;
        NSError *operation=nil;
        NSDictionary *expected=_journal[@"physicalSignature"] ?: @{}, *current=nil;
        if(![_backend respondsToSelector:@selector(physicalSignature:)])
            MLFailure(&operation,@"接管后端未提供物理网络状态检查",ENOTSUP);
        else current=[_backend physicalSignature:&operation];
        BOOL different=!current || ![expected isEqual:current];
        NSMutableArray *fields=[NSMutableArray array];
        if(current){
            NSMutableSet *keys=[NSMutableSet setWithArray:expected.allKeys];[keys addObjectsFromArray:current.allKeys];
            for(NSString *key in [[keys allObjects] sortedArrayUsingSelector:@selector(compare:)]){
                id old=expected[key],new=current[key];if([old isEqual:new])continue;
                if([old isKindOfClass:[NSDictionary class]] && [new isKindOfClass:[NSDictionary class]]){
                    NSMutableSet *children=[NSMutableSet setWithArray:[old allKeys]];[children addObjectsFromArray:[new allKeys]];
                    for(NSString *child in [[children allObjects]sortedArrayUsingSelector:@selector(compare:)])
                        if(![old[child] isEqual:new[child]])[fields addObject:[NSString stringWithFormat:@"%@.%@",key,child]];
                }else [fields addObject:key];
            }
        }
        _lastPathCheck=@{@"checkedAt":@([[NSDate date]timeIntervalSince1970]),@"ok":@(current!=nil),@"changed":@(different),
            @"expectedSignature":expected,@"observedSignature":current ?: @{},@"changedFields":fields,
            @"physicalPath":_journal[@"physicalPath"] ?: @{},
            @"error":operation ? @{@"domain":operation.domain,@"code":@(operation.code),@"message":operation.localizedDescription} : @{}};
        if(changed)*changed=different;
        if(!current){if(error)*error=operation ?: [NSError errorWithDomain:@"E_CAPTURE" code:EIO userInfo:@{NSLocalizedDescriptionKey:@"物理网络检查未返回状态"}];return NO;}
        return YES;
    }
}
- (BOOL)prepare:(NSError **)error {
    @synchronized(self) {
        if(_fileDescriptor>=0 && ([_state isEqual:@"BLOCKING"] || (_resumedGuardian && [_state isEqual:@"PREPARED"]))){
            NSDictionary *path=[_backend physicalPath:error];unsigned outgoing;
            if(!path || !MLUnsigned(path[@"interfaceIndex"],&outgoing) || outgoing==_interfaceIndex)return NO;
            // Keep the old undo information valid until each obsolete exit
            // has been removed. The public split routes remain blocking.
            NSArray *defaults=MLPhysicalDefaults(path);
            NSMutableArray *routes=_journal[@"routes"];
            for(NSDictionary *route in [routes copy]){
                if(![route[@"scoped"] boolValue])continue;
                BOOL keep=NO;for(NSDictionary *candidate in defaults)if(MLSameRoute(route,candidate)){keep=YES;break;}
                if(keep)continue;
                unsigned index=[route[@"interfaceIndex"] unsignedIntValue];
                if([_backend indexForInterface:route[@"interface"]]==index){
                    NSError *operation=nil;
                    NSDictionary *actual=[_backend routeForDestination:route[@"destination"] prefix:0 interfaceIndex:index error:&operation];
                    if(operation){if(error)*error=operation;return NO;}
                    if(MLSameRoute(actual,route) && ![_backend deleteRoute:route error:error])return NO;
                }
                [routes removeObjectIdenticalTo:route];
                if(!MLWrite(_directory,_dirFD,_journal,error))return NO;
            }
            if([_backend respondsToSelector:@selector(physicalSignature:)]){
                NSDictionary *signature=[_backend physicalSignature:error];if(!signature)return NO;_journal[@"physicalSignature"]=signature;
            }
            _outboundInterfaceIndex=outgoing;_journal[@"physicalPath"]=path;_journal[@"outboundInterfaceIndex"]=@(outgoing);
            if(!MLWrite(_directory,_dirFD,_journal,error))return NO;
            _reuseRoutes=YES;_state=@"PREPARED";return YES;
        }
        if (_fileDescriptor >= 0) return MLFailure(error,@"接管设备已经准备",EALREADY);
        NSDictionary *path = [_backend physicalPath:error]; if (!path) return NO;
        unsigned outgoing;
        if (!MLUnsigned(path[@"interfaceIndex"],&outgoing)) return MLFailure(error,@"未能确定物理网络出口",ENXIO);
        NSDictionary *device = [_backend openDevice:error]; if (!device) return NO;
        unsigned index;
        if (!MLName(device[@"interface"]) || !MLUnsigned(device[@"interfaceIndex"],&index) ||
            ![device[@"fd"] isKindOfClass:[NSNumber class]] || [device[@"fd"] intValue] < 0 || index == outgoing) {
            [_backend closeDevice:NULL]; return MLFailure(error,@"内核返回的 utun 设备信息不合法",EPROTO);
        }
        _fileDescriptor = [device[@"fd"] intValue]; _interfaceIndex = index; _outboundInterfaceIndex = outgoing;
        _interfaceName = [device[@"interface"] copy];
        _journal = [@{@"format":@2,@"nonce":[[NSProcessInfo processInfo] globallyUniqueString],
            @"interface":_interfaceName,@"interfaceIndex":@(index),@"outboundInterfaceIndex":@(outgoing),
            @"physicalPath":path,@"routes":[NSMutableArray array],@"state":@"prepared"} mutableCopy];
        if([_backend respondsToSelector:@selector(physicalSignature:)]){
            NSDictionary *signature=[_backend physicalSignature:error];if(!signature){[_backend closeDevice:NULL];_fileDescriptor=-1;_journal=nil;return NO;}_journal[@"physicalSignature"]=signature;
        }
        if (!MLWrite(_directory,_dirFD,_journal,error)) { [_backend closeDevice:NULL]; _fileDescriptor = -1; _journal = nil; return NO; }
        _state = @"PREPARED"; return YES;
    }
}
- (BOOL)activateWithCoreReady:(NSDictionary *)ready error:(NSError **)error {
    @synchronized(self) {
        if (!_journal || ![_state isEqual:@"PREPARED"] || ![ready[@"ready"] isEqual:@YES] ||
            ![ready[@"tcp"] isEqual:@YES] || ![ready[@"udp"] isEqual:@YES] || ![ready[@"ipv6"] isEqual:@YES] || ![ready[@"dns"] isEqual:@YES])
            return MLFailure(error,@"完整数据通路尚未就绪；没有安装任何流量路由",ENOTSUP);
        NSMutableArray *routes = _journal[@"routes"];
        // XNU 2050 needs a scoped default for IP_BOUND_IF sockets once the
        // unscoped longest-prefix route points at utun. Journal these first
        // so reverse-order recovery removes public capture before the exits.
        NSMutableArray *desired=[MLPhysicalDefaults(_journal[@"physicalPath"]) mutableCopy];
        for (NSString *destination in MLDestinations()) {
            [desired addObject:@{@"destination":destination,@"prefix":@1,@"interface":_interfaceName,
                @"interfaceIndex":@(_interfaceIndex),@"gatewayIsLink":@YES}];
        }
        _journal[@"format"]=@2;
        for(NSDictionary *candidate in desired){
            NSString *destination=candidate[@"destination"];
            unsigned prefix=[candidate[@"prefix"] unsignedIntValue],index=[candidate[@"interfaceIndex"] unsignedIntValue];
            BOOL scoped=[candidate[@"scoped"] boolValue];
            NSError *operation = nil;
            NSDictionary *owned=nil;
            if(_reuseRoutes)for(NSDictionary *row in routes)
                if([row[@"destination"] isEqual:destination] && [row[@"prefix"] isEqual:candidate[@"prefix"]] &&
                    [row[@"interfaceIndex"] isEqual:candidate[@"interfaceIndex"]]){owned=row;break;}
            if(_reuseRoutes && (owned || !scoped)){
                if(!owned || !MLSameRoute([_backend routeForDestination:destination prefix:prefix interfaceIndex:index error:&operation],candidate)){
                    if(error)*error=operation ?: [NSError errorWithDomain:@"E_CAPTURE" code:ESTALE userInfo:@{NSLocalizedDescriptionKey:@"守护期间系统路由发生变化，不能恢复接管"}];
                    return NO;
                }
                continue;
            }
            NSDictionary *actual = [_backend routeForDestination:destination prefix:prefix interfaceIndex:scoped?index:0 error:&operation];
            // An existing matching scoped default belongs to the system. It
            // can be reused but must never enter our deletion journal.
            if(!operation && scoped && MLSameRoute(actual,candidate))continue;
            if (operation || actual) {
                if (error) *error = operation ?: [NSError errorWithDomain:@"E_CAPTURE_CONFLICT" code:EEXIST userInfo:@{NSLocalizedDescriptionKey:@"已有相同范围的系统路由，拒绝覆盖"}];
                [self restore:NULL]; return NO;
            }
            NSMutableDictionary *route = [candidate mutableCopy];route[@"state"]=@"pending";
            NSUInteger position=routes.count;
            if(scoped){position=0;while(position<routes.count && [routes[position][@"scoped"] boolValue])position++;}
            [routes insertObject:route atIndex:position];
            if (!MLWrite(_directory,_dirFD,_journal,error) || ![_backend addRoute:route error:error]) { [self restore:NULL]; return NO; }
            route[@"state"] = @"applied";
            if (!MLWrite(_directory,_dirFD,_journal,error)) { [self restore:NULL]; return NO; }
            actual = [_backend routeForDestination:destination prefix:prefix interfaceIndex:index error:error];
            if (!MLSameRoute(actual,route)) { MLFailure(error,@"路由安装后与内核返回不一致，已请求恢复",EIO); [self restore:NULL]; return NO; }
        }
        if(_reuseRoutes && ![_backend withdrawDNS:_journal[@"nonce"] error:error])return NO;
        if (![_backend publishDNS:_interfaceName nonce:_journal[@"nonce"] error:error]) { [self restore:NULL]; return NO; }
        _journal[@"state"] = @"active";
        if (!MLWrite(_directory,_dirFD,_journal,error)) { [self restore:NULL]; return NO; }
        _state = @"ACTIVE"; _problem = nil; return YES;
    }
}
- (BOOL)coreFailedWithStrictBlock:(BOOL)strict error:(NSError **)error {
    @synchronized(self) {
        if (strict && ([_state isEqual:@"ACTIVE"] || [_state isEqual:@"BLOCKING"] || (_reuseRoutes && [_state isEqual:@"PREPARED"]))) {
            if(_guardianFD<0 || !_guardianPID || kill(_guardianPID,0))return MLFailure(error,@"严格阻断需要运行中的独立网络守护进程",ENOTSUP);
            if(![self setStrictBlock:YES error:error])return NO;
            _state = @"BLOCKING"; _problem = @"核心已停止；保留 utun 和已验证路由以阻断外泄";
            _journal[@"state"] = @"blocking";
            return MLWrite(_directory,_dirFD,_journal,error);
        }
        return [self restore:error];
    }
}
- (BOOL)restore:(NSError **)error {
    @synchronized(self) {
        BOOL result = !_journal || MLRecoverJournal(_directory,_dirFD,_journal,_backend,error);
        if (!result) { _state = @"RECOVERY_FAILED"; _problem = error && *error ? (*error).localizedDescription : @"网络恢复仍有未完成操作"; return NO; }
        if(_guardianFD>=0) {
            // Restoration is already durable. If the Guardian died or its
            // channel failed, closing our channel lets a live orphan observe
            // the missing journal; a lost acknowledgement cannot strand us.
            MLGuardianCommand(_guardianFD,'Q',-1,NULL);
            close(_guardianFD);_guardianFD=-1;
            if(_coreLifetimeDescriptor>=0){close(_coreLifetimeDescriptor);_coreLifetimeDescriptor=-1;}
            if(_guardianPID>0){waitpid(_guardianPID,NULL,0);_guardianPID=0;}
        }
        if (![_backend closeDevice:error]) { _state = @"RECOVERY_FAILED"; return NO; }
        if(_resumedGuardian && _fileDescriptor>=0)close(_fileDescriptor);
        _fileDescriptor = -1; _interfaceIndex = _outboundInterfaceIndex = 0; _interfaceName = nil; _journal = nil;
        _resumedGuardian=NO;
        _reuseRoutes=NO;
        _state = @"STOPPED"; _problem = nil; return YES;
    }
}
- (NSDictionary *)status {
    @synchronized(self) {
        BOOL active = [_state isEqual:@"ACTIVE"], blocking = [_state isEqual:@"BLOCKING"];
        NSString *coverage = active ? @"已接管" : (blocking ? @"已阻断" : @"未接管");
        return @{@"backend":@"utun",@"state":_state ?: @"STOPPED",@"interface":_interfaceName ?: @"",
            @"scope":@"public-default-routes",@"bypass":@[@"loopback",@"more-specific-system-routes",@"LAN",@"link-local"],
            @"interfaceIndex":@(_interfaceIndex),@"outboundInterfaceIndex":@(_outboundInterfaceIndex),
            @"physicalPath":_journal[@"physicalPath"] ?: @{},@"message":_problem ?: @"",@"verified":@NO,
            @"physicalSignature":_journal[@"physicalSignature"] ?: @{},@"lastPathCheck":_lastPathCheck ?: @{},
            @"strictBlockAvailable":@(_guardianFD>=0 && _guardianPID>0 && kill(_guardianPID,0)==0),@"guardianPID":@(_guardianPID),
            @"resumedGuardian":@(_resumedGuardian),
            @"coverage":@{@"tcp":coverage,@"udp":coverage,@"ipv4":coverage,@"ipv6":coverage,@"dns":coverage}};
    }
}
@end
