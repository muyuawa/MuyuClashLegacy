#import "MLCaptureInternal.h"
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include <TargetConditionals.h>
extern char **environ;
static volatile sig_atomic_t ended;
static volatile sig_atomic_t restarting;
static void end(int s){(void)s;ended=1;}
static void restart(int s){(void)s;restarting=1;}
@interface Kernel : NSObject <MLCaptureBackend>
@property(nonatomic,strong) NSMutableDictionary *routes;
@property(nonatomic,copy) NSString *directory;
@property(nonatomic) int fd;
@property(nonatomic,strong) id<MLCaptureBackend> system;
@end
@implementation Kernel
- (id)init {if((self=[super init])){_routes=[NSMutableDictionary dictionary];_fd=-1;}return self;}
- (void)record:(NSString *)text {NSString *p=[self.directory stringByAppendingPathComponent:@"events"];int fd=open(p.fileSystemRepresentation,O_WRONLY|O_APPEND|O_CREAT,0600);write(fd,text.UTF8String,strlen(text.UTF8String));write(fd,"\n",1);close(fd);}
- (NSDictionary *)openDevice:(NSError **)error{
#if TARGET_OS_IPHONE
    self.system=MLCaptureSystemBackend();return [self.system openDevice:error];
#else
    (void)error;self.fd=fcntl(0,F_DUPFD,10);fcntl(self.fd,F_SETFD,FD_CLOEXEC);return @{ @"fd":@(self.fd),@"interface":@"utun11",@"interfaceIndex":@12};
#endif
}
- (BOOL)closeDevice:(NSError **)error{
#if TARGET_OS_IPHONE
    return self.system?[self.system closeDevice:error]:YES;
#else
    (void)error;if(self.fd>=0){close(self.fd);self.fd=-1;}return YES;
#endif
}
- (NSDictionary *)physicalPath:(NSError **)error{
#if TARGET_OS_IPHONE
    return [MLCaptureSystemBackend() physicalPath:error];
#else
    (void)error;return @{@"interface":@"en0",@"interfaceIndex":@5};
#endif
}
- (unsigned)indexForInterface:(NSString *)name{
#if TARGET_OS_IPHONE
    return if_nametoindex(name.UTF8String);
#else
    return [name isEqual:@"utun11"]?12:5;
#endif
}
- (NSDictionary *)routeForDestination:(NSString *)dest prefix:(unsigned)p interfaceIndex:(unsigned)i error:(NSError **)e{(void)p;(void)i;(void)e;return self.routes[dest];}
- (BOOL)addRoute:(NSDictionary *)route error:(NSError **)e{(void)e;[self record:[@"add " stringByAppendingString:route[@"destination"]]];self.routes[route[@"destination"]]=[route copy];return YES;}
- (BOOL)deleteRoute:(NSDictionary *)route error:(NSError **)e{(void)e;[self record:[@"delete " stringByAppendingString:route[@"destination"]]];[self.routes removeObjectForKey:route[@"destination"]];return YES;}
- (BOOL)publishDNS:(NSString *)i nonce:(NSString *)n error:(NSError **)e{(void)i;(void)n;(void)e;[self record:@"publish"];return YES;}
- (BOOL)withdrawDNS:(NSString *)n error:(NSError **)e{(void)n;(void)e;[self record:@"withdraw"];return YES;}
@end
static BOOL startChild(MLCaptureCoordinator *c,pid_t *child){
    posix_spawn_file_actions_t actions;posix_spawn_file_actions_init(&actions);posix_spawn_file_actions_adddup2(&actions,c.coreLifetimeDescriptor,4);
    const char *args[]={"/bin/sleep","30",NULL};int code=posix_spawn(child,"/bin/sleep",&actions,NULL,(char *const *)args,environ);
    posix_spawn_file_actions_destroy(&actions);[c coreDidStart];return code==0;
}
int main(int argc,const char **argv){@autoreleasepool{
    if(argc==3 && !strcmp(argv[1],"--guardian")){
        Kernel *k=[Kernel new];k.directory=[NSString stringWithUTF8String:argv[2]];
        NSDictionary *j=[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:[k.directory stringByAppendingPathComponent:@"capture.json"]] options:0 error:NULL];
        for(NSDictionary *r in j[@"routes"])k.routes[r[@"destination"]]=r;
        // Spawn happens before activation: recovery test observes its durable
        // journal rather than this process's earlier in-memory fake kernel.
        for(NSString *d in @[@"0.0.0.0",@"128.0.0.0",@"::",@"8000::"])k.routes[d]=@{@"destination":d,@"prefix":@1,@"interface":j[@"interface"],@"interfaceIndex":j[@"interfaceIndex"],@"gatewayIsLink":@YES};
        for(int fd=7;fd<getdtablesize();fd++)close(fd);
        return MLCaptureGuardianRun(k.directory,3,4,5,6,k);
    }
    if(argc!=3)return 64;
    signal(SIGPIPE,SIG_IGN);signal(SIGTERM,end);signal(SIGUSR1,restart);
    NSString *directory=[NSString stringWithUTF8String:argv[1]];Kernel *k=[Kernel new];k.directory=directory;
    NSData *priorBytes=[NSData dataWithContentsOfFile:[directory stringByAppendingPathComponent:@"capture.json"]];
    NSDictionary *prior=priorBytes?[NSJSONSerialization JSONObjectWithData:priorBytes options:0 error:NULL]:nil;
    for(NSDictionary *row in prior[@"routes"])k.routes[row[@"destination"]]=row;
    NSError *e=nil;MLCaptureCoordinator *c=[[MLCaptureCoordinator alloc]initWithStateDirectory:directory backend:k error:&e];
    BOOL strict=atoi(argv[2])!=0;
    if(!c || ![c prepare:&e] || ![c startGuardianWithExecutable:[NSString stringWithUTF8String:argv[0]] strictBlock:strict error:&e]){fprintf(stderr,"%s\n",e.localizedDescription.UTF8String);return 1;}
    pid_t child;if(!startChild(c,&child))return 1;
    if(![c activateWithCoreReady:@{@"ready":@YES,@"tcp":@YES,@"udp":@YES,@"ipv6":@YES,@"dns":@YES} error:&e])return 1;
    printf("%d %d\n",child,[c.status[@"guardianPID"] intValue]);fflush(stdout);
    while(!ended){
        if(restarting){
            restarting=0;kill(child,SIGTERM);waitpid(child,NULL,0);
            if(![c coreFailedWithStrictBlock:YES error:&e] || ![c prepare:&e])return 1;
            // A failed replacement must keep the old redirect routes blocked.
            if(![c coreFailedWithStrictBlock:YES error:&e] || ![c.status[@"state"] isEqual:@"BLOCKING"] || k.routes.count!=4)return 1;
            if(![c prepare:&e] || ![c prepareCoreLifetime:&e] || !startChild(c,&child) ||
                ![c activateWithCoreReady:@{@"ready":@YES,@"tcp":@YES,@"udp":@YES,@"ipv6":@YES,@"dns":@YES} error:&e])return 1;
            printf("%d %d\n",child,[c.status[@"guardianPID"] intValue]);fflush(stdout);
        }
        usleep(10000);
    }
    BOOL restored=[c restore:&e];kill(child,SIGTERM);return restored?0:1;
}}
