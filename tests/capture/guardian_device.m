// Root lifecycle preflight. Uses real utun descriptors and real Guardian code,
// but all redirect-route and DNS backend mutations are test-only file records.
#define main MLCaptureLifecycleFixtureMain
#include "guardian_harness.m"
#undef main
#include <sys/stat.h>
#include <sys/wait.h>
#include <poll.h>
static BOOL MLWaitGone(NSString *name,unsigned index){for(unsigned i=0;i<100;i++){if(if_nametoindex(name.UTF8String)!=index)return YES;usleep(25000);}return NO;}
static BOOL MLWaitAbsent(NSString *path){for(unsigned i=0;i<100;i++){if(access(path.fileSystemRepresentation,F_OK)){return errno==ENOENT;}usleep(25000);}return NO;}
static BOOL MLFixture(const char *executable,NSString *directory,BOOL strict,pid_t *supervisor,pid_t *core,pid_t *guardian){
    int channel[2];if(pipe(channel))return NO;fcntl(channel[0],F_SETFD,FD_CLOEXEC);fcntl(channel[1],F_SETFD,FD_CLOEXEC);
    posix_spawn_file_actions_t actions;posix_spawn_file_actions_init(&actions);posix_spawn_file_actions_adddup2(&actions,channel[1],1);
    const char *args[]={executable,directory.fileSystemRepresentation,strict?"1":"0",NULL};
    int code=posix_spawn(supervisor,executable,&actions,NULL,(char *const *)args,environ);posix_spawn_file_actions_destroy(&actions);close(channel[1]);
    if(code){close(channel[0]);return NO;}
    char line[96]={0};size_t count=0;
    for(unsigned i=0;i<100 && count<sizeof line-1;i++){
        struct pollfd event={channel[0],POLLIN,0};if(poll(&event,1,100)>0){ssize_t n=read(channel[0],line+count,1);if(n!=1)break;if(line[count++]=='\n')break;}
    }
    close(channel[0]);int a=0,b=0;if(sscanf(line,"%d %d",&a,&b)!=2 || a<=0 || b<=0)return NO;*core=a;*guardian=b;return YES;
}
static BOOL MLStage(const char *executable,NSString *directory,unsigned mode,NSMutableDictionary *report){
    pid_t supervisor=0,core=0,guardian=0,resumed=0,newCore=0,newGuardian=0;BOOL success=NO;
    if(!MLFixture(executable,directory,mode!=1,&supervisor,&core,&guardian))goto done;
    {
        NSString *journal=[directory stringByAppendingPathComponent:@"capture.json"],*channel=[directory stringByAppendingPathComponent:@"guardian.sock"];
        NSData *bytes=[NSData dataWithContentsOfFile:journal];NSDictionary *j=bytes?[NSJSONSerialization JSONObjectWithData:bytes options:0 error:NULL]:nil;
        NSString *name=j[@"interface"];unsigned index=[j[@"interfaceIndex"] unsignedIntValue];
        if(!name || !index)goto done;
        report[@"interface"]=name;report[@"interfaceIndex"]=@(index);
        if(mode==0){
            kill(supervisor,SIGTERM);int status;waitpid(supervisor,&status,0);supervisor=0;
            success=WIFEXITED(status) && WEXITSTATUS(status)==0 && MLWaitAbsent(journal) && MLWaitAbsent(channel) && MLWaitGone(name,index);goto done;
        }
        kill(supervisor,SIGKILL);waitpid(supervisor,NULL,0);supervisor=0;
        if(mode==1){success=MLWaitAbsent(journal) && MLWaitAbsent(channel) && MLWaitGone(name,index);goto done;}
        usleep(300000);if(if_nametoindex(name.UTF8String)!=index || access(journal.fileSystemRepresentation,F_OK))goto done;
        // Guardian must observe Core pipe EOF before allowing another owner.
        kill(core,SIGTERM);core=0;usleep(300000);
        if(if_nametoindex(name.UTF8String)!=index || access(journal.fileSystemRepresentation,F_OK))goto done;
        report[@"retainedAfterSupervisorAndCoreExit"]=@YES;
        if(mode==2){NSError *error=nil;success=MLCaptureEmergencyRecover(directory,&error) && MLWaitAbsent(journal) && MLWaitAbsent(channel) && MLWaitGone(name,index);if(error)report[@"error"]=error.localizedDescription;goto done;}
        if(!MLFixture(executable,directory,YES,&resumed,&newCore,&newGuardian) || newGuardian!=guardian)goto done;
        report[@"adoptedSameGuardian"]=@YES;
        if(if_nametoindex(name.UTF8String)!=index)goto done;
        kill(resumed,SIGTERM);int status;waitpid(resumed,&status,0);resumed=0;
        success=WIFEXITED(status) && WEXITSTATUS(status)==0 && MLWaitAbsent(journal) && MLWaitAbsent(channel) && MLWaitGone(name,index);
    }
done:
    if(supervisor>0){kill(supervisor,SIGKILL);waitpid(supervisor,NULL,0);}if(resumed>0){kill(resumed,SIGKILL);waitpid(resumed,NULL,0);}
    if(core>0)kill(core,SIGTERM);if(newCore>0)kill(newCore,SIGTERM);
    if(!success && guardian>0)kill(guardian,SIGTERM);
    report[@"passed"]=@(success);return success;
}
int main(int argc,const char **argv){@autoreleasepool{
    if(argc==3)return MLCaptureLifecycleFixtureMain(argc,argv);
    if(argc!=1 || geteuid()!=0){fputs("usage (root): muyu-capture-lifecycle\n",stderr);return 77;}
    signal(SIGPIPE,SIG_IGN);char root[]="/private/var/tmp/muyu-guardian-preflight.XXXXXX";
    if(!mkdtemp(root) || chmod(root,0700)){perror("private lifecycle directory");return 73;}
    NSString *directory=[NSString stringWithUTF8String:root];NSMutableArray *stages=[NSMutableArray array];BOOL passed=YES;
    NSArray *names=@[@"normal-disarm",@"supervisor-crash-recovery",@"strict-emergency-recovery",@"strict-supervisor-adoption"];
    for(unsigned i=0;i<4;i++){
        NSString *stage=[directory stringByAppendingPathComponent:[NSString stringWithFormat:@"stage-%u",i]];
        if(mkdir(stage.fileSystemRepresentation,0700)){passed=NO;break;}
        NSMutableDictionary *report=[@{@"stage":names[i]} mutableCopy];BOOL okay=MLStage(argv[0],stage,i,report);[stages addObject:report];if(!okay){passed=NO;break;}
    }
    NSDictionary *result=@{@"preflight":@"real-utun-guardian-lifecycle",@"passed":@(passed),@"redirectRoutesInstalled":@NO,@"dnsPublished":@NO,@"stages":stages,
        @"note":@"utun/IP 配置与文件描述符为真实系统调用；redirect/DNS 操作使用隔离测试后端，没有修改系统路由和 DNS。"};
    NSData *data=[NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:NULL];if(data){fwrite(data.bytes,1,data.length,stdout);putchar('\n');}
    [[NSFileManager defaultManager]removeItemAtPath:directory error:NULL];return passed?0:1;
}}
