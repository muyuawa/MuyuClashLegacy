// Signals only an explicitly identified executable in an isolated test root.
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef int (*Information)(int,int,int,uint64_t,void *,int);
#ifndef ML_TEST_PROCESS_ROOT_PREFIX
#define ML_TEST_PROCESS_ROOT_PREFIX "/private/var/tmp/muyu-capture-lifecycle-"
#endif
static int report(int pid,int alive,int verified,const char *reason,int error,int signaled){
    printf("{\"pid\":%d,\"alive\":%s,\"verified\":%s,\"reason\":\"%s\",\"errno\":%d,\"signaled\":%s}\n",
        pid,alive?"true":"false",verified?"true":"false",reason,error,signaled?"true":"false");return verified||!alive?0:1;
}
int main(int argc,char **argv){
    if(argc!=4||geteuid()!=0)return 77;
    char *end=NULL;unsigned long value=strtoul(argv[1],&end,10);if(!end||*end||value<=1||value>INT_MAX)return 64;int pid=(int)value;
    const char *prefix=ML_TEST_PROCESS_ROOT_PREFIX,*expected=argv[2];
    if(strncmp(expected,prefix,strlen(prefix))||strstr(expected,"/../")||strlen(expected)>=4096)return 77;
    unsigned long number=strtoul(argv[3],&end,10);if(!end||*end||(number&&number!=SIGKILL&&number!=SIGTERM))return 64;
    Information information=NULL;void *symbol=dlsym(RTLD_DEFAULT,"__proc_info");if(symbol)memcpy(&information,&symbol,sizeof information);
    if(!information)return report(pid,1,0,"proc-info-unavailable",ENOTSUP,0);
    char path[4096]={0};errno=0;int result=information(2,pid,11,0,path,sizeof path),error=errno;
    if(result<0||!path[0]||!memchr(path,0,sizeof path)){
        if(kill(pid,0)<0&&errno==ESRCH)return report(pid,0,0,"gone",0,0);
        return report(pid,1,0,"process-path-query",error?:EPROTO,0);
    }
    if(strcmp(path,expected))return report(pid,1,0,"path-mismatch",0,0);
    if(number){
        // Repeat the live path check immediately before signaling. A reused
        // PID or failed query never falls through to an unconditional kill.
        memset(path,0,sizeof path);errno=0;result=information(2,pid,11,0,path,sizeof path);error=errno;
        if(result<0||!path[0]||!memchr(path,0,sizeof path)||strcmp(path,expected)){
            if(kill(pid,0)<0&&errno==ESRCH)return report(pid,0,0,"gone",0,0);
            return report(pid,1,0,"process-changed",error?:ESTALE,0);
        }
    }
    if(kill(pid,(int)number)){
        error=errno;if(error==ESRCH)return report(pid,0,0,"gone",0,0);
        return report(pid,1,0,"signal-error",error,0);
    }
    return report(pid,1,1,number?"signaled":"matched",0,number!=0);
}
