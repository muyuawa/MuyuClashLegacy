#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
typedef int (*ProcInfo)(int,int,int,uint64_t,void *,int);
int main(int argc,char **argv) {
    if(geteuid()!=0||argc>2||(argc==2&&strcmp(argv[1],"--stop")))return 64;
    const char *target="/private/var/tmp/muyu-capture-integration/muyu-supervisor";
    ProcInfo info=NULL;void *symbol=dlsym(RTLD_DEFAULT,"__proc_info");memcpy(&info,&symbol,sizeof(info));if(!info)return 69;
    int pids[4096]={0};int bytes=info(1,1,0,0,pids,sizeof(pids));if(bytes<=0||bytes>=(int)sizeof(pids)||bytes%(int)sizeof(int))return 70;
    int found=0,selected=0;
    for(int i=0;i<bytes/(int)sizeof(int);i++){char path[4096]={0};if(pids[i]>0&&info(2,pids[i],11,0,path,sizeof(path))>=0&&memchr(path,0,sizeof(path))&&!strcmp(path,target)){found++;selected=pids[i];}}
    if(found>1)return 75;
    if(!found){puts("No isolated test Supervisor");return 0;}
    printf("Isolated test Supervisor PID %d\n",selected);
    if(argc==2){char path[4096]={0};if(info(2,selected,11,0,path,sizeof(path))<0||strcmp(path,target))return 75;if(kill(selected,SIGTERM))return 1;}
    return 0;
}
