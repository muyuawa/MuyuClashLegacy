/* Host-only fault injection: report one directory fsync failure after the real
   rename and fsync, preserving the installed pointer bytes as test evidence. */
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static int ml_fault_fsync(int fd) {
    // dyld leaves references from this interposing image bound to the original.
    int result=fsync(fd); if (result) return result;
    const char *arm=getenv("ML_STORAGE_FSYNC_FAULT_ARM"); struct stat status;
    char directory[MAXPATHLEN],target[MAXPATHLEN],parent[MAXPATHLEN];
    if (!arm || fstat(fd,&status) || !S_ISDIR(status.st_mode) || fcntl(fd,F_GETPATH,directory)) return result;
    int input=open(arm,O_RDONLY|O_NOFOLLOW); if (input<0) return result;
    ssize_t count=read(input,target,sizeof target-1); close(input);
    if (count<=0) return result; target[count]=0;
    memcpy(parent,target,(size_t)count+1); char *slash=strrchr(parent,'/'); if (!slash) return result; *slash=0;
    if (strcmp(directory,parent)) return result;
    char evidence[MAXPATHLEN]; if (snprintf(evidence,sizeof evidence,"%s.renamed",arm)>=(int)sizeof evidence) return result;
    int source=open(target,O_RDONLY|O_NOFOLLOW),output=open(evidence,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,0600);
    if (source<0 || output<0) { if (source>=0) close(source); if (output>=0) close(output); return result; }
    char bytes[8192]; while ((count=read(source,bytes,sizeof bytes))>0) {
        ssize_t used=0; while (used<count) { ssize_t n=write(output,bytes+used,(size_t)(count-used)); if (n<=0) break; used+=n; }
    }
    close(source); close(output); unlink(arm); errno=EIO; return -1;
}
__attribute__((used)) static struct { const void *replacement; const void *original; } ml_interpose
__attribute__((section("__DATA,__interpose")))={ (const void *)ml_fault_fsync, (const void *)fsync };
