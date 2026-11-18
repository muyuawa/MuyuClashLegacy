#import "MLCaptureInternal.h"
#include <sys/socket.h>
#include <unistd.h>
int main(int argc,const char **argv) { @autoreleasepool {
    if (argc!=3 || strcmp(argv[1],"--guardian") || geteuid()!=0) return 77;
    int type; socklen_t size=sizeof type;
    if (getsockopt(3,SOL_SOCKET,SO_TYPE,&type,&size) || type!=SOCK_STREAM) return 64;
    for (int fd=7;fd<getdtablesize();fd++) close(fd);
    return MLCaptureGuardianRun([NSString stringWithUTF8String:argv[2]],3,4,5,6,MLCaptureSystemBackend());
}}
