#import "MLCaptureCoordinator.h"
#include <unistd.h>
int main(int argc,const char **argv) { @autoreleasepool {
    BOOL emergency=argc==2 && !strcmp(argv[1],"--emergency");
    if ((argc!=1 && !emergency) || geteuid()!=0) { fputs("usage (root): muyu-network-recover [--emergency]\n",stderr); return 77; }
    NSError *error=nil;
    if (!(emergency?MLCaptureEmergencyRecover(@"/private/var/lib/muyuclash",&error):MLCaptureRecover(@"/private/var/lib/muyuclash",&error))) {
        fprintf(stderr,"%s\n",error.localizedDescription.UTF8String); return 1;
    }
    puts("MuyuClash network recovery completed."); return 0;
}}
