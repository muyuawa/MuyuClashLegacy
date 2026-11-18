#import "MLCaptureCoordinator.h"
#include <net/if.h>
#include <sys/stat.h>
#include <unistd.h>
int main(void) { @autoreleasepool {
    if (geteuid()!=0) { fputs("capture preflight requires root\n",stderr); return 77; }
    char path[]="/private/var/tmp/muyu-capture-preflight.XXXXXX";
    if (!mkdtemp(path) || chmod(path,0700)) { perror("private preflight directory"); return 73; }
    NSString *directory=[NSString stringWithUTF8String:path]; NSError *error=nil;
    MLCaptureCoordinator *capture=[[MLCaptureCoordinator alloc] initWithStateDirectory:directory error:&error];
    BOOL prepared=capture && [capture prepare:&error];
    NSDictionary *before=capture.status ?: @{};
    NSString *name=[capture.interfaceName copy]; unsigned index=capture.interfaceIndex;
    BOOL restored=capture ? [capture restore:&error] : YES;
    BOOL detached=!prepared;
    if (prepared && restored) for (unsigned i=0;i<30;i++) {
        if (if_nametoindex(name.UTF8String)!=index) { detached=YES; break; }
        usleep(50000);
    }
    capture=nil;
    NSMutableDictionary *report=[@{@"preflight":@"prepare-only",@"prepared":@(prepared),@"restored":@(restored),
        @"detached":@(detached),@"capture":before,@"redirectRoutesInstalled":@NO,@"dnsPublished":@NO} mutableCopy];
    if(error) report[@"error"]=@{@"code":@(error.code),@"message":error.localizedDescription};
    NSData *data=[NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:NULL];
    if (data) { fwrite(data.bytes,1,data.length,stdout); putchar('\n'); }
    [[NSFileManager defaultManager] removeItemAtPath:directory error:NULL];
    return prepared && restored && detached ? 0 : 1;
}}
