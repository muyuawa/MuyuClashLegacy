#import "MLCaptureInternal.h"
#include <dlfcn.h>
#include <net/if.h>
#include <sys/stat.h>
#include <unistd.h>
static NSDictionary *dnsState(void){
    void *library=dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration",RTLD_LAZY|RTLD_LOCAL);
    typedef CFTypeRef(*Create)(CFAllocatorRef,CFStringRef,void *,void *);typedef CFPropertyListRef(*Copy)(CFTypeRef,CFStringRef);
    Create create=library?dlsym(library,"SCDynamicStoreCreate"):NULL;Copy copy=library?dlsym(library,"SCDynamicStoreCopyValue"):NULL;
    CFTypeRef store=create?create(NULL,CFSTR("MuyuClash read-only lifecycle probe"),NULL,NULL):NULL;NSMutableDictionary *result=[NSMutableDictionary dictionary];
    if(store&&copy)for(NSString *entity in @[@"DNS",@"IPv4"]){
        NSString *key=[@"State:/Network/Service/com.muyu.clashlegacy.capture/"stringByAppendingString:entity];CFPropertyListRef value=copy(store,(__bridge CFStringRef)key);
        result[entity]=value?CFBridgingRelease(value):(id)[NSNull null];
    }
    if(store)CFRelease(store);return result;
}
int main(int argc,char **argv){@autoreleasepool{
    if(argc!=3&&argc!=5)return 64;if(geteuid()!=0)return 77;
    NSString *mode=[NSString stringWithUTF8String:argv[1]],*directory=[NSString stringWithUTF8String:argv[2]];
    if(![directory hasPrefix:@"/private/var/tmp/muyu-capture-lifecycle-"]||![directory.lastPathComponent isEqual:@"state"])return 77;
    struct stat st;if(lstat(directory.fileSystemRepresentation,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=0||(st.st_mode&0077))return 77;
    NSError *error=nil;BOOL recovered=YES;
    if([mode isEqual:@"emergency"])recovered=MLCaptureEmergencyRecover(directory,&error);
    else if(![mode isEqual:@"status"])return 64;
    id<MLCaptureBackend> backend=MLCaptureSystemBackend();NSDictionary *physical=[backend physicalSignature:&error];
    NSError *physicalError=error;
    NSMutableDictionary *routes=[NSMutableDictionary dictionary],*routeErrors=[NSMutableDictionary dictionary];
    for(NSString *destination in @[@"0.0.0.0",@"128.0.0.0",@"::",@"8000::"]){
        NSError *rowError=nil;NSDictionary *row=[backend routeForDestination:destination prefix:1 interfaceIndex:0 error:&rowError];
        routes[destination]=row ?: (id)[NSNull null];
        if(rowError)routeErrors[destination]=@{@"domain":rowError.domain,@"code":@(rowError.code),@"message":rowError.localizedDescription};
        if(rowError&&!error)error=rowError;
    }
    NSString *journalPath=[directory stringByAppendingPathComponent:@"capture.json"];
    BOOL present=lstat(journalPath.fileSystemRepresentation,&st)==0;NSDictionary *journal=nil;
    if(present&&S_ISREG(st.st_mode)&&st.st_uid==0&&!(st.st_mode&0077)&&st.st_size>0&&st.st_size<=32768){
        NSData *data=[NSData dataWithContentsOfFile:journalPath];id parsed=data?[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL]:nil;
        if([parsed isKindOfClass:[NSDictionary class]])journal=parsed;
    }
    NSMutableDictionary *report=[@{@"readOnly":@([mode isEqual:@"status"]),@"recovered":@(recovered),@"physicalSignature":physical ?: @{},
        @"routes":routes,@"dnsState":dnsState(),@"journalPresent":@(present),@"journal":journal ?: @{},
        @"physicalError":physicalError?@{@"domain":physicalError.domain,@"code":@(physicalError.code),@"message":physicalError.localizedDescription}:@{},
        @"routeErrors":routeErrors,
        @"guardianSocketPresent":@([[NSFileManager defaultManager]fileExistsAtPath:[directory stringByAppendingPathComponent:@"guardian.sock"]]),
        @"error":error?@{@"domain":error.domain,@"code":@(error.code),@"message":error.localizedDescription}:@{}}mutableCopy];
    if(argc==5){NSString *name=[NSString stringWithUTF8String:argv[3]];unsigned old=(unsigned)strtoul(argv[4],NULL,10),current=if_nametoindex(name.UTF8String);
        report[@"observedInterfaceIndex"]=@(current);report[@"sameInterface"]=@(old&&old==current);}
    NSData *data=[NSJSONSerialization dataWithJSONObject:report options:0 error:NULL];fwrite(data.bytes,1,data.length,stdout);putchar('\n');return error||!recovered?1:0;
}}
