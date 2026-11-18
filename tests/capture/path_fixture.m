// Deliberate, short-lived test-only configd route change. Never edits Wi-Fi.
#import <Foundation/Foundation.h>
#include <TargetConditionals.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
static volatile sig_atomic_t finished;
static void stop(int number){(void)number;finished=1;}
int main(int argc,char **argv){@autoreleasepool{
    if(argc!=5||geteuid()!=0)return 77;
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
    NSString *interface=[NSString stringWithUTF8String:argv[1]],*address=[NSString stringWithUTF8String:argv[2]],
        *gateway=[NSString stringWithUTF8String:argv[3]],*nonce=[NSString stringWithUTF8String:argv[4]];
    struct in_addr local,router;
    if(!interface.length||interface.length>=IF_NAMESIZE||!if_nametoindex(interface.UTF8String)||
        !nonce.length||nonce.length>64||[nonce rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"]invertedSet]].location!=NSNotFound||
        inet_pton(AF_INET,address.UTF8String,&local)!=1||inet_pton(AF_INET,gateway.UTF8String,&router)!=1||local.s_addr==router.s_addr)return 64;
    struct ifaddrs *list=NULL;BOOL assigned=NO;if(getifaddrs(&list))return 1;
    for(struct ifaddrs *a=list;a;a=a->ifa_next)if(a->ifa_addr&&a->ifa_addr->sa_family==AF_INET&&(a->ifa_flags&IFF_UP)&&
        !strcmp(a->ifa_name,interface.UTF8String)&&((struct sockaddr_in *)a->ifa_addr)->sin_addr.s_addr==local.s_addr)assigned=YES;
    freeifaddrs(list);if(!assigned)return 77;
    void *library=dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration",RTLD_LAZY|RTLD_LOCAL);
    typedef CFTypeRef(*Create)(CFAllocatorRef,CFStringRef,void *,void *);typedef CFPropertyListRef(*Copy)(CFTypeRef,CFStringRef);
    typedef Boolean(*Add)(CFTypeRef,CFStringRef,CFPropertyListRef);typedef Boolean(*Remove)(CFTypeRef,CFStringRef);
    Create create=library?dlsym(library,"SCDynamicStoreCreate"):NULL;Copy copy=library?dlsym(library,"SCDynamicStoreCopyValue"):NULL;
    Add add=library?dlsym(library,"SCDynamicStoreAddTemporaryValue"):NULL;Remove remove=library?dlsym(library,"SCDynamicStoreRemoveValue"):NULL;
    CFTypeRef store=create?create(NULL,CFSTR("MuyuClash isolated route-change test"),NULL,NULL):NULL;
    if(!store||!copy||!add||!remove){if(store)CFRelease(store);return 1;}
    NSString *key=[NSString stringWithFormat:@"State:/Network/Service/com.muyu.clashlegacy.test-path.%@/IPv4",nonce];
    CFPropertyListRef existing=copy(store,(__bridge CFStringRef)key);if(existing){CFRelease(existing);CFRelease(store);return 77;}
    NSDictionary *value=@{@"InterfaceName":interface,@"Addresses":@[address],@"Router":gateway,@"OverridePrimary":@1,@"MuyuClashTestNonce":nonce};
    if(!add(store,(__bridge CFStringRef)key,(__bridge CFPropertyListRef)value)){CFRelease(store);return 1;}
    signal(SIGTERM,stop);signal(SIGINT,stop);signal(SIGALRM,stop);signal(SIGPIPE,SIG_IGN);alarm(30);
    NSData *json=[NSJSONSerialization dataWithJSONObject:@{@"ready":@YES,@"key":key,@"temporarySession":@YES,@"gateway":gateway}options:0 error:NULL];
    fwrite(json.bytes,1,json.length,stdout);putchar('\n');fflush(stdout);
    while(!finished){struct pollfd input={0,POLLIN|POLLHUP,0};int rc=poll(&input,1,150);if(rc>0){char command[32];ssize_t n=read(0,command,sizeof command);if(n<=0||(n>=7&&!memcmp(command,"restore",7)))break;}}
    CFPropertyListRef current=copy(store,(__bridge CFStringRef)key);
    BOOL owned=current&&CFGetTypeID(current)==CFDictionaryGetTypeID()&&[((__bridge NSDictionary *)current)[@"MuyuClashTestNonce"]isEqual:nonce];
    if(current)CFRelease(current);BOOL removed=!owned||remove(store,(__bridge CFStringRef)key);CFRelease(store);alarm(0);
    puts(removed?"{\"released\":true}":"{\"released\":false}");fflush(stdout);return removed?0:1;
#else
    (void)argv;fputs("Route fixture requires a real root iOS device.\n",stderr);return 77;
#endif
}}
