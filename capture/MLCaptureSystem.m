#import "MLCaptureInternal.h"
#include <TargetConditionals.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "utun_device.h"
#include "utun_route.h"
#include "route_socket.h"
#include "core/route_message.h"
#include "core/senko_time.h"

static BOOL MLSystemError(NSError **error, NSString *message, int code) {
    if (error) *error = [NSError errorWithDomain:@"E_CAPTURE_SYSTEM" code:code ?: EIO userInfo:@{NSLocalizedDescriptionKey:message}];
    return NO;
}
NSDictionary *MLCaptureDNSPublication(NSString *interface, NSString *nonce) {
    return @{@"DNS":@{@"ServerAddresses":@[@"198.18.0.53"],@"InterfaceName":interface,
        @"SupplementalMatchDomains":@[@""],@"SupplementalMatchOrders":@[@0],@"MuyuClashCaptureNonce":nonce}};
}
static NSString *MLLiteral(const uint8_t *bytes, int family) {
    char text[INET6_ADDRSTRLEN];
    return inet_ntop(family,bytes,text,sizeof text) ? [NSString stringWithUTF8String:text] : nil;
}

NSString *MLCaptureIPv6SourceNetwork(const struct in6_addr *address, const struct sockaddr_in6 *mask) {
    const size_t addressOffset = offsetof(struct sockaddr_in6, sin6_addr);
    if (IN6_IS_ADDR_LINKLOCAL(address) || !mask || mask->sin6_len <= addressOffset)
        return MLLiteral(address->s6_addr, AF_INET6);

    // Temporary SLAAC addresses rotate their host bits on the same network.
    // A routing change still matters when the last address in a prefix goes away.
    size_t maskSize = MIN(sizeof mask->sin6_addr, mask->sin6_len - addressOffset);
    struct in6_addr network = {0};
    unsigned prefix = 0;
    for (size_t i = 0; i < maskSize; ++i) {
        uint8_t byte = mask->sin6_addr.s6_addr[i];
        network.s6_addr[i] = address->s6_addr[i] & byte;
        prefix += __builtin_popcount(byte);
    }
    if (!prefix) return MLLiteral(address->s6_addr, AF_INET6);
    return [NSString stringWithFormat:@"%@/%u", MLLiteral(network.s6_addr, AF_INET6), prefix];
}
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
#include <sys/sysctl.h>
#include <sys/sockio.h>
#include "MLCaptureRouteABI.h"
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
_Static_assert(sizeof(struct MLRouteHeader) == ROUTE_MESSAGE_HEADER_LEN,"iOS 6 routing ABI");
struct MLIPv6Lifetime { uint32_t expire, preferred, validLifetime, preferredLifetime; };
struct MLIPv6Alias { char name[IF_NAMESIZE]; struct sockaddr_in6 address, destination, mask; int flags; struct MLIPv6Lifetime lifetime; };
_Static_assert(sizeof(struct MLIPv6Alias) == 120,"ARMv7 IPv6 address ioctl ABI");
#define MLAddIPv6 _IOW('i',26,struct MLIPv6Alias)
static NSString *MLDNSPrefix = @"State:/Network/Service/com.muyu.clashlegacy.capture/";
typedef const struct __SCDynamicStore *MLStoreRef;
typedef MLStoreRef (*MLStoreCreate)(CFAllocatorRef,CFStringRef,void *,void *);
typedef Boolean (*MLStoreAdd)(MLStoreRef,CFStringRef,CFPropertyListRef);
typedef CFPropertyListRef (*MLStoreCopy)(MLStoreRef,CFStringRef);
typedef Boolean (*MLStoreRemove)(MLStoreRef,CFStringRef);
typedef CFArrayRef (*MLStoreKeys)(MLStoreRef,CFStringRef);
static BOOL MLConfigure(const char *name) {
    int fd = socket(AF_INET,SOCK_DGRAM,0); if (fd < 0) return NO;
    struct ifreq request; memset(&request,0,sizeof request); strlcpy(request.ifr_name,name,sizeof request.ifr_name);
    struct sockaddr_in *address = (struct sockaddr_in *)&request.ifr_addr;
    address->sin_len = sizeof *address; address->sin_family = AF_INET;
    inet_pton(AF_INET,"198.18.0.1",&address->sin_addr);
    BOOL ok = ioctl(fd,SIOCSIFADDR,&request) == 0;
    inet_pton(AF_INET,"198.18.0.2",&address->sin_addr);
    if (ok) ok = ioctl(fd,SIOCSIFDSTADDR,&request) == 0;
    address->sin_addr.s_addr = htonl(UINT32_MAX);
    if (ok) ok = ioctl(fd,SIOCSIFNETMASK,&request) == 0;
    if (ok) ok = ioctl(fd,SIOCGIFFLAGS,&request) == 0;
    if (ok) { request.ifr_flags |= IFF_UP | IFF_RUNNING; ok = ioctl(fd,SIOCSIFFLAGS,&request) == 0; }
    if (ok) { request.ifr_mtu = 1500; ok = ioctl(fd,SIOCSIFMTU,&request) == 0; }
    int saved = errno; close(fd);
    if (!ok) { errno = saved; return NO; }
    struct MLIPv6Alias v6; memset(&v6,0,sizeof v6); strlcpy(v6.name,name,sizeof v6.name);
    v6.address.sin6_len = v6.mask.sin6_len = sizeof(struct sockaddr_in6);
    v6.address.sin6_family = v6.mask.sin6_family = AF_INET6;
    inet_pton(AF_INET6,"fd00:5e4b::1",&v6.address.sin6_addr);
    memset(&v6.mask.sin6_addr,0xff,sizeof v6.mask.sin6_addr);
    v6.lifetime.validLifetime = v6.lifetime.preferredLifetime = UINT32_MAX;
    fd = socket(AF_INET6,SOCK_DGRAM,0); if (fd < 0) return NO;
    ok = ioctl(fd,MLAddIPv6,&v6) == 0; saved = errno; close(fd); errno = saved; return ok;
}
static BOOL MLReservedAvailable(NSError **error) {
    struct ifaddrs *interfaces=NULL;
    if(getifaddrs(&interfaces))return MLSystemError(error,@"无法检查虚拟地址与现有接口的冲突",errno);
    uint8_t target4[4],target6[16];inet_pton(AF_INET,"198.18.0.53",target4);inet_pton(AF_INET6,"fd00:5e4b::53",target6);
    BOOL conflict=NO;
    for(struct ifaddrs *entry=interfaces;entry && !conflict;entry=entry->ifa_next){
        if(!entry->ifa_addr || !entry->ifa_netmask || !(entry->ifa_flags&IFF_UP))continue;
        unsigned size=0;const uint8_t *address=NULL,*mask=NULL,*target=NULL;
        if(entry->ifa_addr->sa_family==AF_INET){size=4;address=(const uint8_t *)&((struct sockaddr_in *)entry->ifa_addr)->sin_addr;mask=(const uint8_t *)&((struct sockaddr_in *)entry->ifa_netmask)->sin_addr;target=target4;}
        else if(entry->ifa_addr->sa_family==AF_INET6){size=16;address=(const uint8_t *)&((struct sockaddr_in6 *)entry->ifa_addr)->sin6_addr;mask=(const uint8_t *)&((struct sockaddr_in6 *)entry->ifa_netmask)->sin6_addr;target=target6;}
        if(!size)continue;BOOL same=YES,nonzero=NO;
        for(unsigned i=0;i<size;i++){if(mask[i])nonzero=YES;if((address[i]&mask[i])!=(target[i]&mask[i]))same=NO;}
        if(nonzero && same)conflict=YES;
        // /32 peer configurations also reserve the two utun control addresses.
        if(size==4 && address[0]==198 && address[1]==18 && address[2]==0 && (address[3]==1 || address[3]==2 || address[3]==53))conflict=YES;
        if(size==16 && !memcmp(address,target6,15) && (address[15]==1 || address[15]==2 || address[15]==53))conflict=YES;
    }
    freeifaddrs(interfaces);
    return conflict?MLSystemError(error,@"虚拟接管地址已被现有网络接口使用，拒绝覆盖",EADDRINUSE):YES;
}
static BOOL MLPhysicalInterface(NSString *name) {
    return [name isKindOfClass:[NSString class]] && name.length && ![name hasPrefix:@"utun"] &&
        ![name hasPrefix:@"ipsec"] && ![name hasPrefix:@"ppp"] && ![name hasPrefix:@"lo"];
}
// Reads an exact table row, rather than a longest-prefix GET result. Cleanup
// must not mistake a replacement host route for the split route being removed.
static NSDictionary *MLFindRoute(NSString *literal, unsigned prefix, unsigned desiredIndex, NSError **error) {
    int family = [literal rangeOfString:@":"].location == NSNotFound ? AF_INET : AF_INET6;
    uint8_t desired[16]; if (inet_pton(family,literal.UTF8String,desired) != 1) { MLSystemError(error,@"路由地址无效",EINVAL); return nil; }
    int mib[6] = {CTL_NET,PF_ROUTE,0,family,MLRouteDump,0};
    size_t count = 0;
    if (sysctl(mib,6,NULL,&count,NULL,0) || count > 512*1024) { MLSystemError(error,@"无法读取有界的系统路由表",errno ?: EFBIG); return nil; }
    NSMutableData *table = [NSMutableData dataWithLength:count];
    if (count && sysctl(mib,6,table.mutableBytes,&count,NULL,0)) { MLSystemError(error,@"读取路由表时网络发生变化",errno); return nil; }
    size_t offset = 0;
    while (offset < count) {
        if (count-offset < sizeof(struct MLRouteHeader)) { MLSystemError(error,@"系统路由表被截断",EPROTO); return nil; }
        const struct MLRouteHeader *header = (const struct MLRouteHeader *)((const char *)table.bytes+offset);
        size_t length = header->rtm_msglen;
        if (length < sizeof *header || length > count-offset || header->rtm_version != MLRouteVersion) { MLSystemError(error,@"系统路由记录版本或长度无效",EPROTO); return nil; }
        const uint8_t *row = (const uint8_t *)header;
        const uint8_t *destination = NULL; uint8_t mask[16] = {0}; BOOL link = NO;NSString *gateway=@"";
        uint16_t index = header->rtm_index; size_t cursor = sizeof *header;
        for (unsigned slot=0;slot<MLRouteSlots;slot++) {
            if (!(header->rtm_addrs & (1 << slot))) continue;
            if (cursor >= length) { MLSystemError(error,@"系统路由地址列表无效",EPROTO); return nil; }
            const uint8_t *sa = row+cursor; size_t saLength = sa[0];
            size_t padded = saLength ? (saLength+3)&~(size_t)3 : 4;
            if (padded > length-cursor || (saLength && saLength < 2)) { MLSystemError(error,@"系统路由地址被截断",EPROTO); return nil; }
            size_t addressOffset = family == AF_INET ? 4 : 8, addressLength = family == AF_INET ? 4 : 16;
            if (slot == MLRouteDestination && saLength >= addressOffset+addressLength && sa[1] == family) destination = sa+addressOffset;
            if (slot == MLRouteNetmask && saLength > addressOffset) memcpy(mask,sa+addressOffset,MIN(addressLength,saLength-addressOffset));
            if (slot == MLRouteGateway && saLength >= 4 && sa[1] == AF_LINK) { link = YES; memcpy(&index,sa+2,sizeof index); }
            if(slot==MLRouteGateway && saLength>=addressOffset+addressLength && sa[1]==family)gateway=MLLiteral(sa+addressOffset,family) ?: @"";
            cursor += padded;
        }
        unsigned actualPrefix = 0; BOOL zeroSeen = NO, contiguous = YES;
        for (unsigned b=0;b<(family==AF_INET?32:128);b++) {
            BOOL one = (mask[b/8] & (0x80 >> (b%8))) != 0;
            if (one && zeroSeen) contiguous = NO;
            if (one) actualPrefix++; else zeroSeen = YES;
        }
        if ((header->rtm_flags & MLRouteHost)) actualPrefix = family == AF_INET ? 32 : 128;
        // A scoped /0 for another interface is not the global physical
        // default. Still return a real global utun /0 so the caller detects
        // an unintended route change rather than hiding it.
        BOOL scoped=(header->rtm_flags & MLRouteScoped)!=0;
        if ((!desiredIndex || desiredIndex == index) && !(prefix==0 && scoped != (desiredIndex != 0)) && destination && contiguous && actualPrefix == prefix && !memcmp(destination,desired,family==AF_INET?4:16)) {
            char name[IF_NAMESIZE]; const char *found = if_indextoname(index,name);
            return @{@"destination":literal,@"prefix":@(prefix),@"interfaceIndex":@(index),
                @"interface":found ? [NSString stringWithUTF8String:found] : @"",@"gatewayIsLink":@(link),@"gateway":gateway,
                @"flags":@((uint32_t)header->rtm_flags),@"scoped":@(scoped)};
        }
        offset += length;
    }
    return nil;
}
struct MLRouteFD { int fd; unsigned scope; };
static long MLRouteWrite(void *ctx,const uint8_t *bytes,size_t length,int *error) {
    struct MLRouteFD *channel=ctx;
    uint8_t scoped[ROUTE_MESSAGE_MAX];
    if(channel->scope){
        if(length<sizeof(struct MLRouteHeader) || length>sizeof scoped){*error=EINVAL;return -1;}
        memcpy(scoped,bytes,length);
        struct MLRouteHeader *header=(struct MLRouteHeader *)scoped;
        header->rtm_flags|=MLRouteScoped;header->rtm_index=(uint16_t)channel->scope;
        bytes=scoped;
    }
    ssize_t n=write(channel->fd,bytes,length); *error=n<0?errno:0; return n;
}
static long MLRouteRead(void *ctx,uint8_t *bytes,size_t capacity,int64_t deadline,int *error) {
    int fd=((struct MLRouteFD *)ctx)->fd; int64_t left=deadline-senko_now_ms();
    if (left<=0) return 0;
    fd_set readSet; FD_ZERO(&readSet); FD_SET(fd,&readSet); struct timeval wait={left/1000,(left%1000)*1000};
    int ready=select(fd+1,&readSet,NULL,NULL,&wait); if (ready<=0) { *error=ready<0?errno:0; return ready; }
    ssize_t n=read(fd,bytes,capacity); *error=n<0?errno:0; return n;
}
static int64_t MLRouteNow(void *ctx) { (void)ctx; return senko_now_ms(); }
static BOOL MLChangeRoute(NSDictionary *route, BOOL add, NSError **error) {
    route_message_spec_t spec; memset(&spec,0,sizeof spec);
    spec.type=add?ROUTE_MESSAGE_ADD:ROUTE_MESSAGE_DELETE;
    NSString *destination=route[@"destination"]; int family=[destination rangeOfString:@":"].location==NSNotFound?AF_INET:AF_INET6;
    spec.address_len=family==AF_INET?4:16; spec.prefix=[route[@"prefix"] unsignedIntValue];
    spec.target=[route[@"gatewayIsLink"] boolValue]?ROUTE_TARGET_INTERFACE:ROUTE_TARGET_GATEWAY;
    spec.interface_index=[route[@"interfaceIndex"] unsignedIntValue];
    if(spec.target==ROUTE_TARGET_GATEWAY && inet_pton(family,[route[@"gateway"] UTF8String],spec.gateway)!=1)
        return MLSystemError(error,@"物理出口网关地址无效",EINVAL);
    if (inet_pton(family,destination.UTF8String,spec.destination)!=1) return MLSystemError(error,@"网络路由地址无效",EINVAL);
    struct MLRouteFD fd={socket(AF_ROUTE,SOCK_RAW,0),[route[@"scoped"] boolValue]?spec.interface_index:0};
    if (fd.fd<0) return MLSystemError(error,@"无法打开特权路由通道",errno);
    if (fd.fd>=FD_SETSIZE) { close(fd.fd); return MLSystemError(error,@"路由描述符超出 select 限制",EMFILE); }
    route_io_t io={MLRouteWrite,MLRouteRead,MLRouteNow,&fd,(int32_t)getpid()}; route_error_t result;
    route_socket_status_t status=route_socket_transact(&io,&spec,2000,NULL,&result); close(fd.fd);
    if (status==ROUTE_SOCKET_OK || (!add && status==ROUTE_SOCKET_ALREADY_GONE)) return YES;
    return MLSystemError(error,[NSString stringWithUTF8String:result.message],result.kernel_errno);
}
#endif

@interface MLCaptureDarwinBackend : NSObject <MLCaptureBackend>
@end
@implementation MLCaptureDarwinBackend {
    utun_device_t _device;
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
    MLStoreRef _store;
    MLStoreAdd _add; MLStoreCopy _copy; MLStoreRemove _remove;
    MLStoreKeys _keys;
#endif
}
- (id)init { if ((self=[super init])) utun_device_init(&_device); return self; }
- (void)dealloc {
    utun_device_close(&_device);
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
    if (_store) CFRelease(_store);
#endif
}
- (NSDictionary *)openDevice:(NSError **)error {
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
    if (geteuid()!=0) { MLSystemError(error,@"系统接管需要 root",EPERM); return nil; }
    if(!MLReservedAvailable(error))return nil;
    if (utun_device_open(&_device,0)!=UTUN_DEVICE_OK) { MLSystemError(error,@"旧内核拒绝创建 utun",_device.last_errno); return nil; }
    unsigned index=if_nametoindex(_device.ifname);
    if (!index || index>UINT16_MAX || strncmp(_device.ifname,"utun",4) || !MLConfigure(_device.ifname)) {
        int saved=errno; utun_device_close(&_device); MLSystemError(error,@"无法完整配置 IPv4/IPv6 utun 接口",saved); return nil;
    }
    fcntl(_device.fd,F_SETFD,FD_CLOEXEC);
    return @{@"fd":@(_device.fd),@"interface":[NSString stringWithUTF8String:_device.ifname],@"interfaceIndex":@(index)};
#else
    MLSystemError(error,@"主机构建不会修改系统网络",ENOTSUP); return nil;
#endif
}
- (BOOL)closeDevice:(NSError **)error {
    (void)error; utun_device_close(&_device); return YES;
}
- (NSDictionary *)physicalPath:(NSError **)error {
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
    // Exact default routes remain physical while the more-specific utun /1
    // routes are active. Longest-prefix GET would report our own utun here.
    NSDictionary *path=MLFindRoute(@"0.0.0.0",0,0,error);if(!path){if(error && !*error)MLSystemError(error,@"当前没有 IPv4 物理默认路由",ENETUNREACH);return nil;}
    NSString *name=path[@"interface"];unsigned index=[path[@"interfaceIndex"] unsignedIntValue];
    if (!index || index>UINT16_MAX || !MLPhysicalInterface(name)) {
        MLSystemError(error,@"已有 VPN 或没有可安全绑定的物理出口",EBUSY); return nil;
    }
    NSDictionary *path6=MLFindRoute(@"::",0,0,error);if(error && *error)return nil;BOOL have6=path6!=nil;
    if (have6 && ![name isEqual:path6[@"interface"]]) { MLSystemError(error,@"IPv4 和 IPv6 使用不同物理出口，拒绝不完整接管",ENOTSUP); return nil; }
    if (![self store:error]) return nil;
    NSMutableArray *servers=[NSMutableArray array];
    CFPropertyListRef global=_copy(_store,CFSTR("State:/Network/Global/DNS"));
    if (global && CFGetTypeID(global)==CFDictionaryGetTypeID()) {
        id entries=((__bridge NSDictionary *)global)[@"ServerAddresses"];
        if ([entries isKindOfClass:[NSArray class]]) for (id item in entries) {
            if (![item isKindOfClass:[NSString class]] || servers.count>=16) continue;
            uint8_t address[16];
            if(![item isEqual:@"198.18.0.53"] && ![item isEqual:@"fd00:5e4b::53"] && (inet_pton(AF_INET,[item UTF8String],address)==1 || inet_pton(AF_INET6,[item UTF8String],address)==1) && ![servers containsObject:item]) [servers addObject:item];
        }
    }
    if (global) CFRelease(global);
    if (!servers.count) {
        CFPropertyListRef primary=_copy(_store,CFSTR("State:/Network/Global/IPv4"));
        NSString *service=primary && CFGetTypeID(primary)==CFDictionaryGetTypeID()?((__bridge NSDictionary *)primary)[@"PrimaryService"]:nil;
        if ([service isKindOfClass:[NSString class]] && service.length<=128) {
            CFStringRef key=(__bridge CFStringRef)[NSString stringWithFormat:@"State:/Network/Service/%@/DNS",service];
            CFPropertyListRef dns=_copy(_store,key);
            id entries=dns && CFGetTypeID(dns)==CFDictionaryGetTypeID()?((__bridge NSDictionary *)dns)[@"ServerAddresses"]:nil;
            if ([entries isKindOfClass:[NSArray class]]) for (id item in entries) {
                if (![item isKindOfClass:[NSString class]] || servers.count>=16) continue;
                uint8_t address[16];
                if ((inet_pton(AF_INET,[item UTF8String],address)==1 || inet_pton(AF_INET6,[item UTF8String],address)==1) && ![servers containsObject:item]) [servers addObject:item];
            }
            if (dns) CFRelease(dns);
        }
        if (primary) CFRelease(primary);
    }
    NSArray *physical=[self physicalDNSServers:name error:error];if(!physical)return nil;
    if(physical.count)servers=[physical mutableCopy];
    return @{@"interface":name,@"interfaceIndex":@(index),@"gateway4":path[@"gateway"] ?: @"",
        @"haveIPv6Path":@(have6),@"gateway6":path6[@"gateway"] ?: @"",@"DNSServerAddresses":servers};
#else
    MLSystemError(error,@"主机构建不执行网络接管",ENOTSUP); return nil;
#endif
}
- (NSDictionary *)physicalSignature:(NSError **)error {
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
    NSDictionary *v4=MLFindRoute(@"0.0.0.0",0,0,error);if(!v4){if(error && !*error)MLSystemError(error,@"物理默认路由已断开",ENETUNREACH);return nil;}
    NSDictionary *v6=MLFindRoute(@"::",0,0,error);if(error && *error)return nil;
    NSArray *dns=[self physicalDNSServers:v4[@"interface"] error:error];if(!dns)return nil;
    struct ifaddrs *list=NULL;if(getifaddrs(&list)){MLSystemError(error,@"物理接口地址检查失败",errno);return nil;}
    NSMutableSet *addresses=[NSMutableSet set];
    for(struct ifaddrs *entry=list;entry;entry=entry->ifa_next){
        if(!entry->ifa_addr || !(entry->ifa_flags&IFF_UP))continue;
        NSString *name=[NSString stringWithUTF8String:entry->ifa_name];
        if(!MLPhysicalInterface(name) || (![name isEqual:v4[@"interface"]] && ![name isEqual:v6[@"interface"]]))continue;
        NSString *literal=nil;int family=entry->ifa_addr->sa_family;
        if(family==AF_INET)literal=MLLiteral((const uint8_t *)&((struct sockaddr_in *)entry->ifa_addr)->sin_addr,AF_INET);
        else if(family==AF_INET6)literal=MLCaptureIPv6SourceNetwork(&((struct sockaddr_in6 *)entry->ifa_addr)->sin6_addr,(const struct sockaddr_in6 *)entry->ifa_netmask);
        if(literal)[addresses addObject:[NSString stringWithFormat:@"%@/%@",name,literal]];
    }
    freeifaddrs(list);
    if(!addresses.count){MLSystemError(error,@"物理出口接口已失去地址",ENETDOWN);return nil;}
    return @{@"default4":v4,@"default6":v6 ?: @{},@"addresses":[[addresses allObjects] sortedArrayUsingSelector:@selector(compare:)],@"dns":dns};
#else
    MLSystemError(error,@"主机构建不读取设备物理网络状态",ENOTSUP);return nil;
#endif
}
- (unsigned)indexForInterface:(NSString *)name { return if_nametoindex(name.UTF8String); }
- (NSDictionary *)routeForDestination:(NSString *)destination prefix:(unsigned)prefix interfaceIndex:(unsigned)index error:(NSError **)error {
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
    return MLFindRoute(destination,prefix,index,error);
#else
    (void)destination; (void)prefix; (void)index; MLSystemError(error,@"主机构建不读取接管路由",ENOTSUP); return nil;
#endif
}
- (BOOL)addRoute:(NSDictionary *)route error:(NSError **)error {
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
    return MLChangeRoute(route,YES,error);
#else
    (void)route; return MLSystemError(error,@"主机构建不修改路由",ENOTSUP);
#endif
}
- (BOOL)deleteRoute:(NSDictionary *)route error:(NSError **)error {
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
    return MLChangeRoute(route,NO,error);
#else
    (void)route; return MLSystemError(error,@"主机构建不修改路由",ENOTSUP);
#endif
}
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
- (BOOL)store:(NSError **)error {
    if (_store) return YES;
    void *library=dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration",RTLD_LAZY|RTLD_LOCAL);
    MLStoreCreate create=library?dlsym(library,"SCDynamicStoreCreate"):NULL;
    _add=library?dlsym(library,"SCDynamicStoreAddTemporaryValue"):NULL;
    _copy=library?dlsym(library,"SCDynamicStoreCopyValue"):NULL;
    _remove=library?dlsym(library,"SCDynamicStoreRemoveValue"):NULL;
    _keys=library?dlsym(library,"SCDynamicStoreCopyKeyList"):NULL;
    if (!create || !_add || !_copy || !_remove || !_keys || !(_store=create(kCFAllocatorDefault,CFSTR("MuyuClash capture"),NULL,NULL)))
        return MLSystemError(error,@"旧系统 configd 不提供临时 DNS 配置",ENOTSUP);
    return YES;
}
- (NSArray *)physicalDNSServers:(NSString *)interface error:(NSError **)error {
    if(![self store:error])return nil;
    CFArrayRef keys=_keys(_store,CFSTR("State:/Network/Service/[^/]+/IPv4"));
    if(!keys || CFGetTypeID(keys)!=CFArrayGetTypeID() || CFArrayGetCount(keys)>256){if(keys)CFRelease(keys);MLSystemError(error,@"无法读取有界的物理 DNS 服务列表",EIO);return nil;}
    NSMutableArray *servers=[NSMutableArray array];
    for(NSString *key in (__bridge NSArray *)keys){
        if(![key isKindOfClass:[NSString class]] || key.length>256 || [key hasPrefix:MLDNSPrefix])continue;
        CFPropertyListRef value=_copy(_store,(__bridge CFStringRef)key);
        BOOL matches=value && CFGetTypeID(value)==CFDictionaryGetTypeID() && [((__bridge NSDictionary *)value)[@"InterfaceName"] isEqual:interface];
        if(value)CFRelease(value);if(!matches)continue;
        NSString *dnsKey=[[key stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"DNS"];
        CFPropertyListRef dns=_copy(_store,(__bridge CFStringRef)dnsKey);id entries=dns && CFGetTypeID(dns)==CFDictionaryGetTypeID()?((__bridge NSDictionary *)dns)[@"ServerAddresses"]:nil;
        if([entries isKindOfClass:[NSArray class]])for(id item in entries){
            uint8_t address[16];if(![item isKindOfClass:[NSString class]] || servers.count>=16)continue;
            if((inet_pton(AF_INET,[item UTF8String],address)==1 || inet_pton(AF_INET6,[item UTF8String],address)==1) && ![servers containsObject:item])[servers addObject:item];
        }
        if(dns)CFRelease(dns);
    }
    CFRelease(keys);[servers sortUsingSelector:@selector(compare:)];return servers;
}
#endif
- (BOOL)publishDNS:(NSString *)interface nonce:(NSString *)nonce error:(NSError **)error {
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
    if (![self store:error]) return NO;
    // DNS-only supplemental state is supported by iOS 6 configd. An IPv4
    // entity would asynchronously install a /0 via Router/DestAddresses and
    // change the physical path this coordinator is meant to preserve.
    NSDictionary *publication=MLCaptureDNSPublication(interface,nonce);
    // Reject old/foreign service state before writing any new entry. Keep the
    // old IPv4 check and withdrawal for upgrades from the previous publisher.
    for (NSString *entity in @[@"DNS",@"IPv4"]) {
        CFStringRef key=(__bridge CFStringRef)[MLDNSPrefix stringByAppendingString:entity];
        CFPropertyListRef current=_copy(_store,key);
        if (current) { CFRelease(current); [self withdrawDNS:nonce error:NULL]; return MLSystemError(error,@"已有同名 DNS 服务记录，拒绝覆盖",EEXIST); }
    }
    for(NSString *entity in publication){
        CFStringRef key=(__bridge CFStringRef)[MLDNSPrefix stringByAppendingString:entity];
        if (!_add(_store,key,(__bridge CFPropertyListRef)publication[entity])) {
            [self withdrawDNS:nonce error:NULL]; return MLSystemError(error,@"configd 拒绝临时 DNS 接管配置",EIO);
        }
    }
    return YES;
#else
    (void)interface; (void)nonce; return MLSystemError(error,@"主机构建不修改 DNS",ENOTSUP);
#endif
}
- (BOOL)withdrawDNS:(NSString *)nonce error:(NSError **)error {
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
    if (![self store:error]) return NO;
    BOOL success=YES;
    for (NSString *entity in @[@"DNS",@"IPv4"]) {
        CFStringRef key=(__bridge CFStringRef)[MLDNSPrefix stringByAppendingString:entity];
        CFPropertyListRef current=_copy(_store,key);
        BOOL owned=current && CFGetTypeID(current)==CFDictionaryGetTypeID() &&
            [((__bridge NSDictionary *)current)[@"MuyuClashCaptureNonce"] isEqual:nonce];
        if (current) CFRelease(current);
        if (owned && !_remove(_store,key)) success=NO;
    }
    if (!success) return MLSystemError(error,@"本项目 DNS 服务记录尚未恢复",EIO);
    return YES;
#else
    (void)nonce; (void)error; return YES;
#endif
}
@end
id<MLCaptureBackend> MLCaptureSystemBackend(void) { return [MLCaptureDarwinBackend new]; }
