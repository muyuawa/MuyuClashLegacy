#import "MLCapture.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <TargetConditionals.h>
#include <net/if.h>
#include <string.h>
#if TARGET_OS_IPHONE
// The public iOS SDK omits these kernel-control declarations. ABI definitions
// match Apple's XNU kern_control.h; availability is still probed at runtime.
struct ml_ctl_info { uint32_t ctl_id; char ctl_name[96]; };
#define ML_CTLIOCGINFO _IOWR('N', 3, struct ml_ctl_info)
#define ML_SYSPROTO_CONTROL 2
#else
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#define ml_ctl_info ctl_info
#define ML_CTLIOCGINFO CTLIOCGINFO
#define ML_SYSPROTO_CONTROL SYSPROTO_CONTROL
#endif
#include <unistd.h>
#include <errno.h>

static int MLGetUTunControl(int fd, struct ml_ctl_info *info) {
    memset(info, 0, sizeof(*info));
    strlcpy(info->ctl_name, "com.apple.net.utun_control", sizeof(info->ctl_name));
    return ioctl(fd, ML_CTLIOCGINFO, info);
}

NSDictionary *MLCaptureCoverage(void) {
    // No backend is integrated yet. Probe presence never implies traffic coverage.
    return @{@"tcp":@"未接管",@"udp":@"未接管",@"ipv4":@"未接管",@"ipv6":@"未接管",@"dns":@"未接管"};
}
NSDictionary *MLCaptureProbe(void) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, ML_SYSPROTO_CONTROL);
    BOOL registered = NO; int probeError = fd < 0 ? errno : 0;
    if (fd >= 0) {
        struct ml_ctl_info info;
        registered = MLGetUTunControl(fd, &info) == 0;
        if (!registered) probeError = errno;
        close(fd);
    }
    struct stat status;
    BOOL pfPresent = lstat("/dev/pf", &status) == 0 && S_ISCHR(status.st_mode);
    return @{
        @"utun":@{@"registered":@(registered),@"probeErrno":@(probeError),@"integrated":@NO,@"verified":@NO},
        @"pf":@{@"devicePresent":@(pfPresent),@"integrated":@NO,@"verified":@NO},
        @"socketHook":@{@"integrated":@NO,@"verified":@NO},
        @"strictBlockAvailable":@NO,
        @"coverage":MLCaptureCoverage(),
        @"reason":@"接管后端尚未完成集成和目标设备验证；未修改系统网络。"
    };
}

#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
// XNU sockaddr_ctl and option numbers, also used in the pinned Senko utun_device.c.
struct MLUTunControlAddress {
    uint8_t length;
    uint8_t family;
    uint16_t systemAddress;
    uint32_t controlID;
    uint32_t unit;
    uint32_t reserved[5];
};
enum { MLSystemControlAddress = 2, MLUTunInterfaceNameOption = 2 };
_Static_assert(sizeof(struct MLUTunControlAddress) == 32, "Darwin sockaddr_ctl ABI");
_Static_assert(sizeof(struct ml_ctl_info) == 100, "Darwin ctl_info ABI");

static int MLUTunDetachError(const char *name, unsigned int index) {
    // Verify the original name/index pair. Another process can claim a new unit concurrently.
    for (unsigned int attempt = 0; attempt < 20; ++attempt) {
        errno = 0;
        struct if_nameindex *interfaces = if_nameindex();
        if (!interfaces) return errno ?: EIO;
        BOOL present = NO;
        for (struct if_nameindex *entry = interfaces; entry->if_index != 0; ++entry) {
            if (entry->if_index == index && strcmp(entry->if_name, name) == 0) {
                present = YES;
                break;
            }
        }
        if_freenameindex(interfaces);
        if (!present) return 0;
        if (attempt < 19) usleep(50000);
    }
    return ETIMEDOUT;
}

static void MLProbeUTunLifecycle(NSMutableDictionary *result) {
    if (geteuid() != 0) {
        result[@"stage"] = @"privilege";
        result[@"errno"] = @(EPERM);
        return;
    }

    NSString *stage = @"socket";
    BOOL registered = NO, opened = NO, detached = NO;
    int probeError = 0, closeError = 0;
    char name[IF_NAMESIZE] = {0};
    socklen_t nameSize = sizeof(name);
    unsigned int index = 0;
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, ML_SYSPROTO_CONTROL);
    if (fd < 0) {
        probeError = errno;
        goto report;
    }

    stage = @"control-lookup";
    struct ml_ctl_info info;
    if (MLGetUTunControl(fd, &info) != 0) {
        probeError = errno;
        goto closeSocket;
    }
    registered = YES;

    stage = @"connect";
    struct MLUTunControlAddress address = {
        .length = sizeof(address), .family = AF_SYSTEM,
        .systemAddress = MLSystemControlAddress, .controlID = info.ctl_id,
        .unit = 0 // Allocate a free unit in the kernel.
    };
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        probeError = errno;
        goto closeSocket;
    }
    opened = YES;

    stage = @"interface-name";
    if (getsockopt(fd, ML_SYSPROTO_CONTROL, MLUTunInterfaceNameOption, name, &nameSize) != 0) {
        probeError = errno;
        goto closeSocket;
    }
    if (nameSize < 6 || nameSize > sizeof(name) || !memchr(name, '\0', nameSize) ||
        strncmp(name, "utun", 4) != 0 || !name[4] || name[4 + strspn(name + 4, "0123456789")]) {
        probeError = EPROTO;
        goto closeSocket;
    }
    result[@"interfaceName"] = [NSString stringWithUTF8String:name];

    stage = @"interface-index";
    errno = 0;
    index = if_nametoindex(name);
    if (index == 0) {
        probeError = errno ?: ENXIO;
        goto closeSocket;
    }
    result[@"interfaceIndex"] = @(index);

closeSocket:
    if (close(fd) != 0) closeError = errno;
    if (probeError == 0) {
        if (closeError != 0) {
            stage = @"close";
            probeError = closeError;
        } else {
            stage = @"detach";
            probeError = MLUTunDetachError(name, index);
            detached = probeError == 0;
        }
    }

report:
    if (closeError != 0) result[@"closeErrno"] = @(closeError);
    BOOL unavailable = !opened && (probeError == ENOENT || probeError == ENXIO ||
                        probeError == ENOTSUP || probeError == EAFNOSUPPORT ||
                        probeError == EPROTONOSUPPORT || probeError == EPERM || probeError == EACCES);
    result[@"status"] = detached ? @"success" : (unavailable ? @"unavailable" : @"failed");
    result[@"stage"] = detached ? @"complete" : stage;
    result[@"errno"] = @(probeError);
    result[@"registered"] = @(registered);
    result[@"opened"] = @(opened);
    result[@"detached"] = @(detached);
}
#endif

NSDictionary *MLCaptureUTunLifecycleProbe(void) {
    NSMutableDictionary *result = [@{
        @"probe":@"utun-lifecycle", @"status":@"unavailable", @"stage":@"platform", @"errno":@(ENOTSUP),
        @"registered":@NO, @"opened":@NO, @"detached":@NO,
        @"integrated":@NO, @"verified":@NO, @"coverage":MLCaptureCoverage()
    } mutableCopy];
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
    MLProbeUTunLifecycle(result);
#endif
    return result;
}
