#ifndef ML_CAPTURE_ROUTE_ABI_H
#define ML_CAPTURE_ROUTE_ABI_H
#include <stddef.h>
#include <stdint.h>
// iOS 6/XNU 2050 route.h wire ABI; the public iOS SDK omits this header.
// Widths are fixed even on the host so a host cannot write a different layout.
struct MLRouteHeader {
    uint16_t rtm_msglen;
    uint8_t rtm_version, rtm_type;
    uint16_t rtm_index, padding;
    int32_t rtm_flags, rtm_addrs, rtm_pid, rtm_seq, rtm_errno, rtm_use;
    uint32_t rtm_inits, metrics[14];
};
_Static_assert(sizeof(struct MLRouteHeader)==92,"Darwin routing header width");
_Static_assert(offsetof(struct MLRouteHeader,rtm_flags)==8,"Darwin route flags offset");
_Static_assert(offsetof(struct MLRouteHeader,rtm_addrs)==12,"Darwin route addresses offset");
_Static_assert(offsetof(struct MLRouteHeader,rtm_pid)==16,"Darwin route PID offset");
_Static_assert(offsetof(struct MLRouteHeader,rtm_seq)==20,"Darwin route sequence offset");
_Static_assert(offsetof(struct MLRouteHeader,rtm_errno)==24,"Darwin route errno offset");
enum { MLRouteVersion=5, MLRouteDump=1, MLRouteHost=4, MLRouteScoped=0x01000000, MLRouteSlots=8,
    MLRouteDestination=0, MLRouteGateway=1, MLRouteNetmask=2 };
#endif
