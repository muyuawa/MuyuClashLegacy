#ifndef ML_PROCESS_OWNER_ABI_H
#define ML_PROCESS_OWNER_ABI_H
#include <stdint.h>
#include <stddef.h>
struct MLProcessSocketFD {
    uint8_t file[24],stat[136];uint64_t socket,pcb;
    int32_t type,protocol,family;int16_t flags[8];uint32_t oob;
    uint8_t receive[24],send[24];int32_t kind;uint32_t reserved;uint64_t transport[66];
};
struct MLProcessFD {int32_t descriptor;uint32_t type;};
_Static_assert(sizeof(struct MLProcessSocketFD)==792,"XNU 2050 socket_fdinfo ABI");
_Static_assert(offsetof(struct MLProcessSocketFD,transport)==264,"XNU 2050 socket protocol offset");
#endif
