#ifndef ML_UDP_PACKETS_H
#define ML_UDP_PACKETS_H
#include <stddef.h>
#include <stdint.h>
#include "core/tun_flow.h"
typedef struct MLUDPPackets MLUDPPackets;
typedef int (*MLUDPPacketReceive)(void *,const tun_flow_key_t *,const uint8_t *,size_t);
typedef int (*MLUDPPacketWrite)(void *,const uint8_t *,size_t);
MLUDPPackets *MLUDPPacketsCreate(void);
void MLUDPPacketsDestroy(MLUDPPackets *);
// 1 means consumed (including rejected UDP), 0 leaves TCP/other frames to lwIP.
int MLUDPPacketsInput(MLUDPPackets *,const uint8_t *,size_t,uint64_t,MLUDPPacketReceive,void *);
int MLUDPPacketsReply(MLUDPPackets *,const tun_flow_key_t *,const uint8_t *,size_t,uint64_t);
void MLUDPPacketsDrain(MLUDPPackets *,uint64_t,MLUDPPacketWrite,void *);
size_t MLUDPPacketsPending(const MLUDPPackets *);
void MLUDPPacketsCounts(const MLUDPPackets *,uint64_t *input,uint64_t *output,uint64_t *invalid);
#endif
