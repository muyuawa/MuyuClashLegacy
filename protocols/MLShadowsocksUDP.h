#ifndef ML_SHADOWSOCKS_UDP_H
#define ML_SHADOWSOCKS_UDP_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "vless.h"
typedef struct MLShadowsocksUDP MLShadowsocksUDP;
MLShadowsocksUDP *MLShadowsocksUDPOpen(const char *cipher, const char *password, const vless_dest_t *target);
ssize_t MLShadowsocksUDPEncode(MLShadowsocksUDP *session, const uint8_t *data, size_t size, uint8_t *wire, size_t capacity);
ssize_t MLShadowsocksUDPDecode(MLShadowsocksUDP *session, const uint8_t *wire, size_t size, uint8_t *data, size_t capacity);
void MLShadowsocksUDPClose(MLShadowsocksUDP *session);
#endif
