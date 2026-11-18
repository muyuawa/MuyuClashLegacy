#ifndef ML_TUIC_ENGINE_H
#define ML_TUIC_ENGINE_H
#include "hy2_engine.h"
#include "vless.h"
#include <sys/types.h>
typedef struct {
    hy2_engine_config_t quic;
    uint8_t uuid[16],alpn[256];size_t alpnLength;
    unsigned congestion,heartbeatMS,maxUDPPayload;int disableSNI;
} MLTUICConfig;
typedef struct MLTUICUDP MLTUICUDP;
hy2_engine_t *MLTUICStart(const MLTUICConfig *,char *error,size_t cap);
int MLTUICDial(hy2_engine_t *,char *error,size_t cap);
void MLTUICStop(hy2_engine_t *);
extern const transport_vt_t ml_tuic_transport;
size_t MLTUICAddress(const vless_dest_t *,uint8_t *out,size_t cap);
MLTUICUDP *MLTUICUDPOpen(hy2_engine_t *,const vless_dest_t *,int reliable);
int MLTUICUDPFD(const MLTUICUDP *);
ssize_t MLTUICUDPSend(MLTUICUDP *,const void *,size_t);
ssize_t MLTUICUDPReceive(MLTUICUDP *,void *,size_t);
void MLTUICUDPClose(MLTUICUDP *);
#endif
