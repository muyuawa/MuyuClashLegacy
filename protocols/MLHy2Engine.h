#ifndef ML_HY2_DATAGRAM_ENGINE_H
#define ML_HY2_DATAGRAM_ENGINE_H
#include "hy2_engine.h"
#include <sys/types.h>
typedef struct MLHy2UDP MLHy2UDP;
int MLHy2WaitReady(hy2_engine_t *engine, unsigned timeoutMS);
MLHy2UDP *MLHy2UDPOpen(hy2_engine_t *engine, const char *address);
int MLHy2UDPFD(MLHy2UDP *session);
ssize_t MLHy2UDPSend(MLHy2UDP *session, const void *data, size_t size);
ssize_t MLHy2UDPReceive(MLHy2UDP *session, void *data, size_t size);
void MLHy2UDPClose(MLHy2UDP *session);
#endif
