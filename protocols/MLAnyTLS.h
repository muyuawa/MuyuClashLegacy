#ifndef ML_ANYTLS_H
#define ML_ANYTLS_H
#include "MLStream.h"
#include "vless.h"
typedef struct MLAnyTLS MLAnyTLS;
typedef MLStream *(*MLAnyTLSFactory)(void *context,unsigned timeoutMS);
MLAnyTLS *MLAnyTLSOpen(const char *identity,const char *password,const vless_dest_t *dest,unsigned checkSeconds,unsigned idleSeconds,unsigned minIdle,unsigned timeoutMS,MLAnyTLSFactory,void *context);
MLAnyTLS *MLAnyTLSOpenUDP(const char *identity,const char *password,const vless_dest_t *dest,unsigned checkSeconds,unsigned idleSeconds,unsigned minIdle,unsigned timeoutMS,MLAnyTLSFactory,void *context);
int MLAnyTLSFD(const MLAnyTLS *);
ssize_t MLAnyTLSRead(MLAnyTLS *,void *,size_t);
ssize_t MLAnyTLSWrite(MLAnyTLS *,const void *,size_t);
int MLAnyTLSPump(MLAnyTLS *);
void MLAnyTLSShutdown(MLAnyTLS *);
void MLAnyTLSClose(MLAnyTLS *);
/* Test/diagnostic counters for actual session reuse and per-client schemes. */
unsigned long long MLAnyTLSSequence(const MLAnyTLS *);
int MLAnyTLSPaddingMD5(const MLAnyTLS *,char out[33]);
int MLAnyTLSSessionPaddingMD5(const MLAnyTLS *,char out[33]);
#endif
