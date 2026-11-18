#ifndef ML_SSH_H
#define ML_SSH_H
#include "MLStream.h"
#include <sys/types.h>
typedef struct MLSSH MLSSH;
MLSSH *MLSSHOpen(MLStream *wire,const char *username,const char *password,const char *privateKey,const char *passphrase,const char *hostKeys,const char *algorithms,const char *dest,unsigned short port,unsigned timeoutMS);
ssize_t MLSSHRead(MLSSH *,void *,size_t,short *events);
ssize_t MLSSHWrite(MLSSH *,const void *,size_t,short *events);
int MLSSHShutdown(MLSSH *,short *events);
void MLSSHClose(MLSSH *);
#endif
