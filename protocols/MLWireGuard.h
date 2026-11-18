#ifndef ML_WIREGUARD_H
#define ML_WIREGUARD_H
#include "awg_config.h"
#include "vless.h"
#include <sys/types.h>
typedef struct MLWGSession MLWGSession;
MLWGSession *MLWGOpen(const awg_config_t *,const vless_dest_t *,int udp,unsigned timeoutMS);
int MLWGFD(const MLWGSession *);
ssize_t MLWGRead(MLWGSession *,void *,size_t);
ssize_t MLWGWrite(MLWGSession *,const void *,size_t);
void MLWGShutdown(MLWGSession *);
void MLWGClose(MLWGSession *);
int MLWGParseProfile(const char *,awg_config_t *,char *,size_t);
int MLWGDestinationAllowed(const awg_config_t *,const vless_dest_t *);
int MLWGDestinationPrefix(const awg_config_t *,const vless_dest_t *);
int MLWGResolve(const awg_config_t *,const char *,vless_dest_t *,unsigned timeoutMS);
#ifdef __OBJC__
@class NSDictionary,NSString;
NSString *MLWGValidateNode(NSDictionary *);
MLWGSession *MLWGOpenJSON(const char *,const char *,uint16_t,int,unsigned);
#endif
#endif
