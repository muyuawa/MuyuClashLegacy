/* Verified SSH direct-tcpip channels over the existing bound stream layer. */
#include "MLSSH.h"
#include <errno.h>
#include <libssh2.h>
#include <mach/mach_time.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct MLSSH { MLStream *wire; LIBSSH2_SESSION *session; LIBSSH2_CHANNEL *channel; int closing; };
static pthread_once_t initialization = PTHREAD_ONCE_INIT;
static void initialize(void) { libssh2_init(0); }
static uint64_t millis(void) { mach_timebase_info_data_t tb; mach_timebase_info(&tb); return (mach_absolute_time()/1000000)*tb.numer/tb.denom; }
static LIBSSH2_SEND_FUNC(sendWire) {
    (void)socket;(void)flags;MLSSH *s=*abstract;if(s->closing)return -ECONNRESET;
    ssize_t n=MLStreamWrite(s->wire,buffer,length);return n>=0?n:-errno;
}
static LIBSSH2_RECV_FUNC(recvWire) {
    (void)socket;(void)flags;MLSSH *s=*abstract;if(s->closing)return -ECONNRESET;
    ssize_t n=MLStreamRead(s->wire,buffer,length);return n>=0?n:-errno;
}
static short eventsFor(MLSSH *s) {
    int directions=libssh2_session_block_directions(s->session);
    return MLStreamEvents(s->wire,(directions&LIBSSH2_SESSION_BLOCK_INBOUND)!=0,(directions&LIBSSH2_SESSION_BLOCK_OUTBOUND)!=0);
}
static int waitReady(MLSSH *s,uint64_t deadline) {
    uint64_t now=millis();if(now>=deadline){errno=ETIMEDOUT;return -1;}
    if(MLStreamPendingRead(s->wire))return MLStreamPump(s->wire);
    struct pollfd fd={MLStreamFD(s->wire),eventsFor(s),0};
    if(!fd.events)fd.events=POLLIN|POLLOUT;
    int r;do{r=poll(&fd,1,(int)(deadline-now));}while(r<0&&errno==EINTR);
    if(r==0){errno=ETIMEDOUT;return -1;}if(r<0)return -1;return MLStreamPump(s->wire);
}
static int trusted(LIBSSH2_SESSION *session,const char *pins) {
    size_t size=0;int type=0;const char *key=libssh2_session_hostkey(session,&size,&type);const char *hash=libssh2_hostkey_hash(session,LIBSSH2_HOSTKEY_HASH_SHA256);
    if(!key||!size||size>4096||!hash)return 0;
    unsigned char encoded[5500],digest[45];int n=EVP_EncodeBlock(encoded,(const unsigned char *)key,size);EVP_EncodeBlock(digest,(const unsigned char *)hash,32);digest[43]=0;
    for(const char *p=pins;*p;){const char *end=strchr(p,'\n');size_t length=end?(size_t)(end-p):strlen(p);
        if(length==50&&!memcmp(p,"SHA256:",7)&&!CRYPTO_memcmp(p+7,digest,43))return 1;
        const char *space=memchr(p,' ',length);if(space){size_t skip=space-p+1;p+=skip;length-=skip;}
        if(length==(size_t)n&&!CRYPTO_memcmp(p,encoded,length))return 1;
        if(!end)break;p=end+1;
    }
    return 0;
}
MLSSH *MLSSHOpen(MLStream *wire,const char *username,const char *password,const char *privateKey,const char *passphrase,const char *hostKeys,const char *algorithms,const char *dest,unsigned short port,unsigned timeoutMS) {
    pthread_once(&initialization,initialize);MLSSH *s=calloc(1,sizeof *s);if(!s)return NULL;s->wire=wire;
    s->session=libssh2_session_init_ex(NULL,NULL,NULL,s);if(!s->session){errno=ENOMEM;goto bad;}
    libssh2_session_set_blocking(s->session,0);
    libssh2_session_callback_set2(s->session,LIBSSH2_CALLBACK_SEND,(libssh2_cb_generic *)sendWire);
    libssh2_session_callback_set2(s->session,LIBSSH2_CALLBACK_RECV,(libssh2_cb_generic *)recvWire);
    if(*algorithms&&libssh2_session_method_pref(s->session,LIBSSH2_METHOD_HOSTKEY,algorithms)){errno=ENOTSUP;goto bad;}
    uint64_t deadline=millis()+timeoutMS;int r;
    while((r=libssh2_session_handshake(s->session,MLStreamFD(wire)))==LIBSSH2_ERROR_EAGAIN)if(waitReady(s,deadline))goto bad;
    if(r){errno=EPROTO;goto bad;}if(!trusted(s->session,hostKeys)){errno=EACCES;goto bad;}
    if(*privateKey){while((r=libssh2_userauth_publickey_frommemory(s->session,username,strlen(username),NULL,0,privateKey,strlen(privateKey),passphrase))==LIBSSH2_ERROR_EAGAIN)if(waitReady(s,deadline))goto bad;}
    else{while((r=libssh2_userauth_password_ex(s->session,username,strlen(username),password,strlen(password),NULL))==LIBSSH2_ERROR_EAGAIN)if(waitReady(s,deadline))goto bad;}
    if(r){errno=EACCES;goto bad;}
    do{s->channel=libssh2_channel_direct_tcpip_ex(s->session,dest,port,"127.0.0.1",0);
        if(s->channel)return s;r=libssh2_session_last_errno(s->session);if(r!=LIBSSH2_ERROR_EAGAIN)break;
    }while(!waitReady(s,deadline));
    if(r!=LIBSSH2_ERROR_EAGAIN)errno=ECONNREFUSED;
bad:{int error=errno;MLSSHClose(s);errno=error;return NULL;}
}
static ssize_t result(MLSSH *s,ssize_t n,short *events) {
    if(n>=0)return n;if(n==LIBSSH2_ERROR_EAGAIN){*events=eventsFor(s);errno=EAGAIN;}else errno=EPROTO;return -1;
}
ssize_t MLSSHRead(MLSSH *s,void *data,size_t n,short *events) {
    ssize_t r=libssh2_channel_read_ex(s->channel,0,data,n);
    if(r==0&&!libssh2_channel_eof(s->channel)){*events=eventsFor(s);if(!*events)*events=POLLIN;errno=EAGAIN;return -1;}return result(s,r,events);
}
ssize_t MLSSHWrite(MLSSH *s,const void *data,size_t n,short *events) { return result(s,libssh2_channel_write_ex(s->channel,0,data,n),events); }
int MLSSHShutdown(MLSSH *s,short *events) { return (int)result(s,libssh2_channel_send_eof(s->channel),events); }
void MLSSHClose(MLSSH *s) { if(!s)return;s->closing=1;if(s->session)libssh2_session_free(s->session);OPENSSL_cleanse(s,sizeof *s);free(s); }
