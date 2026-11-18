#ifndef ML_DNS_DOQ_H
#define ML_DNS_DOQ_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* RFC 9250: a verified QUIC connection, one bidi stream, one framed request
   and reply, FIN in both directions, ALPN doq, no 0-RTT. The request ID is
   normalized to zero; the response ID stays zero for the DNS owner to restore.
   Physical socket binding and bootstrap host resolution use MLNetworkBinding.
   Returns response length, or -1 with errno and a bounded diagnostic. */
ssize_t MLDNSDoQQuery(const char *host,uint16_t port,const char *serverName,
                     const char *caFile,const void *query,size_t queryLength,
                     void *response,size_t responseCapacity,unsigned timeoutMS,
                     char *error,size_t errorCapacity);
#endif
