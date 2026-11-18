#import "MLDoH.h"
#include <curl/curl.h>
#include <dispatch/dispatch.h>
#include <TargetConditionals.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../transport/MLNetworkBinding.h"

static int MLDoHSocketOption(void *context, curl_socket_t fd, curlsocktype purpose) {
    (void)context; (void)purpose;
    return MLNetworkBindSocket(fd, AF_UNSPEC) == 0 ? CURL_SOCKOPT_OK : CURL_SOCKOPT_ERROR;
}

static size_t MLDoHReceive(void *bytes, size_t size, size_t count, void *context) {
    if (size && count > SIZE_MAX / size) return 0;
    size_t length = size * count;
    NSMutableData *data = (__bridge NSMutableData *)context;
    if (length > 4096 || data.length > 4096-length) return 0;
    [data appendBytes:bytes length:length];
    return length;
}

NSData *MLDoHQuery(NSString *url, NSData *query, NSString *caPath, long timeoutMS) {
    static dispatch_once_t once;
    dispatch_once(&once,^{ curl_global_init(CURL_GLOBAL_DEFAULT); });
    CURL *request = curl_easy_init();
    if (!request) return nil;
    struct curl_slist *headers = curl_slist_append(NULL,"Content-Type: application/dns-message");
    struct curl_slist *all = headers ? curl_slist_append(headers,"Accept: application/dns-message") : NULL;
    if (!all) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(request);
        return nil;
    }
    NSMutableData *body = [NSMutableData data];
    struct curl_slist *resolved = NULL;
    if (MLNetworkInterfaceIndex()) {
        NSURL *endpoint = [NSURL URLWithString:url];
        NSString *host = endpoint.host;
        if ([host hasPrefix:@"["] && [host hasSuffix:@"]"]) host = [host substringWithRange:NSMakeRange(1,host.length-2)];
        struct in_addr v4; struct in6_addr v6;
        if (inet_pton(AF_INET,host.UTF8String,&v4) != 1 && inet_pton(AF_INET6,host.UTF8String,&v6) != 1) {
            NSString *port = endpoint.port.stringValue ?: @"443";
            struct addrinfo hints = {0}, *addresses = NULL;
            hints.ai_socktype = SOCK_STREAM;
            NSMutableArray *ips = [NSMutableArray array];
            if (MLNetworkResolveBootstrapHost(host.UTF8String,port.UTF8String,&hints,&addresses) == 0) {
                for (struct addrinfo *entry = addresses; entry; entry = entry->ai_next) {
                    char ip[INET6_ADDRSTRLEN];
                    if (!getnameinfo(entry->ai_addr,entry->ai_addrlen,ip,sizeof(ip),NULL,0,NI_NUMERICHOST)) {
                        NSString *text = [NSString stringWithUTF8String:ip];
                        [ips addObject:entry->ai_family == AF_INET6 ? [NSString stringWithFormat:@"[%@]",text] : text];
                    }
                }
                freeaddrinfo(addresses);
            }
            NSString *value = [NSString stringWithFormat:@"%@:%@:%@",host,port,[ips componentsJoinedByString:@","]];
            if (!ips.count || !(resolved = curl_slist_append(NULL,value.UTF8String))) {
                curl_slist_free_all(all); curl_easy_cleanup(request); return nil;
            }
        }
    }
    curl_easy_setopt(request,CURLOPT_HTTPHEADER,all);
    curl_easy_setopt(request,CURLOPT_URL,url.UTF8String);
    curl_easy_setopt(request,CURLOPT_PROTOCOLS_STR,"https");
    curl_easy_setopt(request,CURLOPT_PROXY,"");
    curl_easy_setopt(request,CURLOPT_SOCKOPTFUNCTION,MLDoHSocketOption);
    curl_easy_setopt(request,CURLOPT_RESOLVE,resolved);
    curl_easy_setopt(request,CURLOPT_NOSIGNAL,1L);
    curl_easy_setopt(request,CURLOPT_TIMEOUT_MS,timeoutMS);
    curl_easy_setopt(request,CURLOPT_CONNECTTIMEOUT_MS,MIN(timeoutMS,1500L));
    curl_easy_setopt(request,CURLOPT_SSL_VERIFYPEER,1L);
    curl_easy_setopt(request,CURLOPT_SSL_VERIFYHOST,2L);
#if TARGET_OS_IPHONE
    if (!caPath) caPath = @"/usr/share/muyuclash/cacert.pem";
#endif
    if (caPath) curl_easy_setopt(request,CURLOPT_CAINFO,caPath.fileSystemRepresentation);
    curl_easy_setopt(request,CURLOPT_POSTFIELDS,query.bytes);
    curl_easy_setopt(request,CURLOPT_POSTFIELDSIZE,(long)query.length);
    curl_easy_setopt(request,CURLOPT_WRITEDATA,(__bridge void *)body);
    curl_easy_setopt(request,CURLOPT_WRITEFUNCTION,MLDoHReceive);
    CURLcode result = curl_easy_perform(request);
    long code = 0;
    char *contentType = NULL;
    curl_easy_getinfo(request,CURLINFO_RESPONSE_CODE,&code);
    curl_easy_getinfo(request,CURLINFO_CONTENT_TYPE,&contentType);
    BOOL accepted = result == CURLE_OK && code == 200 && contentType &&
                    strcasecmp(contentType,"application/dns-message") == 0;
    curl_easy_cleanup(request);
    curl_slist_free_all(all);
    curl_slist_free_all(resolved);
    return accepted ? body : nil;
}
