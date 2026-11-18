#import "MLFetch.h"
#include <curl/curl.h>
#include <dispatch/dispatch.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../transport/MLNetworkBinding.h"

typedef struct {
    __unsafe_unretained NSMutableData *data;
    __unsafe_unretained NSMutableDictionary *headers;
    NSUInteger limit;
    BOOL exceededLimit;
} MLFetchBuffer;

static int MLFetchSocketOption(void *context, curl_socket_t fd, curlsocktype purpose) {
    (void)context; (void)purpose;
    return MLNetworkBindSocket(fd, AF_UNSPEC) == 0 ? CURL_SOCKOPT_OK : CURL_SOCKOPT_ERROR;
}
static size_t MLFetchBytes(void *bytes, size_t size, size_t count, void *context) {
    MLFetchBuffer *buffer = context;
    if (size && count > SIZE_MAX / size) return 0;
    size_t length = size * count;
    if (length > buffer->limit || buffer->data.length > buffer->limit - length) {
        buffer->exceededLimit = YES;
        return 0;
    }
    [buffer->data appendBytes:bytes length:length];
    return length;
}
static size_t MLFetchHeader(void *bytes, size_t size, size_t count, void *context) {
    if (size && count > SIZE_MAX / size) return 0;
    size_t length = size * count;
    if (length > 8192) return 0;
    MLFetchBuffer *buffer = context;
    NSString *line = [[NSString alloc] initWithBytes:bytes length:length encoding:NSISOLatin1StringEncoding];
    if ([line hasPrefix:@"HTTP/"]) [buffer->headers removeAllObjects];
    if ([line.lowercaseString hasPrefix:@"location:"]) {
        NSString *value = [[line substringFromIndex:9] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (value.length > 4096 || buffer->headers[@"location"]) return 0;
        buffer->headers[@"location"] = value;
    }
    return length;
}
static NSURL *MLFetchURL(NSString *url) {
    if (![url isKindOfClass:[NSString class]] || url.length > 4096 ||
        [url rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location != NSNotFound) return nil;
    NSURL *parsed = [NSURL URLWithString:url];
    return [parsed.scheme.lowercaseString isEqual:@"https"] && parsed.host.length &&
           !parsed.user.length && !parsed.password.length ? parsed : nil;
}
static struct curl_slist *MLFetchResolved(NSURL *url) {
    if (!MLNetworkInterfaceIndex()) return NULL;
    NSString *host = url.host;
    if ([host hasPrefix:@"["] && [host hasSuffix:@"]"]) host = [host substringWithRange:NSMakeRange(1,host.length-2)];
    struct in_addr v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET,host.UTF8String,&v4) == 1 || inet_pton(AF_INET6,host.UTF8String,&v6) == 1) return NULL;
    NSString *port = url.port.stringValue ?: @"443";
    struct addrinfo hints = {0}, *addresses = NULL;
    hints.ai_socktype = SOCK_STREAM;
    if (MLNetworkResolveBootstrapHost(host.UTF8String,port.UTF8String,&hints,&addresses)) return NULL;
    NSMutableArray *ips = [NSMutableArray array];
    for (struct addrinfo *item = addresses; item; item = item->ai_next) {
        char ip[INET6_ADDRSTRLEN];
        if (getnameinfo(item->ai_addr,item->ai_addrlen,ip,sizeof(ip),NULL,0,NI_NUMERICHOST)) continue;
        NSString *text = [NSString stringWithUTF8String:ip];
        [ips addObject:item->ai_family == AF_INET6 ? [NSString stringWithFormat:@"[%@]",text] : text];
    }
    freeaddrinfo(addresses);
    NSString *entry = [NSString stringWithFormat:@"%@:%@:%@",host,port,[ips componentsJoinedByString:@","]];
    return ips.count ? curl_slist_append(NULL,entry.UTF8String) : NULL;
}
NSData *MLFetchDataWithTimeout(NSString *url, NSString *caPath, NSUInteger limit, NSUInteger timeoutMS, NSError **error) {
    if (error) *error = nil;
    NSURL *parsed = MLFetchURL(url);
    if (!parsed || !limit || limit > 32*1024*1024 || timeoutMS<100 || timeoutMS>120000) {
        if (error) *error = [NSError errorWithDomain:@"E_SUBSCRIPTION_URL" code:1 userInfo:@{NSLocalizedDescriptionKey:@"订阅地址必须是无内嵌凭据的 HTTPS URL，并使用有界下载限制"}];
        return nil;
    }
    static dispatch_once_t once;
    dispatch_once(&once, ^{ curl_global_init(CURL_GLOBAL_DEFAULT); });
    CURL *curl = curl_easy_init();
    if (!curl) return nil;
    NSData *answer = nil;
    CURLcode result = CURLE_OK;
    double deadline = [NSProcessInfo processInfo].systemUptime + timeoutMS/1000.0;
    for (unsigned redirect = 0; redirect <= 3; redirect++) {
        NSMutableData *data = [NSMutableData data];
        NSMutableDictionary *headers = [NSMutableDictionary dictionary];
        MLFetchBuffer buffer = {data,headers,limit,NO};
        struct curl_slist *resolved = MLFetchResolved(parsed);
        NSString *host = parsed.host;
        struct in_addr v4; struct in6_addr v6;
        BOOL numeric = inet_pton(AF_INET,host.UTF8String,&v4) == 1 || inet_pton(AF_INET6,host.UTF8String,&v6) == 1 || [host hasPrefix:@"["];
        if (MLNetworkInterfaceIndex() && !numeric && !resolved) { result = CURLE_COULDNT_RESOLVE_HOST; break; }
        long remaining = (long)((deadline-[NSProcessInfo processInfo].systemUptime)*1000);
        if (remaining <= 0) { curl_slist_free_all(resolved); result = CURLE_OPERATION_TIMEDOUT; break; }
        curl_easy_reset(curl);
        curl_easy_setopt(curl,CURLOPT_URL,parsed.absoluteString.UTF8String);
        curl_easy_setopt(curl,CURLOPT_PROTOCOLS_STR,"https");
        curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,0L);
        curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,1L);
        curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,2L);
        if (caPath) curl_easy_setopt(curl,CURLOPT_CAINFO,caPath.fileSystemRepresentation);
        long connectBudget = timeoutMS > 4000 ? 10000L : 2500L;
        curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT_MS,MIN(connectBudget,remaining));
        curl_easy_setopt(curl,CURLOPT_TIMEOUT_MS,remaining);
        curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);
        curl_easy_setopt(curl,CURLOPT_PROXY,"");
        curl_easy_setopt(curl,CURLOPT_SOCKOPTFUNCTION,MLFetchSocketOption);
        curl_easy_setopt(curl,CURLOPT_RESOLVE,resolved);
        curl_easy_setopt(curl,CURLOPT_USERAGENT,"MuyuClash-Legacy/development");
        curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,MLFetchBytes);
        curl_easy_setopt(curl,CURLOPT_WRITEDATA,&buffer);
        curl_easy_setopt(curl,CURLOPT_HEADERFUNCTION,MLFetchHeader);
        curl_easy_setopt(curl,CURLOPT_HEADERDATA,&buffer);
        result = curl_easy_perform(curl);
        if (buffer.exceededLimit) result = CURLE_FILESIZE_EXCEEDED;
        long status = 0;
        curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
        curl_slist_free_all(resolved);
        if (result != CURLE_OK) break;
        if (status >= 200 && status < 300) { answer = [data copy]; break; }
        if (![@[@301,@302,@303,@307,@308] containsObject:@(status)] || !headers[@"location"] || redirect == 3) { result = CURLE_HTTP_RETURNED_ERROR; break; }
        NSURL *next = [NSURL URLWithString:headers[@"location"] relativeToURL:parsed];
        parsed = MLFetchURL(next.absoluteURL.absoluteString);
        if (!parsed) { result = CURLE_UNSUPPORTED_PROTOCOL; break; }
    }
    curl_easy_cleanup(curl);
    if (!answer && error) {
        NSString *reason = result == CURLE_FILESIZE_EXCEEDED ? [NSString stringWithFormat:@"下载内容超过 %lu KiB 上限",(unsigned long)(limit/1024)] : [NSString stringWithUTF8String:curl_easy_strerror(result)];
        *error = [NSError errorWithDomain:@"E_SUBSCRIPTION_FETCH" code:result userInfo:@{NSLocalizedDescriptionKey:[@"订阅下载失败：" stringByAppendingString:reason]}];
    }
    return answer;
}
NSData *MLFetchData(NSString *url, NSString *caPath, NSUInteger limit, NSError **error) {
    return MLFetchDataWithTimeout(url,caPath,limit,4000,error);
}
NSString *MLFetchSubscription(NSString *url, NSString *caPath, NSError **error) {
    NSData *data = MLFetchData(url,caPath,512*1024,error);
    if (!data) return nil;
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!text && error) *error = [NSError errorWithDomain:@"E_SUBSCRIPTION_FETCH" code:1 userInfo:@{NSLocalizedDescriptionKey:@"订阅不是 UTF-8 文本"}];
    return text;
}
