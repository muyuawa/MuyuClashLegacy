#import "MLDNS.h"
#import "MLDoH.h"
#import "MLDNSWire.h"
#import "../protocols/MLDNSDoQ.h"
#import "../transport/MLNetworkBinding.h"
#import "MLFakeIP.h"
#import "../providers/MLGeoIndex.h"
#import "../routing/MLRouting.h"
#import "../routing/MLRoutingInternal.h"
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#include <string.h>
#include <TargetConditionals.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fnmatch.h>

static NSDictionary *MLDNSSystemHosts(void) {
    int fd=open("/etc/hosts",O_RDONLY|O_NOFOLLOW);
    struct stat status;
    if (fd<0) return @{};
    if (fstat(fd,&status)||!S_ISREG(status.st_mode)||status.st_size>65536) { close(fd); return @{}; }
    uint8_t bytes[65537]; size_t used=0;
    while (used<sizeof(bytes)) { ssize_t n=read(fd,bytes+used,sizeof(bytes)-used); if (n<=0) break; used+=(size_t)n; }
    close(fd);
    if (used>65536) return @{};
    NSString *text=[[NSString alloc]initWithBytes:bytes length:used encoding:NSUTF8StringEncoding];
    NSMutableDictionary *hosts=[NSMutableDictionary dictionary];
    for (NSString *line in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        NSString *content=[[line componentsSeparatedByString:@"#"] firstObject];
        NSMutableArray *fields=[NSMutableArray array];
        for (NSString *field in [content componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]) if (field.length) [fields addObject:field];
        if (fields.count<2) continue;
        struct in_addr v4; struct in6_addr v6;
        if (inet_pton(AF_INET,[fields[0] UTF8String],&v4)!=1&&inet_pton(AF_INET6,[fields[0] UTF8String],&v6)!=1) continue;
        for (NSUInteger index=1;index<fields.count;index++) {
            NSString *host=[fields[index] lowercaseString];
            if (!host.length||host.length>253) continue;
            NSMutableArray *addresses=hosts[host];
            if (!addresses) { addresses=[NSMutableArray array]; hosts[host]=addresses; }
            if (addresses.count<16&&![addresses containsObject:fields[0]]) [addresses addObject:fields[0]];
        }
    }
    return hosts;
}

static BOOL MLBoolean(id value) {
    return [value isKindOfClass:[NSNumber class]] && CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID();
}

static BOOL MLNameserver(NSString *text, union res_sockaddr_union *server, BOOL *tcp) {
    if (![text isKindOfClass:[NSString class]] || !text.length || text.length > 86) return NO;
    *tcp = [text hasPrefix:@"tcp://"];
    if (*tcp || [text hasPrefix:@"udp://"]) text = [text substringFromIndex:6];
    NSString *ip = text, *port = nil;
    NSArray *parts = [text componentsSeparatedByString:@":"];
    if ([text hasPrefix:@"["]) {
        NSRange close = [text rangeOfString:@"]"];
        if (close.location == NSNotFound) return NO;
        ip = [text substringWithRange:NSMakeRange(1,close.location-1)];
        NSString *suffix = [text substringFromIndex:NSMaxRange(close)];
        if (suffix.length) {
            if (![suffix hasPrefix:@":"] || suffix.length < 2) return NO;
            port = [suffix substringFromIndex:1];
        }
    } else if (parts.count == 2) {
        ip = parts[0]; port = parts[1];
    }
    NSCharacterSet *nonDigits = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789"] invertedSet];
    if (port && (port.length > 5 || !port.length ||
                 [port rangeOfCharacterFromSet:nonDigits].location != NSNotFound ||
                 port.integerValue <= 0 || port.integerValue > 65535)) return NO;
    memset(server,0,sizeof(*server));
    in_port_t wirePort = htons(port ? (uint16_t)port.integerValue : 53);
    if (inet_pton(AF_INET,ip.UTF8String,&server->sin.sin_addr) == 1) {
        server->sin.sin_family = AF_INET;
        server->sin.sin_len = sizeof(server->sin);
        server->sin.sin_port = wirePort;
    } else if (inet_pton(AF_INET6,ip.UTF8String,&server->sin6.sin6_addr) == 1) {
        server->sin6.sin6_family = AF_INET6;
        server->sin6.sin6_len = sizeof(server->sin6);
        server->sin6.sin6_port = wirePort;
    } else return NO;
    return YES;
}

static BOOL MLDoHURL(NSString *text) {
    if (![text isKindOfClass:[NSString class]] || text.length > 1024 || ![text hasPrefix:@"https://"]) return NO;
    NSURL *url = [NSURL URLWithString:text];
    return url.host.length && !url.user && !url.password && !url.fragment;
}

static NSURL *MLDNSVerifiedURL(NSString *text, NSString *scheme) {
    if (![text isKindOfClass:[NSString class]] || text.length > 1024 || ![text hasPrefix:[scheme stringByAppendingString:@"://"]] ||
        [text rangeOfCharacterFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].location!=NSNotFound ||
        [text rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound) return nil;
    NSURL *url = [NSURL URLWithString:text];
    if (!url.host.length || url.user || url.password || url.query || url.fragment ||
        (url.path.length && ![url.path isEqual:@"/"]) ||
        (url.port && (url.port.integerValue < 1 || url.port.integerValue > UINT16_MAX))) return nil;
    return url;
}

static NSString *MLDNSBaseServer(NSString *text) {
    if (![text isKindOfClass:[NSString class]]) return nil;
    NSRange fragment=[text rangeOfString:@"#" options:NSBackwardsSearch];
    if (fragment.location==NSNotFound) return text;
    NSString *target=[text substringFromIndex:fragment.location+1];
    if (!target.length || target.length>256 || [target rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound) return nil;
    return [text substringToIndex:fragment.location];
}
static BOOL MLDNSEndpoint(NSString *text, BOOL numeric) {
    NSString *base=MLDNSBaseServer(text); union res_sockaddr_union server; BOOL tcp;
    BOOL doq=base && MLDNSVerifiedURL(base,@"quic")!=nil;
    // The DoQ engine has direct UDP IO; named proxy nesting cannot be applied.
    if (doq && ![text isEqual:base] && ![[text substringFromIndex:base.length+1] isEqual:@"DIRECT"]) return NO;
    return base && (MLNameserver(base,&server,&tcp) || (!numeric && (MLDoHURL(base) || MLDNSVerifiedURL(base,@"tls") || doq)));
}
static NSArray *MLDNSPatterns(NSString *pattern) {
    if (![pattern isKindOfClass:[NSString class]] || !pattern.length || pattern.length>1024) return nil;
    NSString *prefix=[pattern.lowercaseString hasPrefix:@"geosite:"] ? @"geosite:" : ([pattern.lowercaseString hasPrefix:@"rule-set:"] ? @"rule-set:" : nil);
    NSString *body=prefix ? [pattern substringFromIndex:prefix.length] : pattern;
    NSArray *parts=[body componentsSeparatedByString:@","]; if (parts.count>32) return nil;
    NSMutableArray *result=[NSMutableArray array];
    for (NSString *part in parts) {
        if (!part.length || part.length>253 || [part rangeOfCharacterFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].location!=NSNotFound || [part rangeOfString:@":"].location!=NSNotFound) return nil;
        [result addObject:prefix ? [prefix stringByAppendingString:part] : part];
    }
    return result;
}
static NSArray *MLDNSAllDomainPatterns(NSDictionary *options) {
    NSMutableArray *result=[NSMutableArray array];
    if ([options[@"nameserver-policy"] isKindOfClass:[NSDictionary class]]) [result addObjectsFromArray:[options[@"nameserver-policy"] allKeys]];
    if ([options[@"fake-ip-filter"] isKindOfClass:[NSArray class]]) [result addObjectsFromArray:options[@"fake-ip-filter"]];
    return result;
}
NSArray *MLDNSGeoRequests(NSDictionary *options) {
    NSMutableArray *result=[NSMutableArray array];
    for (NSString *entry in MLDNSAllDomainPatterns(options)) for (NSString *pattern in MLDNSPatterns(entry)) if ([pattern hasPrefix:@"geosite:"]) [result addObject:@{@"kind":@"geosite",@"operand":[pattern substringFromIndex:8]}];
    if ([options[@"fallback"] isKindOfClass:[NSArray class]] && [options[@"fallback"] count]) {
        NSDictionary *filter=[options[@"fallback-filter"] isKindOfClass:[NSDictionary class]] ? options[@"fallback-filter"] : @{};
        for (NSString *code in ([filter[@"geosite"] isKindOfClass:[NSArray class]] ? filter[@"geosite"] : @[])) if ([code isKindOfClass:[NSString class]]) [result addObject:@{@"kind":@"geosite",@"operand":code}];
        if (![filter[@"geoip"] isEqual:@NO]) { NSString *code=filter[@"geoip-code"] ?: @"CN"; if ([code isKindOfClass:[NSString class]] && [code caseInsensitiveCompare:@"LAN"]!=NSOrderedSame) [result addObject:@{@"kind":@"geoip",@"operand":code}]; }
    }
    return result;
}
NSArray *MLDNSRuleProviderNames(NSDictionary *options) {
    NSMutableOrderedSet *names=[NSMutableOrderedSet orderedSet];
    for (NSString *entry in MLDNSAllDomainPatterns(options)) for (NSString *pattern in MLDNSPatterns(entry)) if ([pattern hasPrefix:@"rule-set:"]) [names addObject:[pattern substringFromIndex:9]];
    return names.array;
}

NSString *MLDNSUnsupportedField(NSDictionary *options) {
    if (![options isKindOfClass:[NSDictionary class]]) return @"dns";
    for (NSString *key in options) {
        id value = options[key];
        if ([@[@"enable",@"ipv6",@"use-hosts",@"use-system-hosts",@"respect-rules"] containsObject:key]) {
            if (!MLBoolean(value)) return key;
        } else if ([key isEqual:@"enhanced-mode"]) {
            if (![@[@"redir-host",@"fake-ip"] containsObject:value]) return key;
        } else if ([@[@"nameserver",@"default-nameserver",@"proxy-server-nameserver",@"direct-nameserver",@"fallback"] containsObject:key]) {
            if (![value isKindOfClass:[NSArray class]] || [value count] < 1 || [value count] > 8) return key;
            for (id text in value) {
                if (([key isEqual:@"default-nameserver"] || [key isEqual:@"proxy-server-nameserver"]) && [text isKindOfClass:[NSString class]]) {
                    NSRange fragment=[text rangeOfString:@"#" options:NSBackwardsSearch];
                    if (fragment.location!=NSNotFound && ![[text substringFromIndex:fragment.location+1] isEqual:@"DIRECT"]) return key;
                }
                if (!MLDNSEndpoint(text,[key isEqual:@"default-nameserver"])) return key;
            }
        } else if ([key isEqual:@"nameserver-policy"]) {
            if (![value isKindOfClass:[NSDictionary class]] || [value count] > 128) return key;
            for (id pattern in value) {
                if (!MLDNSPatterns(pattern)) return key;
                id list = value[pattern];
                if ([list isKindOfClass:[NSString class]]) list = @[list];
                if (![list isKindOfClass:[NSArray class]] || ![list count] || [list count] > 8) return key;
                for (id text in list) if (!MLDNSEndpoint(text,NO)) return key;
            }
        } else if ([key isEqual:@"fake-ip-filter"]) {
            if (![value isKindOfClass:[NSArray class]] || [value count] > 256) return key;
            for (id pattern in value) if (!MLDNSPatterns(pattern)) return key;
        } else if ([key isEqual:@"fake-ip-filter-mode"]) {
            if (![@[@"blacklist",@"whitelist"] containsObject:value]) return key;
        } else if ([key isEqual:@"fallback-filter"]) {
            if (![value isKindOfClass:[NSDictionary class]]) return key;
            for (NSString *field in value) {
                id entry=value[field];
                if ([field isEqual:@"geoip"]) { if (!MLBoolean(entry)) return key; }
                else if ([field isEqual:@"geoip-code"]) { if (![entry isKindOfClass:[NSString class]] || ![entry length] || [entry length]>64 || [entry rangeOfString:@","].location!=NSNotFound) return key; }
                else if ([@[@"geosite",@"ipcidr",@"domain"] containsObject:field]) {
                    if (![entry isKindOfClass:[NSArray class]] || [entry count]>256) return key;
                    for (NSString *item in entry) {
                        if (![item isKindOfClass:[NSString class]] || !item.length || item.length>253) return key;
                        if ([field isEqual:@"ipcidr"] && MLRouteRuleOperandIssue(@"IP-CIDR",item)) return key;
                        if ([field isEqual:@"domain"] && (!MLDNSPatterns(item) || [item rangeOfString:@":"].location!=NSNotFound)) return key;
                    }
                } else return key;
            }
        } else if ([key isEqual:@"fake-ip-range"] || [key isEqual:@"fake-ip-range6"]) {
            NSString *v4 = [key isEqual:@"fake-ip-range"] ? value : options[@"fake-ip-range"];
            NSString *v6 = [key isEqual:@"fake-ip-range6"] ? value : options[@"fake-ip-range6"];
            if (![value isKindOfClass:[NSString class]] || ![[MLFakeIP alloc] initWithRange:v4 ipv6Range:v6 capacity:512]) return key;
        } else return key;
    }
    if ([options[@"enable"] boolValue] && !options[@"nameserver"]) return @"nameserver";
    if ([options[@"respect-rules"] boolValue] && ![options[@"proxy-server-nameserver"] count]) return @"respect-rules";
    return nil;
}

static BOOL MLDNSPattern(NSString *pattern,NSString *name) {
    pattern=pattern.lowercaseString; name=name.lowercaseString;
    if([pattern hasPrefix:@"+."]) {
        NSString *suffix=[pattern substringFromIndex:2];
        return [name isEqual:suffix] || [name hasSuffix:[@"." stringByAppendingString:suffix]];
    }
    if ([pattern isEqual:@"*"]) return YES;
    NSArray *wanted=[pattern componentsSeparatedByString:@"."], *labels=[name componentsSeparatedByString:@"."];
    if (wanted.count!=labels.count) return NO;
    for (NSUInteger i=0;i<wanted.count;++i) if (fnmatch([wanted[i] UTF8String],[labels[i] UTF8String],0)!=0) return NO;
    return YES;
}

static NSString *MLLowerName(NSString *name) {
    if ([name hasSuffix:@"."]) name = [name substringToIndex:name.length-1];
    return name.lowercaseString;
}

static NSData *MLDNSExchange(NSString *serverText, NSData *request, NSString *caPath, double deadline) {
    double remaining = deadline - [NSProcessInfo processInfo].systemUptime;
    if (remaining <= 0 || request.length < 12 || request.length > 4096) return nil;
    unsigned timeout = (unsigned)MIN(2000.0,remaining*1000);
    if (MLDoHURL(serverText)) return MLDoHQuery(serverText,request,caPath,timeout);
    NSURL *doq=MLDNSVerifiedURL(serverText,@"quic");
    if (doq) {
        NSString *host=doq.host;
        if ([host hasPrefix:@"["] && [host hasSuffix:@"]"]) host=[host substringWithRange:NSMakeRange(1,host.length-2)];
        unsigned left=(unsigned)MIN(60000.0,remaining*1000); if (left<100) return nil;
        uint8_t response[4096]; char diagnostic[256];
        // Let the engine try bootstrap addresses within one absolute timeout.
        ssize_t count=MLDNSDoQQuery(host.UTF8String,(uint16_t)(doq.port ? doq.port.unsignedIntegerValue : 853),host.UTF8String,caPath.fileSystemRepresentation,
            request.bytes,request.length,response,sizeof response,left,diagnostic,sizeof diagnostic);
        if (count<12) return nil;
        const uint8_t *query=request.bytes; response[0]=query[0]; response[1]=query[1];
        return [NSData dataWithBytes:response length:(NSUInteger)count];
    }
    NSURL *dot = MLDNSVerifiedURL(serverText,@"tls");
    if (dot) {
        NSString *host = dot.host;
        if ([host hasPrefix:@"["] && [host hasSuffix:@"]"]) host = [host substringWithRange:NSMakeRange(1,host.length-2)];
        struct addrinfo hints = {0}, *addresses = NULL;
        hints.ai_socktype = SOCK_STREAM;
        if (MLNetworkResolveBootstrapHost(host.UTF8String,(dot.port.stringValue ?: @"853").UTF8String,&hints,&addresses)) return nil;
        NSData *answer = nil;
        for (struct addrinfo *address=addresses;address;address=address->ai_next) {
            remaining = deadline-[NSProcessInfo processInfo].systemUptime;
            if (remaining <= 0) break;
            answer=MLDNSWireQuery(request,address->ai_addr,address->ai_addrlen,YES,YES,host,caPath,(unsigned)MIN(2000.0,remaining*1000));
            if (answer) break;
        }
        freeaddrinfo(addresses);
        return answer;
    }
    union res_sockaddr_union server; BOOL tcp;
    if (!MLNameserver(serverText,&server,&tcp)) return nil;
    socklen_t size = server.sin.sin_family == AF_INET ? sizeof(server.sin) : sizeof(server.sin6);
    NSData *answer=MLDNSWireQuery(request,(struct sockaddr *)&server,size,tcp,NO,nil,nil,timeout);
    if (!tcp && answer.length >= 12 && (((const uint8_t *)answer.bytes)[2] & 2)) {
        remaining=deadline-[NSProcessInfo processInfo].systemUptime;
        if (remaining <= 0) return nil;
        answer=MLDNSWireQuery(request,(struct sockaddr *)&server,size,YES,NO,nil,nil,(unsigned)MIN(2000.0,remaining*1000));
    }
    return answer;
}

static NSData *MLDNSRunExchange(NSString *serverText, NSData *request, NSString *caPath, double deadline, MLDNSExchangeHandler handler, NSString *context) {
    if (handler) return handler(serverText,request,deadline,context ?: @"application");
    // A selected proxy requires the outbound handler; never silently send it directly.
    NSString *base=MLDNSBaseServer(serverText);
    if (!base) return nil;
    if (![serverText isEqual:base] && ![[serverText substringFromIndex:base.length+1] isEqual:@"DIRECT"]) return nil;
    return MLDNSExchange(base,request,caPath,deadline);
}
static NSArray *MLDNSAnswer(NSString *host, NSString *serverText, ns_type type, uint32_t *ttl, NSString *caPath, double deadline, MLDNSExchangeHandler handler, NSString *context) {
    struct __res_state state = {0};
    if (res_ninit(&state)) return nil;
    unsigned char query[512], body[4096];
    int length=res_nmkquery(&state,ns_o_query,host.UTF8String,ns_c_in,type,NULL,0,NULL,query,sizeof(query));
    res_ndestroy(&state);
    if (length < 12) return nil;
    NSData *answer=MLDNSRunExchange(serverText,[NSData dataWithBytes:query length:(NSUInteger)length],caPath,deadline,handler,context);
    if (answer.length < 12 || answer.length > sizeof(body)) return nil;
    [answer getBytes:body length:answer.length];
    if (body[0] != query[0] || body[1] != query[1]) return nil;
    int response=(int)answer.length;
    ns_msg message;
    if (response <= 0 || response > (int)sizeof(body) || ns_initparse(body,response,&message) ||
        ns_msg_getflag(message,ns_f_rcode) != ns_r_noerror ||
        !ns_msg_getflag(message,ns_f_qr) || ns_msg_getflag(message,ns_f_tc) ||
        ns_msg_count(message,ns_s_qd) != 1) return nil;
    ns_rr question;
    NSString *name = MLLowerName(host);
    if (ns_parserr(&message,ns_s_qd,0,&question) ||
        ![MLLowerName([NSString stringWithUTF8String:ns_rr_name(question)]) isEqual:name] ||
        ns_rr_type(question) != type || ns_rr_class(question) != ns_c_in) return nil;

    // Accept addresses only for the question or a CNAME linked to it.
    for (unsigned depth = 0; depth < 8; ++depth) {
        NSString *alias = nil;
        NSMutableArray *results = [NSMutableArray array];
        for (int index = 0; index < ns_msg_count(message,ns_s_an); ++index) {
            ns_rr item;
            if (ns_parserr(&message,ns_s_an,index,&item)) return nil;
            if (ns_rr_class(item) != ns_c_in ||
                ![MLLowerName([NSString stringWithUTF8String:ns_rr_name(item)]) isEqual:name]) continue;
            if (ns_rr_type(item) == ns_t_cname) {
                char target[NS_MAXDNAME];
                int used = dn_expand(body,body+response,ns_rr_rdata(item),target,sizeof(target));
                if (used != ns_rr_rdlen(item)) return nil;
                alias = MLLowerName([NSString stringWithUTF8String:target]);
                *ttl = MIN(*ttl,ns_rr_ttl(item));
            } else if (ns_rr_type(item) == type) {
                char address[INET6_ADDRSTRLEN];
                if (ns_rr_rdlen(item) != (type == ns_t_a ? 4 : 16)) return nil;
                if (inet_ntop(type == ns_t_a ? AF_INET : AF_INET6,ns_rr_rdata(item),address,sizeof(address))) {
                    [results addObject:[NSString stringWithUTF8String:address]];
                    *ttl = MIN(*ttl,ns_rr_ttl(item));
                    if (results.count == 16) break;
                }
            }
        }
        if (results.count) return results;
        if (!alias.length || [alias isEqual:name]) break;
        name = alias;
    }
    return nil;
}

@implementation MLDNS {
    NSArray *_servers;
    BOOL _enabled;
    BOOL _ipv6;
    NSMutableDictionary *_cache;
    NSUInteger _cacheGeneration;
    NSDictionary *_options;
    NSDictionary *_policies;
    NSArray *_fallback;
    NSDictionary *_document, *_providerPolicies;
    NSArray *_policyBlocks;
    MLGeoIndex *_geoIndex;
    NSString *_context;
}

- (id)initWithOptions:(NSDictionary *)options ipv6:(BOOL)ipv6 {
    if (!(self = [super init])) return nil;
    _enabled = [options[@"enable"] boolValue];
    _ipv6 = ipv6 && (!_enabled || [options[@"ipv6"] boolValue]);
    _servers = [options[@"nameserver"] copy];
    _options = [options copy] ?: @{};
    _policies = [options[@"nameserver-policy"] copy] ?: @{};
    _fallback = [options[@"fallback"] copy] ?: @[];
    _cache = [NSMutableDictionary dictionary];
    _context=@"application";
    if ([options[@"use-system-hosts"] boolValue]) self.hosts=MLDNSSystemHosts();
#if TARGET_OS_IPHONE
    self.caPath = @"/usr/share/muyuclash/cacert.pem";
#endif
    return self;
}

- (BOOL)installPreparedDocument:(NSDictionary *)document error:(NSError **)error {
    if (error) *error=nil;
    NSString *invalid=MLDNSUnsupportedField(_options);
    if (invalid) { if (error) *error=[NSError errorWithDomain:@"E_DNS_CONFIG" code:1 userInfo:@{NSLocalizedDescriptionKey:[@"Unsupported DNS field: " stringByAppendingString:invalid]}]; return NO; }
    MLGeoIndex *geo=document[@"_geo-index"] ? [MLGeoIndex indexWithDescriptor:document[@"_geo-index"] error:error] : nil;
    if (document[@"_geo-index"] && !geo) return NO;
    for (NSDictionary *request in MLDNSGeoRequests(_options)) if (![geo containsKind:request[@"kind"] operand:request[@"operand"]]) {
        if (error) *error=[NSError errorWithDomain:@"E_DNS_DATABASE" code:1 userInfo:@{NSLocalizedDescriptionKey:@"A DNS Geo category has no verified prepared index."}]; return NO;
    }
    NSMutableDictionary *providers=[NSMutableDictionary dictionary];
    for (NSString *name in MLDNSRuleProviderNames(_options)) {
        NSDictionary *provider=document[@"_rule-provider-payloads"][name]; NSString *behavior=provider[@"behavior"];
        if (![@[@"domain",@"classical"] containsObject:behavior ?: @""]) {
            if (error) *error=[NSError errorWithDomain:@"E_DNS_PROVIDER" code:1 userInfo:@{NSLocalizedDescriptionKey:@"A DNS rule-set requires a prepared domain or classical Provider."}]; return NO;
        }
        if ([behavior isEqual:@"classical"]) {
            NSMutableArray *payload=[NSMutableArray array];
            for (NSString *rule in provider[@"payload"]) {
                NSArray *parts=MLRouteRuleFields(rule);
                if (parts.count>=2 && [@[@"DOMAIN",@"DOMAIN-SUFFIX",@"DOMAIN-KEYWORD",@"DOMAIN-REGEX",@"GEOSITE"] containsObject:parts[0]]) [payload addObject:rule];
            }
            provider=@{@"behavior":behavior,@"payload":payload};
        }
        NSMutableDictionary *policy=[@{@"rules":@[[NSString stringWithFormat:@"RULE-SET,%@,REJECT,no-resolve",name],@"MATCH,DIRECT"],@"_rule-provider-payloads":@{name:provider}} mutableCopy];
        if (document[@"_geo-index"]) policy[@"_geo-index"]=document[@"_geo-index"];
        NSDictionary *preparedPolicy=[policy copy];
        if (!MLRoutePrepareProviders(preparedPolicy)) {
            if (error) *error=[NSError errorWithDomain:@"E_DNS_PROVIDER" code:1 userInfo:@{NSLocalizedDescriptionKey:@"A DNS rule-set index failed validation."}];
            return NO;
        }
        providers[name]=preparedPolicy;
    }
    NSMutableSet *targets=[NSMutableSet setWithArray:@[@"DIRECT",@"REJECT",@"GLOBAL"]];
    for (NSDictionary *node in document[@"proxies"]) if ([node[@"name"] isKindOfClass:[NSString class]]) [targets addObject:node[@"name"]];
    for (NSDictionary *group in document[@"proxy-groups"]) if ([group[@"name"] isKindOfClass:[NSString class]]) [targets addObject:group[@"name"]];
    NSMutableArray *allServers=[NSMutableArray array];
    for (NSString *key in @[@"nameserver",@"default-nameserver",@"proxy-server-nameserver",@"direct-nameserver",@"fallback"]) [allServers addObjectsFromArray:_options[key] ?: @[]];
    for (id servers in _policies.allValues) [allServers addObjectsFromArray:[servers isKindOfClass:[NSArray class]] ? servers : @[servers]];
    for (NSString *server in allServers) { NSRange fragment=[server rangeOfString:@"#" options:NSBackwardsSearch]; if (fragment.location!=NSNotFound && ![targets containsObject:[server substringFromIndex:fragment.location+1]]) {
        if (error) *error=[NSError errorWithDomain:@"E_DNS_REFERENCE" code:1 userInfo:@{NSLocalizedDescriptionKey:@"A DNS upstream references a missing outbound target."}]; return NO;
    } }
    NSArray *order=document[@"_dns-policy-order"] ?: [_policies.allKeys sortedArrayUsingSelector:@selector(compare:)];
    if (![order isKindOfClass:[NSArray class]] || order.count!=_policies.count || ![[NSSet setWithArray:order] isEqual:[NSSet setWithArray:_policies.allKeys]]) {
        if (error) *error=[NSError errorWithDomain:@"E_DNS_ORDER" code:1 userInfo:@{NSLocalizedDescriptionKey:@"The prepared DNS policy order is invalid."}]; return NO;
    }
    NSMutableArray *blocks=[NSMutableArray array], *ordinary=[NSMutableArray array];
    for (NSString *entry in order) for (NSString *pattern in MLDNSPatterns(entry)) {
        id value=_policies[entry]; NSArray *servers=[value isKindOfClass:[NSArray class]] ? value : @[value];
        if ([pattern hasPrefix:@"geosite:"] || [pattern hasPrefix:@"rule-set:"]) {
            if (ordinary.count) { [blocks addObject:@{@"ordinary":[ordinary copy]}]; [ordinary removeAllObjects]; }
            [blocks addObject:@{@"pattern":pattern,@"servers":servers}];
        } else [ordinary addObject:@{@"pattern":pattern,@"servers":servers}];
    }
    if (ordinary.count) [blocks addObject:@{@"ordinary":[ordinary copy]}];
    _document=[document copy]; _geoIndex=geo; _providerPolicies=[providers copy]; _policyBlocks=[blocks copy]; [self flush]; return YES;
}
- (BOOL)matchesDomainPattern:(NSString *)pattern host:(NSString *)host {
    if ([pattern hasPrefix:@"geosite:"]) { BOOL usable=YES; return [_geoIndex matchKind:@"geosite" operand:[pattern substringFromIndex:8] family:0 address:NULL domain:host usable:&usable] && usable; }
    if ([pattern hasPrefix:@"rule-set:"]) { NSDictionary *policy=_providerPolicies[[pattern substringFromIndex:9]]; return policy && [MLRouteWithRuntime(policy,@"Rule",nil,nil,nil,@{@"host":host},nil)[@"node"] isEqual:@"REJECT"]; }
    return MLDNSPattern(pattern,host);
}
- (NSArray *)policyServersForHost:(NSString *)host {
    if (_policyBlocks) {
        for (NSDictionary *block in _policyBlocks) {
            if (block[@"pattern"]) { if ([self matchesDomainPattern:block[@"pattern"] host:host]) return block[@"servers"]; }
            else {
                NSArray *patterns=[block[@"ordinary"] sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) { NSUInteger al=[a[@"pattern"] length], bl=[b[@"pattern"] length]; return al>bl ? NSOrderedAscending : (al<bl ? NSOrderedDescending : [a[@"pattern"] compare:b[@"pattern"]]); }];
                for (NSDictionary *entry in patterns) if ([self matchesDomainPattern:entry[@"pattern"] host:host]) return entry[@"servers"];
            }
        }
        return nil;
    }
    for (NSString *entry in [_policies.allKeys sortedArrayUsingComparator:^NSComparisonResult(NSString *a,NSString *b) { return a.length>b.length ? NSOrderedAscending : (a.length<b.length ? NSOrderedDescending : [a compare:b]); }]) for (NSString *pattern in MLDNSPatterns(entry)) if ([self matchesDomainPattern:pattern host:host]) { id value=_policies[entry]; return [value isKindOfClass:[NSArray class]] ? value : @[value]; }
    return nil;
}
- (BOOL)onlyFallbackForHost:(NSString *)host {
    if (!_fallback.count) return NO;
    NSDictionary *filter=_options[@"fallback-filter"];
    for (NSString *pattern in filter[@"domain"]) for (NSString *part in MLDNSPatterns(pattern)) if (MLDNSPattern(part,host)) return YES;
    for (NSString *code in filter[@"geosite"]) if ([self matchesDomainPattern:[@"geosite:" stringByAppendingString:code] host:host]) return YES;
    return NO;
}
- (BOOL)fallbackForAddress:(NSString *)address {
    NSDictionary *filter=_options[@"fallback-filter"] ?: @{};
    NSDictionary *metadata=@{@"ip":address};
    for (NSString *cidr in filter[@"ipcidr"]) if ([MLRouteWithRuntime(@{@"rules":@[[NSString stringWithFormat:@"IP-CIDR,%@,REJECT,no-resolve",cidr],@"MATCH,DIRECT"]},@"Rule",nil,nil,nil,metadata,nil)[@"node"] isEqual:@"REJECT"]) return YES;
    if ([filter[@"geoip"] isEqual:@NO]) return NO;
    if ([MLRouteWithRuntime(@{@"rules":@[@"GEOIP,LAN,REJECT,no-resolve",@"MATCH,DIRECT"]},@"Rule",nil,nil,nil,metadata,nil)[@"node"] isEqual:@"REJECT"]) return NO;
    NSString *code=filter[@"geoip-code"] ?: @"CN"; if ([code caseInsensitiveCompare:@"LAN"]==NSOrderedSame) return YES;
    unsigned char bytes[16]={0}; int family=inet_pton(AF_INET,address.UTF8String,bytes)==1 ? AF_INET : AF_INET6;
    if (family==AF_INET6 && inet_pton(AF_INET6,address.UTF8String,bytes)!=1) return NO;
    if (family==AF_INET6) { struct in6_addr v6; memcpy(&v6,bytes,16); if (IN6_IS_ADDR_V4MAPPED(&v6)) { memmove(bytes,bytes+12,4); memset(bytes+4,0,12); family=AF_INET; } }
    BOOL usable=YES; BOOL contained=[_geoIndex matchKind:@"geoip" operand:code family:family address:bytes domain:nil usable:&usable];
    return usable && !contained;
}
- (NSDictionary *)lookup:(NSString *)host {
    if (!host.length || host.length > 253) return nil;
    if ([MLLowerName(host) isEqual:@"localhost"])
        return @{@"addresses":_ipv6 ? @[@"127.0.0.1",@"::1"] : @[@"127.0.0.1"],@"source":@"local"};
    struct in_addr v4; struct in6_addr v6;
    if (inet_pton(AF_INET,host.UTF8String,&v4) == 1 ||
        (_ipv6 && inet_pton(AF_INET6,host.UTF8String,&v6) == 1))
        return @{@"addresses":@[host],@"source":@"literal"};
    id fixed = self.hosts[MLLowerName(host)];
    if (fixed && ![_options[@"use-hosts"] isEqual:@NO]) {
        NSArray *values = [fixed isKindOfClass:[NSArray class]] ? fixed : @[fixed];
        NSMutableArray *addresses = [NSMutableArray array];
        for (id text in values) {
            if (![text isKindOfClass:[NSString class]]) continue;
            if (inet_pton(AF_INET,[text UTF8String],&v4) == 1 || (_ipv6 && inet_pton(AF_INET6,[text UTF8String],&v6) == 1)) [addresses addObject:text];
        }
        if (addresses.count) return @{@"addresses":addresses,@"source":@"hosts",@"ttl":@300};
    }
    if (!_enabled && !MLNetworkInterfaceIndex()) {
        struct addrinfo hints = {0}, *addresses = NULL;
        hints.ai_family = _ipv6 ? AF_UNSPEC : AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host.UTF8String,NULL,&hints,&addresses)) return nil;
        NSMutableArray *results = [NSMutableArray array];
        for (struct addrinfo *it = addresses; it && results.count < 16; it = it->ai_next) {
            char ip[INET6_ADDRSTRLEN];
            if (!getnameinfo(it->ai_addr,it->ai_addrlen,ip,sizeof(ip),NULL,0,NI_NUMERICHOST))
                [results addObject:[NSString stringWithUTF8String:ip]];
        }
        if (addresses) freeaddrinfo(addresses);
        return results.count ? @{@"addresses":results,@"source":@"system"} : nil;
    }
    NSString *key = MLLowerName(host);
    double now = [NSProcessInfo processInfo].systemUptime;
    NSUInteger generation;
    @synchronized(self) {
        generation = _cacheGeneration;
        NSDictionary *cached = _cache[key];
        if ([cached[@"expires"] doubleValue] > now) return cached[@"result"];
        [_cache removeObjectForKey:key];
    }
    NSArray *policy=[self policyServersForHost:key];
    BOOL onlyFallback=!policy && [self onlyFallbackForHost:key];
    NSArray *primary=policy ?: (onlyFallback ? _fallback : (_enabled ? _servers : self.bootstrapServers));
    NSArray *fallback=(!policy && !onlyFallback) ? _fallback : @[];
    for (NSArray *attempts in @[primary ?: @[],fallback]) for (NSString *server in attempts) {
        uint32_t ttl=3600; NSMutableArray *addresses=[NSMutableArray array];
        NSArray *v4Addresses=MLDNSAnswer(key,server,ns_t_a,&ttl,self.caPath,now+3.5,self.exchangeHandler,_context);
        if (v4Addresses) [addresses addObjectsFromArray:v4Addresses];
        if (_ipv6) { NSArray *v6Addresses=MLDNSAnswer(key,server,ns_t_aaaa,&ttl,self.caPath,now+3.5,self.exchangeHandler,_context); if (v6Addresses) [addresses addObjectsFromArray:v6Addresses]; }
        if (!addresses.count) continue;
        BOOL rejected=NO; if (attempts==primary && fallback.count) for (NSString *address in addresses) if ([self fallbackForAddress:address]) { rejected=YES; break; }
        if (rejected) break;
        NSDictionary *result=@{@"addresses":[addresses copy],@"source":server,@"ttl":@(ttl)};
        if (ttl) @synchronized(self) { if (generation==_cacheGeneration) { if (_cache.count>=128) [_cache removeObjectForKey:_cache.allKeys[0]]; _cache[key]=@{@"result":result,@"expires":@(now+ttl)}; } }
        return result;
    }
    return nil;
}

- (NSArray *)serversForHost:(NSString *)host {
    NSString *name=MLLowerName(host); return [self policyServersForHost:name] ?: ([self onlyFallbackForHost:name] ? _fallback : (_enabled ? _servers : self.bootstrapServers));
}
- (NSDictionary *)lookupUsingServers:(NSArray *)servers host:(NSString *)host context:(NSString *)context {
    if (!servers.count && MLNetworkInterfaceIndex()) return nil;
    NSDictionary *options=servers.count?@{@"enable":@YES,@"ipv6":@(_ipv6),@"nameserver":servers}:@{};
    MLDNS *resolver=[[MLDNS alloc]initWithOptions:options ipv6:_ipv6];
    resolver.caPath=self.caPath; resolver.hosts=self.hosts; resolver.bootstrapServers=self.bootstrapServers; resolver.exchangeHandler=self.exchangeHandler; resolver->_context=context;
    return [resolver lookup:host];
}
- (NSDictionary *)lookupBootstrap:(NSString *)host {
    NSArray *servers=_options[@"default-nameserver"]?:self.bootstrapServers;
    if (!servers.count) {
        NSMutableArray *numeric=[NSMutableArray array];
        for (NSString *text in _servers) { union res_sockaddr_union endpoint; BOOL tcp;
            if (MLNameserver(text,&endpoint,&tcp)) [numeric addObject:text];
        }
        servers=numeric;
    }
    return [self lookupUsingServers:servers host:host context:@"bootstrap"];
}
- (NSDictionary *)lookupProxyServer:(NSString *)host {
    NSArray *servers=_options[@"proxy-server-nameserver"];
    return servers.count?[self lookupUsingServers:servers host:host context:@"proxy"]:[self lookupBootstrap:host];
}
- (NSDictionary *)lookupDirect:(NSString *)host {
    NSArray *servers=_options[@"direct-nameserver"];
    return servers.count?[self lookupUsingServers:servers host:host context:@"direct"]:[self lookup:host];
}
- (NSString *)hostForFakeAddress:(NSString *)address { return [self.fakeIP hostForAddress:address]; }
- (void)retainFakeAddress:(NSString *)address { [self.fakeIP retainAddress:address]; }
- (void)releaseFakeAddress:(NSString *)address { [self.fakeIP releaseAddress:address]; }
- (BOOL)responseNeedsFallback:(NSData *)answer host:(NSString *)host type:(unsigned)type {
    ns_msg message; if (ns_initparse(answer.bytes,(int)answer.length,&message) || ns_msg_getflag(message,ns_f_rcode)!=ns_r_noerror) return YES;
    NSMutableSet *names=[NSMutableSet setWithObject:host];
    for (NSUInteger depth=0;depth<8;++depth) for (int i=0;i<ns_msg_count(message,ns_s_an);++i) {
        ns_rr record; if (ns_parserr(&message,ns_s_an,i,&record)) return YES;
        NSString *owner=MLLowerName([NSString stringWithUTF8String:ns_rr_name(record)]);
        if (![names containsObject:owner] || ns_rr_type(record)!=ns_t_cname) continue;
        char target[NS_MAXDNAME]; if (dn_expand(answer.bytes,(const unsigned char *)answer.bytes+answer.length,ns_rr_rdata(record),target,sizeof target)!=ns_rr_rdlen(record)) return YES;
        [names addObject:MLLowerName([NSString stringWithUTF8String:target])];
    }
    BOOL found=NO;
    for (int i=0;i<ns_msg_count(message,ns_s_an);++i) {
        ns_rr record; if (ns_parserr(&message,ns_s_an,i,&record)) return YES;
        if (ns_rr_type(record)!=type || ns_rr_class(record)!=ns_c_in || ![names containsObject:MLLowerName([NSString stringWithUTF8String:ns_rr_name(record)])]) continue;
        if (ns_rr_rdlen(record)!=(type==ns_t_a ? 4 : 16)) return YES;
        char text[INET6_ADDRSTRLEN]; if (!inet_ntop(type==ns_t_a ? AF_INET : AF_INET6,ns_rr_rdata(record),text,sizeof text)) return YES;
        found=YES; if ([self fallbackForAddress:[NSString stringWithUTF8String:text]]) return YES;
    }
    return !found;
}
- (NSData *)answerQuery:(NSData *)query application:(BOOL)application {
    if (query.length<12||query.length>4096) return nil;
    const uint8_t *bytes=query.bytes;
    if (bytes[2]&0xf8) return nil; // QUERY only, never a response or a recursive opcode.
    ns_msg message; ns_rr question;
    if (ns_initparse(query.bytes,(int)query.length,&message)||ns_msg_count(message,ns_s_qd)!=1||
        ns_msg_count(message,ns_s_an)||ns_msg_count(message,ns_s_ns)||ns_parserr(&message,ns_s_qd,0,&question)) return nil;
    NSString *host=MLLowerName([NSString stringWithUTF8String:ns_rr_name(question)]);
    unsigned type=ns_rr_type(question),class=ns_rr_class(question);
    if (!host.length||host.length>253||class!=ns_c_in) return nil;
    BOOL fake=application&&[_options[@"enhanced-mode"]isEqual:@"fake-ip"]&&self.fakeIP;
    BOOL matchedFilter=NO;
    for (NSString *entry in _options[@"fake-ip-filter"]) for (NSString *pattern in MLDNSPatterns(entry)) if ([self matchesDomainPattern:pattern host:host]) { matchedFilter=YES; break; }
    if ([_options[@"fake-ip-filter-mode"] isEqual:@"whitelist"] ? !matchedFilter : matchedFilter) fake=NO;
    BOOL fixed=self.hosts[host]!=nil&&![_options[@"use-hosts"]isEqual:@NO];
    if(fixed)fake=NO;
    BOOL isIP=type==ns_t_a || type==ns_t_aaaa;
    NSArray *policy=[self policyServersForHost:host];
    NSArray *servers=isIP ? [self serversForHost:host] : (policy ?: (_enabled ? _servers : self.bootstrapServers));
    NSArray *fallback=(isIP && !policy && ![self onlyFallbackForHost:host]) ? _fallback : @[];
    if (!fake&&!fixed&&servers.count&&!(type==ns_t_aaaa&&!_ipv6)) {
        double deadline=[NSProcessInfo processInfo].systemUptime+3.5;
        for (NSArray *attempts in @[servers,fallback]) for (NSString *server in attempts) {
            NSData *answer=MLDNSRunExchange(server,query,self.caPath,deadline,self.exchangeHandler,_context);
            if (answer.length<12) continue;
            const uint8_t *response=answer.bytes;
            ns_msg parsed; ns_rr reply;
            if (response[0]!=bytes[0]||response[1]!=bytes[1]||!((response[2]&0x80))||
                ns_initparse(response,(int)answer.length,&parsed)||ns_msg_count(parsed,ns_s_qd)!=1||
                ns_parserr(&parsed,ns_s_qd,0,&reply)||ns_rr_type(reply)!=type||ns_rr_class(reply)!=class||
                ![MLLowerName([NSString stringWithUTF8String:ns_rr_name(reply)])isEqual:host]) continue;
            if (ns_msg_getflag(parsed,ns_f_rcode)==ns_r_servfail) continue;
            if (attempts==servers && fallback.count && [self responseNeedsFallback:answer host:host type:type]) break;
            return answer;
        }
    }
    NSArray *addresses=@[]; uint32_t ttl=300; unsigned rcode=0;
    if (type==ns_t_a||type==ns_t_aaaa) {
        if (fake) {
            NSString *address=(!(_ipv6||type==ns_t_a))?nil:[self.fakeIP addressForHost:host ipv6:type==ns_t_aaaa];
            if (address) addresses=@[address];
            else if (type==ns_t_a||_ipv6) rcode=ns_r_servfail;
        } else {
            NSDictionary *result=(type==ns_t_aaaa&&!_ipv6) ? @{@"addresses":@[]} : ((!fixed&&servers.count) ? nil : [self lookup:host]);
            if (!result) rcode=ns_r_servfail;
            else { addresses=result[@"addresses"]?:@[]; if (result[@"ttl"]) ttl=[result[@"ttl"]unsignedIntValue]; }
        }
    } else rcode=ns_r_servfail;
    NSMutableData *name=[NSMutableData data];
    for (NSString *label in [host componentsSeparatedByString:@"."]) {
        NSData *part=[label dataUsingEncoding:NSASCIIStringEncoding];
        if (!part.length||part.length>63) return nil;
        uint8_t length=(uint8_t)part.length; [name appendBytes:&length length:1]; [name appendData:part];
    }
    uint8_t zero=0; [name appendBytes:&zero length:1];
    NSMutableData *records=[NSMutableData data]; unsigned count=0;
    for (NSString *address in addresses) {
        uint8_t value[16]; size_t size=type==ns_t_a?4:16;
        if (inet_pton(type==ns_t_a?AF_INET:AF_INET6,address.UTF8String,value)!=1) continue;
        uint8_t record[12]={0xc0,0x0c,0,(uint8_t)type,0,1,(uint8_t)(ttl>>24),(uint8_t)(ttl>>16),(uint8_t)(ttl>>8),(uint8_t)ttl,0,(uint8_t)size};
        [records appendBytes:record length:sizeof(record)]; [records appendBytes:value length:size];
        if (++count==16) break;
    }
    uint8_t header[12]={bytes[0],bytes[1],(uint8_t)(0x80|(bytes[2]&1)),(uint8_t)(0x80|rcode),0,1,0,(uint8_t)count,0,0,0,0};
    uint8_t fields[4]={(uint8_t)(type>>8),(uint8_t)type,0,1};
    NSMutableData *answer=[NSMutableData dataWithBytes:header length:12];
    [answer appendData:name]; [answer appendBytes:fields length:4]; [answer appendData:records];
    return answer;
}

- (NSUInteger)count {
    @synchronized(self) {
        double now = [NSProcessInfo processInfo].systemUptime;
        for (NSString *key in _cache.allKeys)
            if ([_cache[key][@"expires"] doubleValue] <= now) [_cache removeObjectForKey:key];
        return _cache.count;
    }
}

- (NSUInteger)flush {
    @synchronized(self) {
        NSUInteger count = _cache.count;
        ++_cacheGeneration;
        [_cache removeAllObjects];
        return count;
    }
}
@end
