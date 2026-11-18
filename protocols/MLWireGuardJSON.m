#import <Foundation/Foundation.h>
#include "MLWireGuard.h"
#include "../transport/MLNetworkBinding.h"
#include "core/senko_time.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <string.h>
static BOOL text(id value,size_t cap){if(![value isKindOfClass:[NSString class]]||![value length]||[value lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>=cap)return NO;
    return [value rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location==NSNotFound;
}
static BOOL number(id value,unsigned max){if(![value isKindOfClass:[NSNumber class]]||CFGetTypeID((__bridge CFTypeRef)value)==CFBooleanGetTypeID())return NO;double n=[value doubleValue];return n>=0&&n<=max&&n==(unsigned)n;}
static BOOL boolean(id value){return [value isKindOfClass:[NSNumber class]]&&CFGetTypeID((__bridge CFTypeRef)value)==CFBooleanGetTypeID();}
static BOOL host(id value){if(!text(value,256))return NO;const char *s=[value UTF8String];uint8_t address[16];if(inet_pton(AF_INET,s,address)==1||inet_pton(AF_INET6,s,address)==1)return YES;
    if(strspn(s,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")!=strlen(s)||s[0]=='.'||s[strlen(s)-1]=='.')return NO;return YES;
}
static BOOL cidr(id value){if(!text(value,80))return NO;char copy[80];strcpy(copy,[value UTF8String]);char *slash=strchr(copy,'/');if(!slash)return NO;*slash++=0;uint8_t address[16];int family=strchr(copy,':')?AF_INET6:AF_INET;char *tail;unsigned long bits=strtoul(slash,&tail,10);return tail!=slash&&!*tail&&bits<=(family==AF_INET6?128:32)&&inet_pton(family,copy,address)==1;}
static NSString *settings(NSDictionary *node,NSDictionary *peer,awg_config_t *cfg){
    if(![node[@"type"] isKindOfClass:[NSString class]]||![@[@"wireguard",@"amneziawg",@"amnezia-wg",@"awg"] containsObject:[node[@"type"] lowercaseString]])return @"type";
    NSArray *keys=@[@"name",@"type",@"server",@"port",@"udp",@"ip",@"ipv6",@"private-key",@"public-key",@"pre-shared-key",@"preshared-key",@"allowed-ips",@"reserved",@"mtu",@"persistent-keepalive",@"remote-dns-resolve",@"dns",@"amnezia-wg-opts",@"amnezia-wg-option",@"jc",@"jmin",@"jmax",@"s1",@"s2",@"s3",@"s4",@"h1",@"h2",@"h3",@"h4",@"peers",@"dialer-proxy"];
    for(id key in node)if(![keys containsObject:key])return key;
    for(id key in peer)if(![@[@"server",@"port",@"public-key",@"pre-shared-key",@"preshared-key",@"allowed-ips",@"reserved",@"persistent-keepalive"] containsObject:key])return @"peers";
    if(!text(node[@"private-key"],65))return @"private-key";NSMutableArray *addresses=[NSMutableArray array];
    for(NSString *key in @[@"ip",@"ipv6"]){id value=node[key];if(!value)continue;uint8_t bytes[16];int family=[key isEqual:@"ip"]?AF_INET:AF_INET6;if(!text(value,46)||inet_pton(family,[value UTF8String],bytes)!=1)return key;[addresses addObject:[value stringByAppendingString:family==AF_INET?@"/32":@"/128"]];}
    if(!addresses.count)return @"ip";
    for(NSDictionary *value in @[node,peer])if(value[@"preshared-key"]&&value[@"pre-shared-key"]&&![value[@"preshared-key"] isEqual:value[@"pre-shared-key"]])return @"preshared-key";
    id server=peer[@"server"]?:node[@"server"],port=peer[@"port"]?:node[@"port"],key=peer[@"public-key"]?:node[@"public-key"],psk=peer[@"preshared-key"]?:peer[@"pre-shared-key"]?:node[@"preshared-key"]?:node[@"pre-shared-key"];
    if(!host(server))return @"server";if(!number(port,65535)||![port unsignedIntValue])return @"port";if(!text(key,65))return @"public-key";if(psk&&!text(psk,65))return @"pre-shared-key";
    id mtu=node[@"mtu"]?:@1280;if(!number(mtu,65535)||[mtu unsignedIntValue]<576||(node[@"ipv6"]&&[mtu unsignedIntValue]<1280))return @"mtu";
    for(NSString *key in @[@"udp",@"remote-dns-resolve"])if(node[key]&&!boolean(node[key]))return key;
    if(node[@"dialer-proxy"]&&!text(node[@"dialer-proxy"],256))return @"dialer-proxy";
    NSArray *dns=node[@"dns"]?:@[];if(![dns isKindOfClass:[NSArray class]]||dns.count>8)return @"dns";
    for(id value in dns){uint8_t bytes[16];if(!text(value,46)||(inet_pton(AF_INET,[value UTF8String],bytes)!=1&&inet_pton(AF_INET6,[value UTF8String],bytes)!=1))return @"dns";}
    if([node[@"remote-dns-resolve"] boolValue]&&!dns.count)return @"dns";
    NSArray *allowed=peer[@"allowed-ips"]?:node[@"allowed-ips"]?:@[@"0.0.0.0/0",@"::/0"];
    if(![allowed isKindOfClass:[NSArray class]]||!allowed.count)return @"allowed-ips";for(id value in allowed)if(!cidr(value))return @"allowed-ips";
    if([[allowed componentsJoinedByString:@","] lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>=sizeof cfg->allowed_ips)return @"allowed-ips";
    NSMutableString *profile=[NSMutableString stringWithFormat:@"[Interface]\nPrivateKey=%@\nAddress=%@\nMTU=%@\n",node[@"private-key"],[addresses componentsJoinedByString:@","],mtu];
    if(dns.count)[profile appendFormat:@"DNS=%@\n",[dns componentsJoinedByString:@","]];
    if(node[@"amnezia-wg-option"]&&node[@"amnezia-wg-opts"]&&![node[@"amnezia-wg-option"] isEqual:node[@"amnezia-wg-opts"]])return @"amnezia-wg-option";
    id sourceAWG=node[@"amnezia-wg-option"]?:node[@"amnezia-wg-opts"]?:@{};if(![sourceAWG isKindOfClass:[NSDictionary class]])return @"amnezia-wg-option";
    NSMutableDictionary *awg=[sourceAWG mutableCopy];for(NSString *key in @[@"jc",@"jmin",@"jmax",@"s1",@"s2",@"s3",@"s4",@"h1",@"h2",@"h3",@"h4"]){if(node[key]){if(awg[key]&&![awg[key] isEqual:node[key]])return key;awg[key]=node[key];}}
    NSDictionary *mapping=@{@"jc":@"Jc",@"jmin":@"Jmin",@"jmax":@"Jmax",@"s1":@"S1",@"s2":@"S2",@"s3":@"S3",@"s4":@"S4",@"h1":@"H1",@"h2":@"H2",@"h3":@"H3",@"h4":@"H4",@"i1":@"I1",@"i2":@"I2",@"i3":@"I3",@"i4":@"I4",@"i5":@"I5",@"j1":@"J1",@"j2":@"J2",@"j3":@"J3",@"itime":@"Itime",@"header-protection-key":@"HeaderProtectionKey",@"content-padding-addition":@"ContentPaddingAddition",@"random-trailers":@"RandomTrailers",@"disable-cookies":@"DisableCookies",@"rekey-after-time":@"RekeyAfterTime",@"rekey-timeout":@"RekeyTimeout",@"reject-after-time":@"RejectAfterTime",@"keepalive-timeout":@"KeepaliveTimeout",@"max-handshake-attempts":@"MaxHandshakeAttempts"};
    for(id key in awg){id value=awg[key];if(!mapping[key])return @"amnezia-wg-opts";
        if([@[@"random-trailers",@"disable-cookies"] containsObject:key]){if(!boolean(value))return @"amnezia-wg-opts";value=[value boolValue]?@"on":@"off";}
        else if(number(value,UINT32_MAX))value=[value stringValue];else if(!text(value,4096))return @"amnezia-wg-opts";
        [profile appendFormat:@"%@=%@\n",mapping[key],value];
    }
    NSArray *reserved=peer[@"reserved"]?:node[@"reserved"];
    if(reserved){if(awg.count||![reserved isKindOfClass:[NSArray class]]||reserved.count!=3)return @"reserved";unsigned header=0;for(unsigned i=0;i<3;i++){if(!number(reserved[i],255))return @"reserved";header|=[reserved[i] unsignedIntValue]<<(8*(i+1));}for(unsigned i=0;i<4;i++)[profile appendFormat:@"H%u=%u\n",i+1,header|i+1];}
    NSString *endpoint=[server rangeOfString:@":"].location!=NSNotFound?[NSString stringWithFormat:@"[%@]",server]:server;
    [profile appendFormat:@"[Peer]\nPublicKey=%@\nEndpoint=%@:%@\nAllowedIPs=%@\n",key,endpoint,port,[allowed componentsJoinedByString:@","]];if(psk)[profile appendFormat:@"PresharedKey=%@\n",psk];
    id keepalive=peer[@"persistent-keepalive"]?:node[@"persistent-keepalive"]?:@0;if(!number(keepalive,65535))return @"persistent-keepalive";[profile appendFormat:@"PersistentKeepalive=%@\n",keepalive];
    char reason[256];if(MLWGParseProfile(profile.UTF8String,cfg,reason,sizeof reason))return awg.count?@"amnezia-wg-opts":@"wireguard-key";return nil;
}
static NSArray *peers(NSDictionary *node){id value=node[@"peers"]?:@[@{}];if(![value isKindOfClass:[NSArray class]]||![value count]||[value count]>8)return nil;for(id p in value)if(![p isKindOfClass:[NSDictionary class]])return nil;return value;}
NSString *MLWGValidateNode(NSDictionary *node){NSArray *values=peers(node);if(!values)return @"peers";awg_config_t *cfg=calloc(1,sizeof *cfg);if(!cfg)return @"memory";NSString *error=nil;for(NSDictionary *p in values)if((error=settings(node,p,cfg)))break;OPENSSL_cleanse(cfg,sizeof *cfg);free(cfg);return error;}
MLWGSession *MLWGOpenJSON(const char *json,const char *hostName,uint16_t port,int udp,unsigned timeoutMS){@autoreleasepool{
    if(!json||!hostName||!port||strnlen(json,65536)==65536){errno=EINVAL;return NULL;}
    id node=[NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:json length:strlen(json)] options:0 error:NULL];if(![node isKindOfClass:[NSDictionary class]]||MLWGValidateNode(node)){errno=EINVAL;return NULL;}
    if(node[@"dialer-proxy"]){errno=ENOTSUP;return NULL;}NSArray *values=peers(node);awg_config_t *configs=calloc(values.count,sizeof *configs);if(!configs)return NULL;vless_dest_t target={.port=port};uint8_t bytes[16];uint64_t deadline=senko_now_ms()+timeoutMS;
    for(NSUInteger i=0;i<values.count;i++)if(settings(node,values[i],&configs[i])){OPENSSL_cleanse(configs,values.count*sizeof *configs);free(configs);errno=EINVAL;return NULL;}
    if(inet_pton(AF_INET,hostName,bytes)==1){target.atyp=VLESS_ADDR_IPV4;memcpy(target.host_addr,bytes,4);}else if(inet_pton(AF_INET6,hostName,bytes)==1){target.atyp=VLESS_ADDR_IPV6;memcpy(target.host_addr,bytes,16);}else target.atyp=VLESS_ADDR_DOMAIN;
    if(target.atyp==VLESS_ADDR_DOMAIN){if([node[@"remote-dns-resolve"] boolValue]){
        int scores[8];NSUInteger order[8];for(NSUInteger i=0;i<values.count;i++){scores[i]=-1;order[i]=i;for(size_t j=0;j<configs[i].dns_count;j++){vless_dest_t dns={.port=53};dns.atyp=strchr(configs[i].dns[j],':')?VLESS_ADDR_IPV6:VLESS_ADDR_IPV4;if(inet_pton(dns.atyp==VLESS_ADDR_IPV4?AF_INET:AF_INET6,configs[i].dns[j],dns.host_addr)==1){int score=MLWGDestinationPrefix(&configs[i],&dns);if(score>scores[i])scores[i]=score;}}}
        for(NSUInteger i=0;i<values.count;i++)for(NSUInteger j=i+1;j<values.count;j++)if(scores[order[j]]>scores[order[i]]){NSUInteger swap=order[i];order[i]=order[j];order[j]=swap;}
        for(NSUInteger i=0;i<values.count;i++){uint64_t now=senko_now_ms();if(now+100>=deadline)break;unsigned budget=(unsigned)((deadline-now)/(values.count-i));if(scores[order[i]]>=0&&MLWGResolve(&configs[order[i]],hostName,&target,budget)==0)break;}
    }else{struct addrinfo hints={0},*result=NULL;hints.ai_family=AF_UNSPEC;hints.ai_socktype=udp?SOCK_DGRAM:SOCK_STREAM;
        if(MLNetworkResolveHost(hostName,NULL,&hints,&result)==0){for(struct addrinfo *a=result;a;a=a->ai_next){vless_dest_t candidate={.port=port};if(a->ai_family==AF_INET){candidate.atyp=VLESS_ADDR_IPV4;memcpy(candidate.host_addr,&((struct sockaddr_in *)a->ai_addr)->sin_addr,4);}else if(a->ai_family==AF_INET6){candidate.atyp=VLESS_ADDR_IPV6;memcpy(candidate.host_addr,&((struct sockaddr_in6 *)a->ai_addr)->sin6_addr,16);}else continue;
            for(NSUInteger i=0;i<values.count;i++)if(MLWGDestinationAllowed(&configs[i],&candidate)){target=candidate;break;}if(target.atyp!=VLESS_ADDR_DOMAIN)break;
        }freeaddrinfo(result);}
    }}
    MLWGSession *session=NULL;int best=-1;NSUInteger selected=0;
    if(target.atyp!=VLESS_ADDR_DOMAIN)for(NSUInteger i=0;i<values.count;i++){int score=MLWGDestinationPrefix(&configs[i],&target);if(score>best){best=score;selected=i;}}
    uint64_t now=senko_now_ms();if(best>=0&&now+100<deadline)session=MLWGOpen(&configs[selected],&target,udp,(unsigned)(deadline-now));
    OPENSSL_cleanse(configs,values.count*sizeof *configs);free(configs);if(!session&&!errno)errno=EHOSTUNREACH;return session;
}}
