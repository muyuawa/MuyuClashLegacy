#import "MLConfig.h"
#import "../dns/MLDNS.h"
#import "../protocols/MLStream.h"
#import "../routing/MLRoutingInternal.h"
#import "../providers/MLGeoIndex.h"
#import "../providers/MLDomainProviderIndex.h"
#include <yaml.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>

static const NSUInteger MLMaxYAML = 512 * 1024;
static const NSUInteger MLMaxNodes = 20000;
static const NSUInteger MLMaxDepth = 32;
static const NSUInteger MLMaxIssues = 256;
static const NSUInteger MLMaxKeyBytes = 256;
static const NSUInteger MLMaxFieldBytes = 1024;

static NSString *MLField(NSString *parent, NSString *key) {
    return parent.length ? [parent stringByAppendingFormat:@".%@",key] : key;
}
static NSString *MLIndex(NSString *parent, NSUInteger index) {
    return [parent stringByAppendingFormat:@"[%lu]",(unsigned long)index];
}
static BOOL MLMatch(NSString *string, NSString *pattern) {
    return [string rangeOfString:pattern options:NSRegularExpressionSearch].location != NSNotFound;
}
static BOOL MLText(id value) { return [value isKindOfClass:[NSString class]] && [value length] > 0; }
static BOOL MLBoolean(id value) {
    return [value isKindOfClass:[NSNumber class]] && CFGetTypeID((__bridge CFTypeRef)value)==CFBooleanGetTypeID();
}
static BOOL MLFlag(id value) { return MLBoolean(value) && [value boolValue]; }
static NSArray *MLList(id value) { return [value isKindOfClass:[NSArray class]] ? value : @[]; }
static NSDictionary *MLIssue(NSString *identifier, NSString *category, NSString *severity,
                             NSString *field, NSNumber *line, NSNumber *column,
                             NSString *reason, NSString *impact, NSString *suggestion) {
    return @{@"id":identifier,@"category":category,@"severity":severity,@"field":field ?: @"",
             @"line":line ?: @0,@"column":column ?: @0,@"reason":reason,
             @"impact":impact,@"suggestion":suggestion};
}

// Resolve only a small, explicit YAML scalar schema; never construct tagged objects.
static id MLScalar(NSString *text, yaml_scalar_style_t style) {
    if (style != YAML_PLAIN_SCALAR_STYLE) return text;
    if ([text isEqual:@"true"] || [text isEqual:@"True"] || [text isEqual:@"TRUE"]) return @YES;
    if ([text isEqual:@"false"] || [text isEqual:@"False"] || [text isEqual:@"FALSE"]) return @NO;
    if (!text.length || [text isEqual:@"null"] || [text isEqual:@"Null"] ||
        [text isEqual:@"NULL"] || [text isEqual:@"~"]) return [NSNull null];
    if (MLMatch(text,@"^[+-]?(0|[1-9][0-9]*)$")) {
        errno=0; char *end=NULL; long long n=strtoll(text.UTF8String,&end,10);
        if (!errno && end && !*end) return @(n);
    }
    if (MLMatch(text,@"^[+-]?([0-9]+\\.[0-9]*|[0-9]*\\.[0-9]+)([eE][+-]?[0-9]+)?$")) {
        errno=0; char *end=NULL; double n=strtod(text.UTF8String,&end);
        if (!errno && end && !*end && isfinite(n)) return @(n);
    }
    return text;
}

@interface MLYAMLReader : NSObject {
    yaml_parser_t _parser;
    BOOL _initialized;
}
@property(nonatomic,strong) NSMutableArray *issues;
@property(nonatomic,strong) NSMutableDictionary *marks;
@property(nonatomic) BOOL failed;
@property(nonatomic) NSUInteger nodes;
- (id)read:(NSData *)data;
@end

@implementation MLYAMLReader
- (id)init {
    if ((self=[super init])) { _issues=[NSMutableArray array];_marks=[NSMutableDictionary dictionary]; }
    return self;
}
- (void)dealloc { if (_initialized) yaml_parser_delete(&_parser); }
- (void)fail:(NSString *)identifier reason:(NSString *)reason field:(NSString *)field mark:(yaml_mark_t)mark {
    if (_failed) return;
    _failed=YES;
    [_issues addObject:MLIssue(identifier,@"parsing",@"block",field,@(mark.line+1),@(mark.column+1),reason,
                              @"The document and remaining configuration checks are incomplete.",
                              @"Correct this YAML issue and check the entire configuration again.")];
}
- (BOOL)next:(yaml_event_t *)event {
    if (_failed) return NO;
    if (yaml_parser_parse(&_parser,event)) return YES;
    NSString *reason=_parser.problem ? [NSString stringWithUTF8String:_parser.problem] : @"Invalid YAML.";
    [self fail:@"YAML_SYNTAX" reason:reason ?: @"Invalid YAML." field:@"" mark:_parser.problem_mark];
    return NO;
}
- (BOOL)count:(yaml_mark_t)mark field:(NSString *)field depth:(NSUInteger)depth {
    if ([field lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>MLMaxFieldBytes) {
        [self fail:@"YAML_FIELD_PATH_LIMIT" reason:@"A diagnostic field path exceeds 1024 UTF-8 bytes." field:@"" mark:mark];return NO;
    }
    if (depth>MLMaxDepth) {
        [self fail:@"YAML_DEPTH_LIMIT" reason:@"YAML nesting exceeds 32 levels." field:field mark:mark];return NO;
    }
    if (++_nodes>MLMaxNodes) {
        [self fail:@"YAML_NODE_LIMIT" reason:@"YAML contains more than 20,000 nodes." field:field mark:mark];return NO;
    }
    return YES;
}
- (BOOL)plainNode:(yaml_event_t *)event field:(NSString *)field {
    yaml_char_t *tag=NULL,*anchor=NULL;
    if(event->type==YAML_SCALAR_EVENT){tag=event->data.scalar.tag;anchor=event->data.scalar.anchor;}
    else if(event->type==YAML_MAPPING_START_EVENT){tag=event->data.mapping_start.tag;anchor=event->data.mapping_start.anchor;}
    else if(event->type==YAML_SEQUENCE_START_EVENT){tag=event->data.sequence_start.tag;anchor=event->data.sequence_start.anchor;}
    if (tag || anchor || event->type==YAML_ALIAS_EVENT) {
        [self fail:event->type==YAML_ALIAS_EVENT ? @"YAML_ALIAS_FORBIDDEN" : (tag ? @"YAML_TAG_FORBIDDEN" : @"YAML_ANCHOR_FORBIDDEN")
             reason:@"Aliases, anchors and explicit YAML tags are not allowed." field:field mark:event->start_mark];
        return NO;
    }
    return YES;
}
- (id)node:(yaml_event_t *)event depth:(NSUInteger)depth field:(NSString *)field {
    yaml_mark_t mark=event->start_mark;
    if (![self count:mark field:field depth:depth] || ![self plainNode:event field:field]) {yaml_event_delete(event);return nil;}
    _marks[field]=@[@(mark.line+1),@(mark.column+1)];
    if (event->type==YAML_SCALAR_EVENT) {
        NSString *text=[[NSString alloc] initWithBytes:event->data.scalar.value length:event->data.scalar.length encoding:NSUTF8StringEncoding];
        id result=text ? MLScalar(text,event->data.scalar.style) : nil;
        if(!text)[self fail:@"YAML_ENCODING" reason:@"A scalar is not valid UTF-8." field:field mark:mark];
        yaml_event_delete(event);return result;
    }
    if (event->type==YAML_MAPPING_START_EVENT) {
        yaml_event_delete(event);
        NSMutableDictionary *map=[NSMutableDictionary dictionary];
        while(!_failed) {
            yaml_event_t keyEvent;if(![self next:&keyEvent])return nil;
            if(keyEvent.type==YAML_MAPPING_END_EVENT){yaml_event_delete(&keyEvent);return [map copy];}
            if(![self count:keyEvent.start_mark field:field depth:depth+1] || ![self plainNode:&keyEvent field:field]){yaml_event_delete(&keyEvent);return nil;}
            if(keyEvent.type!=YAML_SCALAR_EVENT){[self fail:@"YAML_KEY_TYPE" reason:@"Mapping keys must be strings." field:field mark:keyEvent.start_mark];yaml_event_delete(&keyEvent);return nil;}
            if(keyEvent.data.scalar.length>MLMaxKeyBytes){
                [self fail:@"YAML_KEY_LIMIT" reason:@"A mapping key exceeds 256 UTF-8 bytes." field:field mark:keyEvent.start_mark];yaml_event_delete(&keyEvent);return nil;
            }
            NSString *key=[[NSString alloc] initWithBytes:keyEvent.data.scalar.value length:keyEvent.data.scalar.length encoding:NSUTF8StringEncoding];
            if(!key || ![MLScalar(key,keyEvent.data.scalar.style) isKindOfClass:[NSString class]] || !key.length){
                [self fail:@"YAML_KEY_TYPE" reason:@"Mapping keys must be nonempty strings." field:field mark:keyEvent.start_mark];yaml_event_delete(&keyEvent);return nil;
            }
            NSString *child=MLField(field,key);
            if([child lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>MLMaxFieldBytes){
                [self fail:@"YAML_FIELD_PATH_LIMIT" reason:@"A diagnostic field path exceeds 1024 UTF-8 bytes." field:field mark:keyEvent.start_mark];yaml_event_delete(&keyEvent);return nil;
            }
            if(map[key]){[self fail:@"YAML_DUPLICATE_KEY" reason:@"A mapping contains the same key more than once." field:child mark:keyEvent.start_mark];yaml_event_delete(&keyEvent);return nil;}
            _marks[child]=@[@(keyEvent.start_mark.line+1),@(keyEvent.start_mark.column+1)];
            yaml_event_delete(&keyEvent);
            yaml_event_t valueEvent;if(![self next:&valueEvent])return nil;
            id value=[self node:&valueEvent depth:depth+1 field:child];if(!value)return nil;
            map[key]=value;
        }
        return nil;
    }
    if(event->type==YAML_SEQUENCE_START_EVENT){
        yaml_event_delete(event);NSMutableArray *array=[NSMutableArray array];
        while(!_failed){
            yaml_event_t item;if(![self next:&item])return nil;
            if(item.type==YAML_SEQUENCE_END_EVENT){yaml_event_delete(&item);return [array copy];}
            id value=[self node:&item depth:depth+1 field:MLIndex(field,array.count)];if(!value)return nil;
            [array addObject:value];
        }
        return nil;
    }
    [self fail:@"YAML_NODE_TYPE" reason:@"Unexpected YAML node." field:field mark:mark];yaml_event_delete(event);return nil;
}
- (id)read:(NSData *)data {
    if(!yaml_parser_initialize(&_parser)){yaml_mark_t mark={0};[self fail:@"YAML_MEMORY" reason:@"The YAML parser could not allocate memory." field:@"" mark:mark];return nil;}
    _initialized=YES;yaml_parser_set_input_string(&_parser,data.bytes,data.length);
    yaml_event_t event;if(![self next:&event])return nil;
    if(event.type!=YAML_STREAM_START_EVENT){[self fail:@"YAML_SYNTAX" reason:@"Missing YAML stream." field:@"" mark:event.start_mark];yaml_event_delete(&event);return nil;}
    yaml_event_delete(&event);if(![self next:&event])return nil;
    if(event.type!=YAML_DOCUMENT_START_EVENT){[self fail:@"YAML_EMPTY" reason:@"A configuration document is required." field:@"" mark:event.start_mark];yaml_event_delete(&event);return nil;}
    if(event.data.document_start.tag_directives.start!=event.data.document_start.tag_directives.end){[self fail:@"YAML_TAG_FORBIDDEN" reason:@"YAML tag directives are not allowed." field:@"" mark:event.start_mark];yaml_event_delete(&event);return nil;}
    yaml_event_delete(&event);if(![self next:&event])return nil;
    id document=[self node:&event depth:1 field:@""];if(!document)return nil;
    if(![self next:&event])return nil;
    if(event.type!=YAML_DOCUMENT_END_EVENT){[self fail:@"YAML_SYNTAX" reason:@"Expected the document end." field:@"" mark:event.start_mark];yaml_event_delete(&event);return nil;}
    yaml_event_delete(&event);if(![self next:&event])return nil;
    if(event.type!=YAML_STREAM_END_EVENT){[self fail:@"YAML_MULTIPLE_DOCUMENTS" reason:@"Only one YAML document may be imported." field:@"" mark:event.start_mark];yaml_event_delete(&event);return nil;}
    yaml_event_delete(&event);return document;
}
@end

@interface MLConfigValidator : NSObject
@property(nonatomic,strong) NSDictionary *document;
@property(nonatomic,strong) NSDictionary *marks;
@property(nonatomic,strong) NSMutableArray *issues;
@property(nonatomic,strong) NSMutableDictionary *names;
@property(nonatomic,strong) NSMutableDictionary *groups;
@property(nonatomic,strong) NSMutableDictionary *graph;
@property(nonatomic) BOOL prepared;
@property(nonatomic) BOOL classical;
@property(nonatomic,strong) MLGeoIndex *geoIndex;
@property(nonatomic) BOOL unchecked;
- (void)validate;
@end

@implementation MLConfigValidator
- (void)add:(NSString *)identifier category:(NSString *)category severity:(NSString *)severity field:(NSString *)field reason:(NSString *)reason {
    if(_issues.count>=MLMaxIssues){_unchecked=YES;return;}
    NSString *markedField=field;
    while(markedField.length && !_marks[markedField]){
        NSRange dot=[markedField rangeOfString:@"." options:NSBackwardsSearch];
        NSRange bracket=[markedField rangeOfString:@"[" options:NSBackwardsSearch];
        NSUInteger end=dot.location;
        if(end==NSNotFound || (bracket.location!=NSNotFound && bracket.location>end))end=bracket.location;
        markedField=end==NSNotFound?@"":[markedField substringToIndex:end];
    }
    NSArray *mark=_marks[markedField] ?: _marks[@""];
    NSString *impact=[category isEqual:@"parsing"] ? @"The configuration cannot be safely applied." : @"This setting has not been applied or verified by a local runtime.";
    [_issues addObject:MLIssue(identifier,category,severity,field,mark.count?mark[0]:@0,mark.count>1?mark[1]:@0,reason,impact,
                              [category isEqual:@"parsing"] ? @"Correct the field and check again." : @"Use a verified implementation before enabling this capability.")];
}
- (void)bad:(NSString *)identifier field:(NSString *)field reason:(NSString *)reason {
    [self add:identifier category:@"parsing" severity:@"block" field:field reason:reason];
}
- (BOOL)expect:(id)value class:(Class)class field:(NSString *)field {
    if([value isKindOfClass:class])return YES;
    [self bad:@"FIELD_TYPE" field:field reason:[NSString stringWithFormat:@"Expected %@.",NSStringFromClass(class)]];return NO;
}
- (void)unknown:(NSDictionary *)map allowed:(NSString *)keys field:(NSString *)field {
    NSSet *allowed=[NSSet setWithArray:[keys componentsSeparatedByString:@" "]];
    for(NSString *key in map)if(![allowed containsObject:key])
        [self add:@"UNKNOWN_FIELD" category:@"compatibility" severity:@"block" field:MLField(field,key) reason:@"This field is not recognized by the pinned compatibility checker; it will not be silently ignored."];
}
- (void)required:(NSDictionary *)map keys:(NSString *)keys field:(NSString *)field {
    for(NSString *key in [keys componentsSeparatedByString:@" "])
        if(!MLText(map[key]))[self bad:@"REQUIRED_FIELD" field:MLField(field,key) reason:@"A nonempty string is required."];
}
- (void)port:(id)value field:(NSString *)field {
    NSString *text=[value isKindOfClass:[NSString class]] ? value : ([value isKindOfClass:[NSNumber class]] && !MLBoolean(value) ? [value stringValue] : nil);
    if(!text || !MLMatch(text,@"^[0-9]{1,5}$") || text.longLongValue<1 || text.longLongValue>65535)
        [self bad:@"PORT_RANGE" field:field reason:@"Port must be an integer between 1 and 65535."];
}
- (BOOL)strings:(id)value field:(NSString *)field {
    if(![self expect:value class:[NSArray class] field:field])return NO;
    BOOL valid=YES;NSUInteger i=0;
    for(id member in value){if(!MLText(member)){[self bad:@"FIELD_TYPE" field:MLIndex(field,i) reason:@"A nonempty string is required."];valid=NO;}i++;}
    return valid;
}
- (BOOL)number:(id)value low:(double)low high:(double)high field:(NSString *)field {
    if (![value isKindOfClass:[NSNumber class]] || MLBoolean(value) || !isfinite([value doubleValue]) || [value doubleValue]<low || [value doubleValue]>high || floor([value doubleValue])!=[value doubleValue]) {
        [self bad:@"FIELD_RANGE" field:field reason:[NSString stringWithFormat:@"An integer between %.0f and %.0f is required.",low,high]]; return NO;
    }
    return YES;
}
- (void)url:(id)value secure:(BOOL)secure field:(NSString *)field {
    if (!MLText(value) || [value length]>4096 || [value rangeOfCharacterFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].location!=NSNotFound || [value rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound) {
        [self bad:@"URL_FORMAT" field:field reason:@"A bounded URL without whitespace or control characters is required."]; return;
    }
    NSURL *url=[NSURL URLWithString:value];
    if (!url.host.length || url.user || url.password || url.fragment || ![(secure ? @[@"https"] : @[@"http",@"https"]) containsObject:url.scheme.lowercaseString] || (url.port && (url.port.integerValue<1 || url.port.integerValue>65535)))
        [self bad:@"URL_FORMAT" field:field reason:secure ? @"Provider downloads require HTTPS with verified peer and hostname." : @"Health checks require an HTTP or HTTPS URL without userinfo or a fragment."];
}
- (void)patterns:(id)value field:(NSString *)field {
    if (![value isKindOfClass:[NSString class]] || [value length]>4096) { [self bad:@"FIELD_TYPE" field:field reason:@"A filter must be a string of at most 4096 characters."]; return; }
    if (![value length]) return;
    NSArray *parts=[value componentsSeparatedByString:@"`"];
    if (parts.count>16) [self bad:@"PROVIDER_FILTER_LIMIT" field:field reason:@"At most sixteen filter expressions are supported."];
    for (NSString *pattern in parts) if (!pattern.length || ![NSRegularExpression regularExpressionWithPattern:pattern options:0 error:NULL])
        [self bad:@"RULE_REGEX" field:field reason:@"This expression is invalid in the legacy Foundation regex engine."];
}
- (void)privatePath:(id)value field:(NSString *)field {
    if (!MLText(value) || [value isAbsolutePath] || [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>256 || [value rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound) {
        [self bad:@"PROVIDER_PATH" field:field reason:@"A relative path inside the private Provider local directory is required."]; return;
    }
    NSString *relative=[value hasPrefix:@"./"]?[value substringFromIndex:2]:value;
    NSArray *parts=[relative componentsSeparatedByString:@"/"];
    if (parts.count>16) [self bad:@"PROVIDER_PATH" field:field reason:@"Provider paths are limited to sixteen components."];
    for (NSString *part in parts) if (!part.length || [@[@".",@"..",@"~"] containsObject:part]) [self bad:@"PROVIDER_PATH" field:field reason:@"Empty, parent, embedded current and home-directory path components are prohibited."];
}
- (void)reserved:(id)value field:(NSString *)field depth:(NSUInteger)depth {
    if (depth>32) { [self bad:@"YAML_DEPTH_LIMIT" field:field reason:@"The internal generation exceeds 32 levels."]; return; }
    if ([value isKindOfClass:[NSDictionary class]]) for (NSString *key in value) {
        if ([key hasPrefix:@"_"] && (!_prepared || field.length || ![@[@"_rule-provider-payloads",@"_provider-health-checks",@"_provider-generation",@"_geoip",@"_geosite",@"_ip-asn",@"_geo-index"] containsObject:key]))
            [self bad:@"RESERVED_FIELD" field:MLField(field,key) reason:@"Reserved runtime fields cannot be supplied by imported YAML."];
        [self reserved:value[key] field:MLField(field,key) depth:depth+1];
    } else if ([value isKindOfClass:[NSArray class]]) { NSUInteger i=0; for (id item in value) [self reserved:item field:MLIndex(field,i++) depth:depth+1]; }
}
- (void)health:(id)value field:(NSString *)field provider:(BOOL)provider {
    if (![self expect:value class:[NSDictionary class] field:field]) return;
    [self unknown:value allowed:provider ? @"enable url interval timeout lazy expected-status" : @"" field:field];
    if (value[@"enable"] && !MLBoolean(value[@"enable"])) [self bad:@"FIELD_TYPE" field:MLField(field,@"enable") reason:@"A boolean is required."];
    if (value[@"lazy"] && !MLBoolean(value[@"lazy"])) [self bad:@"FIELD_TYPE" field:MLField(field,@"lazy") reason:@"A boolean is required."];
    if (value[@"url"]) [self url:value[@"url"] secure:NO field:MLField(field,@"url")];
    if (value[@"interval"]) [self number:value[@"interval"] low:0 high:86400 field:MLField(field,@"interval")];
    if (value[@"timeout"]) [self number:value[@"timeout"] low:100 high:30000 field:MLField(field,@"timeout")];
    if (MLPolicyStatusIssue(value[@"expected-status"])) [self bad:@"GROUP_STATUS_RANGE" field:MLField(field,@"expected-status") reason:@"Use slash or comma separated HTTP status numbers/ranges, or *."];
}
- (void)registerName:(id)name field:(NSString *)field allowGlobal:(BOOL)allowGlobal {
    if(!MLText(name)){[self bad:@"REQUIRED_FIELD" field:field reason:@"A nonempty name is required."];return;}
    if([name length]>256 || [name rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound){[self bad:@"NAME_FORMAT" field:field reason:@"Names require 1–256 ordinary characters."];return;}
    if(_names[name] || (!allowGlobal && [name isEqual:@"GLOBAL"]) ||
       [@[@"DIRECT",@"REJECT",@"REJECT-DROP",@"PASS",@"PASS-RULE",@"COMPATIBLE"] containsObject:name])
        [self bad:@"NAME_DUPLICATE" field:field reason:@"Proxy and group names must be unique and must not shadow builtins."];
    else _names[name]=field;
}
- (void)registerName:(id)name field:(NSString *)field {
    [self registerName:name field:field allowGlobal:NO];
}
- (void)reference:(NSString *)name field:(NSString *)field {
    if([@[@"REJECT-DROP",@"PASS",@"PASS-RULE",@"COMPATIBLE"] containsObject:name])
        [self add:@"TARGET_UNAVAILABLE" category:@"compatibility" severity:@"block" field:field reason:@"This builtin policy is unavailable in the local core."];
    else if(!_names[name] && ![@[@"DIRECT",@"REJECT",@"GLOBAL"] containsObject:name]) {
        if (!_prepared && [_document[@"proxy-providers"] isKindOfClass:[NSDictionary class]] && [_document[@"proxy-providers"] count])
            [self add:@"REFERENCE_PROVIDER_PENDING" category:@"runtime" severity:@"unverified" field:field reason:@"This target must resolve in the validated Provider generation before activation."];
        else [self bad:@"REFERENCE_MISSING" field:field reason:@"The referenced target does not exist. Inspect the value at the reported field."];
    }
}
- (void)proxyOptions:(NSDictionary *)node field:(NSString *)field runtimeSupported:(BOOL)runtimeSupported {
    NSDictionary *schemas=@{@"ws-opts":@"path headers max-early-data early-data-header-name v2ray-http-upgrade v2ray-http-upgrade-fast-open",
      @"grpc-opts":@"grpc-service-name",@"reality-opts":@"public-key short-id support-x25519mlkem768",
      @"xhttp-opts":@"path mode host",
      @"h2-opts":@"host path",@"http-opts":@"method path headers",@"smux":@"enabled protocol max-connections min-streams max-streams statistic padding only-tcp brutal-opts",
      @"plugin-opts":@"mode host path tls skip-cert-verify mux headers fingerprint",@"ech-opts":@"enable config"};
    for(NSString *key in schemas)if(node[key]){
        NSString *path=MLField(field,key);
        if([self expect:node[key] class:[NSDictionary class] field:path]){
            [self unknown:node[key] allowed:schemas[key] field:path];
            NSDictionary *nested=node[key];
            if(nested[@"headers"]){
                NSString *headersPath=MLField(path,@"headers");
                if([self expect:nested[@"headers"] class:[NSDictionary class] field:headersPath])
                    for(NSString *header in nested[@"headers"]){id v=nested[@"headers"][header];if(![v isKindOfClass:[NSString class]] && ![v isKindOfClass:[NSArray class]])[self bad:@"FIELD_TYPE" field:MLField(headersPath,header) reason:@"HTTP header values must be strings or string lists."];}
            }
            if(!runtimeSupported)_unchecked=YES;
        }
    }
}
- (void)proxies:(id)value {
    if(!value)return;if(![self expect:value class:[NSArray class] field:@"proxies"])return;
    if ([value count]>1024) [self bad:@"PROXY_LIMIT" field:@"proxies" reason:@"At most 1024 proxy nodes are supported."];
    NSUInteger i=0;
    for(id object in value){NSString *field=MLIndex(@"proxies",i++);if(![self expect:object class:[NSDictionary class] field:field])continue;
        NSDictionary *node=object;[self registerName:node[@"name"] field:MLField(field,@"name")];
        [self required:node keys:@"type" field:field];
        [self unknown:node allowed:@"name type server port username password cipher uuid alterId udp tls servername sni skip-cert-verify fingerprint client-fingerprint alpn network ws-opts grpc-opts xhttp-opts reality-opts h2-opts http-opts plugin plugin-opts obfs obfs-param protocol protocol-param flow packet-encoding encryption ip ipv6 private-key public-key preshared-key reserved mtu peers persistent-keepalive allowed-ips dns remote-dns-resolve amnezia-wg-option jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 token udp-relay-mode congestion-controller disable-sni reduce-rtt max-udp-relay-packet-size fast-open heartbeat-interval version psk dialer-proxy interface-name routing-mark tfo mptcp ip-version smux ech-opts ports hop-interval up down obfs-password recv-window-conn recv-window auth auth-str auth_str ca ca-str certificate private-key-path private-key-passphrase host-key host-key-algorithms idle-session-check-interval idle-session-timeout min-idle-session" field:field];
        NSString *type=MLText(node[@"type"]) ? [node[@"type"] lowercaseString] : @"";
        BOOL builtin=[@[@"direct",@"reject"] containsObject:type];
        BOOL wireguard=[@[@"wireguard",@"amneziawg",@"amnezia-wg"] containsObject:type];
        BOOL peers=wireguard&&[node[@"peers"] isKindOfClass:[NSArray class]]&&[node[@"peers"] count]>0;
        if(!builtin&&!peers){[self required:node keys:@"server" field:field];[self port:node[@"port"] field:MLField(field,@"port")];}
        NSString *unsupported=MLStreamValidateNode(node);
        if([unsupported isEqual:@"type"])
            [self add:@"PROTOCOL_UNAVAILABLE" category:@"compatibility" severity:@"block" field:MLField(field,unsupported) reason:@"This node type has no integrated TCP adapter."];
        else if(unsupported)
            [self add:@"PROXY_OPTION_UNAVAILABLE" category:@"compatibility" severity:@"block" field:MLField(field,unsupported) reason:@"This option or value is outside the supported TCP adapter configuration."];
        NSDictionary *required=@{@"ss":@"cipher password",@"ssr":@"cipher password protocol obfs",@"vmess":@"uuid",@"vless":@"uuid",@"trojan":@"password",@"hysteria2":@"password",@"hy2":@"password",@"tuic":@"uuid password",@"anytls":@"password",@"snell":@"psk"};
        if(required[type])[self required:node keys:required[type] field:field];
        if(wireguard) {
            [self required:node keys:peers?@"private-key":@"private-key public-key" field:field];
            if(!MLText(node[@"ip"])&&!MLText(node[@"ipv6"]))[self bad:@"REQUIRED_FIELD" field:MLField(field,@"ip") reason:@"WireGuard needs an IPv4 or IPv6 tunnel address."];
        }
        if(node[@"uuid"] && MLText(node[@"uuid"]) && !MLMatch(node[@"uuid"],@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"))
            [self bad:@"UUID_FORMAT" field:MLField(field,@"uuid") reason:@"UUID must use the standard 8-4-4-4-12 hexadecimal form."];
        for(NSString *key in @[@"udp",@"tls",@"skip-cert-verify",@"tfo",@"mptcp",@"fast-open",@"disable-sni",@"reduce-rtt"])
            if(node[key] && !MLBoolean(node[key]))[self bad:@"FIELD_TYPE" field:MLField(field,key) reason:@"A boolean is required."];
        if(MLBoolean(node[@"skip-cert-verify"]) && [node[@"skip-cert-verify"] boolValue]) [self add:@"TLS_VERIFICATION_DISABLED" category:@"runtime" severity:@"confirm" field:MLField(field,@"skip-cert-verify") reason:@"This configuration asks to disable certificate verification. It is never enabled automatically."];
        if(!unsupported&&[@[@"hy2",@"hysteria2"] containsObject:type]&&node[@"client-fingerprint"]&&_issues.count<MLMaxIssues) {
            NSString *path=MLField(field,@"client-fingerprint");NSArray *mark=_marks[path] ?: _marks[field];
            [_issues addObject:MLIssue(@"HY2_BROWSER_PROFILE_UNUSED",@"runtime",@"warning",path,mark.count?mark[0]:@0,mark.count>1?mark[1]:@0,
                @"Hysteria 2 does not apply client-fingerprint, matching the pinned Mihomo baseline.",
                @"QUIC uses verified TLS without a browser ClientHello profile. Certificate fingerprint pinning remains separate.",
                @"Remove client-fingerprint if you want the configuration to contain only effective Hysteria 2 options.")];
        }
        [self proxyOptions:node field:field runtimeSupported:unsupported==nil];
    }
}
- (void)groups:(id)value {
    if(!value)return;if(![self expect:value class:[NSArray class] field:@"proxy-groups"])return;
    if ([value count]>1024) [self bad:@"GROUP_LIMIT" field:@"proxy-groups" reason:@"At most 1024 policy groups are supported."];
    NSUInteger i=0;
    for(id object in value){NSString *field=MLIndex(@"proxy-groups",i++);if(![self expect:object class:[NSDictionary class] field:field])continue;
        NSDictionary *group=object;[self registerName:group[@"name"] field:MLField(field,@"name") allowGlobal:YES];
        [self unknown:group allowed:@"name type proxies default-selected use url interval lazy tolerance timeout strategy disable-udp hidden icon include-all include-all-proxies include-all-providers filter exclude-filter exclude-type expected-status empty-fallback" field:field];
        [self required:group keys:@"type" field:field];
        if(MLText(group[@"name"]))_groups[group[@"name"]]=@{@"value":group,@"field":field};
        NSString *type=MLText(group[@"type"])?group[@"type"]:@"";
        if(![@[@"select",@"url-test",@"fallback",@"load-balance",@"relay"] containsObject:type])
            [self add:@"GROUP_TYPE_UNSUPPORTED" category:@"compatibility" severity:@"block" field:MLField(field,@"type") reason:@"This policy group type has no local implementation."];
        if(group[@"proxies"])[self strings:group[@"proxies"] field:MLField(field,@"proxies")];
        if(group[@"use"])[self strings:group[@"use"] field:MLField(field,@"use")];
        BOOL dynamic=MLFlag(group[@"include-all"]) || MLFlag(group[@"include-all-proxies"]) || MLFlag(group[@"include-all-providers"]);
        if ((![_document[@"proxy-providers"] isKindOfClass:[NSDictionary class]] || ![_document[@"proxy-providers"] count]) && !MLList(_document[@"proxies"]).count) dynamic=NO;
        BOOL populated=([group[@"proxies"] isKindOfClass:[NSArray class]] && [group[@"proxies"] count]) || ([group[@"use"] isKindOfClass:[NSArray class]] && [group[@"use"] count]) || dynamic || MLText(group[@"empty-fallback"]);
        if(!populated) [self bad:@"GROUP_EMPTY" field:field reason:@"A policy group requires members, Providers, include-all sources or an empty-fallback."];
        if(group[@"default-selected"] && (!MLText(group[@"default-selected"]) || ![group[@"proxies"] isKindOfClass:[NSArray class]] || ![group[@"proxies"] containsObject:group[@"default-selected"]]))
            [self bad:@"GROUP_DEFAULT_SELECTION" field:MLField(field,@"default-selected") reason:@"The default selection must name an immediate group member."];
        if(group[@"empty-fallback"] && !MLText(group[@"empty-fallback"])) [self bad:@"FIELD_TYPE" field:MLField(field,@"empty-fallback") reason:@"A target name is required."];
        for (NSString *key in @[@"lazy",@"disable-udp",@"hidden",@"include-all",@"include-all-proxies",@"include-all-providers"]) if (group[key] && !MLBoolean(group[key])) [self bad:@"FIELD_TYPE" field:MLField(field,key) reason:@"A boolean is required."];
        for (NSString *key in @[@"icon",@"exclude-type"]) if (group[key] && ![group[key] isKindOfClass:[NSString class]]) [self bad:@"FIELD_TYPE" field:MLField(field,key) reason:@"A string is required."];
        for (NSString *key in @[@"filter",@"exclude-filter"]) if (group[key]) [self patterns:group[key] field:MLField(field,key)];
        if (group[@"url"]) [self url:group[@"url"] secure:NO field:MLField(field,@"url")];
        if (MLText(group[@"url"]) && [group[@"url"] length]>1024) [self bad:@"URL_FORMAT" field:MLField(field,@"url") reason:@"Health URLs are limited to 1024 characters."];
        if (group[@"interval"]) [self number:group[@"interval"] low:1 high:86400 field:MLField(field,@"interval")];
        if (group[@"timeout"]) [self number:group[@"timeout"] low:100 high:30000 field:MLField(field,@"timeout")];
        if (group[@"tolerance"]) [self number:group[@"tolerance"] low:0 high:30000 field:MLField(field,@"tolerance")];
        if (![@[@"url-test",@"fallback",@"load-balance"] containsObject:type]) for (NSString *key in @[@"interval",@"timeout",@"lazy",@"tolerance",@"expected-status"]) if (group[key]) [self add:@"GROUP_OPTION_UNAVAILABLE" category:@"compatibility" severity:@"block" field:MLField(field,key) reason:@"This option requires an automatic health-check group."];
        if (group[@"tolerance"] && ![type isEqual:@"url-test"]) [self bad:@"GROUP_OPTION" field:MLField(field,@"tolerance") reason:@"Tolerance applies only to url-test groups."];
        if (MLPolicyStatusIssue(group[@"expected-status"])) [self bad:@"GROUP_STATUS_RANGE" field:MLField(field,@"expected-status") reason:@"Use slash or comma separated HTTP status ranges, or *."];
        if (group[@"strategy"] && (![type isEqual:@"load-balance"] || ![@[@"round-robin",@"consistent-hashing",@"sticky-sessions"] containsObject:group[@"strategy"]])) [self bad:@"GROUP_STRATEGY" field:MLField(field,@"strategy") reason:@"Load-balance supports round-robin, consistent-hashing and sticky-sessions."];
        if ([type isEqual:@"relay"] && (group[@"url"] || group[@"interval"] || group[@"timeout"] || group[@"tolerance"] || group[@"lazy"] || group[@"expected-status"])) [self bad:@"GROUP_OPTION" field:field reason:@"Relay groups cannot specify an automatic health-check policy."];
    }
}
- (NSUInteger)visit:(NSString *)name state:(NSMutableDictionary *)state depth:(NSUInteger)depth {
    NSDictionary *entry=_graph[name]; if (!entry) return 0;
    id cached=state[name];
    if ([cached isKindOfClass:[NSNumber class]]) { [self bad:@"GROUP_CYCLE" field:entry[@"field"] reason:@"Group membership and dialer-proxy references form a cycle."]; return 0; }
    if (depth>32 || ([cached isKindOfClass:[NSDictionary class]] && depth+[cached[@"height"] unsignedIntegerValue]-1>32)) { [self bad:@"GROUP_DEPTH_LIMIT" field:entry[@"field"] reason:@"Combined group and dialer-proxy nesting exceeds 32 levels."]; return 0; }
    if ([cached isKindOfClass:[NSDictionary class]]) return [cached[@"hops"] unsignedIntegerValue];
    state[name]=@(-1); NSUInteger hops=[entry[@"node"] boolValue] && ![@[@"direct",@"reject"] containsObject:entry[@"type"]] ? 1 : 0, height=1;
    BOOL ordered=[entry[@"node"] boolValue] || [entry[@"type"] isEqual:@"relay"];
    for (NSString *child in MLList(entry[@"children"])) {
        NSUInteger childHops=[self visit:child state:state depth:depth+1];
        if (ordered) hops+=childHops; else hops=MAX(hops,childHops);
        if ([state[child] isKindOfClass:[NSDictionary class]]) height=MAX(height,1+[state[child][@"height"] unsignedIntegerValue]);
    }
    if (hops>16) [self bad:@"CHAIN_LIMIT" field:entry[@"field"] reason:@"An outbound chain can contain at most sixteen actual proxy stages."];
    state[name]=@{@"hops":@(hops),@"height":@(height)}; return hops;
}
- (void)checkChain:(NSString *)name prefix:(BOOL)prefix state:(NSDictionary *)state checked:(NSMutableSet *)checked depth:(NSUInteger)depth {
    if (depth>32) return;
    NSString *key=[name stringByAppendingString:prefix ? @"|1" : @"|0"];
    if ([checked containsObject:key]) return; [checked addObject:key]; NSDictionary *entry=_graph[name];
    if ([entry[@"node"] boolValue]) {
        NSUInteger before=0;
        for (NSString *child in MLList(entry[@"children"])) { [self checkChain:child prefix:prefix state:state checked:checked depth:depth+1]; if ([state[child] isKindOfClass:[NSDictionary class]]) before=MAX(before,[state[child][@"hops"] unsignedIntegerValue]); }
        NSDictionary *node=entry[@"value"];
        BOOL physical=[@[@"hy2",@"hysteria2",@"tuic",@"wireguard",@"amneziawg",@"amnezia-wg",@"anytls"] containsObject:entry[@"type"]]||node[@"reality-opts"]||[node[@"flow"] isEqual:@"xtls-rprx-vision"];
        if ((prefix || before) && physical) [self bad:@"CHAIN_PROTOCOL_UNAVAILABLE" field:entry[@"field"] reason:@"This protocol requires a physical first hop and cannot be placed behind a TCP proxy stage."];
    } else {
        BOOL previous=prefix;
        for (NSString *child in MLList(entry[@"children"])) {
            [self checkChain:child prefix:previous state:state checked:checked depth:depth+1];
            if ([entry[@"type"] isEqual:@"relay"] && [state[child] isKindOfClass:[NSDictionary class]] && [state[child][@"hops"] unsignedIntegerValue]) previous=YES;
        }
    }
}
- (void)references {
    _graph=[NSMutableDictionary dictionary];
    for(NSString *name in _groups){NSDictionary *entry=_groups[name];NSDictionary *group=entry[@"value"];NSString *field=entry[@"field"];
        NSMutableArray *children=[NSMutableArray array];
        if([group[@"proxies"] isKindOfClass:[NSArray class]]){
            NSUInteger i=0;
            for(id member in group[@"proxies"]){NSString *path=MLIndex(MLField(field,@"proxies"),i++);
                if(MLText(member)){
                    [children addObject:member];
                    if([member isEqual:@"GLOBAL"] && !_groups[@"GLOBAL"])[self bad:@"GROUP_CYCLE" field:path reason:@"The implicit GLOBAL selector includes this group and cannot be one of its members."];
                    else [self reference:member field:path];
                }
            }
        }
        if (MLText(group[@"empty-fallback"])) { [self reference:group[@"empty-fallback"] field:MLField(field,@"empty-fallback")]; if (!children.count) [children addObject:group[@"empty-fallback"]]; }
        _graph[name]=@{@"field":field,@"type":group[@"type"] ?: @"",@"children":children,@"node":@NO};
        if([group[@"use"] isKindOfClass:[NSArray class]]){NSUInteger i=0;for(id member in group[@"use"]){id providers=_document[@"proxy-providers"];
            if(MLText(member) && (![providers isKindOfClass:[NSDictionary class]] || !providers[member]))[self bad:@"REFERENCE_MISSING" field:MLIndex(MLField(field,@"use"),i) reason:@"Referenced proxy Provider does not exist."];i++;
        }}
    }
    NSUInteger i=0;
    for(id node in MLList(_document[@"proxies"])) {
        NSString *field=MLIndex(@"proxies",i++); if (![node isKindOfClass:[NSDictionary class]] || !MLText(node[@"name"])) continue;
        id dialer=node[@"dialer-proxy"];
        if (dialer) { if(MLText(dialer)) [self reference:dialer field:MLField(field,@"dialer-proxy")]; else [self bad:@"FIELD_TYPE" field:MLField(field,@"dialer-proxy") reason:@"A dialer-proxy target name is required."]; }
        _graph[node[@"name"]]=@{@"field":field,@"type":MLText(node[@"type"]) ? [node[@"type"] lowercaseString] : @"",@"children":MLText(dialer) ? @[dialer] : @[],@"node":@YES,@"value":node};
    }
    NSMutableDictionary *state=[NSMutableDictionary dictionary];for(NSString *name in [_graph.allKeys sortedArrayUsingSelector:@selector(compare:)]) [self visit:name state:state depth:1];
    NSMutableSet *checked=[NSMutableSet set]; for (NSString *name in _graph) [self checkChain:name prefix:NO state:state checked:checked depth:0];
}
- (void)ruleOperand:(NSString *)type operand:(NSString *)operand field:(NSString *)field depth:(NSUInteger)depth {
    if (_classical && [@[@"RULE-SET",@"SUB-RULE",@"MATCH"] containsObject:type]) { [self bad:@"RULE_PROVIDER_RECURSION" field:field reason:@"Classical Provider conditions cannot contain recursive Provider or sub-rule references."]; return; }
    NSString *issue=MLRouteRuleOperandIssue(type,operand);
    if (issue) { [self bad:issue field:field reason:@"The rule operand is malformed or unavailable in the native rule compiler."]; return; }
    if ([@[@"AND",@"OR",@"NOT"] containsObject:type]) {
        for (NSString *child in MLRouteConditionChildren(type,operand)) [self condition:child field:field depth:depth+1];
    } else if ([type isEqual:@"SUB-RULE"]) [self condition:operand field:field depth:depth+1];
    else if ([type isEqual:@"RULE-SET"]) {
        id providers=_document[@"rule-providers"], payloads=_document[@"_rule-provider-payloads"];
        if ((![_document[@"rule-providers"] isKindOfClass:[NSDictionary class]] || !providers[operand]) && (!_prepared || ![payloads isKindOfClass:[NSDictionary class]] || !payloads[operand])) [self bad:@"REFERENCE_MISSING" field:field reason:@"Referenced rule Provider does not exist."];
    } else if ([@[@"GEOIP",@"GEOSITE",@"IP-ASN"] containsObject:type] && !([type isEqual:@"GEOIP"] && [operand caseInsensitiveCompare:@"LAN"]==NSOrderedSame)) {
        NSString *key=[type isEqual:@"GEOIP"] ? @"_geoip" : ([type isEqual:@"GEOSITE"] ? @"_geosite" : @"_ip-asn");
        NSString *name=[type isEqual:@"GEOIP"] ? operand.uppercaseString : ([type isEqual:@"IP-ASN"] && [operand hasPrefix:@"AS"] ? [operand substringFromIndex:2] : operand);
        NSString *kind=[type isEqual:@"GEOIP"] ? @"geoip" : ([type isEqual:@"GEOSITE"] ? @"geosite" : @"asn");
        if (!_prepared) [self add:@"RULE_DATABASE_PENDING" category:@"runtime" severity:@"unverified" field:field reason:@"This rule requires Geo preparation with a validated private local/cache database or verified HTTPS update."];
        else if (![_geoIndex containsKind:kind operand:operand] && (![_document[key] isKindOfClass:[NSDictionary class]] || !_document[key][name])) [self add:@"RULE_DATABASE_UNAVAILABLE" category:@"compatibility" severity:@"block" field:field reason:@"This prepared rule has no validated referenced Geo database category."];
    } else if ([type isEqual:@"NETWORK"] && ![@[@"tcp",@"udp"] containsObject:operand.lowercaseString]) [self bad:@"RULE_NETWORK" field:field reason:@"NETWORK requires TCP or UDP."];
}
- (void)ruleOptions:(NSArray *)parts start:(NSUInteger)start type:(NSString *)type field:(NSString *)field {
    BOOL source=[@[@"IP-CIDR",@"IP-CIDR6",@"GEOIP",@"IP-ASN"] containsObject:type];
    BOOL lazy=source || [@[@"RULE-SET",@"AND",@"OR",@"NOT",@"SUB-RULE"] containsObject:type];
    NSMutableSet *seen=[NSMutableSet set];
    for (NSUInteger i=start;i<parts.count;++i) {
        NSString *option=parts[i];
        if ([seen containsObject:option] || !(([option isEqual:@"src"] && source) || ([option isEqual:@"no-resolve"] && lazy))) [self bad:@"RULE_OPTION" field:field reason:@"This rule option is invalid or repeated."];
        [seen addObject:option];
    }
}
- (void)condition:(NSString *)line field:(NSString *)field depth:(NSUInteger)depth {
    if (depth>32 || line.length>4096 || ![line hasPrefix:@"("] || ![line hasSuffix:@")"]) { [self bad:@"RULE_LOGICAL" field:field reason:@"Logical conditions require balanced parentheses and at most 32 levels."]; return; }
    NSArray *parts=MLRouteRuleFields([line substringWithRange:NSMakeRange(1,line.length-2)]);
    if (parts.count<2 || parts.count>4 || [parts[0] isEqual:@"MATCH"] || [parts[0] isEqual:@"SUB-RULE"] || ![parts[1] length]) { [self bad:@"RULE_LOGICAL" field:field reason:@"A logical child must contain a rule type, operand and optional source/no-resolve flags."]; return; }
    [self ruleOptions:parts start:2 type:parts[0] field:field];
    [self ruleOperand:parts[0] operand:parts[1] field:field depth:depth];
}
- (void)rules:(id)value field:(NSString *)root {
    if(!value)return;if(![self expect:value class:[NSArray class] field:root])return;
    if ([value count]>10000) [self bad:@"RULE_LIMIT" field:root reason:@"At most 10000 rules are supported."];
    NSUInteger i=0;
    for(id rule in value){NSString *field=MLIndex(root,i++);if(!MLText(rule) || [rule length]>4096){[self bad:@"FIELD_TYPE" field:field reason:@"A rule must be a nonempty string of at most 4096 characters."];continue;}
        NSArray *parts=MLRouteRuleFields(rule); NSString *type=parts[0]; BOOL match=[type isEqual:@"MATCH"]; NSUInteger expected=match?2:3;
        if(parts.count<expected || parts.count>expected+2){[self bad:@"FIELD_TYPE" field:field reason:@"The rule has an invalid number of fields."];continue;}
        BOOL empty=NO;for(NSString *part in parts)if(!part.length)empty=YES;
        if(empty){[self bad:@"FIELD_TYPE" field:field reason:@"Rule fields cannot be empty."];continue;}
        if ([type isEqual:@"SUB-RULE"]) {
            id nested=_document[@"sub-rules"];
            if (![nested isKindOfClass:[NSDictionary class]] || !nested[parts[2]]) [self bad:@"REFERENCE_MISSING" field:field reason:@"Referenced sub-rule list does not exist."];
        } else [self reference:parts[expected-1] field:field];
        [self ruleOptions:parts start:expected type:type field:field];
        if(!match) [self ruleOperand:type operand:parts[1] field:field depth:0];
    }
}
- (void)rulePayload:(id)value behavior:(NSString *)behavior field:(NSString *)field {
    if (![self strings:value field:field]) return;
    if ([value count]>10000) [self bad:@"RULE_LIMIT" field:field reason:@"A rule Provider is limited to 10000 entries."];
    for (NSString *rule in value) {
        if ([behavior isEqual:@"domain"]) {
            if (rule.length>255 || [rule rangeOfCharacterFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].location!=NSNotFound || [rule rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound || [rule rangeOfString:@","].location!=NSNotFound) [self bad:@"RULE_DOMAIN" field:field reason:@"A domain Provider contains a malformed pattern."];
        } else if ([behavior isEqual:@"ipcidr"]) {
            if (MLRouteRuleOperandIssue(@"IP-CIDR",rule)) [self bad:@"RULE_CIDR" field:field reason:@"An IP Provider entry must contain a valid IPv4 or IPv6 prefix."];
        } else if ([behavior isEqual:@"classical"]) {
            BOOL previous=_classical; _classical=YES;
            NSArray *parts=MLRouteRuleFields(rule);
            if (parts.count<2 || parts.count>4 || [@[@"MATCH",@"RULE-SET",@"SUB-RULE"] containsObject:parts[0]]) [self bad:@"RULE_PROVIDER_RECURSION" field:field reason:@"Classical Provider rules contain conditions, without targets or recursive Provider/sub-rule references."];
            else { [self ruleOptions:parts start:2 type:parts[0] field:field]; [self ruleOperand:parts[0] operand:parts[1] field:field depth:0]; }
            _classical=previous;
        }
    }
}
- (void)providerOverride:(id)value field:(NSString *)field {
    if (![self expect:value class:[NSDictionary class] field:field]) return;
    [self unknown:value allowed:@"tfo mptcp udp udp-over-tcp up down dialer-proxy skip-cert-verify name-cert-verify interface-name routing-mark ip-version additional-prefix additional-suffix proxy-name" field:field];
    for (NSString *key in @[@"tfo",@"mptcp",@"udp",@"udp-over-tcp",@"skip-cert-verify",@"name-cert-verify"]) if (value[key] && !MLBoolean(value[key])) [self bad:@"FIELD_TYPE" field:MLField(field,key) reason:@"A boolean is required."];
    for (NSString *key in @[@"additional-prefix",@"additional-suffix",@"dialer-proxy",@"interface-name",@"ip-version"]) if (value[key] && (![value[key] isKindOfClass:[NSString class]] || [value[key] length]>256)) [self bad:@"FIELD_TYPE" field:MLField(field,key) reason:@"A string of at most 256 characters is required."];
    if (MLFlag(value[@"skip-cert-verify"])) [self add:@"TLS_VERIFICATION_DISABLED" category:@"runtime" severity:@"confirm" field:MLField(field,@"skip-cert-verify") reason:@"The configuration explicitly requests disabled node certificate verification."];
    if (value[@"proxy-name"] && [self expect:value[@"proxy-name"] class:[NSArray class] field:MLField(field,@"proxy-name")]) for (id entry in value[@"proxy-name"]) {
        if (![self expect:entry class:[NSDictionary class] field:MLField(field,@"proxy-name")]) continue;
        [self unknown:entry allowed:@"pattern target" field:MLField(field,@"proxy-name")];
        if (![entry[@"pattern"] isKindOfClass:[NSString class]] || [entry[@"pattern"] length]>1024 || ![NSRegularExpression regularExpressionWithPattern:entry[@"pattern"] options:0 error:NULL] || ![entry[@"target"] isKindOfClass:[NSString class]] || [entry[@"target"] length]>256) [self bad:@"PROVIDER_OVERRIDE" field:field reason:@"Proxy name replacement requires a valid bounded pattern and replacement string."];
    }
}
- (void)providers:(id)value kind:(NSString *)kind {
    NSString *root=[kind isEqual:@"proxy"] ? @"proxy-providers" : @"rule-providers";
    if (!value || ![self expect:value class:[NSDictionary class] field:root]) return;
    for (NSString *name in value) {
        NSString *field=MLField(root,name); id spec=value[name];
        if (!name.length || name.length>256 || [name rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound) [self bad:@"NAME_FORMAT" field:field reason:@"Provider names require 1–256 ordinary characters."];
        if (![self expect:spec class:[NSDictionary class] field:field]) continue;
        BOOL proxy=[kind isEqual:@"proxy"];
        [self unknown:spec allowed:proxy ? @"type url path interval payload filter exclude-filter exclude-type override health-check" : @"type url path interval payload behavior format" field:field];
        NSString *type=spec[@"type"] ?: @"http";
        if (![@[@"http",@"file",@"inline"] containsObject:type]) [self bad:@"PROVIDER_TYPE" field:MLField(field,@"type") reason:@"Providers support http, file and inline sources."];
        if ([type isEqual:@"http"]) [self url:spec[@"url"] secure:YES field:MLField(field,@"url")];
        if ([type isEqual:@"file"] || spec[@"path"]) [self privatePath:spec[@"path"] field:MLField(field,@"path")];
        if (spec[@"interval"]) [self number:spec[@"interval"] low:0 high:31*86400 field:MLField(field,@"interval")];
        if (proxy) {
            for (NSString *key in @[@"filter",@"exclude-filter"]) if (spec[key]) [self patterns:spec[key] field:MLField(field,key)];
            if (spec[@"exclude-type"] && ![spec[@"exclude-type"] isKindOfClass:[NSString class]]) [self bad:@"FIELD_TYPE" field:MLField(field,@"exclude-type") reason:@"A type exclusion string is required."];
            if (spec[@"override"]) [self providerOverride:spec[@"override"] field:MLField(field,@"override")];
            if (spec[@"health-check"]) [self health:spec[@"health-check"] field:MLField(field,@"health-check") provider:YES];
            if ([type isEqual:@"inline"]) {
                if ([self expect:spec[@"payload"] class:[NSArray class] field:MLField(field,@"payload")]) {
                    NSMutableArray *nodes=[NSMutableArray array];
                    for (id original in spec[@"payload"]) if ([original isKindOfClass:[NSDictionary class]]) { NSMutableDictionary *node=[original mutableCopy]; [node removeObjectForKey:@"dialer-proxy"]; [nodes addObject:node]; } else [self bad:@"FIELD_TYPE" field:MLField(field,@"payload") reason:@"A proxy Provider payload must contain node mappings."];
                    NSData *data=[NSJSONSerialization dataWithJSONObject:@{@"proxies":nodes,@"rules":@[@"MATCH,DIRECT"]} options:0 error:NULL];
                    NSDictionary *report=data ? [MLConfig checkYAML:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]] : nil;
                    if (![report[@"valid"] boolValue]) [self bad:@"PROVIDER_PAYLOAD" field:MLField(field,@"payload") reason:@"The inline Provider contains invalid or unavailable node options."];
                }
            }
        } else {
            NSString *behavior=spec[@"behavior"], *format=spec[@"format"] ?: @"yaml";
            if (![@[@"domain",@"ipcidr",@"classical"] containsObject:behavior ?: @""]) [self bad:@"PROVIDER_BEHAVIOR" field:MLField(field,@"behavior") reason:@"Rule Providers require domain, ipcidr or classical behavior."];
            if (![@[@"yaml",@"text",@"mrs"] containsObject:format] || ([format isEqual:@"mrs"] && ([type isEqual:@"inline"] || [behavior isEqual:@"classical"]))) [self bad:@"PROVIDER_FORMAT" field:MLField(field,@"format") reason:@"MRS supports only HTTP/file domain or IP rules; other rule sources support YAML/text."];
            if ([type isEqual:@"inline"]) [self rulePayload:spec[@"payload"] behavior:behavior field:MLField(field,@"payload")];
        }
    }
}
- (NSUInteger)visitSubRule:(NSString *)name map:(NSDictionary *)map states:(NSMutableDictionary *)states depth:(NSUInteger)depth {
    if ([states[name] isEqual:@(-1)] || depth>32) { [self bad:@"SUB_RULE_CYCLE" field:MLField(@"sub-rules",name) reason:@"Sub-rule references form a cycle or exceed 32 levels."]; return 33; }
    if (states[name]) {
        NSUInteger height=[states[name] unsignedIntegerValue];
        if (height+depth>32) [self bad:@"SUB_RULE_CYCLE" field:MLField(@"sub-rules",name) reason:@"Sub-rule references exceed 32 levels."];
        return height;
    }
    states[name]=@(-1);
    NSUInteger height=0;
    for (id rule in MLList(map[name])) if (MLText(rule)) { NSArray *parts=MLRouteRuleFields(rule); if (parts.count>=3 && [parts[0] isEqual:@"SUB-RULE"] && map[parts[2]]) height=MAX(height,1+[self visitSubRule:parts[2] map:map states:states depth:depth+1]); }
    states[name]=@(MIN(height,33)); return MIN(height,33);
}
- (void)subRules:(id)value {
    if (!value || ![self expect:value class:[NSDictionary class] field:@"sub-rules"]) return;
    if ([value count]>256) [self bad:@"SUB_RULE_LIMIT" field:@"sub-rules" reason:@"At most 256 sub-rule lists are supported."];
    NSUInteger count=0; NSMutableDictionary *states=[NSMutableDictionary dictionary];
    for (NSString *name in value) { [self rules:value[name] field:MLField(@"sub-rules",name)]; count+=MLList(value[name]).count; [self visitSubRule:name map:value states:states depth:0]; }
    if (count>10000) [self bad:@"RULE_LIMIT" field:@"sub-rules" reason:@"Sub-rule lists are limited to 10000 combined entries."];
}
- (void)internalData {
    if (_document[@"_geo-index"]) {
        if ([self expect:_document[@"_geo-index"] class:[NSDictionary class] field:@"_geo-index"]) [self unknown:_document[@"_geo-index"] allowed:@"path sha256 owner size" field:@"_geo-index"];
        if (!_geoIndex) [self bad:@"GEO_INDEX_UNAVAILABLE" field:@"_geo-index" reason:@"The prepared Geo index failed owner, immutable-file, hash or format validation."];
    }
    NSMutableSet *jobs=[NSMutableSet set];
    for (id group in MLList(_document[@"proxy-groups"])) if ([group isKindOfClass:[NSDictionary class]] && [@[@"url-test",@"fallback",@"load-balance"] containsObject:group[@"type"] ?: @""])
        for (NSString *name in MLList(group[@"proxies"])) if (MLText(name)) [jobs addObject:[NSString stringWithFormat:@"%@\n%@",name,group[@"url"] ?: @"http://www.gstatic.com/generate_204"]];
    id providers=_document[@"_rule-provider-payloads"];
    if (providers && [self expect:providers class:[NSDictionary class] field:@"_rule-provider-payloads"]) {
        NSUInteger count=0;
        for (NSString *name in providers) {
            NSString *field=MLField(@"_rule-provider-payloads",name); id provider=providers[name];
            if (![self expect:provider class:[NSDictionary class] field:field]) continue;
            [self unknown:provider allowed:@"behavior payload index" field:field];
            if (![@[@"domain",@"ipcidr",@"classical"] containsObject:provider[@"behavior"] ?: @""]) [self bad:@"PROVIDER_BEHAVIOR" field:field reason:@"A prepared rule Provider has an invalid behavior."];
            if (provider[@"index"]) {
                if (provider[@"payload"] || ![provider[@"behavior"] isEqual:@"domain"] ||
                    ![MLDomainProviderIndex indexWithDescriptor:provider[@"index"] error:NULL])
                    [self bad:@"RULE_INDEX_UNAVAILABLE" field:MLField(field,@"index") reason:@"The prepared domain Provider index failed validation."];
                continue;
            }
            [self rulePayload:provider[@"payload"] behavior:provider[@"behavior"] field:MLField(field,@"payload")]; count+=MLList(provider[@"payload"]).count;
        }
        if (count>10000) [self bad:@"RULE_LIMIT" field:@"_rule-provider-payloads" reason:@"The generation exceeds 10000 combined Provider entries."];
    }
    for (NSString *key in @[@"_geoip",@"_geosite",@"_ip-asn"]) if (_document[key] && [self expect:_document[key] class:[NSDictionary class] field:key]) {
        NSUInteger count=0;
        for (NSString *name in _document[key]) { NSArray *entries=_document[key][name]; [self rulePayload:entries behavior:[key isEqual:@"_geosite"] ? @"domain" : @"ipcidr" field:MLField(key,name)]; count+=MLList(entries).count; }
        if (count>10000) [self bad:@"RULE_LIMIT" field:key reason:@"Internal geodata exceeds the bounded generation budget."];
    }
    id checks=_document[@"_provider-health-checks"];
    if (checks && [self expect:checks class:[NSArray class] field:@"_provider-health-checks"]) {
        if ([checks count]>32) [self bad:@"PROVIDER_LIMIT" field:@"_provider-health-checks" reason:@"At most 32 Provider health policies are supported."];
        for (id check in checks) {
            if (![self expect:check class:[NSDictionary class] field:@"_provider-health-checks"]) continue;
            [self unknown:check allowed:@"name nodes url interval timeout lazy expected-status" field:@"_provider-health-checks"];
            [self required:check keys:@"name url" field:@"_provider-health-checks"];
            if ([self strings:check[@"nodes"] field:@"_provider-health-checks.nodes"]) for (NSString *name in check[@"nodes"]) [self reference:name field:@"_provider-health-checks.nodes"];
            for (NSString *name in MLList(check[@"nodes"])) if (MLText(name)) [jobs addObject:[NSString stringWithFormat:@"%@\n%@",name,check[@"url"] ?: @"http://www.gstatic.com/generate_204"]];
            NSMutableDictionary *health=[check mutableCopy]; [health removeObjectForKey:@"name"]; [health removeObjectForKey:@"nodes"]; [self health:health field:@"_provider-health-checks" provider:YES];
        }
    }
    if (jobs.count>2048) [self bad:@"HEALTH_POLICY_LIMIT" field:@"proxy-groups" reason:@"A generation is limited to 2048 distinct target/URL health jobs."];
    if (_document[@"_provider-generation"] && (!MLText(_document[@"_provider-generation"]) || !MLMatch(_document[@"_provider-generation"],@"^[0-9A-Fa-f-]{36}$"))) [self bad:@"PROVIDER_GENERATION" field:@"_provider-generation" reason:@"The Provider generation identifier is invalid."];
}
- (void)dns:(id)value {
    if(!value || ![self expect:value class:[NSDictionary class] field:@"dns"])return;
    NSString *unsupported=MLDNSUnsupportedField(value);
    if(unsupported){
        [self add:@"DNS_OPTION_UNAVAILABLE" category:@"compatibility" severity:@"block" field:MLField(@"dns",unsupported)
             reason:@"This DNS option or value is outside the supported resolver configuration."];
        _unchecked=YES; return;
    }
    for (NSDictionary *request in MLDNSGeoRequests(value)) {
        if (!_prepared) [self add:@"DNS_DATABASE_PENDING" category:@"runtime" severity:@"unverified" field:@"dns" reason:@"A DNS policy/filter requires Geo preparation."];
        else if (![_geoIndex containsKind:request[@"kind"] operand:request[@"operand"]]) [self bad:@"DNS_DATABASE_UNAVAILABLE" field:@"dns" reason:@"A DNS policy/filter references an unavailable prepared Geo category."];
    }
    for (NSString *name in MLDNSRuleProviderNames(value)) {
        id provider=_prepared ? _document[@"_rule-provider-payloads"][name] : _document[@"rule-providers"][name];
        if (![provider isKindOfClass:[NSDictionary class]] || ![@[@"domain",@"classical"] containsObject:provider[@"behavior"] ?: @""]) [self bad:@"DNS_PROVIDER_REFERENCE" field:@"dns" reason:@"DNS rule-set filters require a referenced domain/classical Provider."];
    }
    NSMutableSet *targets=[NSMutableSet setWithArray:@[@"DIRECT",@"REJECT",@"GLOBAL"]];
    for (id node in MLList(_document[@"proxies"])) if ([node isKindOfClass:[NSDictionary class]] && MLText(node[@"name"])) [targets addObject:node[@"name"]];
    for (id group in MLList(_document[@"proxy-groups"])) if ([group isKindOfClass:[NSDictionary class]] && MLText(group[@"name"])) [targets addObject:group[@"name"]];
    NSMutableArray *servers=[NSMutableArray array];
    for (NSString *key in @[@"nameserver",@"default-nameserver",@"proxy-server-nameserver",@"direct-nameserver",@"fallback"]) [servers addObjectsFromArray:MLList(value[key])];
    for (id policy in [value[@"nameserver-policy"] allValues]) [servers addObjectsFromArray:[policy isKindOfClass:[NSString class]] ? @[policy] : MLList(policy)];
    for (NSString *server in servers) { NSRange fragment=[server rangeOfString:@"#" options:NSBackwardsSearch]; if (fragment.location!=NSNotFound && ![targets containsObject:[server substringFromIndex:fragment.location+1]]) [self bad:@"DNS_TARGET_REFERENCE" field:@"dns" reason:@"A DNS upstream references a missing outbound target."]; }
    if (_prepared && _document[@"_dns-policy-order"]) {
        id order=_document[@"_dns-policy-order"]; NSArray *keys=[value[@"nameserver-policy"] allKeys] ?: @[];
        if (![order isKindOfClass:[NSArray class]] || [order count]!=keys.count || ![[NSSet setWithArray:order] isEqual:[NSSet setWithArray:keys]]) [self bad:@"DNS_POLICY_ORDER" field:@"_dns-policy-order" reason:@"Prepared DNS policy order must contain each policy key once."];
    }
}
- (void)hosts:(id)value {
    if (!value || ![self expect:value class:[NSDictionary class] field:@"hosts"]) return;
    if ([value count]>1024) [self bad:@"HOSTS_LIMIT" field:@"hosts" reason:@"At most 1024 exact host entries are supported."];
    for (NSString *name in value) {
        NSString *field=MLField(@"hosts",name);
        if (!name.length || name.length>253 || [name rangeOfCharacterFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].location!=NSNotFound || [name rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound || [name rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"*+/?#@:"]].location!=NSNotFound || [name hasPrefix:@"."] || [name rangeOfString:@".."].location!=NSNotFound)
            [self bad:@"HOSTS_NAME" field:field reason:@"Hosts supports bounded exact host names without wildcard or alias syntax."];
        NSArray *addresses=[value[name] isKindOfClass:[NSString class]] ? @[value[name]] : value[name];
        if (![self strings:addresses field:field]) continue;
        if (!addresses.count || addresses.count>16) [self bad:@"HOSTS_LIMIT" field:field reason:@"An exact host requires one to sixteen numeric IP addresses."];
        for (NSString *address in addresses) {
            unsigned char bytes[16];
            if (address.length>45 || (inet_pton(AF_INET,address.UTF8String,bytes)!=1 && inet_pton(AF_INET6,address.UTF8String,bytes)!=1)) [self bad:@"HOSTS_ADDRESS" field:field reason:@"Hosts values must be numeric IPv4/IPv6 addresses; aliases are unavailable."];
        }
    }
}
- (void)geoSettings {
    for (NSString *key in @[@"geodata-mode",@"geo-auto-update"]) if (_document[key] && !MLBoolean(_document[key])) [self bad:@"FIELD_TYPE" field:key reason:@"A boolean is required."];
    if (_document[@"geo-update-interval"]) [self number:_document[@"geo-update-interval"] low:1 high:720 field:@"geo-update-interval"];
    if (_document[@"geodata-loader"] && ![@[@"memconservative",@"memc"] containsObject:_document[@"geodata-loader"]]) [self add:@"GEO_LOADER_UNAVAILABLE" category:@"compatibility" severity:@"block" field:@"geodata-loader" reason:@"The legacy Core uses the bounded memory-conservative Geo loader."];
    if (_document[@"geox-url"] && [self expect:_document[@"geox-url"] class:[NSDictionary class] field:@"geox-url"]) {
        [self unknown:_document[@"geox-url"] allowed:@"geoip geosite mmdb asn" field:@"geox-url"];
        for (NSString *kind in _document[@"geox-url"]) [self url:_document[@"geox-url"][kind] secure:YES field:MLField(@"geox-url",kind)];
    }
}
- (void)validate {
    _names=[NSMutableDictionary dictionary];_groups=[NSMutableDictionary dictionary];
    if (_prepared && _document[@"_geo-index"]) _geoIndex=[MLGeoIndex indexWithDescriptor:_document[@"_geo-index"] error:NULL];
    [self reserved:_document field:@"" depth:0];
    [self unknown:_document allowed:@"name mode ipv6 log-level proxies proxy-groups proxy-providers rules rule-providers sub-rules dns sniffer tun listeners profile geox-url hosts port socks-port mixed-port redir-port tproxy-port allow-lan bind-address external-controller external-controller-tls external-controller-unix external-ui external-ui-name external-ui-url secret authentication skip-auth-prefixes lan-allowed-ips lan-disallowed-ips routing-mark interface-name find-process-mode geodata-mode geodata-loader geo-auto-update geo-update-interval global-client-fingerprint unified-delay tcp-concurrent enable-process keep-alive-interval keep-alive-idle global-ua etag inbound-tfo experimental ntp clash-for-android _dns-policy-order _rule-provider-payloads _provider-health-checks _provider-generation _geoip _geosite _ip-asn _geo-index" field:@""];
    if(_document[@"mode"] && (!MLText(_document[@"mode"]) || ![@[@"rule",@"global",@"direct"] containsObject:_document[@"mode"]]))[self bad:@"FIELD_VALUE" field:@"mode" reason:@"Mode must be rule, global or direct."];
    if(_document[@"ipv6"] && !MLBoolean(_document[@"ipv6"]))[self bad:@"FIELD_TYPE" field:@"ipv6" reason:@"ipv6 must be a boolean."];
    if(_document[@"log-level"] && ![@[@"silent",@"error",@"warning",@"info",@"debug"] containsObject:_document[@"log-level"]])[self bad:@"FIELD_VALUE" field:@"log-level" reason:@"Unknown log level."];
    if(_document[@"socks-port"]){
        [self port:_document[@"socks-port"] field:@"socks-port"];
        id value = _document[@"socks-port"];
        if (([value isKindOfClass:[NSString class]] || [value isKindOfClass:[NSNumber class]]) && [value integerValue]<1024)
            [self bad:@"SOCKS_PORT_UNPRIVILEGED" field:@"socks-port" reason:@"The unprivileged core requires a SOCKS port between 1024 and 65535."];
    }
    if (_document[@"allow-lan"] && (!MLBoolean(_document[@"allow-lan"]) || [_document[@"allow-lan"] boolValue]))
        [self add:@"LAN_LISTENER_UNAVAILABLE" category:@"compatibility" severity:@"block" field:@"allow-lan"
            reason:@"The current listener binds only to IPv4 loopback."];
    NSSet *checked=[NSSet setWithArray:@[@"name",@"mode",@"ipv6",@"log-level",@"proxies",@"proxy-groups",@"rules",@"dns",@"hosts",@"socks-port",@"allow-lan",@"proxy-providers",@"rule-providers",@"sub-rules",@"_dns-policy-order",@"_rule-provider-payloads",@"_provider-health-checks",@"_provider-generation",@"_geoip",@"_geosite",@"_ip-asn",@"_geo-index",@"geodata-mode",@"geo-auto-update",@"geo-update-interval",@"geodata-loader",@"geox-url"]];
    for(NSString *key in _document)if(![checked containsObject:key]){
        [self add:@"SETTING_UNAVAILABLE" category:@"compatibility" severity:@"block" field:key reason:@"This configuration section is retained but has no integrated implementation; its nested fields have not been checked."];
        _unchecked=YES;
    }
    if(_document[@"name"] && !MLText(_document[@"name"]))[self bad:@"FIELD_TYPE" field:@"name" reason:@"Configuration name must be a nonempty string."];
    [self proxies:_document[@"proxies"]];[self groups:_document[@"proxy-groups"]];
    [self providers:_document[@"proxy-providers"] kind:@"proxy"]; [self providers:_document[@"rule-providers"] kind:@"rule"];
    NSUInteger providerCount=([_document[@"proxy-providers"] isKindOfClass:[NSDictionary class]] ? [_document[@"proxy-providers"] count] : 0)+([_document[@"rule-providers"] isKindOfClass:[NSDictionary class]] ? [_document[@"rule-providers"] count] : 0);
    if (providerCount>32) [self bad:@"PROVIDER_LIMIT" field:@"" reason:@"At most 32 Providers are supported."];
    [self references]; [self rules:_document[@"rules"] field:@"rules"]; [self subRules:_document[@"sub-rules"]];
    if (_prepared) [self internalData];
    [self dns:_document[@"dns"]];
    [self hosts:_document[@"hosts"]]; [self geoSettings];
    [self add:@"RUNTIME_UNVERIFIED" category:@"runtime" severity:@"unverified" field:@"" reason:@"This report checks configuration structure only. Core forwarding, DNS, capture coverage and target-device behavior are not verified."];
    if(_issues.count>=MLMaxIssues){
        [_issues removeLastObject];[_issues addObject:MLIssue(@"ISSUE_LIMIT",@"parsing",@"block",@"",@0,@0,@"The report reached its 256-issue limit.",@"Remaining fields have not been checked.",@"Fix reported issues and check again.")];_unchecked=YES;
    }
}
@end

@implementation MLConfig
+ (NSDictionary *)checkPreparedDocument:(NSDictionary *)document {
    NSData *data=nil;
    @try { if ([document isKindOfClass:[NSDictionary class]] && [NSJSONSerialization isValidJSONObject:document]) data=[NSJSONSerialization dataWithJSONObject:document options:0 error:NULL]; } @catch (NSException *exception) { (void)exception; }
    if (!data || data.length>768*1024) return @{@"valid":@NO,@"syntaxValid":@NO,@"document":[NSNull null],@"unchecked":@YES,@"issues":@[MLIssue(@"PROVIDER_GENERATION_SIZE",@"parsing",@"block",@"",@0,@0,@"The internal generation must be a bounded JSON mapping of at most 768 KiB.",@"This generation cannot be activated.",@"Reduce Provider payloads and retry.")]};
    NSDictionary *immutable=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    MLConfigValidator *validator=[[MLConfigValidator alloc] init]; validator.document=immutable; validator.marks=@{}; validator.issues=[NSMutableArray array]; validator.prepared=YES; [validator validate];
    BOOL valid=YES; for (NSDictionary *item in validator.issues) if ([item[@"severity"] isEqual:@"block"]) valid=NO;
    return @{@"valid":@(valid),@"syntaxValid":@YES,@"document":immutable,@"issues":[validator.issues copy],@"unchecked":@(validator.unchecked)};
}
+ (NSDictionary *)checkYAML:(NSString *)yaml {
    NSData *data=[yaml isKindOfClass:[NSString class]]?[yaml dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO]:nil;
    if(!data || data.length>MLMaxYAML){
        NSDictionary *item=MLIssue(data?@"YAML_SIZE_LIMIT":@"YAML_ENCODING",@"parsing",@"block",@"",@0,@0,data?@"UTF-8 YAML exceeds 512 KiB.":@"Configuration must be a valid UTF-8 string.",@"No configuration fields were checked.",@"Import a valid UTF-8 document of at most 512 KiB.");
        return @{@"valid":@NO,@"syntaxValid":@NO,@"document":[NSNull null],@"issues":@[item],@"unchecked":@YES};
    }
    MLYAMLReader *reader=[[MLYAMLReader alloc]init];id document=[reader read:data];
    if(!document || reader.failed)return @{@"valid":@NO,@"syntaxValid":@NO,@"document":[NSNull null],@"issues":[reader.issues copy],@"unchecked":@YES};
    if(![document isKindOfClass:[NSDictionary class]])return @{@"valid":@NO,@"syntaxValid":@NO,@"document":[NSNull null],@"issues":@[MLIssue(@"YAML_ROOT_TYPE",@"parsing",@"block",@"",@1,@1,@"The root of a Clash configuration must be a mapping.",@"No configuration fields were checked.",@"Use a single mapping document.")],@"unchecked":@YES};
    MLConfigValidator *validator=[[MLConfigValidator alloc]init];validator.document=document;validator.marks=reader.marks;validator.issues=reader.issues;[validator validate];
    BOOL valid=YES;for(NSDictionary *item in validator.issues)if([item[@"severity"] isEqual:@"block"])valid=NO;
    if ([document[@"dns"] isKindOfClass:[NSDictionary class]] && [document[@"dns"][@"nameserver-policy"] isKindOfClass:[NSDictionary class]]) {
        NSArray *order=[[document[@"dns"][@"nameserver-policy"] allKeys] sortedArrayUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
            NSArray *am=reader.marks[MLField(@"dns.nameserver-policy",a)], *bm=reader.marks[MLField(@"dns.nameserver-policy",b)];
            NSComparisonResult line=[am[0] compare:bm[0]]; return line==NSOrderedSame ? [am[1] compare:bm[1]] : line;
        }];
        NSMutableDictionary *expanded=[document mutableCopy]; expanded[@"_dns-policy-order"]=order; document=[expanded copy];
    }
    return @{@"valid":@(valid),@"syntaxValid":@YES,@"document":document,@"issues":[validator.issues copy],@"unchecked":@(validator.unchecked)};
}
@end
