#import "MLRouting.h"
#import "MLRoutingInternal.h"
#import "MLPublicSuffix.h"
#import "../providers/MLGeoIndex.h"
#import "../providers/MLDomainProviderIndex.h"
#include <arpa/inet.h>
#include <objc/runtime.h>
#include <string.h>
#include <float.h>

typedef struct {
    int family;
    struct in6_addr address;
} MLAddress;

typedef struct {
    uint16_t low, high;
} MLPortRange;

typedef NS_ENUM(NSUInteger, MLRuleKind) {
    MLUnknown, MLMatch, MLDomain, MLDomainSuffix, MLDomainKeyword, MLDomainRegex,
    MLDestinationCIDR, MLSourceCIDR, MLSourcePort, MLDestinationPort, MLNetwork,
    MLProcessName, MLProcessPath, MLCountry, MLSite, MLASN, MLRuleSet,
    MLAnd, MLOr, MLNot, MLSubRule, MLProviderDomain
};

@interface MLRouteRule : NSObject {
@public
    MLRuleKind kind;
    MLAddress prefix;
    NSUInteger prefixLength;
    BOOL noResolve;
    BOOL sourceAddress;
}
@property(nonatomic,copy) NSString *line, *target, *text;
@property(nonatomic,strong) NSRegularExpression *regex;
@property(nonatomic,copy) NSData *ports;
@property(nonatomic,copy) NSArray *children;
@end
@implementation MLRouteRule
@end

@interface MLCompiledPolicy : NSObject
@property(nonatomic,copy) NSArray *rules, *groupNames;
@property(nonatomic,copy) NSDictionary *groups, *nodeTypes, *nodes, *ruleSets, *subRules;
@property(nonatomic,copy) NSDictionary *domainIndexes;
@property(nonatomic) BOOL domainIndexUnavailable;
@property(nonatomic,strong) MLGeoIndex *geoIndex;
@property(nonatomic) BOOL geoIndexUnavailable;
@end
@implementation MLCompiledPolicy
@end

static NSArray *MLArray(id value) {
    return [value isKindOfClass:[NSArray class]] ? value : @[];
}

static NSString *MLString(id value) {
    return [value isKindOfClass:[NSString class]] ? value : nil;
}

static NSArray *MLSplitRuleFields(NSString *line) {
    NSMutableArray *fields = [NSMutableArray array];
    NSMutableArray *parts = [NSMutableArray array];
    NSUInteger start = 0, depth = 0;
    for (NSUInteger i = 0; i < line.length; ++i) {
        unichar c = [line characterAtIndex:i];
        if (c == '(') ++depth;
        else if (c == ')' && depth) --depth;
        else if (c == ',' && !depth) { [parts addObject:[line substringWithRange:NSMakeRange(start,i-start)]]; start = i+1; }
    }
    [parts addObject:[line substringFromIndex:start]];
    for (NSString *part in parts) {
        [fields addObject:[part stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]];
    }
    return fields;
}

NSArray *MLRouteRuleFields(NSString *line) {
    NSMutableArray *fields = [MLSplitRuleFields(line) mutableCopy];
    if (!fields.count) return @[];
    fields[0] = [fields[0] uppercaseString];
    if ([fields[0] isEqual:@"DOMAIN-REGEX"] && fields.count > 3) {
        NSString *pattern = [[fields subarrayWithRange:NSMakeRange(1, fields.count - 2)] componentsJoinedByString:@","];
        return @[fields[0], pattern, fields.lastObject];
    }
    return fields;
}

static MLAddress MLParseAddress(NSString *literal) {
    MLAddress result = {0};
    if (!literal.length) return result;
    const char *text = literal.UTF8String;
    if (!text || strlen(text) != [literal lengthOfBytesUsingEncoding:NSUTF8StringEncoding]) return result;
    if (inet_pton(AF_INET, text, result.address.s6_addr) == 1) result.family = AF_INET;
    else if (inet_pton(AF_INET6, text, &result.address) == 1) result.family = AF_INET6;
    return result;
}

static MLAddress MLRouteAddress(NSString *literal, BOOL unmap) {
    NSRange zone = [literal rangeOfString:@"%"];
    NSString *address = literal;
    if (zone.location != NSNotFound) {
        if (!zone.location || NSMaxRange(zone) == literal.length) return (MLAddress){0};
        address = [literal substringToIndex:zone.location];
    }
    MLAddress result = MLParseAddress(address);
    if (result.family == AF_INET && zone.location != NSNotFound) return (MLAddress){0};
    if (unmap && result.family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&result.address)) {
        memmove(result.address.s6_addr, result.address.s6_addr + 12, 4);
        result.family = AF_INET;
    }
    return result;
}

static BOOL MLDecimal(NSString *text, NSUInteger maximum, NSUInteger *number) {
    if (!text.length || text.length > (maximum>UINT16_MAX ? 10 : 5)) return NO;
    NSUInteger result = 0;
    for (NSUInteger i = 0; i < text.length; i++) {
        unichar digit = [text characterAtIndex:i];
        if (digit < '0' || digit > '9') return NO;
        if (result>maximum/10 || (result==maximum/10 && (NSUInteger)(digit-'0')>maximum%10)) return NO;
        result = result * 10 + digit - '0';
    }
    if (result > maximum) return NO;
    *number = result;
    return YES;
}

static MLRouteRule *MLCompileCondition(NSString *line, NSUInteger depth);
NSArray *MLRouteConditionChildren(NSString *type, NSString *operand) {
    if (![operand hasPrefix:@"("] || ![operand hasSuffix:@")"]) return nil;
    NSString *inside=[operand substringWithRange:NSMakeRange(1,operand.length-2)];
    NSArray *parts=MLSplitRuleFields(inside);
    if ([type isEqual:@"NOT"] && parts.count>=2 && ![parts[0] hasPrefix:@"("]) parts=@[operand];
    return parts;
}
static NSString *MLCompileOperand(MLRouteRule *rule, NSString *type, NSString *operand, NSUInteger depth) {
    if (depth > 32) return @"RULE_LOGICAL";
    if ([type isEqual:@"MATCH"]) rule->kind = MLMatch;
    else if ([type isEqual:@"DOMAIN"]) rule->kind = MLDomain;
    else if ([type isEqual:@"DOMAIN-SUFFIX"]) rule->kind = MLDomainSuffix;
    else if ([type isEqual:@"DOMAIN-KEYWORD"]) rule->kind = MLDomainKeyword;
    else if ([type isEqual:@"DOMAIN-REGEX"]) {
        rule->kind = MLDomainRegex;
        rule.regex = [NSRegularExpression regularExpressionWithPattern:operand
                                                               options:NSRegularExpressionCaseInsensitive error:NULL];
        if (!rule.regex) return @"RULE_REGEX";
    } else if ([type isEqual:@"IP-CIDR"] || [type isEqual:@"IP-CIDR6"] || [type isEqual:@"SRC-IP-CIDR"]) {
        rule->kind = [type isEqual:@"SRC-IP-CIDR"] ? MLSourceCIDR : MLDestinationCIDR;
        NSArray *cidr = [operand componentsSeparatedByString:@"/"];
        if (cidr.count != 2) return @"RULE_CIDR";
        rule->prefix = MLParseAddress(cidr[0]);
        NSUInteger maxBits = rule->prefix.family == AF_INET ? 32 : 128;
        if (!rule->prefix.family || [cidr[1] length] > 3 || !MLDecimal(cidr[1], maxBits, &rule->prefixLength)) return @"RULE_CIDR";
    } else if ([type isEqual:@"SRC-PORT"] || [type isEqual:@"DST-PORT"]) {
        rule->kind = [type isEqual:@"SRC-PORT"] ? MLSourcePort : MLDestinationPort;
        NSMutableData *ports = [NSMutableData data];
        NSArray *segments = [operand componentsSeparatedByString:@"/"];
        if (segments.count > 28) return @"RULE_PORT";
        for (NSString *segment in segments) {
            NSArray *range = [segment componentsSeparatedByString:@"-"];
            NSUInteger low = 0, high = 0;
            if ((range.count != 1 && range.count != 2) || !MLDecimal(range[0], UINT16_MAX, &low) ||
                !MLDecimal(range.lastObject, UINT16_MAX, &high) || !low || high < low) return @"RULE_PORT";
            MLPortRange interval = {(uint16_t)low, (uint16_t)high};
            [ports appendBytes:&interval length:sizeof interval];
        }
        rule.ports = ports;
    } else if ([type isEqual:@"NETWORK"]) rule->kind = MLNetwork;
    else if ([type isEqual:@"PROCESS-NAME"]) rule->kind = MLProcessName;
    else if ([type isEqual:@"PROCESS-PATH"]) rule->kind = MLProcessPath;
    else if ([type isEqual:@"GEOIP"]) rule->kind = MLCountry;
    else if ([type isEqual:@"GEOSITE"]) rule->kind = MLSite;
    else if ([type isEqual:@"IP-ASN"]) {
        NSString *number=[operand.uppercaseString hasPrefix:@"AS"] ? [operand substringFromIndex:2] : operand; NSUInteger value=0;
        if (!MLDecimal(number,UINT32_MAX,&value)) return @"RULE_ASN";
        rule->kind = MLASN;
    }
    else if ([type isEqual:@"RULE-SET"]) rule->kind = MLRuleSet;
    else if ([type isEqual:@"SUB-RULE"]) {
        rule->kind = MLSubRule;
        MLRouteRule *condition = MLCompileCondition(operand,depth+1);
        if (!condition || condition->kind == MLUnknown) return @"RULE_LOGICAL";
        rule.children = @[condition];
    } else if ([@[@"AND",@"OR",@"NOT"] containsObject:type]) {
        rule->kind = [type isEqual:@"AND"] ? MLAnd : ([type isEqual:@"OR"] ? MLOr : MLNot);
        NSArray *parts=MLRouteConditionChildren(type,operand);
        if (!parts.count || parts.count > 32 || (rule->kind == MLNot && parts.count != 1)) return @"RULE_LOGICAL";
        NSMutableArray *children = [NSMutableArray array];
        for (NSString *part in parts) {
            MLRouteRule *child = MLCompileCondition(part,depth+1);
            if (!child || child->kind == MLUnknown) return @"RULE_LOGICAL";
            [children addObject:child];
        }
        rule.children = children;
    } else return @"RULE_TYPE";

    if (rule->kind == MLDomainSuffix) rule.text = [@"." stringByAppendingString:operand.lowercaseString];
    else if (rule->kind == MLDomain || rule->kind == MLDomainKeyword || rule->kind == MLNetwork)
        rule.text = operand.lowercaseString;
    else if (rule->kind==MLASN) rule.text=[operand.uppercaseString hasPrefix:@"AS"] ? [operand substringFromIndex:2] : operand;
    else rule.text = operand;
    return nil;
}

static MLRouteRule *MLCompileCondition(NSString *line, NSUInteger depth) {
    if (depth > 32 || !line.length || line.length > 4096) return nil;
    if ([line hasPrefix:@"("] && [line hasSuffix:@")"]) line = [line substringWithRange:NSMakeRange(1,line.length-2)];
    NSArray *fields = MLRouteRuleFields(line);
    MLRouteRule *rule = [MLRouteRule new];
    rule.line = line;
    if (fields.count < 2 || MLCompileOperand(rule,fields[0],fields[1],depth)) return nil;
    if (fields.count > 2) rule->noResolve = [fields containsObject:@"no-resolve"];
    rule->sourceAddress=[fields containsObject:@"src"];
    if (rule->sourceAddress && rule->kind==MLDestinationCIDR) rule->kind=MLSourceCIDR;
    return rule;
}

NSString *MLRouteRuleOperandIssue(NSString *type, NSString *operand) {
    return MLCompileOperand([MLRouteRule new], type, operand,0);
}

static MLRouteRule *MLCompileRule(NSString *line) {
    NSArray *fields = MLRouteRuleFields(line);
    MLRouteRule *rule = [MLRouteRule new];
    rule.line = line;
    NSUInteger target = [fields[0] isEqual:@"MATCH"] ? 1 : 2;
    if (fields.count <= target) return rule;
    rule.target = fields[target];
    if (MLCompileOperand(rule, fields[0], target == 2 ? fields[1] : nil,0)) rule->kind = MLUnknown;
    if (fields.count > target+1) {
        NSArray *options = [fields subarrayWithRange:NSMakeRange(target+1, fields.count-target-1)];
        if (rule->kind == MLDestinationCIDR && [options containsObject:@"src"]) rule->kind = MLSourceCIDR;
        rule->sourceAddress=[options containsObject:@"src"];
        rule->noResolve = [options containsObject:@"no-resolve"];
    }
    return rule;
}

static MLCompiledPolicy *MLCompilePolicy(NSDictionary *document) {
    MLCompiledPolicy *policy = [MLCompiledPolicy new];
    if (document[@"_geo-index"]) { policy.geoIndex=[MLGeoIndex indexWithDescriptor:document[@"_geo-index"] error:NULL]; policy.geoIndexUnavailable=policy.geoIndex==nil; }
    NSMutableDictionary *nodes = [NSMutableDictionary dictionary];
    NSMutableDictionary *nodeTypes = [NSMutableDictionary dictionaryWithDictionary:@{@"DIRECT":@"direct", @"REJECT":@"reject"}];
    NSMutableArray *globalMembers = [NSMutableArray arrayWithArray:@[@"DIRECT", @"REJECT"]];
    for (id node in MLArray(document[@"proxies"])) {
        if (![node isKindOfClass:[NSDictionary class]]) continue;
        NSString *name = MLString(node[@"name"]), *type = MLString(node[@"type"]);
        if (!name.length || !type.length || nodeTypes[name]) continue;
        nodeTypes[name] = type.lowercaseString;
        nodes[name] = node;
        [globalMembers addObject:name];
    }
    NSMutableDictionary *groups = [NSMutableDictionary dictionary];
    NSMutableArray *groupNames = [NSMutableArray array];
    for (id group in MLArray(document[@"proxy-groups"])) {
        if (![group isKindOfClass:[NSDictionary class]]) continue;
        NSString *name = MLString(group[@"name"]), *type = MLString(group[@"type"]);
        if (!name.length || !type.length || groups[name] || nodeTypes[name]) continue;
        NSMutableArray *members = [NSMutableArray array];
        for (id member in MLArray(group[@"proxies"]))
            if (MLString(member).length) [members addObject:member];
        NSMutableDictionary *entry = [group mutableCopy];
        entry[@"type"] = type;
        entry[@"members"] = [members copy];
        entry[@"default"] = MLString(group[@"default-selected"]) ?: @"";
        groups[name] = [entry copy];
        [groupNames addObject:name];
    }
    if (document && !groups[@"GLOBAL"]) {
        [globalMembers addObjectsFromArray:groupNames];
        groups[@"GLOBAL"] = @{@"type":@"select", @"members":[globalMembers copy], @"default":@""};
        [groupNames addObject:@"GLOBAL"];
    }
    NSMutableArray *rules = [NSMutableArray array];
    for (id line in MLArray(document[@"rules"])) {
        if (MLString(line).length) [rules addObject:MLCompileRule(line)];
    }
    policy.rules = rules;
    policy.nodeTypes = nodeTypes;
    policy.nodes = nodes;
    policy.groups = groups;
    policy.groupNames = groupNames;
    NSMutableDictionary *ruleSets = [NSMutableDictionary dictionary], *subRules = [NSMutableDictionary dictionary];
    NSMutableDictionary *domainIndexes = [NSMutableDictionary dictionary];
    for (NSString *name in document[@"_rule-provider-payloads"]) {
        NSDictionary *provider = document[@"_rule-provider-payloads"][name];
        if (provider[@"index"]) {
            MLDomainProviderIndex *index = [MLDomainProviderIndex indexWithDescriptor:provider[@"index"] error:NULL];
            if (index) domainIndexes[name] = index;
            else policy.domainIndexUnavailable = YES;
            continue;
        }
        NSMutableArray *compiled = [NSMutableArray array];
        for (NSString *operand in MLArray(provider[@"payload"])) {
            if (!MLString(operand)) continue;
            MLRouteRule *rule = [MLRouteRule new];
            if ([provider[@"behavior"] isEqual:@"domain"]) {
                rule->kind = MLProviderDomain; rule.text = operand.lowercaseString;
                NSString *pattern = [NSRegularExpression escapedPatternForString:rule.text];
                if ([rule.text hasPrefix:@"+."]) pattern = [@"(?:[^.]+\\.)*" stringByAppendingString:[NSRegularExpression escapedPatternForString:[rule.text substringFromIndex:2]]];
                else {
                    pattern = [pattern stringByReplacingOccurrencesOfString:@"\\*" withString:@"[^.]*"];
                    if ([rule.text hasPrefix:@"."]) pattern = [@"(?:[^.]+\\.)+" stringByAppendingString:[NSRegularExpression escapedPatternForString:[rule.text substringFromIndex:1]]];
                }
                rule.regex = [NSRegularExpression regularExpressionWithPattern:[NSString stringWithFormat:@"^%@$",pattern] options:NSRegularExpressionCaseInsensitive error:NULL];
                if (!rule.regex) rule->kind = MLUnknown;
            } else if ([provider[@"behavior"] isEqual:@"ipcidr"]) {
                if (MLCompileOperand(rule,@"IP-CIDR",operand,0)) rule->kind = MLUnknown;
            } else {
                rule = MLCompileCondition(operand,0) ?: rule;
            }
            [compiled addObject:rule];
        }
        ruleSets[name] = [compiled copy];
    }
    for (NSString *name in document[@"sub-rules"]) {
        NSMutableArray *compiled = [NSMutableArray array];
        for (NSString *line in MLArray(document[@"sub-rules"][name])) if (MLString(line)) [compiled addObject:MLCompileRule(line)];
        subRules[name] = [compiled copy];
    }
    policy.ruleSets = ruleSets; policy.subRules = subRules; policy.domainIndexes = domainIndexes;
    return policy;
}

static MLCompiledPolicy *MLPolicy(NSDictionary *document) {
    if (!document) return MLCompilePolicy(nil);
    static char policyKey;
    // Each immutable parsed configuration keeps its own compiled rule order.
    @synchronized (document) {
        MLCompiledPolicy *policy = objc_getAssociatedObject(document, &policyKey);
        if (!policy) {
            policy = MLCompilePolicy(document);
            objc_setAssociatedObject(document, &policyKey, policy, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        return policy;
    }
}

BOOL MLRoutePrepareProviders(NSDictionary *document) {
    return !MLPolicy(document).domainIndexUnavailable;
}

static BOOL MLCIDRContains(MLAddress prefix, NSUInteger bits, MLAddress ip) {
    if (ip.family != prefix.family || !ip.family) return NO;
    const unsigned char *a = prefix.address.s6_addr;
    const unsigned char *b = ip.address.s6_addr;
    NSUInteger complete = bits / 8, remaining = bits % 8;
    if (memcmp(a, b, complete) != 0) return NO;
    if (!remaining) return YES;
    unsigned char mask = (unsigned char)(0xFF << (8 - remaining));
    return (a[complete] & mask) == (b[complete] & mask);
}

static BOOL MLPortMatches(NSData *intervals, NSUInteger port) {
    const MLPortRange *ranges = intervals.bytes;
    for (NSUInteger i = 0; i < intervals.length / sizeof *ranges; i++) {
        if (port >= ranges[i].low && port <= ranges[i].high) return YES;
    }
    return NO;
}

static BOOL MLRegexMatches(NSRegularExpression *regex, NSString *host, BOOL *usable) {
    NSTimeInterval deadline = [NSProcessInfo processInfo].systemUptime + 0.05;
    __block BOOL matched = NO;
    [regex enumerateMatchesInString:host
                           options:NSMatchingReportProgress | NSMatchingReportCompletion
                             range:NSMakeRange(0, host.length)
                        usingBlock:^(NSTextCheckingResult *result, NSMatchingFlags flags, BOOL *stop) {
        if (flags & NSMatchingInternalError || (!result && [NSProcessInfo processInfo].systemUptime > deadline)) {
            *usable = NO;
            *stop = YES;
        } else if (result) {
            matched = YES;
            *stop = YES;
        }
    }];
    return matched;
}

NSString *MLPolicyMeasurementKey(NSString *name, NSString *url) {
    return [NSString stringWithFormat:@"%@\n%@",name ?: @"",url ?: @""];
}

static NSString *MLDefaultURL(NSDictionary *group) { return MLString(group[@"url"]) ?: @"http://www.gstatic.com/generate_204"; }
NSString *MLPolicyStatusIssue(NSString *expectedStatus) {
    if (!expectedStatus) return nil;
    if (!MLString(expectedStatus) || expectedStatus.length>1024) return @"GROUP_STATUS_RANGE";
    NSString *text=[expectedStatus stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if (!text.length || [text isEqual:@"*"]) return nil;
    NSArray *parts=[[text stringByReplacingOccurrencesOfString:@"," withString:@"/"] componentsSeparatedByString:@"/"];
    if (parts.count>28) return @"GROUP_STATUS_RANGE";
    for (NSString *part in parts) {
        if (!part.length) continue;
        NSArray *range=[part componentsSeparatedByString:@"-"]; NSUInteger low=0,high=0;
        if ((range.count!=1 && range.count!=2) || !MLDecimal(range[0],65535,&low) || !MLDecimal(range.lastObject,65535,&high) || high<low) return @"GROUP_STATUS_RANGE";
    }
    return nil;
}
static BOOL MLStatusMatches(NSUInteger status, NSString *expectedStatus) {
    if (MLPolicyStatusIssue(expectedStatus)) return NO;
    NSString *text=[expectedStatus stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if (!text.length || [text isEqual:@"*"]) return YES;
    for (NSString *part in [[text stringByReplacingOccurrencesOfString:@"," withString:@"/"] componentsSeparatedByString:@"/"]) {
        if (!part.length) continue;
        NSArray *range=[part componentsSeparatedByString:@"-"];
        if (status>=(NSUInteger)[range[0] longLongValue] && status<=(NSUInteger)[range.lastObject longLongValue]) return YES;
    }
    return NO;
}
static NSDictionary *MLExpectedMeasurement(NSDictionary *raw, NSString *expected) {
    NSUInteger status=[raw[@"status"] unsignedIntegerValue];
    if (status<100 || status>599) return raw;
    NSMutableDictionary *result=[raw mutableCopy]; result[@"health"]=MLStatusMatches(status,expected) ? @"healthy" : @"failed";
    return result;
}
static BOOL MLAlive(NSDictionary *measurement) {
    NSString *health = measurement[@"health"];
    // An untested node remains selectable, but is never called healthy.
    return ![@[@"failed",@"timeout",@"invalid"] containsObject:health];
}
static uint64_t MLHash(NSString *text) {
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    uint64_t value = 1469598103934665603ULL;
    const uint8_t *bytes = data.bytes;
    for (NSUInteger i=0; i<data.length; ++i) { value ^= bytes[i]; value *= 1099511628211ULL; }
    return value;
}
static NSUInteger MLJumpHash(uint64_t key, NSUInteger count) {
    int64_t b = -1, j = 0;
    while (j < (int64_t)count) {
        b = j; key = key * 2862933555777941757ULL + 1;
        j = (int64_t)((double)(b+1) * ((double)(1ULL << 31) / (double)((key >> 33)+1)));
    }
    return (NSUInteger)b;
}
static NSString *MLHashDestination(NSDictionary *metadata) {
    NSString *host = MLString(metadata[@"host"]);
    if (MLParseAddress(host).family) return host;
    return MLEffectiveDomain(host) ?: MLString(metadata[@"ip"]) ?: @"";
}

static NSString *MLChoose(MLCompiledPolicy *, NSString *, NSDictionary *, NSDictionary *, NSMutableDictionary *, NSDictionary *, NSUInteger, BOOL);
static NSString *MLSingleLeaf(MLCompiledPolicy *policy, NSString *target, NSDictionary *selections, NSDictionary *measurements,
                              NSMutableDictionary *counters, NSDictionary *metadata, NSUInteger depth, BOOL touch) {
    if (depth > 34 || !target.length) return @"REJECT";
    if (policy.nodeTypes[target]) return target;
    NSString *next = MLChoose(policy,target,selections,measurements,counters,metadata,depth+1,touch);
    return next ? MLSingleLeaf(policy,next,selections,measurements,counters,metadata,depth+1,touch) : @"REJECT";
}
static NSDictionary *MLTargetMeasurement(MLCompiledPolicy *policy, NSString *target, NSString *url, NSDictionary *selections,
                                         NSDictionary *measurements, NSUInteger depth, NSString *expectedStatus) {
    NSDictionary *own=measurements[MLPolicyMeasurementKey(target,url)];
    if (own) return MLExpectedMeasurement(own,expectedStatus);
    NSString *leaf = MLSingleLeaf(policy,target,selections,measurements,nil,@{},depth,NO);
    if ([leaf isEqual:@"REJECT"]) return @{@"health":@"failed"};
    return MLExpectedMeasurement(measurements[MLPolicyMeasurementKey(leaf,url)] ?: @{@"health":@"unknown"},expectedStatus);
}
static NSString *MLChoose(MLCompiledPolicy *policy, NSString *name, NSDictionary *selections, NSDictionary *measurements,
                         NSMutableDictionary *counters, NSDictionary *metadata, NSUInteger depth, BOOL touch) {
    if (depth > 34) return nil;
    NSDictionary *group = policy.groups[name]; NSArray *members = group[@"members"];
    if (!members.count) return nil;
    NSString *type = group[@"type"], *selected = selections[name], *url = MLDefaultURL(group), *chosen = nil;
    if ([group[@"disable-udp"] boolValue] && [MLString(metadata[@"network"]).lowercaseString isEqual:@"udp"]) return nil;
    if ([type isEqual:@"select"]) {
        if ([members containsObject:selected]) chosen = selected;
        else if ([members containsObject:group[@"default"]]) chosen = group[@"default"];
        else chosen = members[0];
    } else if ([type isEqual:@"relay"]) {
        chosen = members.lastObject;
    } else if ([@[@"url-test",@"fallback"] containsObject:type]) {
        if ([members containsObject:selected] && MLAlive(MLTargetMeasurement(policy,selected,url,selections,measurements,depth+1,group[@"expected-status"]))) chosen = selected;
        if (!chosen && [type isEqual:@"fallback"]) {
            for (NSString *member in members) if (MLAlive(MLTargetMeasurement(policy,member,url,selections,measurements,depth+1,group[@"expected-status"]))) { chosen = member; break; }
        } else if (!chosen) {
            double best = DBL_MAX;
            for (NSString *member in members) {
                NSDictionary *measurement = MLTargetMeasurement(policy,member,url,selections,measurements,depth+1,group[@"expected-status"]);
                if ([measurement[@"health"] isEqual:@"healthy"] && measurement[@"delay"] && [measurement[@"delay"] doubleValue] < best) {
                    best = [measurement[@"delay"] doubleValue]; chosen = member;
                }
            }
            NSString *previous = counters[[@"@choice." stringByAppendingString:name]] ?: measurements[@"_choices"][name];
            NSDictionary *prior = MLTargetMeasurement(policy,previous,url,selections,measurements,depth+1,group[@"expected-status"]);
            double tolerance = group[@"tolerance"] ? [group[@"tolerance"] doubleValue] : 0;
            if ([members containsObject:previous] && [prior[@"health"] isEqual:@"healthy"] && [prior[@"delay"] doubleValue] <= best+tolerance) chosen = previous;
        }
        if (!chosen) chosen = members[0];
    } else if ([type isEqual:@"load-balance"]) {
        NSString *strategy = group[@"strategy"] ?: @"consistent-hashing";
        if ([strategy isEqual:@"round-robin"]) {
            NSString *key = [@"@round." stringByAppendingString:name]; NSUInteger offset = [counters[key] unsignedIntegerValue] % members.count;
            for (NSUInteger i=0; i<members.count; ++i) {
                NSString *member = members[(offset+i)%members.count];
                if (MLAlive(MLTargetMeasurement(policy,member,url,selections,measurements,depth+1,group[@"expected-status"]))) {
                    chosen = member; if (touch) counters[key] = @((offset+i+1)%members.count); break;
                }
            }
        } else if ([@[@"consistent-hashing",@"sticky-sessions"] containsObject:strategy]) {
            NSString *destination = MLHashDestination(metadata);
            if ([group[@"hash-key"] isEqual:@"in-user"] && [metadata[@"inUser"] length]) destination = metadata[@"inUser"];
            if ([strategy isEqual:@"sticky-sessions"]) destination = [(MLString(metadata[@"source"]) ?: @"") stringByAppendingString:destination];
            uint64_t hash = MLHash(destination);
            NSMutableDictionary *sessions = nil; NSString *sessionKey = [NSString stringWithFormat:@"%llu",(unsigned long long)hash];
            if ([strategy isEqual:@"sticky-sessions"] && counters) {
                NSString *key = [@"@sticky." stringByAppendingString:name]; sessions = counters[key];
                if (!sessions && touch) { sessions = [NSMutableDictionary dictionary]; counters[key] = sessions; }
                NSDictionary *cached = sessions[sessionKey];
                if ([NSProcessInfo processInfo].systemUptime-[cached[@"time"] doubleValue] < 600 && [members containsObject:cached[@"member"]] &&
                    MLAlive(MLTargetMeasurement(policy,cached[@"member"],url,selections,measurements,depth+1,group[@"expected-status"]))) chosen = cached[@"member"];
                if (!chosen) hash ^= (uint64_t)([NSProcessInfo processInfo].systemUptime*1000000000);
            }
            for (NSUInteger i=0; !chosen && i<5; ++i) {
                NSString *member = members[MLJumpHash(hash+i,members.count)];
                if (MLAlive(MLTargetMeasurement(policy,member,url,selections,measurements,depth+1,group[@"expected-status"]))) chosen = member;
            }
            if (chosen && sessions && touch) {
                if (sessions.count >= 1000 && !sessions[sessionKey]) {
                    NSString *oldest = nil; double time = DBL_MAX;
                    for (NSString *key in sessions) if ([sessions[key][@"time"] doubleValue] < time) { time = [sessions[key][@"time"] doubleValue]; oldest = key; }
                    if (oldest) [sessions removeObjectForKey:oldest];
                }
                sessions[sessionKey] = @{@"member":chosen,@"time":@([NSProcessInfo processInfo].systemUptime)};
            }
        } else return nil;
        if (!chosen) for (NSString *member in members) if (MLAlive(MLTargetMeasurement(policy,member,url,selections,measurements,depth+1,group[@"expected-status"]))) { chosen = member; break; }
        if (!chosen) chosen = members[0];
    }
    if (chosen && touch && counters) counters[[@"@choice." stringByAppendingString:name]] = chosen;
    return chosen;
}

static BOOL MLPath(MLCompiledPolicy *policy, NSString *target, NSDictionary *selections, NSDictionary *measurements,
                   NSMutableDictionary *counters, NSDictionary *metadata, NSMutableArray *chain, NSMutableOrderedSet *groups, NSUInteger depth) {
    if (depth > 34 || !target.length) return NO;
    if (policy.nodeTypes[target]) {
        NSString *dialer = MLString(policy.nodes[target][@"dialer-proxy"]);
        if (dialer && !MLPath(policy,dialer,selections,measurements,counters,metadata,chain,groups,depth+1)) return NO;
        if ([target isEqual:@"REJECT"]) return NO;
        if (![target isEqual:@"DIRECT"] || !chain.count) {
            if (chain.count >= 16) return NO;
            [chain addObject:target];
        }
        return YES;
    }
    NSDictionary *group = policy.groups[target];
    if (!group) return NO;
    [groups addObject:target];
    if ([group[@"disable-udp"] boolValue] && [MLString(metadata[@"network"]).lowercaseString isEqual:@"udp"]) return NO;
    if ([group[@"type"] isEqual:@"relay"]) {
        if ([MLString(metadata[@"network"]).lowercaseString isEqual:@"udp"]) return NO;
        for (NSString *member in group[@"members"]) if (!MLPath(policy,member,selections,measurements,counters,metadata,chain,groups,depth+1)) return NO;
        return chain.count > 0;
    }
    return MLPath(policy,MLChoose(policy,target,selections,measurements,counters,metadata,depth,counters!=nil),selections,measurements,counters,metadata,chain,groups,depth+1);
}
NSArray *MLPolicyChain(NSDictionary *document, NSString *target, NSDictionary *selections, NSDictionary *measurements) {
    NSMutableArray *chain=[NSMutableArray array]; NSMutableOrderedSet *groups=[NSMutableOrderedSet orderedSet];
    return MLPath(MLPolicy(document),target,selections,measurements,nil,@{},chain,groups,0) ? [chain copy] : @[@"REJECT"];
}

@interface MLRuleContext : NSObject {
@public MLAddress destination, origin;
}
@property(nonatomic,copy) NSString *domain, *ip, *network;
@property(nonatomic,copy) NSDictionary *metadata, *document;
@property(nonatomic,strong) MLCompiledPolicy *policy;
@property(nonatomic,copy) NSString *(^resolver)(void);
@property(nonatomic) BOOL attempted;
@end
@implementation MLRuleContext
@end
static void MLResolve(MLRuleContext *context, BOOL noResolve) {
    if (noResolve || context->destination.family || context.attempted || !context.domain.length || !context.resolver) return;
    context.attempted = YES;
    NSString *answer = context.resolver(); context->destination = MLRouteAddress(answer,YES);
    if (context->destination.family) context.ip = answer;
}
static BOOL MLLocalAddress(MLAddress address) {
    if (address.family == AF_INET) {
        const unsigned char *b=address.address.s6_addr;
        return (!b[0] && !b[1] && !b[2] && !b[3]) || (b[0]>=224 && b[0]<=239) || b[0]==10 || b[0]==127 || (b[0]==172 && b[1]>=16 && b[1]<=31) || (b[0]==192 && b[1]==168) || (b[0]==169 && b[1]==254);
    }
    return address.family == AF_INET6 && (IN6_IS_ADDR_UNSPECIFIED(&address.address) || IN6_IS_ADDR_MULTICAST(&address.address) || IN6_IS_ADDR_LOOPBACK(&address.address) || IN6_IS_ADDR_LINKLOCAL(&address.address) || (address.address.s6_addr[0]&0xfe)==0xfc);
}
static BOOL MLRuleMatches(MLRouteRule *, MLRuleContext *, NSUInteger, BOOL *, BOOL);
static BOOL MLRuleListMatches(NSArray *rules, MLRuleContext *context, NSUInteger depth, BOOL *usable, BOOL noResolve) {
    if (depth > 32) { *usable=NO; return NO; }
    for (MLRouteRule *rule in rules) {
        if (MLRuleMatches(rule,context,depth+1,usable,noResolve)) return YES;
        if (!*usable) return NO;
    }
    return NO;
}
static BOOL MLRuleMatches(MLRouteRule *rule, MLRuleContext *context, NSUInteger depth, BOOL *usable, BOOL inheritedNoResolve) {
    if (depth > 32) { *usable=NO; return NO; }
    BOOL noResolve = inheritedNoResolve || rule->noResolve;
    switch (rule->kind) {
        case MLMatch: return YES;
        case MLDomain: return [context.domain isEqual:rule.text];
        case MLDomainSuffix: return [context.domain hasSuffix:rule.text] || [context.domain isEqual:[rule.text substringFromIndex:1]];
        case MLDomainKeyword: return [context.domain rangeOfString:rule.text].location != NSNotFound;
        case MLDomainRegex: case MLProviderDomain: return MLRegexMatches(rule.regex,context.domain,usable);
        case MLDestinationCIDR: MLResolve(context,noResolve); return MLCIDRContains(rule->prefix,rule->prefixLength,context->destination);
        case MLSourceCIDR: return MLCIDRContains(rule->prefix,rule->prefixLength,context->origin);
        case MLSourcePort: return MLPortMatches(rule.ports,[context.metadata[@"sourcePort"] unsignedIntegerValue]);
        case MLDestinationPort: return MLPortMatches(rule.ports,[context.metadata[@"destPort"] unsignedIntegerValue]);
        case MLNetwork: return [context.network isEqual:rule.text];
        case MLProcessName: return MLString(context.metadata[@"processName"]) && [context.metadata[@"processName"] isEqual:rule.text];
        case MLProcessPath: return MLString(context.metadata[@"processPath"]) && [context.metadata[@"processPath"] isEqual:rule.text];
        case MLCountry: {
            if (!rule->sourceAddress) MLResolve(context,noResolve);
            MLAddress address=rule->sourceAddress ? context->origin : context->destination;
            if ([rule.text caseInsensitiveCompare:@"LAN"]==NSOrderedSame) return MLLocalAddress(address);
            if (context.policy.geoIndexUnavailable) { *usable=NO; return NO; }
            if (context.policy.geoIndex) return [context.policy.geoIndex matchKind:@"geoip" operand:rule.text family:address.family address:address.address.s6_addr domain:nil usable:usable];
            NSString *country=rule->sourceAddress ? nil : MLString(context.metadata[@"country"]);
            if (country) return [country caseInsensitiveCompare:rule.text]==NSOrderedSame;
            NSArray *ranges=context.document[@"_geoip"][rule.text.uppercaseString];
            if (!ranges) { *usable=NO; return NO; }
            for (NSString *range in ranges) { MLRouteRule *prefix=[MLRouteRule new]; if (!MLCompileOperand(prefix,@"IP-CIDR",range,0) && MLCIDRContains(prefix->prefix,prefix->prefixLength,address)) return YES; }
            return NO;
        }
        case MLASN: {
            if (!rule->sourceAddress) MLResolve(context,noResolve);
            MLAddress address=rule->sourceAddress ? context->origin : context->destination;
            NSString *number=[rule.text hasPrefix:@"AS"] ? [rule.text substringFromIndex:2] : rule.text;
            if (context.policy.geoIndexUnavailable) { *usable=NO; return NO; }
            if (context.policy.geoIndex) return [context.policy.geoIndex matchKind:@"asn" operand:rule.text family:address.family address:address.address.s6_addr domain:nil usable:usable];
            if (!rule->sourceAddress && context.metadata[@"asn"]) return [[context.metadata[@"asn"] description] isEqual:number];
            NSArray *ranges=context.document[@"_ip-asn"][number];
            if (!ranges) { *usable=NO; return NO; }
            for (NSString *range in ranges) { MLRouteRule *prefix=[MLRouteRule new]; if (!MLCompileOperand(prefix,@"IP-CIDR",range,0) && MLCIDRContains(prefix->prefix,prefix->prefixLength,address)) return YES; }
            return NO;
        }
        case MLSite: {
            if (context.policy.geoIndexUnavailable) { *usable=NO; return NO; }
            if (context.policy.geoIndex) return [context.policy.geoIndex matchKind:@"geosite" operand:rule.text family:0 address:NULL domain:context.domain usable:usable];
            NSArray *domains=context.document[@"_geosite"][rule.text];
            if (!domains) { *usable=NO; return NO; }
            for (NSString *domain in domains) if ([context.domain isEqual:domain] || [context.domain hasSuffix:[@"." stringByAppendingString:domain]]) return YES;
            return NO;
        }
        case MLRuleSet: {
            MLDomainProviderIndex *index = context.policy.domainIndexes[rule.text];
            if (index) return [index matchesHost:context.domain];
            NSArray *rules=context.policy.ruleSets[rule.text];
            if (!rules) { *usable=NO; return NO; }
            return MLRuleListMatches(rules,context,depth+1,usable,noResolve);
        }
        case MLAnd: {
            for (MLRouteRule *child in rule.children) if (!MLRuleMatches(child,context,depth+1,usable,noResolve) || !*usable) return NO;
            return YES;
        }
        case MLOr: return MLRuleListMatches(rule.children,context,depth+1,usable,noResolve);
        case MLNot: { BOOL match=MLRuleMatches(rule.children[0],context,depth+1,usable,noResolve); return *usable && !match; }
        case MLSubRule: return MLRuleMatches(rule.children[0],context,depth+1,usable,noResolve);
        case MLUnknown: *usable=NO; return NO;
    }
    *usable=NO; return NO;
}
static MLRouteRule *MLFindRule(NSArray *rules, MLRuleContext *context, NSUInteger depth, BOOL *usable, BOOL inheritedNoResolve) {
    if (depth>32) { *usable=NO; return nil; }
    for (MLRouteRule *rule in rules) {
        BOOL matches=MLRuleMatches(rule,context,depth,usable,inheritedNoResolve);
        if (!*usable) return rule;
        if (!matches) continue;
        if (rule->kind != MLSubRule) return rule;
        NSArray *children=context.policy.subRules[rule.target];
        if (!children) { *usable=NO; return rule; }
        MLRouteRule *selected=MLFindRule(children,context,depth+1,usable,inheritedNoResolve || rule->noResolve);
        if (selected) return selected;
    }
    return nil;
}

NSDictionary *MLRouteWithRuntime(NSDictionary *document, NSString *mode, NSDictionary *selections,
                                NSDictionary *measurements, NSMutableDictionary *counters,
                                NSDictionary *metadata, NSString *(^resolveIP)(void)) {
    MLCompiledPolicy *policy=MLPolicy(document); MLRuleContext *context=[MLRuleContext new];
    context.policy=policy; context.metadata=metadata ?: @{}; context.document=document;
    context.domain=MLString(metadata[@"host"]).lowercaseString ?: @"";
    if ([context.domain hasSuffix:@"."]) context.domain=[context.domain substringToIndex:context.domain.length-1];
    context.ip=MLString(metadata[@"ip"]); context.network=MLString(metadata[@"network"]).lowercaseString;
    context->destination=MLRouteAddress(context.ip,YES); context->origin=MLRouteAddress(MLString(metadata[@"source"]),NO);
    MLAddress literal=MLRouteAddress(context.domain,YES);
    if (literal.family) { context->destination=literal; context.ip=context.domain; context.domain=@""; }
    if (!context->destination.family) context.ip=nil;
    context.resolver=resolveIP;
    NSString *target=@"DIRECT", *line=@""; BOOL usable=YES;
    if ([mode.lowercaseString isEqual:@"global"]) target=@"GLOBAL";
    else if (![mode.lowercaseString isEqual:@"direct"]) {
        MLRouteRule *rule=MLFindRule(policy.rules,context,0,&usable,NO);
        if (rule) { target=usable ? rule.target : @"REJECT"; line=rule.line; }
    }
    NSMutableArray *chain=[NSMutableArray array]; NSMutableOrderedSet *groups=[NSMutableOrderedSet orderedSet];
    @synchronized(counters ?: policy) {
        if (!MLPath(policy,target,selections,measurements,counters,metadata,chain,groups,0)) { [chain removeAllObjects]; [chain addObject:@"REJECT"]; }
    }
    NSMutableDictionary *result=[@{@"target":target ?: @"REJECT",@"node":chain.lastObject ?: @"REJECT",@"chain":[chain copy],
                                   @"groups":groups.array,@"group":policy.groups[target] ? target : @"",@"rule":line,@"ruleUsable":@(usable)} mutableCopy];
    if (context.ip) result[@"ip"]=context.ip;
    return [result copy];
}
NSDictionary *MLRouteTargetWithRuntime(NSDictionary *document, NSString *target, NSDictionary *selections,
                                      NSDictionary *measurements, NSMutableDictionary *counters, NSDictionary *metadata) {
    target=MLString(target) ?: @"REJECT";
    MLCompiledPolicy *policy=MLPolicy(document); NSMutableArray *chain=[NSMutableArray array]; NSMutableOrderedSet *groups=[NSMutableOrderedSet orderedSet]; BOOL usable;
    @synchronized(counters ?: policy) { usable=MLPath(policy,target,selections,measurements,counters,metadata ?: @{},chain,groups,0); }
    if (!usable) { [chain removeAllObjects]; [chain addObject:@"REJECT"]; }
    NSMutableDictionary *result=[@{@"target":target ?: @"REJECT",@"node":chain.lastObject ?: @"REJECT",@"chain":[chain copy],@"groups":groups.array,@"group":policy.groups[target] ? target : @"",@"rule":@"",@"ruleUsable":@(usable)} mutableCopy];
    if (MLString(metadata[@"ip"])) result[@"ip"]=metadata[@"ip"]; return [result copy];
}
NSDictionary *MLDefaultRouteWithRuntime(NSDictionary *document, NSString *mode, NSDictionary *selections, NSDictionary *measurements) {
    NSString *target=@"DIRECT";
    if ([mode.lowercaseString isEqual:@"global"]) target=@"GLOBAL";
    else if (![mode.lowercaseString isEqual:@"direct"]) {
        for (MLRouteRule *rule in MLPolicy(document).rules) if (rule->kind==MLMatch) { target=rule.target; break; }
    }
    return MLRouteTargetWithRuntime(document,target,selections,measurements,nil,@{});
}
NSDictionary *MLRouteWithResolver(NSDictionary *document, NSString *mode, NSDictionary *selections,
                                  NSString *host, NSString *ip, NSString *source, NSUInteger sourcePort,
                                  NSUInteger destPort, NSString *network, NSString *(^resolveIP)(void)) {
    NSMutableDictionary *metadata=[@{@"sourcePort":@(sourcePort),@"destPort":@(destPort)} mutableCopy];
    if (host) metadata[@"host"]=host; if (ip) metadata[@"ip"]=ip; if (source) metadata[@"source"]=source; if (network) metadata[@"network"]=network;
    return MLRouteWithRuntime(document,mode,selections,nil,nil,metadata,resolveIP);
}
NSDictionary *MLRoute(NSDictionary *document, NSString *mode, NSDictionary *selections, NSString *host, NSString *ip,
                      NSString *source, NSUInteger sourcePort, NSUInteger destPort, NSString *network) {
    return MLRouteWithResolver(document,mode,selections,host,ip,source,sourcePort,destPort,network,nil);
}
NSArray *MLGroupsWithRuntime(NSDictionary *document, NSDictionary *selections, NSDictionary *measurements) {
    MLCompiledPolicy *policy=MLPolicy(document); NSMutableArray *items=[NSMutableArray array];
    for (NSString *name in policy.groupNames) {
        NSDictionary *group=policy.groups[name]; NSString *selected=MLChoose(policy,name,selections,measurements,nil,@{},0,NO);
        NSMutableArray *chain=[NSMutableArray array]; NSMutableOrderedSet *visited=[NSMutableOrderedSet orderedSet];
        BOOL valid=MLPath(policy,name,selections,measurements,nil,@{},chain,visited,0);
        NSString *actual=valid ? chain.lastObject : @"REJECT";
        NSDictionary *health=MLTargetMeasurement(policy,selected,MLDefaultURL(group),selections,measurements,0,group[@"expected-status"]);
        NSMutableDictionary *item=[@{@"name":name,@"type":group[@"type"],@"selected":selected ?: @"",@"actual":actual ?: @"REJECT",@"chain":valid ? chain : @[@"REJECT"],@"health":health[@"health"] ?: @"unknown",@"members":group[@"members"] ?: @[]} mutableCopy];
        if (health[@"delay"]) item[@"delay"]=health[@"delay"];
        if (group[@"hidden"]) item[@"hidden"]=group[@"hidden"];
        if (group[@"icon"]) item[@"icon"]=group[@"icon"];
        [items addObject:[item copy]];
    }
    return items;
}
NSArray *MLGroups(NSDictionary *document, NSDictionary *selections) { return MLGroupsWithRuntime(document,selections,nil); }
NSArray *MLProxiesWithRuntime(NSDictionary *document, NSDictionary *selections, NSDictionary *measurements, NSString *group) {
    MLCompiledPolicy *policy=MLPolicy(document); NSString *name=group.length ? group : @"GLOBAL";
    NSDictionary *entry=policy.groups[name]; NSString *selected=MLChoose(policy,name,selections,measurements,nil,@{},0,NO);
    NSMutableArray *items=[NSMutableArray array];
    for (NSString *member in entry[@"members"]) {
        NSString *type=policy.groups[member] ? @"group" : policy.nodeTypes[member]; if (!type) continue;
        NSDictionary *measurement=MLTargetMeasurement(policy,member,MLDefaultURL(entry),selections,measurements,0,entry[@"expected-status"]);
        NSMutableDictionary *item=[@{@"name":member,@"type":type,@"health":measurement[@"health"] ?: @"unknown",@"selected":@([selected isEqual:member])} mutableCopy];
        if (measurement[@"delay"]) item[@"delay"]=measurement[@"delay"];
        [items addObject:[item copy]];
    }
    return items;
}
NSArray *MLProxies(NSDictionary *document, NSDictionary *selections, NSString *group) { return MLProxiesWithRuntime(document,selections,nil,group); }
BOOL MLCanSelect(NSDictionary *document, NSString *group, NSString *node) {
    if (!group.length || !node.length) return NO;
    MLCompiledPolicy *policy=MLPolicy(document); NSDictionary *entry=policy.groups[group];
    return [@[@"select",@"url-test",@"fallback"] containsObject:entry[@"type"]] && [entry[@"members"] containsObject:node] && (policy.groups[node] || policy.nodeTypes[node]);
}
