#import "MLFakeIP.h"
#include <arpa/inet.h>
#include <math.h>
#include <mach/mach_time.h>

static const NSUInteger MLMaximumFakeEntries = 512;
static const NSUInteger MLMaximumRetiredFakeEntries = 512;
static const NSUInteger MLMaximumFakeSnapshotBytes = 256 * 1024;
static const NSTimeInterval MLFakeRetirementSeconds = 300;

static NSString *MLFakeHost(NSString *host) {
    if (![host isKindOfClass:[NSString class]] || !host.length || host.length > 253) return nil;
    if ([host hasSuffix:@"."]) host = [host substringToIndex:host.length-1];
    host = host.lowercaseString;
    NSData *ascii = [host dataUsingEncoding:NSASCIIStringEncoding allowLossyConversion:NO];
    if (!ascii.length) return nil;
    for (NSString *label in [host componentsSeparatedByString:@"."]) {
        if (!label.length || label.length > 63) return nil;
        for (NSUInteger i=0;i<label.length;i++) {
            unichar c = [label characterAtIndex:i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return nil;
        }
    }
    return host;
}
static BOOL MLFakeInteger(id value, uint32_t minimum, uint32_t maximum, uint32_t *result) {
    if (![value isKindOfClass:[NSNumber class]] || CFGetTypeID((__bridge CFTypeRef)value)==CFBooleanGetTypeID()) return NO;
    double number = [value doubleValue];
    if (!isfinite(number) || floor(number)!=number || number < minimum || number > maximum) return NO;
    if (result) *result = (uint32_t)number;
    return YES;
}
static BOOL MLFakeKeys(NSDictionary *dictionary, NSArray *allowed) {
    if (![dictionary isKindOfClass:[NSDictionary class]] || dictionary.count > allowed.count) return NO;
    for (id key in dictionary) if (![allowed containsObject:key]) return NO;
    return YES;
}
static BOOL MLFakeError(NSError **error, NSString *reason) {
    if (error) *error = [NSError errorWithDomain:@"com.muyu.clashlegacy.fake-ip" code:1
        userInfo:@{NSLocalizedDescriptionKey:reason}];
    return NO;
}

@implementation MLFakeIP {
    uint32_t _base, _slots, _next;
    struct in6_addr _base6;
    BOOL _hasIPv6;
    NSUInteger _capacity;
    NSMutableDictionary *_byHost, *_byAddress, *_retired;
    NSString *_range, *_range6;
    BOOL (^_persistenceHandler)(NSDictionary *);
    BOOL _persisting;
    NSUInteger _persistenceFailures, _restores;
    uint64_t _useSerial;
}
- (id)initWithRange:(NSString *)range ipv6Range:(NSString *)range6 capacity:(NSUInteger)capacity {
    if (!(self = [super init])) return nil;
    NSArray *parts = [(range ?: @"198.18.0.0/16") componentsSeparatedByString:@"/"];
    struct in_addr address;
    if (parts.count != 2 || inet_pton(AF_INET,[parts[0] UTF8String],&address) != 1) return nil;
    NSString *bits = parts[1];
    if (!bits.length || bits.length > 2 || [bits rangeOfCharacterFromSet:[[NSCharacterSet decimalDigitCharacterSet] invertedSet]].location != NSNotFound) return nil;
    unsigned prefix = (unsigned)[bits integerValue];
    if (prefix < 8 || prefix > 28 || !capacity || capacity > 4096) return nil;
    _slots = 1U << (32-prefix);
    _base = ntohl(address.s_addr) & (UINT32_MAX << (32-prefix));
    address.s_addr = htonl(_base);
    char text[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET,&address,text,sizeof(text))) return nil;
    _range = [NSString stringWithFormat:@"%s/%u",text,prefix];
    _next = 4;
    if (range6) {
        NSArray *v6 = [range6 componentsSeparatedByString:@"/"];
        if (v6.count != 2 || ![v6[1] isEqual:@"112"] || inet_pton(AF_INET6,[v6[0] UTF8String],&_base6) != 1) return nil;
        _base6.s6_addr[14] = _base6.s6_addr[15] = 0;
        if (!inet_ntop(AF_INET6,&_base6,text,sizeof(text))) return nil;
        _range6 = [NSString stringWithFormat:@"%s/112",text];
        _hasIPv6 = YES;
        _slots = MIN(_slots,65536U);
    }
    _capacity = MIN(MIN(capacity,MLMaximumFakeEntries),(NSUInteger)_slots-5-(_slots > 54 ? 1 : 0));
    _byHost = [NSMutableDictionary dictionary]; _byAddress = [NSMutableDictionary dictionary];
    _retired = [NSMutableDictionary dictionary];
    return self;
}
- (NSTimeInterval)monotonicNow {
    mach_timebase_info_data_t scale;
    if (mach_timebase_info(&scale)!=KERN_SUCCESS || !scale.denom) return NAN;
    return (NSTimeInterval)mach_absolute_time() * scale.numer / scale.denom / 1e9;
}
- (BOOL (^)(NSDictionary *))persistenceHandler {
    @synchronized(self) { return _persistenceHandler; }
}
- (void)setPersistenceHandler:(BOOL (^)(NSDictionary *))handler {
    @synchronized(self) { _persistenceHandler = [handler copy]; }
}
- (NSDictionary *)snapshot {
    @synchronized(self) {
        NSArray *ordered = [_byHost.allValues sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            NSComparisonResult order = [a[@"used"] compare:b[@"used"]];
            return order == NSOrderedSame ? [a[@"host"] compare:b[@"host"]] : order;
        }];
        NSMutableArray *entries = [NSMutableArray arrayWithCapacity:ordered.count];
        for (NSDictionary *entry in ordered) {
            NSMutableDictionary *saved = [@{@"host":entry[@"host"],@"v4":entry[@"v4"]} mutableCopy];
            if (entry[@"v6"]) saved[@"v6"] = entry[@"v6"];
            [entries addObject:[saved copy]];
        }
        NSMutableArray *retired = [NSMutableArray arrayWithCapacity:_retired.count];
        for (NSString *address in [_retired.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
            NSDictionary *entry = _retired[address];
            NSMutableDictionary *saved = [@{@"v4":entry[@"v4"]} mutableCopy];
            if (entry[@"v6"]) saved[@"v6"] = entry[@"v6"];
            [retired addObject:[saved copy]];
        }
        return @{@"version":@1,@"range":_range,@"ipv6Range":_range6 ?: (id)[NSNull null],
            @"next":@(_next),@"entries":[entries copy],@"retired":[retired copy]};
    }
}
- (BOOL)validateAddresses:(NSDictionary *)saved seen:(NSMutableSet *)seen error:(NSError **)error {
    NSString *v4 = saved[@"v4"], *v6 = saved[@"v6"];
    if (![v4 isKindOfClass:[NSString class]] || v4.length > INET_ADDRSTRLEN-1)
        return MLFakeError(error,@"Invalid Fake-IP address");
    struct in_addr address; char text[INET6_ADDRSTRLEN];
    if (inet_pton(AF_INET,v4.UTF8String,&address)!=1 || !inet_ntop(AF_INET,&address,text,sizeof(text)) ||
        ![v4 isEqual:[NSString stringWithUTF8String:text]]) return MLFakeError(error,@"Invalid IPv4 address");
    uint64_t value = ntohl(address.s_addr);
    if (value < _base+4ULL || value >= (uint64_t)_base+_slots-1 || value-_base==53 || [seen containsObject:v4])
        return MLFakeError(error,@"Reserved, duplicate or out-of-range Fake-IP address");
    uint32_t slot = (uint32_t)(value-_base);
    if (_hasIPv6) {
        struct in6_addr address6;
        if (![v6 isKindOfClass:[NSString class]] || v6.length > INET6_ADDRSTRLEN-1 ||
            inet_pton(AF_INET6,v6.UTF8String,&address6)!=1 || memcmp(address6.s6_addr,_base6.s6_addr,14) ||
            (((unsigned)address6.s6_addr[14]<<8)|address6.s6_addr[15])!=slot || [seen containsObject:v6] ||
            !inet_ntop(AF_INET6,&address6,text,sizeof(text)) || ![v6 isEqual:[NSString stringWithUTF8String:text]])
            return MLFakeError(error,@"Invalid, duplicate or mismatched IPv6 address");
    }
    [seen addObject:v4];
    if (_hasIPv6) [seen addObject:v6];
    return YES;
}
- (BOOL)restoreSnapshot:(NSDictionary *)snapshot error:(NSError **)error {
    @synchronized(self) {
        if (_persisting) return MLFakeError(error,@"Cannot restore during persistence");
        if (!MLFakeKeys(snapshot,@[@"version",@"range",@"ipv6Range",@"next",@"entries",@"retired"]) ||
            snapshot.count!=(snapshot[@"retired"] ? 6U : 5U) ||
            !MLFakeInteger(snapshot[@"version"],1,1,NULL) ||
            ![snapshot[@"range"] isKindOfClass:[NSString class]] || ![snapshot[@"range"] isEqual:_range] ||
            ![snapshot[@"ipv6Range"] isEqual:_range6 ?: (id)[NSNull null]])
            return MLFakeError(error,@"Snapshot version or range does not match");
        uint32_t next;
        if (!MLFakeInteger(snapshot[@"next"],4,_slots-2,&next)) return MLFakeError(error,@"Invalid next Fake-IP slot");
        NSArray *entries = snapshot[@"entries"];
        if (![entries isKindOfClass:[NSArray class]] || entries.count > _capacity || entries.count > MLMaximumFakeEntries)
            return MLFakeError(error,@"Snapshot entries exceed capacity");
        NSArray *retiredEntries = snapshot[@"retired"] ?: @[];
        if (![retiredEntries isKindOfClass:[NSArray class]] || retiredEntries.count > MLMaximumRetiredFakeEntries)
            return MLFakeError(error,@"Snapshot retired addresses exceed capacity");
        NSMutableDictionary *hosts = [NSMutableDictionary dictionary], *addresses = [NSMutableDictionary dictionary];
        NSMutableSet *seen = [NSMutableSet set];
        uint64_t used = 0;
        for (NSDictionary *saved in entries) {
            if (!MLFakeKeys(saved,@[@"host",@"v4",@"v6"]) || saved.count != (_hasIPv6 ? 3U : 2U))
                return MLFakeError(error,@"Invalid Fake-IP entry");
            NSString *host = MLFakeHost(saved[@"host"]), *v4 = saved[@"v4"], *v6 = saved[@"v6"];
            if (!host || ![host isEqual:saved[@"host"]] || hosts[host])
                return MLFakeError(error,@"Invalid or duplicate Fake-IP hostname/address");
            if (![self validateAddresses:saved seen:seen error:error]) return NO;
            NSMutableDictionary *entry = [@{@"host":host,@"v4":v4,@"used":@(++used),@"pins":@0} mutableCopy];
            if (_hasIPv6) entry[@"v6"] = v6;
            hosts[host] = entry; addresses[v4] = entry;
            if (_hasIPv6) addresses[v6] = entry;
        }
        NSMutableDictionary *retired = [NSMutableDictionary dictionary];
        for (NSDictionary *saved in retiredEntries) {
            if (!MLFakeKeys(saved,@[@"v4",@"v6"]) || saved.count != (_hasIPv6 ? 2U : 1U))
                return MLFakeError(error,@"Invalid retired Fake-IP address");
            if (![self validateAddresses:saved seen:seen error:error]) return NO;
            retired[saved[@"v4"]] = [saved mutableCopy];
        }
        NSData *json = [NSJSONSerialization dataWithJSONObject:snapshot options:0 error:NULL];
        if (!json || json.length > MLMaximumFakeSnapshotBytes) return MLFakeError(error,@"Snapshot exceeds byte limit");
        NSTimeInterval now = [self monotonicNow];
        if (!isfinite(now) || now < 0 || !isfinite(now+MLFakeRetirementSeconds))
            return MLFakeError(error,@"Monotonic Fake-IP clock unavailable");
        // A persisted deadline cannot be compared across boots. All saved
        // retired pairs conservatively cool for a fresh complete DNS TTL.
        for (NSMutableDictionary *entry in retired.allValues) entry[@"until"] = @(now+MLFakeRetirementSeconds);
        _byHost = hosts; _byAddress = addresses; _retired = retired; _next = next; _useSerial = used; _restores++;
        return YES;
    }
}
- (void)remove:(NSDictionary *)entry {
    [_byHost removeObjectForKey:entry[@"host"]];
    [_byAddress removeObjectForKey:entry[@"v4"]];
    if (entry[@"v6"]) [_byAddress removeObjectForKey:entry[@"v6"]];
}
- (NSString *)addressForHost:(NSString *)host ipv6:(BOOL)ipv6 {
    host = MLFakeHost(host);
    if (!host || (ipv6 && !_hasIPv6)) return nil;
    @synchronized(self) {
        if (_persisting) return nil;
        NSMutableDictionary *entry = _byHost[host];
        if (entry) { entry[@"used"] = @(++_useSerial); return entry[ipv6 ? @"v6" : @"v4"]; }
        NSTimeInterval now = [self monotonicNow];
        if (!isfinite(now) || now < 0 || !isfinite(now+MLFakeRetirementSeconds)) return nil;
        // Expiration is staged with the new mapping. Neither exhaustion nor
        // a failed persistence ACK may silently discard the retired journal.
        NSMutableDictionary *retired = [NSMutableDictionary dictionary];
        for (NSDictionary *candidate in _retired.allValues)
            if ([candidate[@"until"] doubleValue] > now) retired[candidate[@"v4"]] = candidate;
        NSDictionary *oldest = nil;
        if (_byHost.count >= _capacity) {
            for (NSDictionary *candidate in _byHost.allValues) {
                if ([candidate[@"pins"] unsignedIntegerValue]) continue;
                if (!oldest || [candidate[@"used"] doubleValue] < [oldest[@"used"] doubleValue]) oldest = candidate;
            }
            if (!oldest) return nil;
            if (retired.count >= MLMaximumRetiredFakeEntries) return nil;
        }
        uint32_t previousNext = _next;
        uint32_t next = _next;
        NSString *v4 = nil, *v6 = nil;
        for (uint32_t attempt=0;attempt<_slots;attempt++) {
            uint32_t slot = next++;
            if (next >= _slots-1) next = 4;
            // Interface/DNS endpoints and network/broadcast addresses are reserved.
            if (slot < 4 || slot == 53 || slot >= _slots-1) continue;
            struct in_addr address = {htonl(_base + slot)};
            char buffer[INET6_ADDRSTRLEN];
            if (!inet_ntop(AF_INET,&address,buffer,sizeof(buffer))) return nil;
            NSString *candidate = [NSString stringWithUTF8String:buffer];
            // A victim remains occupied until it is retired. Reusing its
            // slot here would misroute a still-cached DNS answer immediately.
            if (_byAddress[candidate] || retired[candidate]) continue;
            v4 = candidate;
            if (_hasIPv6) {
                struct in6_addr address6 = _base6;
                address6.s6_addr[14] = (uint8_t)(slot >> 8); address6.s6_addr[15] = (uint8_t)slot;
                if (!inet_ntop(AF_INET6,&address6,buffer,sizeof(buffer))) return nil;
                v6 = [NSString stringWithUTF8String:buffer];
            }
            break;
        }
        if (!v4) return nil;
        NSMutableDictionary *previousRetired = _retired;
        uint64_t previousSerial = _useSerial;
        _next = next;
        if (oldest) {
            [self remove:oldest];
            NSMutableDictionary *saved = [@{@"v4":oldest[@"v4"],@"until":@(now+MLFakeRetirementSeconds)} mutableCopy];
            if (oldest[@"v6"]) saved[@"v6"] = oldest[@"v6"];
            retired[oldest[@"v4"]] = saved;
        }
        _retired = retired;
        entry = [@{@"host":host,@"v4":v4,@"used":@(++_useSerial),@"pins":@0} mutableCopy];
        if (v6) entry[@"v6"] = v6;
        _byHost[host] = entry; _byAddress[v4] = entry;
        if (v6) _byAddress[v6] = entry;
        BOOL (^handler)(NSDictionary *) = _persistenceHandler;
        if (handler) {
            NSDictionary *saved = [self snapshot];
            NSData *json = [NSJSONSerialization dataWithJSONObject:saved options:0 error:NULL];
            _persisting = YES;
            BOOL persisted = NO;
            @try { if (json && json.length <= MLMaximumFakeSnapshotBytes) persisted = handler(saved); }
            @catch (NSException *exception) { (void)exception; }
            _persisting = NO;
            if (!persisted) {
                [self remove:entry];
                if (oldest) {
                    _byHost[oldest[@"host"]] = oldest; _byAddress[oldest[@"v4"]] = oldest;
                    if (oldest[@"v6"]) _byAddress[oldest[@"v6"]] = oldest;
                }
                _next = previousNext; _useSerial = previousSerial; _retired = previousRetired; _persistenceFailures++;
                return nil;
            }
        }
        return entry[ipv6 ? @"v6" : @"v4"];
    }
}
- (NSString *)hostForAddress:(NSString *)address {
    if (!address) return nil;
    @synchronized(self) {
        NSMutableDictionary *entry = _byAddress[address];
        if (entry && !_persisting) entry[@"used"] = @(++_useSerial);
        return entry[@"host"];
    }
}
- (BOOL)containsAddress:(NSString *)address {
    struct in_addr v4; struct in6_addr v6;
    if (inet_pton(AF_INET,address.UTF8String,&v4)==1)
        return ntohl(v4.s_addr)>=_base && (uint64_t)ntohl(v4.s_addr)<(uint64_t)_base+_slots;
    return _hasIPv6 && inet_pton(AF_INET6,address.UTF8String,&v6)==1 && !memcmp(v6.s6_addr,_base6.s6_addr,14);
}
- (void)retainAddress:(NSString *)address {
    if (!address) return;
    @synchronized(self) {
        NSMutableDictionary *entry = _byAddress[address];
        if (entry) entry[@"pins"] = @([entry[@"pins"] unsignedIntegerValue]+1);
    }
}
- (void)releaseAddress:(NSString *)address {
    if (!address) return;
    @synchronized(self) {
        NSMutableDictionary *entry = _byAddress[address];
        NSUInteger count = [entry[@"pins"] unsignedIntegerValue];
        if (entry && count) entry[@"pins"] = @(count-1);
    }
}
- (NSDictionary *)statistics {
    @synchronized(self) {
        NSUInteger pins = 0;
        for (NSDictionary *entry in _byHost.allValues) pins += [entry[@"pins"] unsignedIntegerValue];
        return @{@"entries":@(_byHost.count),@"capacity":@(_capacity),@"pins":@(pins),
            @"retired":@(_retired.count),@"retiredCapacity":@(MLMaximumRetiredFakeEntries),@"retirementSeconds":@(MLFakeRetirementSeconds),
            @"persistenceEnabled":@(_persistenceHandler!=nil),@"persistenceFailures":@(_persistenceFailures),@"restores":@(_restores)};
    }
}
@end
