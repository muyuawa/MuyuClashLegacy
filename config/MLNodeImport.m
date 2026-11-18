#import "MLNodeImport.h"
#import "../protocols/MLStream.h"
#include <arpa/inet.h>

static const NSUInteger MLNodeImportMaxBytes = 256 * 1024;
static const NSUInteger MLNodeImportMaxURIBytes = 8192;
static const NSUInteger MLNodeImportMaxCount = 128;

static NSString *MLImportError(NSError **error, NSString *message, NSUInteger item) {
    if (error) {
        NSString *detail = item ? [NSString stringWithFormat:@"Node %lu. %@", (unsigned long)item, message] : message;
        *error = [NSError errorWithDomain:@"com.muyu.clashlegacy.node-import" code:1
                                 userInfo:@{NSLocalizedDescriptionKey:detail}];
    }
    return nil;
}

static NSString *MLBefore(NSString *text, NSString *delimiter, NSString **after) {
    NSRange split = [text rangeOfString:delimiter];
    if (split.location == NSNotFound) {
        *after = nil;
        return text;
    }
    *after = [text substringFromIndex:NSMaxRange(split)];
    return [text substringToIndex:split.location];
}

static BOOL MLHex(unichar c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

static NSString *MLURIDecode(NSString *text) {
    if (!text) return nil;
    for (NSUInteger i = 0; i < text.length; i++) {
        if ([text characterAtIndex:i] == '%') {
            if (i + 2 >= text.length || !MLHex([text characterAtIndex:i + 1]) ||
                !MLHex([text characterAtIndex:i + 2])) return nil;
            i += 2;
        }
    }
    NSString *decoded = [text stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    if (!decoded || [decoded rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location != NSNotFound) return nil;
    return decoded;
}

static NSString *MLDecodeBase64(NSString *text) {
    NSMutableData *decoded = [NSMutableData dataWithLength:text.length * 3 / 4];
    uint8_t *bytes = decoded.mutableBytes;
    NSUInteger length = 0, symbols = 0, padding = 0;
    unsigned accumulator = 0, bits = 0;
    BOOL standard = NO, urlSafe = NO;
    for (NSUInteger i = 0; i < text.length; i++) {
        unichar c = [text characterAtIndex:i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c == '=') {
            if (++padding > 2) return nil;
            continue;
        }
        if (padding) return nil;
        unsigned digit;
        if (c >= 'A' && c <= 'Z') digit = c - 'A';
        else if (c >= 'a' && c <= 'z') digit = c - 'a' + 26;
        else if (c >= '0' && c <= '9') digit = c - '0' + 52;
        else if (c == '+' || c == '/' || c == '-' || c == '_') {
            digit = (c == '+' || c == '-') ? 62 : 63;
            standard |= c == '+' || c == '/';
            urlSafe |= c == '-' || c == '_';
            if (standard && urlSafe) return nil;
        } else return nil;
        symbols++;
        accumulator = (accumulator << 6) | digit;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            bytes[length++] = accumulator >> bits;
            accumulator &= (1U << bits) - 1;
        }
    }
    NSUInteger remainder = symbols % 4;
    if (!length || remainder == 1 || (padding && padding != (4 - remainder) % 4) || accumulator) return nil;
    decoded.length = length;
    return [[NSString alloc] initWithData:decoded encoding:NSUTF8StringEncoding];
}

static NSNumber *MLURIPort(NSString *text) {
    if (!text.length || text.length > 5) return nil;
    NSUInteger port = 0;
    for (NSUInteger i = 0; i < text.length; i++) {
        unichar c = [text characterAtIndex:i];
        if (c < '0' || c > '9') return nil;
        port = port * 10 + c - '0';
    }
    return port > 0 && port <= UINT16_MAX ? @(port) : nil;
}

static NSString *MLServer(NSString *address, NSString **port) {
    *port = nil;
    if (![address hasPrefix:@"["]) return MLBefore(address, @":", port);
    NSString *suffix = nil;
    NSString *server = MLBefore([address substringFromIndex:1], @"]", &suffix);
    struct in6_addr bytes;
    if (inet_pton(AF_INET6, server.UTF8String, &bytes) != 1 || !suffix) return nil;
    if (suffix.length) {
        if (![suffix hasPrefix:@":"]) return nil;
        *port = [suffix substringFromIndex:1];
    }
    return server;
}

static NSDictionary *MLReadQuery(NSString *query) {
    if (!query) return @{};
    NSMutableDictionary *options = [NSMutableDictionary dictionary];
    for (NSString *item in [query componentsSeparatedByString:@"&"]) {
        NSString *rawValue = nil;
        NSString *key = MLURIDecode(MLBefore(item, @"=", &rawValue));
        NSString *value = MLURIDecode(rawValue);
        if (!key.length || !value || options[key]) return nil;
        options[key] = value;
    }
    return options;
}

static BOOL MLQueryOptions(NSDictionary *options, NSMutableDictionary *node) {
    if (!options) return NO;
    if (!options.count) return YES;
    NSString *type = node[@"type"];
    BOOL vless = [type isEqual:@"vless"];
    BOOL trojan = [type isEqual:@"trojan"];
    BOOL hy2 = [type isEqual:@"hysteria2"];
    if (!vless && !trojan && !hy2) return NO;
    for (NSString *key in options) {
        NSString *value = options[key];
        if (hy2) {
            if (([key isEqual:@"sni"] || [key isEqual:@"peer"]) && value.length) node[@"sni"] = value;
            else if ([key isEqual:@"obfs"] && [value isEqual:@"salamander"]) node[@"obfs"] = value;
            else if ([key isEqual:@"obfs-password"] && value.length) node[@"obfs-password"] = value;
            else if ([key isEqual:@"pinSHA256"] && value.length) node[@"fingerprint"] = value;
            else if (([key isEqual:@"insecure"] || [key isEqual:@"allowInsecure"]) &&
                     [@[@"0", @"false"] containsObject:value]) node[@"skip-cert-verify"] = @NO;
            else return NO;
            continue;
        }
        if ([key isEqual:@"security"] && [value isEqual:@"tls"]) node[@"tls"] = @YES;
        else if ([key isEqual:@"security"] && vless && [value isEqual:@"none"]) node[@"tls"] = @NO;
        else if ([key isEqual:@"sni"] && value.length) node[@"sni"] = value;
        else if ([key isEqual:@"type"] && [@[@"tcp", @"raw"] containsObject:value]) node[@"network"] = @"tcp";
        else if ([key isEqual:@"allowInsecure"] && [@[@"0", @"false"] containsObject:value]) node[@"skip-cert-verify"] = @NO;
        else if ([key isEqual:@"encryption"] && vless && [value isEqual:@"none"]) node[@"encryption"] = value;
        else if ([key isEqual:@"headerType"] && [value isEqual:@"none"]) continue;
        else if ([key isEqual:@"flow"] && vless && !value.length) continue;
        else return NO;
    }
    return YES;
}

static NSMutableDictionary *MLNodeFromURI(NSString *line, NSString **problem) {
    *problem = @"Malformed proxy share URI.";
    if ([line rangeOfCharacterFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].location != NSNotFound ||
        [line rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location != NSNotFound) return nil;

    NSString *uri = nil;
    NSString *scheme = [MLBefore(line, @"://", &uri) lowercaseString];
    if (!uri.length) return nil;
    if ([scheme isEqual:@"hy2"]) scheme = @"hysteria2";
    if (![@[@"socks5", @"http", @"https", @"trojan", @"vless", @"hysteria2"] containsObject:scheme]) {
        *problem = @"Unsupported proxy share URI scheme. Use SOCKS5, HTTP, HTTPS, Trojan, VLESS or Hysteria2.";
        return nil;
    }

    NSString *fragment = nil, *query = nil, *path = nil;
    uri = MLBefore(uri, @"#", &fragment);
    uri = MLBefore(uri, @"?", &query);
    NSString *authority = MLBefore(uri, @"/", &path);
    if (path.length || (fragment && [fragment rangeOfString:@"#"].location != NSNotFound)) return nil;
    NSString *label = fragment ? MLURIDecode(fragment) : @"";
    if (!label || [label lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 240) return nil;

    NSString *address = nil;
    NSString *userInfo = MLBefore(authority, @"@", &address);
    if (!address) {
        address = userInfo;
        userInfo = nil;
    } else if ([address rangeOfString:@"@"].location != NSNotFound) return nil;
    NSString *portText = nil;
    NSString *server = MLServer(address, &portText);
    if (!server.length) return nil;
    NSDictionary *defaultPorts = @{@"socks5":@1080, @"http":@80, @"https":@443, @"hysteria2":@443};
    NSNumber *port = portText ? MLURIPort(portText) : defaultPorts[scheme];
    if (!port) return nil;
    if (!label.length) label = [NSString stringWithFormat:@"%@ %@:%@", scheme.uppercaseString, server, port];
    NSMutableDictionary *node = [@{@"name":label, @"type":scheme, @"server":server, @"port":port} mutableCopy];

    if ([@[@"socks5", @"http", @"https"] containsObject:scheme]) {
        if (userInfo) {
            NSString *password = nil;
            NSString *username = MLURIDecode(MLBefore(userInfo, @":", &password));
            password = MLURIDecode(password);
            if (!username.length || !password.length) return nil;
            node[@"username"] = username;
            node[@"password"] = password;
        }
    } else {
        NSString *credential = MLURIDecode(userInfo);
        if (!credential.length) return nil;
        node[[scheme isEqual:@"vless"] ? @"uuid" : @"password"] = credential;
    }
    if (!MLQueryOptions(MLReadQuery(query), node) || MLStreamValidateNode(node)) {
        *problem = @"The node uses an option or value unavailable in the local TCP adapter.";
        return nil;
    }
    return node;
}

NSString *MLImportNodeText(NSString *text, NSError **error) {
    if (![text isKindOfClass:[NSString class]] || !text.length)
        return MLImportError(error, @"Enter a proxy share URI or an encoded list of URIs.", 0);
    NSUInteger bytes = [text lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    if (!bytes || bytes > MLNodeImportMaxBytes)
        return MLImportError(error, @"The input must be valid UTF-8 and at most 256 KiB.", 0);

    NSString *lines = text;
    if ([lines rangeOfString:@"://"].location == NSNotFound) {
        lines = MLDecodeBase64(lines);
        if (!lines) return MLImportError(error, @"The input contains invalid Base64.", 0);
    }
    NSMutableArray *proxies = [NSMutableArray array];
    NSMutableArray *members = [NSMutableArray array];
    NSMutableSet *names = [NSMutableSet setWithArray:@[@"PROXY", @"GLOBAL", @"DIRECT", @"REJECT",
                                                      @"REJECT-DROP", @"PASS", @"PASS-RULE", @"COMPATIBLE"]];
    NSCharacterSet *space = [NSCharacterSet whitespaceAndNewlineCharacterSet];
    for (NSString *raw in [lines componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        NSString *line = [raw stringByTrimmingCharactersInSet:space];
        if (!line.length) continue;
        NSUInteger item = proxies.count + 1;
        if (item > MLNodeImportMaxCount)
            return MLImportError(error, @"A list can contain up to 128 nodes.", 0);
        if ([line lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > MLNodeImportMaxURIBytes)
            return MLImportError(error, @"A share URI can contain up to 8 KiB.", item);
        NSString *problem = nil;
        NSMutableDictionary *node = MLNodeFromURI(line, &problem);
        if (!node) return MLImportError(error, problem, item);
        NSString *base = node[@"name"], *name = base;
        for (NSUInteger suffix = 2; [names containsObject:name]; suffix++)
            name = [NSString stringWithFormat:@"%@ (%lu)", base, (unsigned long)suffix];
        node[@"name"] = name;
        [names addObject:name];
        [members addObject:name];
        [proxies addObject:node];
    }
    if (!proxies.count) return MLImportError(error, @"The input contains no proxy share URIs.", 0);
    NSDictionary *document = @{@"mode":@"rule", @"proxies":proxies,
                               @"proxy-groups":@[@{@"name":@"PROXY", @"type":@"select", @"proxies":members}],
                               @"rules":@[@"MATCH,PROXY"]};
    NSData *yaml = [NSJSONSerialization dataWithJSONObject:document options:NSJSONWritingPrettyPrinted error:NULL];
    if (!yaml || yaml.length > 512 * 1024)
        return MLImportError(error, @"The generated configuration exceeds the import limits.", 0);
    return [[NSString alloc] initWithData:yaml encoding:NSUTF8StringEncoding];
}
