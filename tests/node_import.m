#import <Foundation/Foundation.h>
#import "MLConfig.h"
#import "MLNodeImport.h"
#import "MLRouting.h"
#include <assert.h>

static NSDictionary *import(NSString *text) {
    NSError *error = nil;
    NSString *yaml = MLImportNodeText(text, &error);
    assert(yaml.length && !error);
    NSDictionary *report = [MLConfig checkYAML:yaml];
    assert([report[@"valid"] boolValue]);
    return report[@"document"];
}

int main(void) {
    @autoreleasepool {
        NSDictionary *config = import(@"  socks5://us%2Ber:p%3Aa%40ss@[2001:db8::1]:2080#Lab%20Proxy\r\n"
                                      @"https://user:password@proxy.example#Lab%20Proxy\n"
                                      @"trojan://sekret%3Aword@relay.example:8443?sni=public.example&security=tls&type=tcp#DIRECT\n"
                                      @"vless://a2a2a2a2-c3c3-4d4d-a5a5-121212121212@vless.example:443?type=raw&security=tls&sni=front.example&encryption=none&flow=#TLS\n");
        NSArray *nodes = config[@"proxies"];
        assert(nodes.count == 4);
        assert([nodes[0][@"name"] isEqual:@"Lab Proxy"] && [nodes[1][@"name"] isEqual:@"Lab Proxy (2)"]);
        assert([nodes[0][@"server"] isEqual:@"2001:db8::1"] && [nodes[0][@"port"] integerValue] == 2080);
        assert([nodes[0][@"username"] isEqual:@"us+er"] && [nodes[0][@"password"] isEqual:@"p:a@ss"]);
        assert([nodes[1][@"type"] isEqual:@"https"] && [nodes[1][@"port"] integerValue] == 443);
        assert([nodes[2][@"name"] isEqual:@"DIRECT (2)"] && [nodes[2][@"sni"] isEqual:@"public.example"]);
        assert([nodes[2][@"password"] isEqual:@"sekret:word"]);
        assert([nodes[3][@"uuid"] isEqual:@"a2a2a2a2-c3c3-4d4d-a5a5-121212121212"] && [nodes[3][@"tls"] boolValue]);
        assert([MLRoute(config, @"Rule", nil, @"example.test", nil, nil, 0, 443, @"tcp")[@"node"] isEqual:@"Lab Proxy"]);
        assert(MLCanSelect(config, @"PROXY", @"TLS"));

        NSDictionary *base64 = import(@"c29ja3M1Oi8vbm9kZS5leGFt\n cGxlOjEwODA=\r\n");
        assert([base64[@"proxies"][0][@"server"] isEqual:@"node.example"]);
        NSDictionary *URLSafe = import(@"aHR0cDovL25vZGUuZXhhbXBsZTo4MDgwI_CfmoAKc29ja3M1Oi8vcHJveHkuZXhhbXBsZToxMDgw");
        assert([URLSafe[@"proxies"] count] == 2 && [URLSafe[@"proxies"][0][@"name"] isEqual:@"🚀"]);
        assert([import(@"http://proxy.example") [@"proxies"][0][@"port"] integerValue] == 80);
        NSDictionary *hy2 = import(@"hy2://p%3Aa%40ss@hy2.example/?sni=front.example&obfs=salamander&obfs-password=cover%3Aword&insecure=0#Hy2\n"
                                  @"hysteria2://second@proxy.example:5443#Alternate");
        assert([hy2[@"proxies"] count] == 2);
        assert([hy2[@"proxies"][0][@"type"] isEqual:@"hysteria2"]);
        assert([hy2[@"proxies"][0][@"port"] integerValue] == 443);
        assert([hy2[@"proxies"][0][@"password"] isEqual:@"p:a@ss"]);
        assert([hy2[@"proxies"][0][@"obfs-password"] isEqual:@"cover:word"]);
        assert([hy2[@"proxies"][1][@"port"] integerValue] == 5443);

        NSArray *bad = @[
            @"", @"not Base64 !", @"aHR0cHM6Ly9ub2RlLmV4YW1wbGV=", @"c29ja3M1Oi8vbm9kZS5leGFtcGxlOjEwODA==",
            @"https://proxy.example/subscription", @"socks5://proxy.example:0", @"socks5://[myhost]:1080",
            @"socks5://user@proxy.example:1080", @"socks5://user:p%00ass@proxy.example:1080",
            @"trojan://private-secret@relay.example:443?allowInsecure=1",
            @"trojan://private-secret@relay.example:443?security=none",
            @"trojan://private-secret@relay.example:443?sni=one.example&sni=two.example",
            @"vless://a2a2a2a2-c3c3-4d4d-a5a5-121212121212@proxy.example:443?type=ws",
            @"vless://a2a2a2a2-c3c3-4d4d-a5a5-121212121212@proxy.example:443?security=reality",
            @"vless://a2a2a2a2-c3c3-4d4d-a5a5-121212121212@proxy.example",
            @"socks5://proxy.example:1080\nss://private-secret"
            , @"hy2://private-secret@node.example?insecure=1"
            , @"hy2://private-secret@node.example?obfs=salamander"
            , @"hy2://private-secret@node.example?pinSHA256=wrong"
            , @"hy2://node.example:443"
        ];
        for (NSString *text in bad) {
            NSError *error = nil;
            assert(!MLImportNodeText(text, &error) && error);
            assert([error.localizedDescription rangeOfString:@"private-secret"].location == NSNotFound);
        }
        NSMutableString *many = [NSMutableString string];
        for (NSUInteger i = 0; i < 129; i++) [many appendString:@"http://proxy.example:80\n"];
        assert(!MLImportNodeText(many, NULL));
        puts("PASS node import: share URI formats, Base64, validated configuration and bounded rejection");
    }
    return 0;
}
