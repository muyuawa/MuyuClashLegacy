#import <Foundation/Foundation.h>
#import "MLConfig.h"
#import "MLRouting.h"
#include <assert.h>

static NSDictionary *document(NSString *yaml) {
    NSDictionary *checked = [MLConfig checkYAML:yaml];
    assert([checked[@"valid"] boolValue]);
    return checked[@"document"];
}

static NSString *node(NSDictionary *config, NSString *host, NSString *ip,
                      NSString *source, NSUInteger sourcePort, NSUInteger destPort) {
    return MLRoute(config, @"Rule", nil, host, ip, source, sourcePort, destPort, @"tcp")[@"node"];
}

int main(void) {
    @autoreleasepool {
        NSDictionary *domains = document(@"rules:\n"
                                           @"- 'DOMAIN,api.example.test,DIRECT'\n"
                                           @"- 'DOMAIN-SUFFIX,example.test,REJECT'\n"
                                           @"- 'DOMAIN-KEYWORD,tracker,REJECT'\n"
                                           @"- 'domain-regex,^ab{2,3}\\.test$,REJECT'\n");
        NSDictionary *first = MLRoute(domains, @"Rule", nil, @"Api.Example.Test", nil, nil, 0, 443, @"tcp");
        assert([first[@"rule"] isEqual:@"DOMAIN,api.example.test,DIRECT"]);
        assert([node(domains, @"x.example.test", nil, nil, 0, 443) isEqual:@"REJECT"]);
        assert([node(domains, @"example.test", nil, nil, 0, 443) isEqual:@"REJECT"]);
        assert([node(domains, @"notexample.test", nil, nil, 0, 443) isEqual:@"DIRECT"]);
        assert([node(domains, @"XtrackerZ.test", nil, nil, 0, 443) isEqual:@"REJECT"]);
        assert([node(domains, @"ABB.test", nil, nil, 0, 443) isEqual:@"REJECT"]);
        assert([node(domains, @"ab.test", nil, nil, 0, 443) isEqual:@"DIRECT"]);

        NSDictionary *addresses = document(@"rules:\n"
                                             @"- 'IP-CIDR,10.0.0.0/9,REJECT,no-resolve'\n"
                                             @"- 'IP-CIDR6,2001:db8::/33,REJECT'\n"
                                             @"- 'IP-CIDR,192.0.2.0/24,REJECT,src'\n"
                                             @"- 'SRC-IP-CIDR,2001:db8:1::/48,REJECT'\n"
                                             @"- 'MATCH,DIRECT'\n");
        assert([node(addresses, @"10.127.255.255", nil, nil, 0, 443) isEqual:@"REJECT"]);
        assert([node(addresses, nil, @"::ffff:10.10.10.10", nil, 0, 443) isEqual:@"REJECT"]);
        assert([node(addresses, nil, @"10.128.0.0", nil, 0, 443) isEqual:@"DIRECT"]);
        assert([node(addresses, nil, @"2001:db8:7fff::f", nil, 0, 443) isEqual:@"REJECT"]);
        assert([node(addresses, nil, @"2001:db8:8000::", nil, 0, 443) isEqual:@"DIRECT"]);
        assert([node(addresses, @"test", nil, @"192.0.2.2", 0, 443) isEqual:@"REJECT"]);
        assert([node(addresses, @"test", nil, @"2001:db8:1::f", 0, 443) isEqual:@"REJECT"]);
        NSDictionary *ports = document(@"rules:\n"
                                         @"- 'SRC-PORT,125/200-210,REJECT'\n"
                                         @"- 'DST-PORT,81/8080-8088,REJECT'\n"
                                         @"- 'NETWORK,TcP,DIRECT'\n"
                                         @"- 'MATCH,REJECT'\n");
        assert([node(ports, @"test", nil, nil, 210, 443) isEqual:@"REJECT"]);
        assert([node(ports, @"test", nil, nil, 211, 443) isEqual:@"DIRECT"]);
        assert([node(ports, @"test", nil, nil, 0, 8088) isEqual:@"REJECT"]);
        assert([node(ports, @"test", nil, nil, 0, 8089) isEqual:@"DIRECT"]);
        assert([MLRoute(ports, @"Rule", nil, @"test", nil, nil, 0, 443, @"TCP")[@"rule"] isEqual:@"NETWORK,TcP,DIRECT"]);

        NSDictionary *lazy = document(@"rules:\n"
                                        @"- 'DOMAIN,early.test,REJECT'\n"
                                        @"- 'IP-CIDR,192.0.2.0/24,REJECT,no-resolve'\n"
                                        @"- 'IP-CIDR,10.0.0.0/8,DIRECT'\n"
                                        @"- 'IP-CIDR,192.0.2.0/24,DIRECT,no-resolve'\n"
                                        @"- 'IP-CIDR,::/0,DIRECT'\n"
                                        @"- 'MATCH,REJECT'\n");
        __block NSUInteger calls = 0;
        NSString *(^resolver)(void) = ^NSString *{ calls++; return @"192.0.2.1"; };
        assert([MLRouteWithResolver(lazy, @"Rule", nil, @"early.test", nil, nil, 0, 443, @"tcp", resolver)[@"node"] isEqual:@"REJECT"]);
        assert(calls == 0);
        NSDictionary *resolved = MLRouteWithResolver(lazy, @"Rule", nil, @"test", nil, nil, 0, 443, @"tcp", resolver);
        assert([resolved[@"rule"] isEqual:@"IP-CIDR,192.0.2.0/24,DIRECT,no-resolve"]);
        assert([resolved[@"ip"] isEqual:@"192.0.2.1"] && calls == 1);
        assert([MLRouteWithResolver(lazy, @"Rule", nil, @"test", nil, nil, 0, 443, @"tcp", ^NSString *{ calls++; return nil; })[@"node"] isEqual:@"REJECT"]);
        assert(calls == 2);

        NSDictionary *groups = document(@"proxy-groups:\n"
                                          @"- {name: Outer, type: select, proxies: [Inner, DIRECT]}\n"
                                          @"- {name: Inner, type: select, proxies: [DIRECT, REJECT], default-selected: REJECT}\n"
                                          @"rules: ['MATCH,Outer']\n");
        assert([node(groups, @"test", nil, nil, 0, 443) isEqual:@"REJECT"]);
        NSDictionary *selection = @{@"Inner":@"DIRECT", @"Outer":@"old-choice", @"GLOBAL":@"Outer"};
        NSDictionary *global = MLRoute(groups, @"Global", selection, @"test", nil, nil, 0, 443, @"tcp");
        assert([global[@"group"] isEqual:@"GLOBAL"] && [global[@"node"] isEqual:@"DIRECT"]);
        assert([MLRoute(groups, @"Direct", nil, @"test", nil, nil, 0, 443, @"tcp")[@"node"] isEqual:@"DIRECT"]);
        assert(MLCanSelect(groups, @"Outer", @"Inner") && !MLCanSelect(groups, @"Outer", @"REJECT"));
        assert(!MLCanSelect(groups, @"missing", @"DIRECT"));
        NSDictionary *outer = MLGroups(groups, selection)[0];
        assert([outer[@"selected"] isEqual:@"Inner"] && [outer[@"actual"] isEqual:@"DIRECT"]);
        NSArray *members = MLProxies(groups, selection, @"Outer");
        assert(members.count == 2 && [members[0][@"type"] isEqual:@"group"] && [members[0][@"selected"] boolValue]);
        assert([MLProxies(groups, nil, @"GLOBAL")[0][@"name"] isEqual:@"DIRECT"]);
        assert([MLRoute(groups, @"Global", nil, @"test", nil, nil, 0, 443, @"tcp")[@"node"] isEqual:@"DIRECT"]);

        NSDictionary *explicitGlobal = document(@"proxy-groups: [{name: GLOBAL, type: select, proxies: [REJECT, DIRECT]}]");
        assert([MLRoute(explicitGlobal, @"Global", nil, @"test", nil, nil, 0, 443, @"tcp")[@"node"] isEqual:@"REJECT"]);
        assert([MLRoute(explicitGlobal, @"Rule", nil, @"test", nil, nil, 0, 443, @"tcp")[@"node"] isEqual:@"DIRECT"]);
        assert(MLGroups(explicitGlobal, nil).count == 1);
        puts("PASS routing: ordered rules, address families, DNS timing, nested selectors and modes");
    }
    return 0;
}
