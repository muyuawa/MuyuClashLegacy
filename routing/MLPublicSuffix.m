#import "MLPublicSuffix.h"
#include <dispatch/dispatch.h>
NSString *MLEffectiveDomain(NSString *host) {
    if (![host isKindOfClass:[NSString class]] || !host.length || host.length > 253) return nil;
    static NSSet *rules;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        const char *text =
#include "MLPublicSuffixData.inc"
        ;
        rules = [NSSet setWithArray:[[NSString stringWithUTF8String:text] componentsSeparatedByString:@"\n"]];
    });
    NSString *domain = [host lowercaseString];
    if ([domain hasSuffix:@"."]) domain = [domain substringToIndex:domain.length-1];
    NSArray *parts = [domain componentsSeparatedByString:@"."];
    if (parts.count < 2 || [parts containsObject:@""]) return nil;
    NSUInteger suffix = 1;
    for (NSUInteger i = 0; i < parts.count; ++i) {
        NSString *candidate = [[parts subarrayWithRange:NSMakeRange(i,parts.count-i)] componentsJoinedByString:@"."];
        if ([rules containsObject:[@"!" stringByAppendingString:candidate]]) { suffix = parts.count-i-1; break; }
        if ([rules containsObject:candidate]) suffix = MAX(suffix,parts.count-i);
        if (i > 0 && [rules containsObject:[@"*." stringByAppendingString:candidate]]) suffix = MAX(suffix,parts.count-i+1);
    }
    if (parts.count <= suffix) return nil;
    return [[parts subarrayWithRange:NSMakeRange(parts.count-suffix-1,suffix+1)] componentsJoinedByString:@"."];
}
