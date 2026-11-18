#import "../providers/MLDomainProviderIndex.h"
#include <assert.h>
#include <CommonCrypto/CommonDigest.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static NSDictionary *writeIndex(NSData *compiled, NSString *path) {
    assert([compiled writeToFile:path atomically:YES]);
    assert(chmod(path.fileSystemRepresentation, 0444) == 0);
    uint8_t bytes[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(compiled.bytes, (CC_LONG)compiled.length, bytes);
    NSMutableString *hash = [NSMutableString string];
    for (size_t i = 0; i < sizeof bytes; i++) [hash appendFormat:@"%02x", bytes[i]];
    return @{@"path":path, @"size":@(compiled.length), @"owner":@(getuid()), @"sha256":hash};
}

static void checkPatterns(NSString *path) {
    NSString *yaml = @"# list\npayload:\n  - 'Exact.test' # notation\n  - \"+.suffix.test\"\n"
        @"  - .desc.test\n  - '*.star.test'\n  - 'ab*cd.match.test'\n  - '+.*.mixed.test'\n"
        @"  - '+.münchen.test'\n  - EXACT.TEST\n  - merge.test\n  - .merge.test\n  - 'star.*'\n";
    NSError *error = nil;
    NSUInteger count = 0;
    NSData *compiled = MLDomainProviderCompile([yaml dataUsingEncoding:NSUTF8StringEncoding], @"yaml", &count, &error);
    assert(compiled && !error && count == 11);
    NSDictionary *descriptor = writeIndex(compiled, path);
    MLDomainProviderIndex *index = [MLDomainProviderIndex indexWithDescriptor:descriptor error:&error];
    if (!index) fprintf(stderr, "%s\n", error.localizedDescription.UTF8String);
    assert(index && !error && index.count == 11);
    for (NSString *host in @[@"EXACT.test.", @"suffix.test", @"x.y.suffix.test", @"x.desc.test", @"x.y.desc.test",
                             @"one.star.test", @"abcd.match.test", @"ab000cd.match.test", @"x.mixed.test", @"deep.x.mixed.test",
                             @"MÜNCHEN.TEST", @"xx.münchen.test", @"merge.test", @"x.merge.test", @"star.example", @"star.test."])
        assert([index matchesHost:host]);
    for (NSString *host in @[@"x.exact.test", @"suffix.test.fake", @"badsuffix.test", @"desc.test", @"x..desc.test",
                             @"two.one.star.test", @"ab0.cd.match.test", @"mixed.test", @"star",
                             @"other.star.example"])
        assert(![index matchesHost:host]);
    NSMutableDictionary *invalid = [descriptor mutableCopy];
    invalid[@"sha256"] = [@"0" stringByPaddingToLength:64 withString:@"0" startingAtIndex:0];
    assert(![MLDomainProviderIndex indexWithDescriptor:invalid error:&error] && error);
    assert(chmod(path.fileSystemRepresentation, 0644) == 0);
    assert(![MLDomainProviderIndex indexWithDescriptor:descriptor error:&error] && error);
    NSMutableData *corrupt = [compiled mutableCopy];
    ((uint8_t *)corrupt.mutableBytes)[0] = 'x';
    assert(![MLDomainProviderIndex indexWithDescriptor:writeIndex(corrupt, path) error:&error] && error);
}

static void checkBadInput(void) {
    for (NSString *source in @[@"payload: wrong", @"payload: [example.test, [nested.test]]", @"payload: [&x example.test, *x]",
                               @"payload: [!!str example.test]", @"payload: [example.test]\n---\npayload: []", @"payload: [example.test]\npayload: []",
                               @"payload: ['+.', 'x....test']", @"payload: ['x/y.test']", @"payload: ['x y.test']", @"payload: [\"foo\\0.test\"]"]) {
        NSUInteger count = 99;
        NSError *error = nil;
        assert(!MLDomainProviderCompile([source dataUsingEncoding:NSUTF8StringEncoding], @"yaml", &count, &error));
        assert(count == 0 && error);
    }
}

static void checkText(NSString *path) {
    static const char text[] = "\xef\xbb\xbf# comment\r\n// comment\n\n exact.test \r\n\t+.text.test\t\r\n";
    NSUInteger count = 0;
    NSData *compiled = MLDomainProviderCompile([NSData dataWithBytes:text length:sizeof text - 1], @"text", &count, NULL);
    assert(compiled && count == 2);
    MLDomainProviderIndex *index = [MLDomainProviderIndex indexWithDescriptor:writeIndex(compiled, path) error:NULL];
    assert(index && [index matchesHost:@"exact.test"] && [index matchesHost:@"x.text.test"] && ![index matchesHost:@"a.exact.test"]);
}

static void checkLargeProvider(NSString *path) {
    static const char prefix[] = "payload:\n";
    NSMutableData *source = [NSMutableData dataWithBytes:prefix length:sizeof prefix - 1];
    for (int i = 199999; i >= 0; i--) {
        char row[64];
        int length = snprintf(row, sizeof row, "  - '+.host-%06d.provider.test'\n", i);
        [source appendBytes:row length:(NSUInteger)length];
    }
    assert(source.length > 5 * 1024 * 1024);
    NSUInteger count = 0;
    NSData *compiled = MLDomainProviderCompile(source, @"yaml", &count, NULL);
    assert(compiled && count == 200000 && compiled.length <= MLDomainProviderIndexLimit);
    MLDomainProviderIndex *index = [MLDomainProviderIndex indexWithDescriptor:writeIndex(compiled, path) error:NULL];
    assert(index && index.count == 200000);
    assert([index matchesHost:@"host-000000.provider.test"]);
    assert([index matchesHost:@"child.host-199999.provider.test"]);
    assert(![index matchesHost:@"host-200000.provider.test"]);
    printf("PASS 200000 patterns (%lu YAML bytes, %lu mapped bytes)\n", (unsigned long)source.length, (unsigned long)compiled.length);
}

int main(void) { @autoreleasepool {
    char root[PATH_MAX];
    assert(realpath(NSTemporaryDirectory().fileSystemRepresentation, root));
    NSString *directory = [[NSString stringWithUTF8String:root] stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    NSFileManager *files = [NSFileManager defaultManager];
    assert([files createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:@{@"NSFilePosixPermissions":@0700} error:NULL]);
    NSString *path = [directory stringByAppendingPathComponent:@"domain.index"];
    checkPatterns(path);
    checkBadInput();
    checkText(path);
    checkLargeProvider(path);
    assert([files removeItemAtPath:directory error:NULL]);
    puts("PASS domain Provider normalization, matching and descriptor verification");
    return 0;
} }
