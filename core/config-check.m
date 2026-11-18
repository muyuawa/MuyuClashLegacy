#import <Foundation/Foundation.h>
#import "MLConfig.h"
int main(int argc, const char *argv[]) { @autoreleasepool {
    if (argc != 2) { fputs("usage: muyu-config-check CONFIG.yaml\n",stderr); return 64; }
    NSError *error = nil;
    NSString *yaml = [NSString stringWithContentsOfFile:[NSString stringWithUTF8String:argv[1]] encoding:NSUTF8StringEncoding error:&error];
    if (!yaml) { fputs("Cannot read UTF-8 configuration.\n",stderr); return 66; }
    NSDictionary *report = [MLConfig checkYAML:yaml];
    // A diagnostic report excludes the parsed document containing secrets.
    NSMutableDictionary *publicReport = [report mutableCopy]; [publicReport removeObjectForKey:@"document"];
    NSData *data = [NSJSONSerialization dataWithJSONObject:publicReport options:NSJSONWritingPrettyPrinted error:NULL];
    fwrite(data.bytes,1,data.length,stdout); putchar('\n');
    return [report[@"valid"] boolValue] ? 0 : 2;
}}
