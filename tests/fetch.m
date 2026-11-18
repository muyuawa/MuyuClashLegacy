#import <Foundation/Foundation.h>
#import "MLFetch.h"
int main(int argc,const char *argv[]) { @autoreleasepool {
    if(argc != 3) return 64;
    NSString *ca = [NSString stringWithUTF8String:argv[2]];
    NSError *error = nil;
    NSString *text = MLFetchSubscription([NSString stringWithUTF8String:argv[1]], [ca isEqual:@"-"] ? nil : ca, &error);
    if (!text) { fputs("fetch-rejected\n",stderr); return 1; }
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    fwrite(data.bytes,1,data.length,stdout); return 0;
}}
