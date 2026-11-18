#import "MLIPC.h"
int main(int argc, const char *argv[]) { @autoreleasepool {
    if (argc < 3 || argc > 4) { fputs("usage: muyu-cli SOCKET METHOD [PARAMS_JSON]\n",stderr); return 64; }
    NSError *error = nil;
    NSDictionary *params = @{};
    if (argc == 4) {
        NSData *data = [[NSString stringWithUTF8String:argv[3]] dataUsingEncoding:NSUTF8StringEncoding];
        id value = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
        if (![value isKindOfClass:[NSDictionary class]]) { fputs("PARAMS_JSON must be an object\n",stderr); return 64; }
        params = value;
    }
    NSDictionary *result = MLIPCRequest([NSString stringWithUTF8String:argv[1]],[NSString stringWithUTF8String:argv[2]],params,&error);
    if (!result) { fprintf(stderr,"%s\n",error.localizedDescription.UTF8String ?: "IPC failed"); return 1; }
    NSData *data = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:&error];
    fwrite(data.bytes,1,data.length,stdout); putchar('\n');
    return 0;
}}
