#import "MLCapture.h"
#include <string.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        BOOL open = argc == 2 && strcmp(argv[1], "--open") == 0;
        if (argc != 1 && !open) {
            fputs("usage: muyu-capture-probe [--open]\n", stderr);
            return 64;
        }
        NSDictionary *report = open ? MLCaptureUTunLifecycleProbe() : MLCaptureProbe();
        NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:NULL];
        if (!data || fwrite(data.bytes, 1, data.length, stdout) != data.length || putchar('\n') == EOF) return 1;
        return open && ![report[@"detached"] boolValue] ? 1 : 0;
    }
}
