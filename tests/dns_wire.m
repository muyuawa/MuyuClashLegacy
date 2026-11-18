#import <Foundation/Foundation.h>
#import "../dns/MLDNSWire.h"
#import "../transport/MLNetworkBinding.h"
#include <arpa/inet.h>
#include <net/if.h>
int main(int argc, char **argv) { @autoreleasepool {
    if (argc != 6 && argc != 7) return 64;
    struct sockaddr_in endpoint = {0};
    endpoint.sin_family = AF_INET;
    endpoint.sin_len = sizeof(endpoint);
    endpoint.sin_port = htons((uint16_t)atoi(argv[2]));
    inet_pton(AF_INET,"127.0.0.1", &endpoint.sin_addr);
    unsigned char question[] = {0x12,0x34,1,0,0,1,0,0,0,0,0,0,5,'b','o','u','n','d',4,'t','e','s','t',0,0,1,0,1};
    if (argc == 7) MLNetworkSetInterfaceIndex(if_nametoindex(argv[6]));
    NSData *reply = MLDNSWireQuery([NSData dataWithBytes:question length:sizeof(question)],
        (struct sockaddr *)&endpoint, sizeof(endpoint), strcmp(argv[1],"udp") != 0,
        strcmp(argv[1],"tls") == 0, [NSString stringWithUTF8String:argv[3]],
        [NSString stringWithUTF8String:argv[4]], (unsigned)atoi(argv[5]));
    if (!reply) return 1;
    fwrite(reply.bytes,1,reply.length,stdout);
    return 0;
}}
