#import <Foundation/Foundation.h>
#import "MLStream.h"

uint64_t MLMilliseconds(void);
BOOL MLInboundReply(int fd, BOOL http, uint8_t status);
NSString *MLInboundDestination(int fd, uint16_t *port, NSString **ip, BOOL *http);
void MLRelay(int client, MLStream *stream, void (^record)(size_t up, size_t down));
