#import "MLIPC.h"
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/un.h>
#include <stdlib.h>
#include <dispatch/dispatch.h>

int main(void) { @autoreleasepool {
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    MLIPCSetTimeout(pair[0], 1); MLIPCSetTimeout(pair[1], 1);
    NSDictionary *request = @{ @"version":@1, @"id":@"r1", @"method":@"service.status", @"params":@{} };
    NSError *error = nil;
    assert(MLIPCValidRequest(request));
    assert(!MLIPCValidRequest(@{@"version":@2,@"id":@"x",@"method":@"service.start",@"params":@{}}));
    assert(!MLIPCValidRequest(@{@"version":@1,@"id":@3,@"method":@"service.start",@"params":@{}}));
    assert(!MLIPCValidRequest(@{@"version":@1,@"id":@"x",@"method":@"service.start",@"params":@[]}));
    assert(MLIPCWriteFrame(pair[0], request, &error));
    assert([MLIPCReadFrame(pair[1], &error) isEqual:request]);
    assert(MLIPCPeerAllowed(pair[0], getuid()));
    assert(!MLIPCPeerAllowed(pair[0], (uid_t)123456));
    uint32_t oversize = htonl(1024*1024+1);
    assert(write(pair[0], &oversize, 4) == 4);
    assert(MLIPCReadFrame(pair[1], &error) == nil && error);
    close(pair[0]); close(pair[1]);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    uint32_t truncated = htonl(20);
    assert(write(pair[0], &truncated, 4) == 4); close(pair[0]);
    error = nil;
    assert(MLIPCReadFrame(pair[1], &error) == nil && error);
    close(pair[1]);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    NSMutableString *huge = [NSMutableString string];
    for (int i = 0; i < 1024 * 1024 + 1; i++) [huge appendString:@"x"];
    assert(MLIPCWriteReply(pair[0], request, MLIPCResponse(request, @{@"data":huge}, nil, nil)));
    NSDictionary *bounded = MLIPCReadFrame(pair[1], &error);
    assert([bounded[@"error"][@"code"] isEqual:@"E_RESPONSE_SIZE"]);
    close(pair[0]); close(pair[1]);
    NSDictionary *response = MLIPCResponse(request, nil, @"E_CAPTURE_UNVERIFIED", @"capture unavailable");
    assert([response[@"id"] isEqual:@"r1"]);
    assert([response[@"error"][@"code"] isEqual:@"E_CAPTURE_UNVERIFIED"]);
    char directory[]="/private/tmp/mlipc-XXXXXX";assert(mkdtemp(directory));
    NSString *path=[[NSString stringWithUTF8String:directory] stringByAppendingPathComponent:@"control.sock"];
    int listener=socket(AF_UNIX,SOCK_STREAM,0);assert(listener>=0);
    struct sockaddr_un address={0};address.sun_family=AF_UNIX;strlcpy(address.sun_path,path.fileSystemRepresentation,sizeof(address.sun_path));
    assert(!bind(listener,(struct sockaddr *)&address,sizeof(address))&&!listen(listener,2));
    dispatch_group_t delayed=dispatch_group_create();
    dispatch_group_async(delayed,dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{@autoreleasepool{
        for(unsigned i=0;i<2;i++) {
            int client=accept(listener,NULL,NULL);assert(client>=0);MLIPCSetTimeout(client,1);
            NSDictionary *incoming=MLIPCReadFrame(client,NULL);
            if(incoming){usleep(100000);assert(MLIPCWriteFrame(client,MLIPCResponse(incoming,@{@"delayed":@YES},nil,nil),NULL));}
            close(client);
        }
    }});
    assert([MLIPCRequestWithOwner(path,getuid(),@"service.status",@{},NULL)[@"delayed"] boolValue]);
    error=nil;assert(!MLIPCRequestWithOwner(path,(uid_t)123456,@"service.status",@{},&error)&&error.code==EACCES);
    assert(!dispatch_group_wait(delayed,dispatch_time(DISPATCH_TIME_NOW,3*NSEC_PER_SEC)));
    close(listener);unlink(path.fileSystemRepresentation);rmdir(directory);
    puts("PASS IPC: framing, schema, peer identity, oversized/truncated input");
} return 0; }
