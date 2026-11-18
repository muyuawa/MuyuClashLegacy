#import "MLService.h"
#import "MLConfig.h"
#import "MLConfigStore.h"
#import "MLFetch.h"
#import "MLCapture.h"
#import "MLCoreProcess.h"
#import "MLRouting.h"
#import "MLDNS.h"
#import "MLNodeImport.h"
#import "MLCaptureCoordinator.h"
#import "MLProviderManager.h"
#import "MLGeoDataManager.h"
#import "MLProcessOwner.h"
#import "MLFakeIP.h"
#include <arpa/inet.h>
#import "../transport/MLNetworkBinding.h"
#include <TargetConditionals.h>
#include <dispatch/dispatch.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static BOOL MLFail(NSError **error, NSString *code, NSString *message) {
    if (error) *error = [NSError errorWithDomain:code code:1 userInfo:@{NSLocalizedDescriptionKey:message}];
    return NO;
}
static NSString *MLString(id value) { return [value isKindOfClass:[NSString class]] ? value : nil; }

static BOOL MLWriteSettings(NSString *path, NSDictionary *values, NSError **error) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:values options:0 error:error];
    if (!data) return NO;
    struct stat status;
    if (lstat(path.fileSystemRepresentation, &status) == 0 && (!S_ISREG(status.st_mode) || status.st_nlink != 1))
        return MLFail(error,@"E_STORAGE",@"设置文件不是安全的普通文件");
    NSString *temporary = [path stringByAppendingString:@".XXXXXX"];
    char *template = strdup(temporary.fileSystemRepresentation);
    int fd = mkstemp(template);
    if (fd < 0) { free(template); return MLFail(error,@"E_STORAGE",@"无法创建设置临时文件"); }
    BOOL ok = fchmod(fd, 0600) == 0;
    size_t offset = 0;
    while (ok && offset < data.length) {
        ssize_t count = write(fd, (const char *)data.bytes + offset, data.length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = NO; break; }
        offset += (size_t)count;
    }
    if (ok) ok = fsync(fd) == 0;
    close(fd);
    if (ok) ok = rename(template, path.fileSystemRepresentation) == 0;
    if (!ok) unlink(template);
    free(template);
    if (!ok) return MLFail(error,@"E_STORAGE",@"设置写入失败，保留原设置");
    int parent = open(path.stringByDeletingLastPathComponent.fileSystemRepresentation, O_RDONLY);
    if(parent<0)return MLFail(error,@"E_STORAGE",@"无法确认设置目录持久化");
    ok=fsync(parent)==0;close(parent);
    if(!ok)return MLFail(error,@"E_STORAGE",@"设置目录持久化失败，未确认写入");
    return YES;
}

@interface MLService ()
@property(nonatomic,strong) MLConfigStore *store;
@property(nonatomic,copy) NSString *caPath;
@property(nonatomic,copy) NSString *settingsPath;
@property(nonatomic,strong) NSMutableDictionary *settings;
@property(nonatomic,strong) NSMutableArray *logs;
@property(nonatomic,strong) NSLock *fetchLock;
@property(nonatomic,strong) NSLock *dnsLock;
@property(nonatomic,copy) NSString *state;
@property(nonatomic,copy) NSString *statusMessage;
@property(nonatomic,strong) MLCoreProcess *core;
@property(nonatomic,strong) NSDictionary *document;
@property(nonatomic,strong) NSError *configurationError;
@property(nonatomic,strong) NSMutableDictionary *selections;
@property(nonatomic,copy) NSString *configName;
@property(nonatomic,copy) NSString *mode;
@property(nonatomic) BOOL wantsRunning;
@property(nonatomic) double retryAt;
@property(nonatomic) double coreStartedAt;
@property(nonatomic) NSUInteger retries;
@property(nonatomic,copy) NSString *directory;
@property(nonatomic,strong) MLCaptureCoordinator *capture;
@property(nonatomic,strong) MLProviderManager *providers;
@property(nonatomic,strong) MLGeoDataManager *geo;
@property(nonatomic,strong) MLDNS *outboundDNS;
@property(nonatomic,strong) NSMutableDictionary *jobs;
@property(nonatomic,copy) NSString *pendingJob;
@property(nonatomic,strong) NSDictionary *sourceDocument;
@property(nonatomic,strong) MLProcessOwner *processOwner;
@property(nonatomic,strong) NSLock *ownerLock;
@property(nonatomic,strong) NSLock *fakeLock;
@property(nonatomic,copy) NSString *fakeStatePath;
@property(nonatomic,copy) NSString *fakeToken;
@property(nonatomic,strong) NSArray *fakeStates;
@property(nonatomic) BOOL fakeStateDamaged;
@end

static BOOL MLValidFakeSnapshot(NSDictionary *snapshot) {
    if(![snapshot isKindOfClass:[NSDictionary class]])return NO;
    id v6=snapshot[@"ipv6Range"];
    MLFakeIP *pool=[[MLFakeIP alloc]initWithRange:MLString(snapshot[@"range"]) ipv6Range:[v6 isKindOfClass:[NSString class]]?v6:nil capacity:512];
    return pool&&[pool restoreSnapshot:snapshot error:NULL];
}
static NSString *MLFakeIdentity(NSDictionary *snapshot) {
    return [NSString stringWithFormat:@"%@|%@",snapshot[@"range"],snapshot[@"ipv6Range"]];
}
static BOOL MLFakeSnapshotsOverlap(NSDictionary *a,NSDictionary *b) {
    MLFakeIP *first=[[MLFakeIP alloc]initWithRange:a[@"range"] ipv6Range:MLString(a[@"ipv6Range"]) capacity:512];
    MLFakeIP *second=[[MLFakeIP alloc]initWithRange:b[@"range"] ipv6Range:MLString(b[@"ipv6Range"]) capacity:512];
    for(NSString *key in @[@"range",@"ipv6Range"]) {
        NSString *left=[MLString(a[key]) componentsSeparatedByString:@"/"][0];
        NSString *right=[MLString(b[key]) componentsSeparatedByString:@"/"][0];
        if((right&&[first containsAddress:right])||(left&&[second containsAddress:left]))return YES;
    }
    return NO;
}
static NSString *MLFakeToken(void) {
    unsigned char bytes[32];char hex[65];arc4random_buf(bytes,sizeof(bytes));
    for(unsigned i=0;i<sizeof(bytes);i++)sprintf(hex+i*2,"%02x",bytes[i]);hex[64]=0;
    return [NSString stringWithUTF8String:hex];
}
static size_t MLServiceBootstrap(const char *host,char addresses[][46],size_t capacity,void *context);
@implementation MLService
@synthesize coreExecutable = _coreExecutable;
- (id)initWithDirectory:(NSString *)directory caPath:(NSString *)caPath error:(NSError **)error {
    if (!(self = [super init])) return nil;
    _store = [[MLConfigStore alloc] initWithDirectory:directory error:error];
    if (!_store) return nil;
    _directory=[directory copy];
    NSString *geoReadable=[directory.stringByDeletingLastPathComponent stringByAppendingPathComponent:@"geo-readable"];
#if TARGET_OS_IPHONE
    if([directory isEqual:@"/private/var/lib/muyuclash"])geoReadable=@"/private/var/db/muyuclash-geodata";
#endif
    _geo=[[MLGeoDataManager alloc]initWithDirectory:[directory stringByAppendingPathComponent:@"geo"] readableDirectory:geoReadable caPath:caPath error:error];
    if(!_geo)return nil;
    _providers=[[MLProviderManager alloc]initWithDirectory:[directory stringByAppendingPathComponent:@"providers"]
        readableDirectory:[geoReadable stringByAppendingPathComponent:@"providers"] caPath:caPath error:error];
    if(!_providers)return nil;
    _jobs=[NSMutableDictionary dictionary];
    _processOwner=[[MLProcessOwner alloc]initWithBudgetMilliseconds:75];_ownerLock=[NSLock new];
    _fakeLock=[NSLock new];_fakeStates=@[];_fakeStatePath=[directory stringByAppendingPathComponent:@"fake-ip.json"];
    struct stat fakeStatus;
    if(!lstat(_fakeStatePath.fileSystemRepresentation,&fakeStatus)) {
        BOOL safe=S_ISREG(fakeStatus.st_mode)&&fakeStatus.st_nlink==1&&fakeStatus.st_uid==geteuid()&&!(fakeStatus.st_mode&0077)&&fakeStatus.st_size<=512*1024;
        NSData *data=safe?[NSData dataWithContentsOfFile:_fakeStatePath]:nil;
        NSDictionary *saved=data?[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL]:nil;
        if([saved[@"version"] isEqual:@1]&&[saved[@"pools"] isKindOfClass:[NSArray class]]&&[saved[@"pools"] count]<=2) {
            BOOL valid=YES;for(NSDictionary *snapshot in saved[@"pools"])if(!MLValidFakeSnapshot(snapshot))valid=NO;
            NSArray *pools=saved[@"pools"];
            if(pools.count==2&&MLFakeSnapshotsOverlap(pools[0],pools[1]))valid=NO;
            if(valid)_fakeStates=pools;else _fakeStateDamaged=YES;
        } else _fakeStateDamaged=YES;
    } else if(errno!=ENOENT)_fakeStateDamaged=YES;
    _caPath = [caPath copy];
    _settingsPath = [directory stringByAppendingPathComponent:@"settings.json"];
    _settings = [@{@"autoStart":@NO,@"autoReconnect":@NO,@"background":@NO,@"mode":@"Rule",@"captureBackend":@"unverified",@"protectionMode":@"restore",@"dnsMode":@"follow-config",@"logLevel":@"info",@"maxProbeConcurrency":@3,@"theme":@"light",@"language":@"zh-Hans",@"schemaVersion":@2} mutableCopy];
#if TARGET_OS_IPHONE
    _settings[@"captureBackend"]=@"utun";
#endif
    struct stat status;
    if (lstat(_settingsPath.fileSystemRepresentation, &status) == 0) {
        if (!S_ISREG(status.st_mode) || status.st_nlink != 1 || status.st_uid != geteuid() || (status.st_mode & 0077) || status.st_size > 16384) {
            MLFail(error,@"E_STORAGE",@"设置文件权限或大小不安全"); return nil;
        }
        NSData *data = [NSData dataWithContentsOfFile:_settingsPath];
        NSDictionary *values = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:error] : nil;
        if (![values isKindOfClass:[NSDictionary class]]) { MLFail(error,@"E_STORAGE",@"设置文件损坏"); return nil; }
#if TARGET_OS_IPHONE
        BOOL legacy=[values[@"schemaVersion"] integerValue]<2;
#else
        BOOL legacy=NO;
#endif
        for (NSString *key in @[@"logLevel",@"maxProbeConcurrency",@"theme",@"language",@"autoStart",@"autoReconnect",@"captureBackend",@"protectionMode",@"dnsMode"]) {
            id value = values[key];
            if(legacy&&[key isEqual:@"captureBackend"]&&[value isEqual:@"unverified"])continue;
            if (value && [self validateSetting:key value:value error:NULL]) _settings[key] = value;
        }
    }
    _logs = [NSMutableArray array]; _fetchLock = [[NSLock alloc] init]; _dnsLock = [NSLock new]; _state = @"STOPPED"; _statusMessage = @"未连接";
    _core = [MLCoreProcess new];
    _selections = [NSMutableDictionary dictionary];
    _mode = @"Rule";
    [self log:@"info" message:@"Supervisor 已启动"];
    NSString *active = [_store activeID];
    if (active) {
        NSError *restoreError=nil;
        NSDictionary *source = [_store sourceForID:active error:&restoreError];
        if (source) {
            NSDictionary *report = [MLConfig checkYAML:source[@"yaml"]];
            if ([report[@"valid"] boolValue]) {
                _sourceDocument=report[@"document"];
                NSDictionary *expanded=[_providers prepareDocument:_sourceDocument refreshNames:[NSSet set] error:&restoreError];
                NSDictionary *geoPrepared=expanded?[_geo prepareDocument:expanded fetch:NO refresh:NO error:&restoreError]:nil;
                if(geoPrepared&&[[MLConfig checkPreparedDocument:geoPrepared][@"valid"] boolValue]) {
                    id providersBefore=[_providers captureCheckpoint],geoBefore=[_geo captureCheckpoint];
                    if([_providers commitPreparedDocument:expanded error:&restoreError]&&[_geo commitPreparedDocument:geoPrepared error:&restoreError])_document=geoPrepared;
                    else {[_providers restoreCheckpoint:providersBefore error:NULL];[_geo restoreCheckpoint:geoBefore error:NULL];}
                }
                _configName = source[@"name"];
                _mode = [self configurationMode:_document];
                _selections = [self savedSelections:active document:_document];
            }
        }
        if (!_document) {
            [_providers discardPreparedDocument]; [_geo discardPreparedDocument];
            _configurationError=restoreError ?: [NSError errorWithDomain:@"E_CONFIG_RESTORE" code:1 userInfo:@{NSLocalizedDescriptionKey:@"保存的配置未能通过恢复检查"}];
            _state=@"FAILED"; _statusMessage=[@"配置恢复失败：" stringByAppendingString:_configurationError.localizedDescription];
            [self log:@"error" message:_statusMessage];
        } else _statusMessage=@"配置已就绪，未连接";
    }
    MLNetworkSetBootstrapResolver(MLServiceBootstrap,(__bridge void *)self);
    return self;
}
- (void)dealloc { MLNetworkSetBootstrapResolver(NULL,NULL);MLNetworkSetInterfaceIndex(0); }
- (NSDictionary *)runtimeParameters {
    NSArray *servers=self.capture.status[@"physicalPath"][@"DNSServerAddresses"] ?: @[];
    self.outboundDNS=[[MLDNS alloc]initWithOptions:self.document[@"dns"] ipv6:[self.document[@"ipv6"] boolValue]];
    if(self.document)[self.outboundDNS installPreparedDocument:self.document error:NULL];
    self.outboundDNS.bootstrapServers=servers;self.outboundDNS.caPath=self.caPath;
    NSMutableDictionary *hosts=[self.outboundDNS.hosts mutableCopy] ?: [NSMutableDictionary dictionary];
    for(NSString *name in self.document[@"hosts"]) hosts[name.lowercaseString]=self.document[@"hosts"][name];
    self.outboundDNS.hosts=hosts;
    return @{@"caPath":self.caPath ?: @"",@"bootstrapServers":servers,@"ownerSocket":self.controlSocket ?: @"",@"ownerUID":@(geteuid()),@"fakeToken":self.fakeToken ?: @"",@"dnsMode":self.settings[@"dnsMode"] ?: @"follow-config"};
}
- (void)log:(NSString *)level message:(NSString *)message {
    // Only controlled messages are logged. Never record request payloads, URLs,
    // imported YAML, passwords, or raw third-party exception descriptions.
    NSArray *levels = @[@"debug",@"info",@"warning",@"error",@"silent"];
    NSString *effective = self.document[@"log-level"] ?: self.settings[@"logLevel"];
    NSUInteger threshold = [levels indexOfObject:effective];
    if (threshold == NSNotFound) threshold = 1;
    if ([levels indexOfObject:level] < threshold) return;
    [self.logs addObject:@{@"id":[[NSProcessInfo processInfo] globallyUniqueString],@"time":@([[NSDate date] timeIntervalSince1970]),@"level":level,@"category":@"supervisor",@"message":message}];
    while (self.logs.count > 256) [self.logs removeObjectAtIndex:0];
}
- (BOOL)validateSetting:(NSString *)key value:(id)value error:(NSError **)error {
    BOOL allowed = NO;
    if ([key isEqual:@"logLevel"]) allowed = [@[@"debug",@"info",@"warning",@"error"] containsObject:value ?: [NSNull null]];
    else if ([key isEqual:@"maxProbeConcurrency"]) allowed = [value isKindOfClass:[NSNumber class]] && [value doubleValue] == [value integerValue] && [value integerValue] >= 1 && [value integerValue] <= 3;
    else if ([key isEqual:@"autoStart"] || [key isEqual:@"autoReconnect"])
        allowed = [value isKindOfClass:[NSNumber class]] && CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID();
    else if ([key isEqual:@"theme"]) allowed = [value isEqual:@"light"];
    else if ([key isEqual:@"language"]) allowed = [value isEqual:@"zh-Hans"];
    else if([key isEqual:@"captureBackend"]) allowed=[value isEqual:@"unverified"]||(TARGET_OS_IPHONE&&[value isEqual:@"utun"]);
    else if([key isEqual:@"protectionMode"]) allowed=[value isEqual:@"restore"]||(TARGET_OS_IPHONE&&[value isEqual:@"strict"]);
    else if([key isEqual:@"dnsMode"]) allowed=[@[@"follow-config",@"redir-host",@"fake-ip"] containsObject:value ?: @""]&&(![value isEqual:@"fake-ip"]||[self.settings[@"captureBackend"] isEqual:@"utun"]);
    else return MLFail(error,@"E_UNAVAILABLE",@"此设置依赖尚未集成并验证的核心或网络后端，未应用修改");
    return allowed || MLFail(error,@"E_SETTING_VALUE",@"设置值无效或当前版本不可用");
}
- (NSMutableDictionary *)savedSelections:(NSString *)identifier document:(NSDictionary *)document {
    NSMutableDictionary *choices = [NSMutableDictionary dictionary];
    NSDictionary *saved = [self.store selectionsForID:identifier];
    for (NSString *group in saved) {
        NSString *node = MLString(saved[group]);
        if (node && MLCanSelect(document,group,node)) choices[group] = node;
    }
    return choices;
}

- (NSString *)configurationMode:(NSDictionary *)document {
    NSString *mode = document[@"mode"];
    if ([mode isEqual:@"global"]) return @"Global";
    if ([mode isEqual:@"direct"]) return @"Direct";
    return @"Rule";
}

- (NSUInteger)configurationPort:(NSDictionary *)document {
    id value = document[@"socks-port"];
    return value ? (NSUInteger)[value integerValue] : self.corePort;
}

- (void)handleCoreFailure {
    [self.core stop];
    BOOL strict=[self.settings[@"protectionMode"] isEqual:@"strict"];
    NSError *recovery=nil;
    BOOL restored=!self.capture||[self.capture coreFailedWithStrictBlock:strict error:&recovery];
    NSString *captureState=self.capture.status[@"state"];
    if(![captureState isEqual:@"BLOCKING"])MLNetworkSetInterfaceIndex(0);
    self.state=@"FAILED";
    self.statusMessage=!restored?@"Core 已停止，网络恢复尚未完成":[captureState isEqual:@"BLOCKING"]?@"Core 已停止，接管范围维持严格阻断":@"Core 已停止，网络已恢复";
    [self log:@"error" message:self.statusMessage];
}
- (BOOL)startCore:(NSError **)error {
    BOOL ok=[self startCoreImplementation:error];
    if(!ok&&![self.state isEqual:@"FAILED"]) { self.state=@"FAILED";self.statusMessage=@"核心或网络准备失败";[self log:@"error" message:self.statusMessage]; }
    return ok;
}
- (BOOL)startCoreImplementation:(NSError **)error {
    if ([self.core running]) return YES;
    if (!self.document || !self.store.activeID) { self.state=@"FAILED";[self log:@"error" message:@"没有已应用的可用配置"];return MLFail(error,@"E_CONFIG_REQUIRED",@"请先应用可用配置"); }
    NSString *dnsMode=self.settings[@"dnsMode"];
    BOOL fake=[dnsMode isEqual:@"fake-ip"]||([dnsMode isEqual:@"follow-config"]&&[self.document[@"dns"][@"enhanced-mode"] isEqual:@"fake-ip"]);
    if(self.fakeStateDamaged&&fake) return MLFail(error,@"E_FAKE_STATE",@"Fake-IP 恢复记录损坏，保留现有文件并拒绝启用");
    self.state=@"PREPARING";
    BOOL capture=[self.settings[@"captureBackend"] isEqual:@"utun"];
    BOOL strict=[self.settings[@"protectionMode"] isEqual:@"strict"];
    if(capture) {
        if(!self.capture) self.capture=[[MLCaptureCoordinator alloc]initWithStateDirectory:self.directory error:error];
        if(!self.capture)return NO;
        if(![self.capture prepare:error])return NO;
        NSString *guardian=[self.coreExecutable.stringByDeletingLastPathComponent stringByAppendingPathComponent:@"muyu-capture-guardian"];
        if(![self.capture.status[@"strictBlockAvailable"] boolValue]) {
            if(![self.capture startGuardianWithExecutable:guardian strictBlock:strict error:error]) { [self.capture restore:NULL];return NO; }
        } else if(![self.capture prepareCoreLifetime:error])return NO;
        MLNetworkSetInterfaceIndex(self.capture.outboundInterfaceIndex);
    }
    self.state=@"STARTING";
    [self.fakeLock lock];self.fakeToken=MLFakeToken();NSArray *fakeStates=[self.fakeStates copy];[self.fakeLock unlock];
    NSDictionary *runtime=[self runtimeParameters];
    BOOL started=NO;
    @try {
        started=[self.core start:self.coreExecutable port:[self configurationPort:self.document]
            captureFD:capture?self.capture.fileDescriptor:-1 lifetimeFD:capture?self.capture.coreLifetimeDescriptor:-1
            outboundInterface:capture?self.capture.outboundInterfaceIndex:0 interfaceName:self.capture.interfaceName error:error];
    } @finally { if(capture)[self.capture coreDidStart]; }
    NSDictionary *ready=nil;
    if(started && [self.core request:@"fake.restore" params:@{@"pools":fakeStates} error:error] && [self.core request:@"prepare" params:@{@"document":self.document,@"runtime":runtime} error:error])
        ready=[self.core request:@"commit" params:@{@"id":self.store.activeID,@"mode":self.mode,@"selections":[self.selections copy]} error:error];
    if(!ready || (capture&&![self.capture activateWithCoreReady:ready[@"capture"] error:error])) {
        [self.core stop];if(capture)[self.capture coreFailedWithStrictBlock:strict error:NULL];
        if(![self.capture.status[@"state"] isEqual:@"BLOCKING"])MLNetworkSetInterfaceIndex(0);
        self.state=@"FAILED";self.statusMessage=@"核心或网络接管启动失败";[self log:@"error" message:self.statusMessage];return NO;
    }
    self.state=capture?@"RUNNING":@"DEGRADED";
    self.statusMessage=capture?@"系统公网流量已接管，局域网和链路本地地址绕过":@"本机 SOCKS5 / HTTP CONNECT 已监听，系统流量未接管";
    self.retryAt=0;self.coreStartedAt=[NSProcessInfo processInfo].systemUptime;
    [self log:@"info" message:self.statusMessage];return YES;
}

- (void)tick {
    @synchronized(self) {
        if(!self.pendingJob&&self.document) {
            NSSet *due=self.providers.dueProviderNames;
            BOOL geoDue=self.geo.dueRefresh;
            if(due.count||geoDue){NSMutableSet *refresh=[due mutableCopy];if(geoDue)[refresh addObject:@"__geo__"];[self enqueueApply:self.store.activeID refresh:refresh error:NULL];}
        }
        if (!self.wantsRunning || self.pendingJob) return;
        double now = [[NSProcessInfo processInfo] systemUptime];
        if ([self.core running]) {
            BOOL changed=NO;NSError *pathError=nil;
            BOOL captured=[self.capture.status[@"state"] isEqual:@"ACTIVE"];
            NSDictionary *bridge=captured?[self.core request:@"network.status" params:nil error:NULL]:nil;
            BOOL pathValid=!captured||[self.capture checkPhysicalPathChanged:&changed error:&pathError];
            if(captured&&(![bridge[@"ready"] boolValue]||!pathValid||changed)) {
                [self.core stop];[self.capture coreFailedWithStrictBlock:[self.settings[@"protectionMode"] isEqual:@"strict"] error:NULL];
                if(![self.capture.status[@"state"] isEqual:@"BLOCKING"])MLNetworkSetInterfaceIndex(0);
                BOOL retry=[self.settings[@"autoReconnect"] boolValue]&&self.retries<3;
                self.state=retry?@"RECOVERING":@"FAILED";
                NSString *cause=![bridge[@"ready"] boolValue]?@"数据转发线程未就绪":!pathValid?@"物理网络检查失败":@"物理网络路径变化";
                NSString *outcome=[self.capture.status[@"state"] isEqual:@"BLOCKING"]?@"接管范围维持严格阻断":@"网络已恢复";
                self.statusMessage=[NSString stringWithFormat:@"%@，%@%@",cause,outcome,retry?@"，正在重连":@"，可手动重连"];
                self.retryAt=retry?now+1:0;[self log:@"error" message:self.statusMessage];
                return;
            }
            if (now - self.coreStartedAt >= 60) self.retries = 0;
            return;
        }
        if([self.state isEqual:@"DEGRADED"]||[self.state isEqual:@"RUNNING"]||
           [@[@"ACTIVE",@"PREPARED"] containsObject:self.capture.status[@"state"] ?: @""]) [self handleCoreFailure];
        if (![self.settings[@"autoReconnect"] boolValue] || self.retries >= 3) return;
        if (!self.retryAt) self.retryAt = now + 1;
        if (now < self.retryAt) return;
        ++self.retries;
        if (![self startCore:NULL]) self.retryAt = now + (1U << self.retries);
    }
}

- (void)setCoreExecutable:(NSString *)coreExecutable {
    @synchronized(self) {
        _coreExecutable = [coreExecutable copy];
    }
}
- (void)controlListenerReady {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{ @autoreleasepool {
        @synchronized(self) {
            if(![self.settings[@"autoStart"] boolValue])return;
            self.wantsRunning=YES;
            if(self.document)[self startCore:NULL];
            else if(self.store.activeID)[self enqueueApply:self.store.activeID refresh:nil error:NULL];
        }
    }});
}

- (void)shutdown {
    @synchronized(self) {
        self.wantsRunning = NO;
        self.retryAt = 0;
        [self.core stop];
        if(self.capture&&![self.capture restore:NULL]) { self.state=@"FAILED";self.statusMessage=@"网络恢复尚未完成，请使用紧急恢复工具";return; }
        MLNetworkSetInterfaceIndex(0);
        self.state = @"STOPPED";
        self.statusMessage = @"未连接";
    }
}

- (NSDictionary *)settingValues {
    NSMutableDictionary *values = [self.settings mutableCopy];
    values[@"mode"] = self.mode;
    if (self.document[@"log-level"]) values[@"logLevel"] = self.document[@"log-level"];
    values[@"background"] = @YES;
    return values;
}

- (NSDictionary *)status {
    BOOL running = [self.core running];
    if (!running && ([self.state isEqual:@"DEGRADED"]||[self.state isEqual:@"RUNNING"]||
        [@[@"ACTIVE",@"PREPARED"] containsObject:self.capture.status[@"state"] ?: @""])) [self handleCoreFailure];
    NSString *active = self.store.activeID ?: @"";
    id activeConfig = active.length ? @{@"id":active,@"name":self.configName ?: active} : @"";
    NSMutableDictionary *result = [@{@"state":self.state,@"message":self.statusMessage,@"mode":self.mode,
                                      @"activeConfig":activeConfig,@"coverage":self.capture.status[@"coverage"] ?: MLCaptureCoverage(),@"capture":self.capture.status ?: @{},
                                      @"configurationReady":@(self.document!=nil && active.length>0),@"coreIntegrated":@YES} mutableCopy];
    if (self.configurationError) result[@"configurationError"]=@{@"code":self.configurationError.domain,@"message":self.configurationError.localizedDescription};
    if (self.pendingJob) result[@"jobID"]=self.pendingJob;
    if (running) {
        NSDictionary *statistics = [self.core request:@"statistics" params:nil error:NULL];
        if (statistics) {
            result[@"statistics"] = statistics;
            for (NSString *key in @[@"actual",@"group",@"protocol",@"latency"]) {
                if (statistics[key]) result[key] = statistics[key];
            }
            result[@"listeners"] = @{@"address":@"127.0.0.1",@"socks5":@(self.core.port),@"httpConnect":@(self.core.port)};
            result[@"corePID"] = @(self.core.pid);
        } else {
            [self handleCoreFailure];
            result[@"state"] = self.state;
            result[@"message"] = self.statusMessage;
            result[@"capture"]=self.capture.status ?: @{};
            result[@"coverage"]=self.capture.status[@"coverage"] ?: MLCaptureCoverage();
        }
    }
    return result;
}

- (NSDictionary *)capabilities {
    NSMutableArray *protocols = [NSMutableArray array];
    NSSet *implemented = [NSSet setWithArray:@[@"http",@"https",@"socks5",@"ss",@"ss2022",@"vmess",@"vless",@"trojan",@"hysteria2",@"tuic",@"wireguard",@"amneziawg",@"ssh",@"anytls"]];
    for (NSString *name in @[@"http",@"https",@"socks5",@"ss",@"ss2022",@"vmess",@"vless",@"trojan",@"hysteria2",@"tuic",@"wireguard",@"amneziawg",@"anytls",@"snell",@"ssh",@"ssr"]) {
        BOOL available = [implemented containsObject:name];
        [protocols addObject:@{@"name":name,@"integrated":@(available),@"verified":@NO,
                               @"transport":available ? ([name isEqual:@"http"]||[name isEqual:@"https"]||[name isEqual:@"ssh"]?@"TCP":@"TCP/UDP") : @"", @"reason":available ? @"仅限配置检查通过的协议/传输组合，待逐项真机验收" : @"核心未接入该协议"}];
    }
    return @{@"releaseReady":@NO,@"buildKind":@"internal-development",@"ipcVersion":@1,
             @"baseline":@{@"mihomo":@"v1.19.34",@"commit":@"0455d0d28c4526937380505153e65a843d8612e8"},
             @"protocols":protocols,@"capture":self.capture.status ?: MLCaptureProbe(),@"coreIntegrated":@YES,
             @"system":[[NSProcessInfo processInfo] operatingSystemVersionString]};
}
- (NSDictionary *)importSubscription:(NSString *)method params:(NSDictionary *)params error:(NSError **)error {
    // One download at a time; keep the remaining IPC workers and service
    // monitor available for status/stop instead of queuing timed-out imports.
    if (![self.fetchLock tryLock]) { MLFail(error,@"E_BUSY",@"已有订阅正在下载，请稍后重试"); return nil; }
    @try {
        NSString *url = MLString(params[@"url"]), *name = MLString(params[@"name"]);
        if ([method isEqual:@"config.update"]) {
            NSDictionary *old = [self.store sourceForID:MLString(params[@"id"]) error:error];
            if (!old) return nil;
            url = MLString(old[@"source"]); name = MLString(old[@"name"]);
        }
        NSString *yaml = MLFetchSubscription(url, self.caPath, error);
        if (!yaml) return nil;
        if (![[MLConfig checkYAML:yaml][@"syntaxValid"] boolValue]) {
            yaml = MLImportNodeText(yaml,error);
            if (!yaml) return nil;
        }
        NSDictionary *result = [self.store importYAML:yaml name:name source:url error:error];
        if (result) { @synchronized(self) { [self log:@"info" message:@"订阅候选已下载并保存；原配置未被覆盖。"];} }
        return result;
    } @finally { [self.fetchLock unlock]; }
}
- (NSDictionary *)applyID:(NSString *)identifier refresh:(NSSet *)refresh error:(NSError **)error {
    if(![self.fetchLock tryLock]) { MLFail(error,@"E_BUSY",@"已有下载或配置准备任务");return nil; }
    @try {
        NSDictionary *source=[self.store sourceForID:identifier error:error];if(!source)return nil;
        NSDictionary *report=[MLConfig checkYAML:source[@"yaml"]];
        if(![report[@"valid"] boolValue]) { MLFail(error,@"E_CONFIG_BLOCKED",@"配置有阻断问题，请打开兼容性检查");return nil; }
        NSString *previous;NSDictionary *oldDocument;
        @synchronized(self) { previous=self.store.activeID;oldDocument=self.document; }
        id providersBefore=[self.providers captureCheckpoint],geoBefore=[self.geo captureCheckpoint];
        NSDictionary *providerPrepared=[self.providers prepareDocument:report[@"document"] refreshNames:refresh error:error];
        if(!providerPrepared)return nil;
        NSDictionary *expanded=[self.geo prepareDocument:providerPrepared fetch:YES refresh:[refresh containsObject:@"__geo__"] error:error];
        if(!expanded){[self.providers discardPreparedDocument];return nil;}
        if(![[MLConfig checkPreparedDocument:expanded][@"valid"] boolValue]) {
            [self.providers discardPreparedDocument];[self.geo discardPreparedDocument];MLFail(error,@"E_PROVIDER_CONFIG",@"Provider 展开后有不支持的字段或引用");return nil;
        }
        @synchronized(self) {
            if(self.document!=oldDocument || ![(self.store.activeID ?: @"") isEqual:(previous ?: @"")]) {
                [self.providers discardPreparedDocument];[self.geo discardPreparedDocument];MLFail(error,@"E_CONFIG_STALE",@"准备期间活动配置已改变，请重新应用");return nil;
            }
            BOOL running=[self.core running];
            if(running&&[self configurationPort:expanded]!=[self configurationPort:self.document]) {
                [self.providers discardPreparedDocument];[self.geo discardPreparedDocument];MLFail(error,@"E_PORT_RESTART",@"请先停止连接再更改监听端口");return nil;
            }
            NSDictionary *runtime=[self runtimeParameters];
            if(running&&![self.core request:@"prepare" params:@{@"document":expanded,@"runtime":runtime} error:error]) {
                [self.providers discardPreparedDocument];[self.geo discardPreparedDocument];if(![self.core running])[self handleCoreFailure];return nil;
            }
            if(![self.store activatePreparedID:identifier expectedYAML:source[@"yaml"] ifActiveID:previous error:error]) {
                if(running)[self.core request:@"discard" params:nil error:NULL];[self.providers discardPreparedDocument];[self.geo discardPreparedDocument];return nil;
            }
            NSString *newMode=[identifier isEqual:previous]?self.mode:[self configurationMode:expanded];
            NSMutableDictionary *saved=[self savedSelections:identifier document:expanded];
            BOOL committed=[self.providers commitPreparedDocument:providerPrepared error:error];
            if(committed)committed=[self.geo commitPreparedDocument:expanded error:error];
            if(committed&&running)committed=[self.core request:@"commit" params:@{@"id":identifier,@"mode":newMode,@"selections":saved} error:error]!=nil;
            if(!committed) {
                [self.providers discardPreparedDocument];[self.geo discardPreparedDocument];
                BOOL providersRestored=[self.providers restoreCheckpoint:providersBefore error:NULL];
                BOOL geoRestored=[self.geo restoreCheckpoint:geoBefore error:NULL];
                BOOL marker=[self.store restoreActiveID:previous ifCurrent:identifier error:NULL];
                BOOL coreRestored=!running;
                if(running&&oldDocument&&[self.core running]) {
                    coreRestored=[self.core request:@"prepare" params:@{@"document":oldDocument,@"runtime":runtime} error:NULL] &&
                        [self.core request:@"commit" params:@{@"id":previous ?: @"",@"mode":self.mode,@"selections":self.selections} error:NULL];
                }
                if(!marker||!coreRestored||!providersRestored||!geoRestored) {
                    [self.core stop];[self.capture coreFailedWithStrictBlock:[self.settings[@"protectionMode"] isEqual:@"strict"] error:NULL];
                    self.state=@"FAILED";self.statusMessage=@"配置切换失败，网络已进入恢复或阻断流程";
                    if(![self.capture.status[@"state"] isEqual:@"BLOCKING"])MLNetworkSetInterfaceIndex(0);
                }
                return nil;
            }
            self.document=expanded;self.configurationError=nil;self.sourceDocument=report[@"document"];self.configName=source[@"name"];self.mode=newMode;self.selections=saved;
            [self runtimeParameters];
            if(!running){self.state=@"STOPPED";self.statusMessage=@"配置已应用，未连接";}
            [self log:@"info" message:@"配置及 Provider 快照已原子应用"];
            return @{@"active":identifier};
        }
    } @finally { [self.fetchLock unlock]; }
}
- (NSDictionary *)enqueueApply:(NSString *)identifier refresh:(NSSet *)refresh error:(NSError **)error {
    if(!identifier.length) { MLFail(error,@"E_CONFIG_REQUIRED",@"请先选择配置");return nil; }
    @synchronized(self) {
        if(self.pendingJob){MLFail(error,@"E_BUSY",@"已有配置准备任务");return nil;}
        NSString *jobID=[[NSProcessInfo processInfo] globallyUniqueString];
        self.pendingJob=jobID;
        NSString *previousState=self.state,*previousMessage=self.statusMessage;
        self.jobs[jobID]=@{@"id":jobID,@"state":@"PREPARING",@"configID":identifier};
        if(![self.core running]) { self.state=@"PREPARING";self.statusMessage=@"正在准备配置、规则和 GeoIP 数据"; }
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{ @autoreleasepool {
            NSError *failure=nil;NSDictionary *result=[self applyID:identifier refresh:refresh error:&failure];
            @synchronized(self) {
                self.pendingJob=nil;
                if (!result) {
                    if (!self.document) {
                        self.configurationError=failure; self.wantsRunning=NO; self.state=@"FAILED";
                        self.statusMessage=[@"配置准备失败：" stringByAppendingString:failure.localizedDescription ?: @"请重试"];
                    } else if ([self.state isEqual:@"PREPARING"]) { self.state=previousState;self.statusMessage=previousMessage; }
                    [self log:@"error" message:[@"配置准备失败：" stringByAppendingString:failure.localizedDescription ?: @"未知错误"]];
                }
                if(result&&self.wantsRunning&&![self.core running]&&![self startCore:&failure])result=nil;
                self.jobs[jobID]=result?@{@"id":jobID,@"state":@"COMPLETE",@"result":result}:
                    @{@"id":jobID,@"state":@"FAILED",@"error":@{@"code":failure.domain ?: @"E_CONFIG",@"message":failure.localizedDescription ?: @"配置准备失败"}};
                while(self.jobs.count>16) {
                    NSString *old=self.jobs.allKeys[0];if([old isEqual:jobID])old=self.jobs.allKeys[1];[self.jobs removeObjectForKey:old];
                }
            }
        }});
        return @{@"state":@"PREPARING",@"jobID":jobID};
    }
}
- (NSDictionary *)handleMethod:(NSString *)method params:(NSDictionary *)params error:(NSError **)error {
    if (![method isKindOfClass:[NSString class]] || ![params isKindOfClass:[NSDictionary class]]) {
        MLFail(error,@"E_REQUEST",@"方法和参数格式无效"); return nil;
    }
    if([method isEqual:@"network.fake.persist"]) {
        if(![self.fakeLock tryLock]) { MLFail(error,@"E_BUSY",@"Fake-IP 正在持久化");return nil; }
        @try {
            if(!self.fakeToken.length||![params[@"token"] isEqual:self.fakeToken]) { MLFail(error,@"E_FAKE_TOKEN",@"拒绝未认证的映射写入");return nil; }
            NSDictionary *snapshot=params[@"snapshot"];
            if(self.fakeStateDamaged||!MLValidFakeSnapshot(snapshot)) { MLFail(error,@"E_FAKE_STATE",@"Fake-IP 映射快照无效");return nil; }
            NSMutableArray *pools=[self.fakeStates mutableCopy];NSString *identity=MLFakeIdentity(snapshot);BOOL replaced=NO;
            for(NSUInteger i=0;i<pools.count;i++)if([MLFakeIdentity(pools[i]) isEqual:identity]){pools[i]=snapshot;replaced=YES;break;}
            if(!replaced){
                if(pools.count>=2){MLFail(error,@"E_FAKE_CAPACITY",@"已保留两个 Fake-IP 地址池，请停止后清理缓存再更改范围");return nil;}
                for(NSDictionary *existing in pools)if(MLFakeSnapshotsOverlap(existing,snapshot)){MLFail(error,@"E_FAKE_OVERLAP",@"Fake-IP 地址池与保留范围重叠");return nil;}
                [pools addObject:snapshot];
            }
            NSDictionary *state=@{@"version":@1,@"pools":pools};
            NSData *data=[NSJSONSerialization dataWithJSONObject:state options:0 error:NULL];
            if(!data||data.length>512*1024||!MLWriteSettings(self.fakeStatePath,state,error))return nil;
            self.fakeStates=[pools copy];return @{@"saved":@YES};
        } @finally { [self.fakeLock unlock]; }
    }
    if([method isEqual:@"system.flow-owner"]) {
        NSString *source=MLString(params[@"source"]),*destination=MLString(params[@"destination"]),*network=MLString(params[@"network"]);
        struct in_addr v4;struct in6_addr v6;
        BOOL literals=source&&destination&&(inet_pton(AF_INET,source.UTF8String,&v4)==1||inet_pton(AF_INET6,source.UTF8String,&v6)==1)&&
            (inet_pton(AF_INET,destination.UTF8String,&v4)==1||inet_pton(AF_INET6,destination.UTF8String,&v6)==1);
        id sourcePort=params[@"sourcePort"],destinationPort=params[@"destinationPort"];
        BOOL ports=[sourcePort isKindOfClass:[NSNumber class]]&&[destinationPort isKindOfClass:[NSNumber class]]&&
            [sourcePort doubleValue]==[sourcePort integerValue]&&[destinationPort doubleValue]==[destinationPort integerValue]&&
            [sourcePort integerValue]>0&&[sourcePort integerValue]<=65535&&[destinationPort integerValue]>0&&[destinationPort integerValue]<=65535;
        if(!literals||!ports||![@[@"TCP",@"UDP"] containsObject:network ?: @""]) { MLFail(error,@"E_OWNER_TUPLE",@"进程查询需要真实数值套接字四元组");return nil; }
        if(![self.ownerLock tryLock])return @{@"verified":@NO,@"reason":@"busy"};
        @try { return [self.processOwner lookupSource:source sourcePort:[sourcePort unsignedIntValue] destination:destination destinationPort:[destinationPort unsignedIntValue] network:network]; }
        @finally { [self.ownerLock unlock]; }
    }
    if ([method isEqual:@"config.importURL"] || [method isEqual:@"config.update"])
        return [self importSubscription:method params:params error:error];
    if([method isEqual:@"geodata.update"])return [self enqueueApply:self.store.activeID refresh:[NSSet setWithObject:@"__geo__"] error:error];
    if ([method isEqual:@"provider.update"]) {
        NSString *name=MLString(params[@"name"]);
        NSMutableSet *names=[NSMutableSet set];
        if(name)[names addObject:name];else for(NSString *kind in @[@"proxy-providers",@"rule-providers"])for(NSString *key in self.sourceDocument[kind])[names addObject:key];
        return [self enqueueApply:self.store.activeID refresh:names error:error];
    }
    if ([method isEqual:@"config.apply"]) {
        @synchronized(self) { if(self.pendingJob) { MLFail(error,@"E_BUSY",@"已有配置准备任务");return nil; } }
        NSDictionary *source=[self.store sourceForID:MLString(params[@"id"]) error:error];if(!source)return nil;
        NSDictionary *report=[MLConfig checkYAML:source[@"yaml"]];NSDictionary *document=report[@"document"];
        BOOL geoPending=NO;for(NSDictionary *issue in report[@"issues"])if([issue[@"id"] isEqual:@"RULE_DATABASE_PENDING"])geoPending=YES;
        if([document isKindOfClass:[NSDictionary class]]&&([document[@"proxy-providers"] count]||[document[@"rule-providers"] count]||geoPending))
            return [self enqueueApply:MLString(params[@"id"]) refresh:nil error:error];
    }
    if ([method isEqual:@"dns.query"]) {
        NSString *name = MLString(params[@"name"]);
        if (!name.length || name.length > 253 ||
            [name rangeOfString:@"^[A-Za-z0-9._:-]+$" options:NSRegularExpressionSearch].location == NSNotFound) {
            MLFail(error,@"E_DNS_NAME",@"请输入域名或 IP 地址"); return nil;
        }
        if (![self.dnsLock tryLock]) {
            MLFail(error,@"E_BUSY",@"已有 DNS 查询，请稍后重试"); return nil;
        }
        @try {
            NSDictionary *document;
            @synchronized(self) { document = self.document; }
            if (!document) { MLFail(error,@"E_CONFIG_REQUIRED",@"请先应用配置"); return nil; }
            @synchronized(self) { if([self.core running])return [self.core request:@"dns.query" params:@{@"name":name} error:error]; }
            MLDNS *resolver = [[MLDNS alloc] initWithOptions:document[@"dns"] ipv6:[document[@"ipv6"] boolValue]];
            resolver.caPath = self.caPath;
            NSDictionary *result = [resolver lookup:name];
            if (!result) MLFail(error,@"E_DNS_RESOLVE",@"当前配置的 DNS 未返回可用地址");
            return result;
        } @finally { [self.dnsLock unlock]; }
    }
    @synchronized (self) {
        if ([method isEqual:@"service.status"]) return [self status];
        if ([method isEqual:@"system.capabilities"]) return [self capabilities];
        if ([method isEqual:@"service.start"]) {
            self.retries = 0;
            self.retryAt = 0;
            if (self.pendingJob) {
                self.wantsRunning=YES;
                return @{@"state":@"PREPARING",@"jobID":self.pendingJob};
            }
            if (!self.document && self.store.activeID) {
                NSDictionary *job=[self enqueueApply:self.store.activeID refresh:nil error:error];
                if (job) self.wantsRunning=YES;
                return job;
            }
            if (![self startCore:error]) return nil;
            self.wantsRunning = YES;
            return [self status];
        }
        if ([method isEqual:@"service.stop"]) {
            [self shutdown];
            [self log:@"info" message:@"本机代理已停止"];
            return @{@"state":self.state};
        }
        if ([method isEqual:@"service.mode"]) {
            NSString *mode = MLString(params[@"mode"]);
            if (!mode || ![@[@"Rule",@"Direct",@"Global"] containsObject:mode]) {
                MLFail(error,@"E_MODE",@"未知代理模式"); return nil;
            }
            if ([self.core running] && ![self.core request:@"mode" params:@{@"mode":mode} error:error]) return nil;
            self.mode = mode;
            return @{@"mode":mode};
        }
        if ([method isEqual:@"config.check"]) {
            NSString *yaml = MLString(params[@"yaml"]);
            if (!yaml) { MLFail(error,@"E_CONFIG_INPUT",@"缺少 YAML 文本"); return nil; }
            NSMutableDictionary *report = [[MLConfig checkYAML:yaml] mutableCopy];
            [report removeObjectForKey:@"document"];
            return report;
        }
        if ([method isEqual:@"config.list"]) return @{@"items":[self.store list]};
        if ([method isEqual:@"config.source"]) return [self.store sourceForID:MLString(params[@"id"]) error:error];
        if ([method isEqual:@"config.import"]) {
            NSDictionary *result = [self.store importYAML:MLString(params[@"yaml"]) name:MLString(params[@"name"]) source:MLString(params[@"source"]) error:error];
            if (result) [self log:@"info" message:@"配置候选已保存；尚未应用。"];
            return result;
        }
        if ([method isEqual:@"config.importNodes"]) {
            NSString *text = MLString(params[@"text"]);
            NSString *yaml = MLImportNodeText(text,error);
            return yaml ? [self.store importYAML:yaml name:MLString(params[@"name"]) source:nil error:error] : nil;
        }
        if ([method isEqual:@"config.metadata"]) {
            NSString *source = MLString(params[@"source"]);
            if (source.length) {
                NSURL *url = [NSURL URLWithString:source];
                if (![[url.scheme lowercaseString] isEqual:@"https"] || !url.host.length || url.user || url.password) {
                    MLFail(error,@"E_SUBSCRIPTION_URL",@"订阅地址必须是 HTTPS URL，留空可清除订阅地址");
                    return nil;
                }
            }
            NSString *identifier = MLString(params[@"id"]);
            NSDictionary *result = [self.store renameID:identifier name:MLString(params[@"name"]) source:source error:error];
            if (result && [self.store.activeID isEqual:identifier]) self.configName = result[@"name"];
            return result;
        }
        if ([method isEqual:@"config.apply"]) {
            return [self applyID:MLString(params[@"id"]) refresh:nil error:error];
        }
        if ([method isEqual:@"config.delete"]) {
            BOOL removed = [self.store removeID:MLString(params[@"id"]) error:error];
            if (removed) [self log:@"info" message:@"配置候选已删除。"];
            return removed ? @{@"deleted":@YES} : nil;
        }
        if ([method isEqual:@"logs.list"]) {
            NSMutableArray *items = [NSMutableArray array];
            NSString *search = MLString(params[@"search"]), *level = MLString(params[@"level"]);
            for (NSDictionary *entry in self.logs) {
                if (level.length && ![entry[@"level"] isEqual:level]) continue;
                if (search.length && [entry[@"message"] rangeOfString:search options:NSCaseInsensitiveSearch].location == NSNotFound) continue;
                [items addObject:entry];
            }
            return @{@"items":items,@"redacted":@YES,@"capacity":@256};
        }
        if ([method isEqual:@"logs.clear"]) { [self.logs removeAllObjects]; return @{@"cleared":@YES}; }
        if ([method isEqual:@"settings.get"]) return @{@"values":[self settingValues],@"capabilities":@{@"strictBlockAvailable":self.capture.status[@"strictBlockAvailable"] ?: @NO,@"coreIntegrated":@YES}};
        if ([method isEqual:@"settings.set"]) {
            NSString *key = MLString(params[@"key"]); id value = params[@"value"];
            if ([key isEqual:@"logLevel"] && self.document[@"log-level"]) {
                MLFail(error,@"E_CONFIG_OVERRIDE",@"当前配置指定了 log-level，请在配置中修改"); return nil;
            }
            if ([self.core running]&&[@[@"captureBackend",@"protectionMode",@"dnsMode"] containsObject:key]) { MLFail(error,@"E_SETTING_RESTART",@"请停止连接后更改网络设置");return nil; }
            if (![self validateSetting:key value:value error:error]) return nil;
            if([key isEqual:@"captureBackend"]&&[value isEqual:@"unverified"]&&[self.settings[@"dnsMode"] isEqual:@"fake-ip"]) {MLFail(error,@"E_FAKE_CAPTURE",@"Fake-IP 模式需要系统流量接管，请先更改 DNS 模式");return nil;}
            NSMutableDictionary *candidate = [self.settings mutableCopy]; candidate[key] = value;
            if (!MLWriteSettings(self.settingsPath, candidate, error)) return nil;
            self.settings = candidate;
            return @{@"values":[self settingValues]};
        }
        if ([method isEqual:@"dns.status"]) {
            NSDictionary *dns = self.document[@"dns"] ?: @{};
            NSString *mode=[self.settings[@"dnsMode"] isEqual:@"follow-config"]?(dns[@"enhanced-mode"] ?: @"redir-host"):self.settings[@"dnsMode"];
            return @{@"enabled":@([dns[@"enable"] boolValue]),@"nameservers":dns[@"nameserver"] ?: @[],
                     @"mode":mode ?: @"redir-host",@"configuredMode":dns[@"enhanced-mode"] ?: @"redir-host",
                     @"ipv6":@([self.document[@"ipv6"] boolValue] && [dns[@"ipv6"] boolValue]),
                     @"systemCapture":@([self.state isEqual:@"RUNNING"]),@"encryptedUpstreamTypes":@[@"DoH",@"DoT",@"DoQ"]};
        }
        if ([method isEqual:@"dns.cache"] || [method isEqual:@"dns.clear"])
            return [self.core request:[method isEqual:@"dns.clear"] ? @"dns.flush" : method params:nil error:error];
        if ([method isEqual:@"system.dependencies"])
            return @{@"libyaml":@"0.2.5",@"curl":@"8.23.0",@"mbedTLS":@"3.6.7",@"OpenSSL":@"3.5.9",
                     @"libssh2":@"1.11.1",@"zstd":@"1.5.7",@"libmaxminddb":@"1.14.1",
                     @"Senko":@"b9f7e6ab9c369f9acf753b00b49143269ed15ca8"};
        if ([method isEqual:@"diagnostics.run"]) return @{@"state":self.state,@"capture":self.capture.status ?: MLCaptureProbe(),@"coreIntegrated":@YES,
            @"networkModified":@([@[@"ACTIVE",@"BLOCKING",@"PREPARED"] containsObject:self.capture.status[@"state"] ?: @"STOPPED"]),
            @"message":@"当前运行诊断；能力按实际接管范围和节点配置判断"};
        if ([method isEqual:@"network.restore"]) {
            self.wantsRunning=NO;[self.core stop];
            if(self.capture&&![self.capture restore:error])return nil;
            MLNetworkSetInterfaceIndex(0);self.state=@"STOPPED";self.statusMessage=@"网络已恢复";
            return @{@"restored":@YES,@"networkModified":@NO};
        }
        if ([method isEqual:@"provider.list"]) return @{@"items":self.providers.list};
        if([method isEqual:@"geodata.list"])return @{@"items":self.geo.list};
        if ([method isEqual:@"provider.import"]) {
            if(self.pendingJob){MLFail(error,@"E_BUSY",@"已有配置准备任务");return nil;}
            return [self.providers importLocalText:MLString(params[@"text"]) path:MLString(params[@"path"]) error:error]?@{@"imported":@YES}:nil;
        }
        if ([method isEqual:@"config.job"]) {
            NSDictionary *job=self.jobs[MLString(params[@"id"]) ?: @""];
            if(!job)MLFail(error,@"E_JOB",@"没有该配置准备任务");return job;
        }
        if ([method isEqual:@"group.list"]) return [self.core running]?[self.core request:method params:nil error:error]:@{@"items":self.document ? MLGroups(self.document,self.selections) : @[]};
        if ([method isEqual:@"proxy.list"]) {
            BOOL running=[self.core running];
            NSDictionary *coreResult=running?[self.core request:@"proxy.list" params:params error:error]:nil;
            if(running&&!coreResult)return nil;
            NSMutableDictionary *result=[coreResult mutableCopy] ?: [NSMutableDictionary dictionary];
            NSString *name=MLString(params[@"group"]);if(!name.length)name=@"GLOBAL";
            NSArray *proxies=coreResult?coreResult[@"items"]:(self.document ? MLProxies(self.document,self.selections,name) : @[]);
            if(!coreResult)for(NSDictionary *group in MLGroups(self.document,self.selections))if([group[@"name"] isEqual:name]) {
                NSMutableDictionary *parent=[group mutableCopy];
                parent[@"manualSelectable"]=@([@[@"select",@"url-test",@"fallback"] containsObject:group[@"type"]]);
                result[@"group"]=parent;result[@"selected"]=group[@"selected"] ?: @"";break;
            }
            result[@"items"]=proxies ?: @[];
            NSDictionary *measurements = [self.core running] ? [self.core request:@"proxy.measurements" params:nil error:NULL] : nil;
            if (!measurements.count) return result;
            NSMutableArray *items = [NSMutableArray arrayWithCapacity:proxies.count];
            for (NSDictionary *proxy in proxies) {
                NSMutableDictionary *row = [proxy mutableCopy];
                NSDictionary *measurement = measurements[proxy[@"name"]];
                if (measurement) [row addEntriesFromDictionary:measurement];
                [items addObject:row];
            }
            result[@"items"]=items;return result;
        }
        if ([method isEqual:@"proxy.test"]) {
            NSArray *rows = self.document ? MLProxies(self.document,self.selections,MLString(params[@"group"])) : @[];
            NSString *requested = MLString(params[@"proxy"]);
            NSString *url = MLString(params[@"url"]) ?: @"http://www.gstatic.com/generate_204";
            NSMutableArray *targets = [NSMutableArray array];
            for (NSDictionary *row in rows) {
                NSString *name = row[@"name"];
                if (requested && ![requested isEqual:name]) continue;
                if ([@[@"group",@"direct",@"reject"] containsObject:row[@"type"]]) continue;
                [targets addObject:name];
                if (targets.count >= 24) break;
            }
            if (!targets.count) { MLFail(error,@"E_PROXY_TEST",@"没有该组内可测速的节点"); return nil; }
            return [self.core request:@"proxy.probe" params:@{@"targets":targets,@"url":url,
                                                               @"concurrency":self.settings[@"maxProbeConcurrency"]} error:error];
        }
        if ([method isEqual:@"group.select"]) {
            NSString *group = MLString(params[@"group"]), *proxy = MLString(params[@"proxy"]);
            if (!group || !proxy || !self.document || !MLCanSelect(self.document,group,proxy)) {
                MLFail(error,@"E_SELECTION",@"该节点不属于可切换的策略组"); return nil;
            }
            NSString *identifier = self.store.activeID;
            NSMutableDictionary *updated = [self.selections mutableCopy];
            updated[group] = proxy;
            if (![self.store saveSelections:updated forID:identifier error:error]) return nil;
            if ([self.core running] && ![self.core request:@"select" params:@{@"group":group,@"proxy":proxy} error:error]) {
                if (![self.store saveSelections:self.selections forID:identifier error:NULL])
                    [self log:@"error" message:@"策略组选择历史无法回滚"];
                return nil;
            }
            self.selections = updated;
            return @{@"group":group,@"selected":proxy};
        }
        if ([method isEqual:@"connections.list"])
            return [self.core running] ? [self.core request:method params:nil error:error] : @{@"items":@[]};
        if ([method isEqual:@"connections.close"]) {
            NSString *identifier = MLString(params[@"id"]);
            if (!identifier.length) { MLFail(error,@"E_REQUEST",@"缺少连接 ID"); return nil; }
            return [self.core request:method params:@{@"id":identifier} error:error];
        }
        MLFail(error,@"E_UNAVAILABLE",@"请求的功能尚未完成核心集成，操作未执行"); return nil;
    }
}
@end

static size_t MLServiceBootstrap(const char *host,char addresses[][46],size_t capacity,void *context) {
    @autoreleasepool {
        MLService *service=(__bridge MLService *)context;MLDNS *resolver;
        @synchronized(service) { resolver=service.outboundDNS; }
        if(!resolver)resolver=[[MLDNS alloc]initWithOptions:@{} ipv6:YES];
        NSArray *results=[resolver lookupBootstrap:[NSString stringWithUTF8String:host]][@"addresses"];
        size_t count=0;for(NSString *address in results) { if(count>=capacity)break;if(address.length>=46)continue;strlcpy(addresses[count++],address.UTF8String,46); }
        return count;
    }
}
