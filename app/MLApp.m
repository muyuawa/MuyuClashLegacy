#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <dispatch/dispatch.h>
#import "MLIPCBridge.h"
#import "MLQR.h"

// All dynamic runtime facts come from the local supervisor. This UI never
// infers capture coverage from the existence of a process or an open socket.
static NSString * const MLSocket = @"/var/run/muyuclash/control.sock";
static UIColor *MLColor(unsigned int c) {
    return [UIColor colorWithRed:((c >> 16) & 255) / 255.0
                           green:((c >> 8) & 255) / 255.0
                            blue:(c & 255) / 255.0 alpha:1];
}
static UIColor *MLAccent(void) { return MLColor(0x70558F); }
static UIColor *MLTextColor(void) { return MLColor(0x25232A); }
static UIColor *MLMuted(void) { return MLColor(0x66616E); }
static UIImage *MLFill(UIColor *color) {
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(1, 1), YES, 1);
    [color setFill]; UIRectFill(CGRectMake(0, 0, 1, 1));
    UIImage *image = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext(); return image;
}
static NSString *MLString(id value) {
    if (!value || value == [NSNull null]) return @"—";
    if ([value isKindOfClass:[NSString class]]) return [value length] ? value : @"—";
    if ([value isKindOfClass:[NSNumber class]]) return [value description];
    return @"—";
}
static NSDictionary *MLDict(id value) {
    return [value isKindOfClass:[NSDictionary class]] ? value : @{};
}
static NSArray *MLArray(id value) {
    return [value isKindOfClass:[NSArray class]] ? value : @[];
}
static NSString *MLJSON(id value) {
    if (!value) return @"未提供数据";
    if (![NSJSONSerialization isValidJSONObject:value]) return MLString(value);
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingPrettyPrinted error:NULL];
    return data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"数据无法显示";
}
static NSString *MLSourceLabel(id value) {
    NSString *text = MLString(value);
    NSURL *url = [NSURL URLWithString:text];
    if (url.host.length && url.scheme.length)
        return [NSString stringWithFormat:@"%@://%@/…", url.scheme, url.host];
    return text;
}
static id MLRedact(id value) {
    if ([value isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *output = [NSMutableDictionary dictionary];
        for (NSString *key in value) {
            NSString *lower = [key lowercaseString];
            BOOL secret = [lower rangeOfString:@"password"].location != NSNotFound ||
                          [lower rangeOfString:@"token"].location != NSNotFound ||
                          [lower rangeOfString:@"secret"].location != NSNotFound ||
                          [lower rangeOfString:@"uuid"].location != NSNotFound ||
                          [lower rangeOfString:@"private"].location != NSNotFound ||
                          [lower rangeOfString:@"preshared"].location != NSNotFound ||
                          [@[@"psk",@"auth",@"auth-str",@"auth_str",@"cookie",@"set-cookie",@"document",@"yaml"] containsObject:lower] ||
                          [lower isEqualToString:@"authorization"];
            BOOL link = [lower hasSuffix:@"url"] || [lower isEqualToString:@"source"] || [lower isEqualToString:@"uri"];
            output[key] = secret ? @"[已隐藏]" : (link && [value[key] isKindOfClass:[NSString class]] ? MLSourceLabel(value[key]) : MLRedact(value[key]));
        }
        return output;
    }
    if ([value isKindOfClass:[NSArray class]]) {
        NSMutableArray *output = [NSMutableArray array];
        for (id item in value) [output addObject:MLRedact(item)];
        return output;
    }
    return value ?: [NSNull null];
}
static NSString *MLBytes(id value) {
    if (![value isKindOfClass:[NSNumber class]]) return @"未提供";
    double bytes = [value doubleValue];
    if (bytes < 1024) return [NSString stringWithFormat:@"%.0f B", bytes];
    if (bytes < 1024 * 1024) return [NSString stringWithFormat:@"%.1f KB", bytes / 1024];
    return [NSString stringWithFormat:@"%.1f MB", bytes / (1024 * 1024)];
}
static NSString *MLDate(id value) {
    if (![value isKindOfClass:[NSNumber class]]) return MLString(value);
    NSDateFormatter *formatter = [NSDateFormatter new];
    formatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"zh_CN"];
    formatter.dateFormat = @"MM-dd HH:mm:ss";
    return [formatter stringFromDate:[NSDate dateWithTimeIntervalSince1970:[value doubleValue]]];
}
static NSString *MLState(NSString *state) {
    NSDictionary *names = @{@"STOPPED":@"未连接", @"VALIDATING":@"正在检查配置",
        @"PREPARING":@"正在准备", @"STARTING":@"正在连接", @"RUNNING":@"已连接",
        @"DEGRADED":@"部分降级", @"RECOVERING":@"正在恢复", @"STOPPING":@"正在断开",
        @"FAILED":@"连接错误"};
    return names[state ?: @""] ?: @"状态未知";
}
static UIButton *MLButton(NSString *title, id target, SEL action) {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeCustom];
    button.frame = CGRectMake(0, 0, 64, 44);
    [button setTitle:title forState:UIControlStateNormal];
    [button setTitleColor:MLAccent() forState:UIControlStateNormal];
    [button setTitleColor:MLColor(0xA99AC8) forState:UIControlStateHighlighted];
    [button setTitleColor:MLMuted() forState:UIControlStateDisabled];
    button.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    button.accessibilityLabel = title;
    [button addTarget:target action:action forControlEvents:UIControlEventTouchUpInside];
    return button;
}
static void MLStyleSegments(UISegmentedControl *control) {
    control.tintColor = MLAccent();
    [control setBackgroundImage:MLFill([UIColor whiteColor]) forState:UIControlStateNormal barMetrics:UIBarMetricsDefault];
    [control setBackgroundImage:MLFill(MLAccent()) forState:UIControlStateSelected barMetrics:UIBarMetricsDefault];
    [control setBackgroundImage:MLFill(MLColor(0xA99AC8)) forState:UIControlStateHighlighted barMetrics:UIBarMetricsDefault];
    [control setBackgroundImage:MLFill(MLAccent()) forState:UIControlStateSelected | UIControlStateHighlighted barMetrics:UIBarMetricsDefault];
    [control setDividerImage:MLFill(MLColor(0xD8D0E2)) forLeftSegmentState:UIControlStateNormal rightSegmentState:UIControlStateNormal barMetrics:UIBarMetricsDefault];
    [control setTitleTextAttributes:@{UITextAttributeTextColor:MLAccent(), UITextAttributeFont:[UIFont boldSystemFontOfSize:13], UITextAttributeTextShadowOffset:[NSValue valueWithUIOffset:UIOffsetZero]} forState:UIControlStateNormal];
    [control setTitleTextAttributes:@{UITextAttributeTextColor:[UIColor whiteColor], UITextAttributeFont:[UIFont boldSystemFontOfSize:13], UITextAttributeTextShadowOffset:[NSValue valueWithUIOffset:UIOffsetZero]} forState:UIControlStateSelected];
    control.layer.borderColor = MLColor(0xD8D0E2).CGColor; control.layer.borderWidth = 1;
    control.layer.cornerRadius = 4; control.layer.masksToBounds = YES;
}
static UIImage *MLTabIcon(NSUInteger index) {
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(26, 26), NO, 1);
    UIBezierPath *path = [UIBezierPath bezierPath]; path.lineWidth = 1.8;
    if (index == 0) {
        [path moveToPoint:CGPointMake(3, 12)]; [path addLineToPoint:CGPointMake(13, 3)];
        [path addLineToPoint:CGPointMake(23, 12)]; [path moveToPoint:CGPointMake(6, 10)];
        [path addLineToPoint:CGPointMake(6, 23)]; [path addLineToPoint:CGPointMake(20, 23)];
        [path addLineToPoint:CGPointMake(20, 10)];
    } else if (index == 1) {
        [path appendPath:[UIBezierPath bezierPathWithOvalInRect:CGRectMake(10, 2, 6, 6)]];
        [path appendPath:[UIBezierPath bezierPathWithOvalInRect:CGRectMake(2, 18, 6, 6)]];
        [path appendPath:[UIBezierPath bezierPathWithOvalInRect:CGRectMake(18, 18, 6, 6)]];
        [path moveToPoint:CGPointMake(13, 8)]; [path addLineToPoint:CGPointMake(5, 18)];
        [path moveToPoint:CGPointMake(13, 8)]; [path addLineToPoint:CGPointMake(21, 18)];
    } else if (index == 2) {
        [path appendPath:[UIBezierPath bezierPathWithRect:CGRectMake(5, 2, 16, 22)]];
        for (int y = 8; y <= 18; y += 5) { [path moveToPoint:CGPointMake(8, y)]; [path addLineToPoint:CGPointMake(18, y)]; }
    } else {
        for (int y = 5; y <= 21; y += 8) {
            [path moveToPoint:CGPointMake(3, y)]; [path addLineToPoint:CGPointMake(6, y)];
            [path moveToPoint:CGPointMake(10, y)]; [path addLineToPoint:CGPointMake(23, y)];
        }
    }
    [[UIColor blackColor] setStroke]; [path stroke];
    UIImage *image = UIGraphicsGetImageFromCurrentImageContext(); UIGraphicsEndImageContext(); return image;
}

@interface MLRow : NSObject
@property(nonatomic,copy) NSString *title;
@property(nonatomic,copy) NSString *detail;
@property(nonatomic,copy) void (^action)(void);
@property(nonatomic,copy) void (^longAction)(void);
@property(nonatomic) BOOL selected;
+ (instancetype)title:(NSString *)title detail:(NSString *)detail action:(void (^)(void))action;
@end
@implementation MLRow
+ (instancetype)title:(NSString *)title detail:(NSString *)detail action:(void (^)(void))action {
    MLRow *row = [MLRow new]; row.title = title; row.detail = detail; row.action = action; return row;
}
@end

@interface MLScreen : UITableViewController <UIAlertViewDelegate>
@property(nonatomic,strong) NSArray *sections;
@property(nonatomic,strong) NSArray *sectionTitles;
@property(nonatomic,copy) NSString *problem;
@property(nonatomic) BOOL busy;
@property(nonatomic,copy) void (^confirmation)(void);
- (void)refresh;
- (void)reloadRows;
- (void)request:(NSString *)method params:(NSDictionary *)params completion:(void (^)(NSDictionary *result))completion;
- (void)mutate:(NSString *)method params:(NSDictionary *)params completion:(void (^)(NSDictionary *result))completion;
- (void)message:(NSString *)message;
- (void)confirm:(NSString *)message action:(void (^)(void))action;
- (void)push:(UIViewController *)controller;
- (void)waitForJob:(NSString *)identifier completion:(void (^)(NSDictionary *))completion;
- (void)showJSON:(id)data title:(NSString *)title;
@end
@interface MLChoice : MLScreen
@property(nonatomic,strong) NSArray *options;
@property(nonatomic,copy) void (^choose)(id value);
- (instancetype)initWithTitle:(NSString *)title options:(NSArray *)options choose:(void (^)(id value))choose;
@end
@interface MLText : UIViewController
@property(nonatomic,strong) UITextView *textView;
@property(nonatomic,copy) NSString *content;
@property(nonatomic,copy) NSString *configName;
@property(nonatomic,strong) NSDictionary *previousReport;
@property(nonatomic) BOOL editable;
@property(nonatomic) BOOL busy;
- (instancetype)initWithTitle:(NSString *)title text:(NSString *)text editable:(BOOL)editable;
- (void)jumpToLine:(NSUInteger)line column:(NSUInteger)column;
- (void)check;
@end
@interface MLReport : MLScreen
@property(nonatomic,strong) NSDictionary *report;
@property(nonatomic,strong) NSDictionary *previousReport;
@property(nonatomic,weak) MLText *editor;
@property(nonatomic,strong) UISegmentedControl *filter;
- (instancetype)initWithReport:(NSDictionary *)report previous:(NSDictionary *)previous editor:(MLText *)editor;
- (void)build;
@end
@interface MLInput : MLScreen <UITextFieldDelegate>
@property(nonatomic,strong) UITextField *nameField;
@property(nonatomic,strong) UITextView *input;
@property(nonatomic,copy) NSString *kind;
@property(nonatomic,copy) NSString *configID;
- (instancetype)initWithKind:(NSString *)kind initial:(NSString *)initial;
@end
@interface MLFiles : MLScreen
@end
@interface MLHome : MLScreen
@property(nonatomic,strong) NSDictionary *status;
@property(nonatomic,strong) NSTimer *timer;
@property(nonatomic) BOOL refreshingStatus;
@property(nonatomic) NSUInteger statusGeneration;
@property(nonatomic,copy) NSArray *renderedLayout;
@property(nonatomic,copy) NSString *connectionAction;
@property(nonatomic,strong) UILabel *stateLabel;
@property(nonatomic,strong) UILabel *stateMessage;
@property(nonatomic,strong) UIButton *connectButton;
@property(nonatomic,strong) UISegmentedControl *mode;
- (void)build;
- (void)updateConnectionControls;
- (void)completeConnectionRequest:(NSDictionary *)result;
- (void)pollConnectionJob:(NSString *)identifier;
@end
@interface MLGroups : MLScreen
@end
@interface MLProviders : MLScreen
@end
@interface MLProxies : MLScreen <UISearchBarDelegate>
@property(nonatomic,copy) NSString *group;
@property(nonatomic,strong) NSArray *items;
@property(nonatomic,strong) UISearchBar *search;
@property(nonatomic,strong) UISegmentedControl *sort;
@property(nonatomic,copy) NSString *selectedProxy;
@property(nonatomic,strong) NSDictionary *parentGroup;
- (instancetype)initWithGroup:(NSString *)group selected:(NSString *)selected;
- (void)build;
@end
@interface MLConfigs : MLScreen
@end
@interface MLConfigDetail : MLScreen
@property(nonatomic,strong) NSDictionary *config;
- (instancetype)initWithConfig:(NSDictionary *)config;
@end
@interface MLImport : MLScreen
@end
@interface MLLogs : MLScreen <UISearchBarDelegate>
@property(nonatomic,strong) UISegmentedControl *mode;
@property(nonatomic,strong) UISearchBar *search;
@property(nonatomic,strong) NSArray *items;
@property(nonatomic,copy) NSString *level;
@property(nonatomic) NSTimeInterval sinceInterval;
- (void)build;
@end
@interface MLConnection : MLScreen
@property(nonatomic,strong) NSDictionary *connection;
- (instancetype)initWithConnection:(NSDictionary *)connection;
@end
@interface MLSettings : MLScreen
@property(nonatomic,strong) NSDictionary *values;
- (void)build;
@end
@interface MLDNS : MLScreen
@end
@interface MLDiagnostic : MLScreen
@end

@implementation MLScreen
- (instancetype)init { return [super initWithStyle:UITableViewStylePlain]; }
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = MLColor(0xF7F7F9);
    self.tableView.backgroundColor = MLColor(0xF7F7F9);
    self.tableView.separatorColor = MLColor(0xE5E1E9);
    self.tableView.rowHeight = 56;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithCustomView:MLButton(@"刷新", self, @selector(refresh))];
    if (self.navigationController.viewControllers.count > 1)
        self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc] initWithCustomView:MLButton(@"‹ 返回", self, @selector(goBack))];
    UILongPressGestureRecognizer *press = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(longPress:)];
    [self.tableView addGestureRecognizer:press];
    [self reloadRows];
}
- (void)viewWillAppear:(BOOL)animated { [super viewWillAppear:animated]; [self refresh]; }
- (void)goBack { [self.navigationController popViewControllerAnimated:YES]; }
- (void)refresh { [self reloadRows]; }
- (void)push:(UIViewController *)controller { [self.navigationController pushViewController:controller animated:YES]; }
- (void)message:(NSString *)message {
    [[[UIAlertView alloc] initWithTitle:@"MuyuClash" message:message delegate:nil cancelButtonTitle:@"知道了" otherButtonTitles:nil] show];
}
- (void)confirm:(NSString *)message action:(void (^)(void))action {
    self.confirmation = action;
    [[[UIAlertView alloc] initWithTitle:@"请确认" message:message delegate:self cancelButtonTitle:@"取消" otherButtonTitles:@"继续", nil] show];
}
- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
    void (^action)(void) = self.confirmation; self.confirmation = nil;
    if (buttonIndex == 1 && action) action();
}
- (void)request:(NSString *)method params:(NSDictionary *)params completion:(void (^)(NSDictionary *))completion {
    __weak typeof(self) weakSelf = self;
    if (self.busy) return;
    self.busy = YES;
    self.problem = @"正在等待本机后台响应…";
    self.tableView.userInteractionEnabled = NO;
    self.navigationItem.rightBarButtonItem.enabled = NO;
    [self reloadRows];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            NSError *error = nil;
            NSDictionary *result = MLIPCRequest(MLSocket, method, params ?: @{}, &error);
            NSString *failure = error.localizedDescription ?: @"后台未返回有效结果";
            dispatch_async(dispatch_get_main_queue(), ^{
                MLScreen *screen = weakSelf; if (!screen) return;
                screen.busy = NO;
                screen.tableView.userInteractionEnabled = YES;
                screen.navigationItem.rightBarButtonItem.enabled = YES;
                screen.problem = result ? nil : [NSString stringWithFormat:@"%@：%@", method, failure];
                if (completion) completion(result);
                [screen reloadRows];
            });
        }
    });
}
- (void)mutate:(NSString *)method params:(NSDictionary *)params completion:(void (^)(NSDictionary *))completion {
    __weak typeof(self) weakSelf = self;
    [self request:method params:params completion:^(NSDictionary *result) {
        if (result[@"jobID"]) [weakSelf waitForJob:result[@"jobID"] completion:completion];
        else if (result) { if (completion) completion(result); }
        else [weakSelf message:weakSelf.problem];
    }];
}
- (void)waitForJob:(NSString *)identifier completion:(void (^)(NSDictionary *))completion {
    self.problem=@"正在下载和准备配置…";[self reloadRows];
    __weak typeof(self) weakSelf=self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC),dispatch_get_main_queue(),^{
        if(weakSelf.busy){[weakSelf waitForJob:identifier completion:completion];return;}
        [weakSelf request:@"config.job" params:@{@"id":identifier} completion:^(NSDictionary *job) {
            if([job[@"state"] isEqual:@"COMPLETE"]) { if(completion)completion(job[@"result"]); }
            else if([job[@"state"] isEqual:@"FAILED"]) [weakSelf message:job[@"error"][@"message"] ?: @"配置准备失败，原配置保留"];
            else if(job)[weakSelf waitForJob:identifier completion:completion];
            else [weakSelf message:weakSelf.problem];
        }];
    });
}
- (void)showJSON:(id)data title:(NSString *)title {
    [self push:[[MLText alloc] initWithTitle:title text:MLJSON(MLRedact(data)) editable:NO]];
}
- (void)reloadRows {
    if (!self.isViewLoaded) return;
    NSString *text = self.problem;
    if (!text && self.sections.count == 0) text = @"暂无数据。请确认本机后台服务已安装并运行，然后点刷新。";
    if (text) {
        CGFloat width = MAX(100, self.view.bounds.size.width - 32);
        CGFloat height = MAX(72, [text sizeWithFont:[UIFont systemFontOfSize:13]
                                constrainedToSize:CGSizeMake(width, CGFLOAT_MAX)
                                    lineBreakMode:NSLineBreakByWordWrapping].height + 28);
        UILabel *footer = [[UILabel alloc] initWithFrame:CGRectMake(16, 0, width, height)];
        footer.backgroundColor = [UIColor clearColor]; footer.textColor = MLMuted();
        footer.font = [UIFont systemFontOfSize:13]; footer.numberOfLines = 0;
        footer.text = text;
        UIView *container = [[UIView alloc] initWithFrame:CGRectMake(0, 0, self.view.bounds.size.width, height)];
        [container addSubview:footer]; self.tableView.tableFooterView = container;
    } else self.tableView.tableFooterView = [UIView new];
    [self.tableView reloadData];
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return self.sections.count; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section { return [self.sections[section] count]; }
- (CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section {
    NSString *title=(NSUInteger)section<self.sectionTitles.count?self.sectionTitles[section]:@"";
    return [title rangeOfString:@"\n"].location==NSNotFound?32:52;
}
- (UIView *)tableView:(UITableView *)tableView viewForHeaderInSection:(NSInteger)section {
    UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, tableView.bounds.size.width, [self tableView:tableView heightForHeaderInSection:section])];
    label.backgroundColor = MLColor(0xF0EDF4); label.font = [UIFont boldSystemFontOfSize:13]; label.textColor = MLAccent();
    NSString *title = section >= 0 && (NSUInteger)section < self.sectionTitles.count ? self.sectionTitles[section] : @"";
    label.numberOfLines=2;label.text = [@"    " stringByAppendingString:title]; return label;
}
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"row"];
    if (!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"row"];
    MLRow *row = self.sections[indexPath.section][indexPath.row];
    cell.backgroundColor = [UIColor whiteColor]; cell.textLabel.text = row.title;
    cell.textLabel.font = [UIFont systemFontOfSize:15]; cell.textLabel.textColor = MLTextColor();
    cell.textLabel.lineBreakMode = NSLineBreakByTruncatingTail;
    cell.detailTextLabel.text = row.detail; cell.detailTextLabel.font = [UIFont systemFontOfSize:12];
    cell.detailTextLabel.textColor = MLMuted(); cell.detailTextLabel.numberOfLines = 2;
    cell.detailTextLabel.lineBreakMode = NSLineBreakByTruncatingTail;
    cell.accessoryType = row.selected ? UITableViewCellAccessoryCheckmark : (row.action ? UITableViewCellAccessoryDisclosureIndicator : UITableViewCellAccessoryNone);
    cell.selectionStyle = row.action ? UITableViewCellSelectionStyleGray : UITableViewCellSelectionStyleNone;
    UIView *selection = [UIView new]; selection.backgroundColor = MLColor(0xF0EDF4); cell.selectedBackgroundView = selection;
    cell.accessibilityLabel = [NSString stringWithFormat:@"%@，%@%@", row.title, row.detail ?: @"", row.selected ? @"，已选择" : @""];
    return cell;
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    MLRow *row = self.sections[indexPath.section][indexPath.row];
    if (!self.busy && row.action) row.action();
}
- (void)longPress:(UILongPressGestureRecognizer *)recognizer {
    if (recognizer.state != UIGestureRecognizerStateBegan || self.busy) return;
    NSIndexPath *path = [self.tableView indexPathForRowAtPoint:[recognizer locationInView:self.tableView]];
    if (!path) return;
    MLRow *row = self.sections[path.section][path.row]; if (row.longAction) row.longAction();
}
@end

@implementation MLChoice
- (instancetype)initWithTitle:(NSString *)title options:(NSArray *)options choose:(void (^)(id))choose {
    if ((self = [super init])) { self.title = title; self.options = options; self.choose = choose; } return self;
}
- (void)refresh {
    __weak typeof(self) weakSelf = self;
    NSMutableArray *rows = [NSMutableArray array];
    for (NSDictionary *option in self.options) {
        [rows addObject:[MLRow title:option[@"title"] detail:option[@"detail"] action:^{
            void (^choose)(id) = weakSelf.choose;
            [weakSelf.navigationController popViewControllerAnimated:YES]; if (choose) choose(option[@"value"]);
        }]];
    }
    self.sections = @[rows]; self.sectionTitles = @[@"选择后提交到后台确认"]; [self reloadRows];
}
@end

@implementation MLHome
- (void)viewDidLoad {
    [super viewDidLoad]; self.title = @"MuyuClash";
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithCustomView:MLButton(@"设置", self, @selector(settings))];
    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 320, 154)];
    header.backgroundColor = [UIColor whiteColor]; header.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    self.stateLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 12, 190, 28)];
    self.stateLabel.font = [UIFont boldSystemFontOfSize:22]; self.stateLabel.textColor = MLTextColor();
    self.stateLabel.backgroundColor = [UIColor clearColor]; [header addSubview:self.stateLabel];
    self.stateMessage = [[UILabel alloc] initWithFrame:CGRectMake(16, 44, 192, 46)];
    self.stateMessage.numberOfLines = 2; self.stateMessage.font = [UIFont systemFontOfSize:12];
    self.stateMessage.textColor = MLMuted(); self.stateMessage.backgroundColor = [UIColor clearColor];
    [header addSubview:self.stateMessage];
    self.connectButton = MLButton(@"连接", self, @selector(connect));
    self.connectButton.frame = CGRectMake(224, 20, 80, 48);
    self.connectButton.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin;
    self.connectButton.backgroundColor = MLAccent(); self.connectButton.layer.cornerRadius = 4;
    [self.connectButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [self.connectButton setTitleColor:[UIColor whiteColor] forState:UIControlStateDisabled];
    [self.connectButton setTitleColor:[UIColor whiteColor] forState:UIControlStateHighlighted];
    self.connectButton.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    [header addSubview:self.connectButton];
    self.mode = [[UISegmentedControl alloc] initWithItems:@[@"按规则", @"全局代理", @"直连"]];
    self.mode.frame = CGRectMake(16, 98, 288, 44); self.mode.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    MLStyleSegments(self.mode);
    [self.mode addTarget:self action:@selector(modeChanged) forControlEvents:UIControlEventValueChanged];
    [header addSubview:self.mode]; self.tableView.tableHeaderView = header; [self build];
}
- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self.timer invalidate]; self.timer = [NSTimer scheduledTimerWithTimeInterval:2 target:self selector:@selector(refresh) userInfo:nil repeats:YES];
}
- (void)viewWillDisappear:(BOOL)animated { [super viewWillDisappear:animated]; [self.timer invalidate]; self.timer = nil; }
- (void)settings { [self push:[MLSettings new]]; }
- (void)refresh {
    __weak typeof(self) weakSelf = self;
    if (self.busy || self.connectionAction || self.refreshingStatus || self.navigationController.topViewController != self || [UIApplication sharedApplication].applicationState != UIApplicationStateActive) return;
    // Polling keeps the existing controls and rows visible and interactive.
    self.refreshingStatus = YES;
    NSUInteger generation = ++self.statusGeneration;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            NSError *error = nil;
            NSDictionary *result = MLIPCRequest(MLSocket, @"service.status", @{}, &error);
            NSString *failure = error.localizedDescription ?: @"后台未返回有效结果";
            dispatch_async(dispatch_get_main_queue(), ^{
                MLHome *screen = weakSelf;
                if (!screen || screen.statusGeneration != generation) return;
                screen.refreshingStatus = NO;
                if (screen.busy) return;
                screen.problem = result ? nil : [@"service.status：" stringByAppendingString:failure];
                if (result) screen.status = result;
                [screen build];
            });
        }
    });
}
- (void)connect {
    __weak typeof(self) weakSelf = self;
    if (self.busy || self.connectionAction) return;
    if (!self.status) { [self refresh]; return; }
    self.statusGeneration++; self.refreshingStatus = NO;
    NSString *state = MLString(self.status[@"state"]);
    BOOL active = [@[@"RUNNING", @"DEGRADED", @"RECOVERING"] containsObject:state];
    self.connectionAction=active ? @"stop" : @"start";
    [self updateConnectionControls];
    [self request:active ? @"service.stop" : @"service.start" params:nil completion:^(NSDictionary *result) { [weakSelf completeConnectionRequest:result]; }];
}
- (void)completeConnectionRequest:(NSDictionary *)result {
    if (result[@"jobID"]) { self.connectionAction=@"prepare";[self pollConnectionJob:result[@"jobID"]];return; }
    self.connectionAction=nil;
    if (result[@"state"]) {
        NSMutableDictionary *status=[self.status mutableCopy] ?: [NSMutableDictionary dictionary];
        [status addEntriesFromDictionary:result];
        if ([result[@"state"] isEqual:@"STOPPED"]) {
            [status removeObjectsForKeys:@[@"statistics",@"group",@"actual",@"protocol",@"latency"]];
            status[@"message"]=@"已断开连接";
        }
        self.status=status;
    }
    [self build];
    if (!result) [self message:self.problem ?: @"连接操作失败，请重试"];
    [self refresh];
}
- (void)pollConnectionJob:(NSString *)identifier {
    [self updateConnectionControls];
    __weak typeof(self) weakSelf=self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC),dispatch_get_main_queue(),^{
        MLHome *screen=weakSelf;if (!screen || !screen.connectionAction) return;
        [screen request:@"config.job" params:@{@"id":identifier} completion:^(NSDictionary *job) {
            MLHome *home=weakSelf;if (!home) return;
            if ([job[@"state"] isEqual:@"COMPLETE"]) [home completeConnectionRequest:job[@"result"] ?: @{}];
            else if (!job || [job[@"state"] isEqual:@"FAILED"]) {
                if (job) home.problem=job[@"error"][@"message"] ?: @"配置准备失败，原配置保留";
                [home completeConnectionRequest:nil];
            } else [home pollConnectionJob:identifier];
        }];
    });
}
- (void)updateConnectionControls {
    NSString *state=MLString(self.status[@"state"]);
    BOOL stopping=[self.connectionAction isEqual:@"stop"] || [state isEqual:@"STOPPING"];
    BOOL preparing=[self.connectionAction isEqual:@"prepare"] || [state isEqual:@"PREPARING"];
    BOOL validating=[state isEqual:@"VALIDATING"];
    BOOL starting=[self.connectionAction isEqual:@"start"] || [state isEqual:@"STARTING"];
    BOOL active=[@[@"RUNNING",@"DEGRADED",@"RECOVERING"] containsObject:state];
    NSString *title=!self.status ? @"读取中…" : stopping ? @"断开中…" : preparing ? @"准备中…" : validating ? @"检查中…" : starting ? @"连接中…" : active ? @"断开" : @"连接";
    if (![[self.connectButton titleForState:UIControlStateNormal] isEqual:title]) [self.connectButton setTitle:title forState:UIControlStateNormal];
    self.connectButton.accessibilityLabel=title;
    self.connectButton.enabled=self.status && !self.busy && !self.connectionAction && [@[@"STOPPED",@"FAILED",@"RUNNING",@"DEGRADED",@"RECOVERING"] containsObject:state];
    self.mode.enabled=self.status && !self.busy && !self.connectionAction;
    NSString *label=self.status ? MLState(state) : @"等待后台";
    NSString *message=self.status ? MLString(self.status[@"message"]) : @"读取本机服务状态后显示连接信息";
    if (self.connectionAction) {
        label=stopping ? @"正在断开" : preparing ? @"正在准备配置" : @"正在连接";
        message=stopping ? @"正在停止代理并恢复网络，请稍候" : preparing ? @"正在准备配置与规则，完成后自动连接" : @"正在启动本机代理，成功后按钮显示“断开”";
    } else if (self.status && self.problem && !self.busy) label=[@"上次：" stringByAppendingString:label];
    if (![self.stateLabel.text isEqual:label]) self.stateLabel.text=label;
    if (![self.stateMessage.text isEqual:message]) self.stateMessage.text=message;
}
- (void)modeChanged {
    __weak typeof(self) weakSelf = self;
    NSInteger index = self.mode.selectedSegmentIndex;
    if (index < 0 || index > 2) return;
    self.statusGeneration++; self.refreshingStatus = NO;
    NSString *requested = @[@"Rule", @"Global", @"Direct"][index];
    // Revert the optimistic UIKit highlight immediately; only an acknowledged
    // service.status value can change the displayed selection.
    [self build];
    [self mutate:@"service.mode" params:@{@"mode":requested} completion:^(NSDictionary *result) { [weakSelf refresh]; }];
}
- (void)build {
    __weak typeof(self) weakSelf = self;
    [self updateConnectionControls];
    NSArray *modes = @[@"Rule", @"Global", @"Direct"];
    NSUInteger index = [modes indexOfObject:MLString(self.status[@"mode"])];
    NSInteger selected = index == NSNotFound ? UISegmentedControlNoSegment : (NSInteger)index;
    if (self.mode.selectedSegmentIndex != selected) self.mode.selectedSegmentIndex = selected;
    if (!self.status) { self.sections = @[]; self.sectionTitles = @[]; [self reloadRows]; return; }
    id activeConfig = self.status[@"activeConfig"];
    NSString *configName = [activeConfig isKindOfClass:[NSDictionary class]] ? MLString(activeConfig[@"name"]) : MLString(activeConfig);
    if ([activeConfig isKindOfClass:[NSDictionary class]] && [self.status[@"configurationReady"] isEqual:@NO])
        configName=[configName stringByAppendingString:@" · 待准备"];
    NSDictionary *outbound=MLDict(self.status[@"statistics"][@"outbound"]);
    NSString *group = MLString(outbound[@"group"] ?: self.status[@"group"]);
    NSString *actual = MLString(outbound[@"actual"] ?: self.status[@"actual"]);
    BOOL hasGroup=group.length && ![group isEqual:@"—"];
    BOOL recent=[outbound[@"source"] isEqual:@"recent"];
    NSString *protocol=MLString(outbound[@"protocol"] ?: self.status[@"protocol"]);
    protocol=[protocol isEqual:@"direct"] ? @"直连" : [protocol isEqual:@"reject"] ? @"拒绝连接" : [protocol uppercaseString];
    NSString *latency=@"未测速";id delay=outbound[@"latency"] ?: self.status[@"latency"];
    NSString *health=outbound[@"latencyState"];
    if ([health isEqual:@"testing"]) latency=@"测速中…";
    else if ([@[@"failed",@"invalid"] containsObject:health ?: @""]) latency=@"测速失败";
    else if ([health isEqual:@"timeout"]) latency=@"测速超时";
    else if ([health isEqual:@"not-applicable"]) latency=@"不适用";
    else if ([delay isKindOfClass:[NSNumber class]]) latency=[NSString stringWithFormat:@"%.0f ms",[delay doubleValue]];
    NSString *state=MLString(self.status[@"state"]);
    BOOL connected=[@[@"RUNNING",@"DEGRADED",@"RECOVERING"] containsObject:state];
    if (!connected) {group=@"连接后显示";actual=@"连接后显示";protocol=@"未连接";latency=@"连接后测速";hasGroup=NO;}
    NSArray *current = @[
        [MLRow title:@"当前配置" detail:configName action:^{ weakSelf.tabBarController.selectedIndex = 2; }],
        [MLRow title:recent ? @"最近命中策略组" : @"当前默认策略组" detail:hasGroup ? group : connected ? @"直连或节点直出（未经过策略组）" : group action:^{
            if (!hasGroup) weakSelf.tabBarController.selectedIndex = 1;
            else [weakSelf push:[[MLProxies alloc] initWithGroup:group selected:nil]];
        }],
        [MLRow title:recent ? @"最近实际出口节点" : @"待使用出口节点" detail:actual action:nil],
        [MLRow title:@"节点协议与延迟" detail:[NSString stringWithFormat:@"%@ · %@",protocol,latency] action:nil]
    ];
    NSDictionary *stats = MLDict(self.status[@"statistics"]);
    NSArray *traffic = @[
        [MLRow title:@"实时上传 / 下载" detail:[NSString stringWithFormat:@"%@/s  ↑    %@/s  ↓", MLBytes(stats[@"uploadRate"]), MLBytes(stats[@"downloadRate"])] action:nil],
        [MLRow title:@"本次上传 / 下载" detail:[NSString stringWithFormat:@"%@  ↑    %@  ↓", MLBytes(stats[@"uploadBytes"]), MLBytes(stats[@"downloadBytes"])] action:nil],
        [MLRow title:@"连接时长 / 活动连接" detail:[NSString stringWithFormat:@"%@ 秒 · %@ 条", MLString(stats[@"duration"]), MLString(stats[@"connections"])] action:nil]
    ];
    NSDictionary *coverage = MLDict(self.status[@"coverage"]);
    NSMutableArray *network = [NSMutableArray array];
    for (NSString *key in @[@"tcp", @"udp", @"ipv4", @"ipv6", @"dns"])
        [network addObject:[MLRow title:[key uppercaseString] detail:MLString(coverage[key]) action:nil]];
    NSNumber *port = self.status[@"listeners"][@"socks5"];
    if ([port isKindOfClass:[NSNumber class]])
        [network addObject:[MLRow title:@"SOCKS5 / HTTP CONNECT" detail:[NSString stringWithFormat:@"127.0.0.1:%@",port] action:nil]];
    [network addObject:[MLRow title:@"网络诊断" detail:@"核对当前设备与后台能力" action:^{ [weakSelf push:[MLDiagnostic new]]; }]];
    self.sections = @[current, traffic, network]; self.sectionTitles = @[@"当前代理", @"流量统计 · 后台测量值", @"网络覆盖 · 分项状态"];
    [self reloadRows];
}
- (void)reloadRows {
    if (!self.isViewLoaded) return;
    NSMutableArray *counts = [NSMutableArray array];
    for (NSArray *section in self.sections) [counts addObject:@(section.count)];
    NSArray *layout = @[self.sectionTitles ?: @[], counts, self.problem ?: @""];
    if (![self.renderedLayout isEqual:layout]) {
        [super reloadRows];
        self.renderedLayout = layout;
    } else {
        // Updating visible labels avoids reloadData's full redraw on iOS 6.
        for (NSIndexPath *path in [self.tableView indexPathsForVisibleRows]) {
            if ((NSUInteger)path.section >= self.sections.count || (NSUInteger)path.row >= [self.sections[path.section] count]) continue;
            MLRow *row = self.sections[path.section][path.row];
            UITableViewCell *cell = [self.tableView cellForRowAtIndexPath:path];
            if (![cell.textLabel.text isEqual:row.title]) cell.textLabel.text = row.title;
            if (![cell.detailTextLabel.text isEqual:row.detail]) cell.detailTextLabel.text = row.detail;
            cell.accessoryType = row.selected ? UITableViewCellAccessoryCheckmark : (row.action ? UITableViewCellAccessoryDisclosureIndicator : UITableViewCellAccessoryNone);
            cell.selectionStyle = row.action ? UITableViewCellSelectionStyleGray : UITableViewCellSelectionStyleNone;
            cell.accessibilityLabel = [NSString stringWithFormat:@"%@，%@%@", row.title, row.detail ?: @"", row.selected ? @"，已选择" : @""];
        }
    }
    [self updateConnectionControls];
}
@end

@implementation MLGroups
- (void)viewDidLoad { [super viewDidLoad]; self.title = @"代理"; }
- (void)refresh {
    __weak typeof(self) weakSelf = self;
    [self request:@"group.list" params:nil completion:^(NSDictionary *result) {
        if (!result) return;
        NSMutableArray *rows = [NSMutableArray array];
        for (NSDictionary *group in MLArray(result[@"items"])) {
            if (![group isKindOfClass:[NSDictionary class]]) continue;
            NSString *name = MLString(group[@"name"]);
            NSString *detail = [NSString stringWithFormat:@"%@ · 选择 %@\n实际 %@ · %@", MLString(group[@"type"]), MLString(group[@"selected"]), MLString(group[@"actual"]), MLString(group[@"health"])];
            MLRow *row = [MLRow title:name detail:detail action:^{ [weakSelf push:[[MLProxies alloc] initWithGroup:name selected:group[@"selected"]]]; }];
            row.longAction = ^{ [weakSelf showJSON:group title:@"策略组详情"]; }; [rows addObject:row];
        }
        weakSelf.sections = rows.count ? @[rows] : @[]; weakSelf.sectionTitles = @[@"策略组 · 长按查看详情"];
        if (!rows.count) weakSelf.problem = @"尚无策略组。请先导入并应用可用配置。";
    }];
}
@end

@implementation MLProxies
- (instancetype)initWithGroup:(NSString *)group selected:(NSString *)selected {
    if ((self = [super init])) { self.group = group; self.title = group; self.selectedProxy = selected; } return self;
}
- (void)viewDidLoad {
    [super viewDidLoad];
    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 320, 104)];
    self.search = [[UISearchBar alloc] initWithFrame:CGRectMake(0, 0, 320, 52)];
    self.search.delegate = self; self.search.placeholder = @"搜索节点名称或协议"; self.search.tintColor = MLAccent();
    self.search.backgroundImage = MLFill(MLColor(0xF7F7F9));
    self.search.autoresizingMask = UIViewAutoresizingFlexibleWidth; [header addSubview:self.search];
    self.sort = [[UISegmentedControl alloc] initWithItems:@[@"原始顺序", @"延迟", @"名称"]];
    self.sort.frame = CGRectMake(12, 56, 296, 44); self.sort.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    MLStyleSegments(self.sort); self.sort.selectedSegmentIndex = 0;
    [self.sort addTarget:self action:@selector(build) forControlEvents:UIControlEventValueChanged]; [header addSubview:self.sort];
    self.tableView.tableHeaderView = header;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithCustomView:MLButton(@"测速", self, @selector(testAll))];
}
- (void)refresh {
    __weak typeof(self) weakSelf = self;
    [self request:@"proxy.list" params:@{@"group":self.group} completion:^(NSDictionary *result) {
        if (result) { weakSelf.items = MLArray(result[@"items"]); weakSelf.parentGroup=result[@"group"]; if (result[@"selected"]) weakSelf.selectedProxy = result[@"selected"]; [weakSelf build]; }
    }];
}
- (void)pollProbeResults:(NSUInteger)remaining {
    if (!remaining) return;
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC),dispatch_get_main_queue(),^{
        MLProxies *screen = weakSelf;
        if (!screen || !screen.isViewLoaded || !screen.view.window) return;
        [screen refresh];
        [screen pollProbeResults:remaining-1];
    });
}
- (void)testAll {
    __weak typeof(self) weakSelf = self;
    [self mutate:@"proxy.test" params:@{@"group":self.group} completion:^(NSDictionary *result) {
        [weakSelf refresh];
        [weakSelf pollProbeResults:MIN((NSUInteger)45,[result[@"queued"] unsignedIntegerValue]*2+1)];
    }];
}
- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText { [self build]; }
- (void)searchBarSearchButtonClicked:(UISearchBar *)searchBar { [searchBar resignFirstResponder]; }
- (void)build {
    __weak typeof(self) weakSelf = self;
    NSMutableArray *items = [NSMutableArray array];
    NSString *query = self.search.text ?: @"";
    for (NSDictionary *node in self.items) {
        if (![node isKindOfClass:[NSDictionary class]]) continue;
        NSString *text = [NSString stringWithFormat:@"%@ %@", MLString(node[@"name"]), MLString(node[@"type"])];
        if (query.length == 0 || [text rangeOfString:query options:NSCaseInsensitiveSearch].location != NSNotFound) [items addObject:node];
    }
    NSInteger sort = self.sort.selectedSegmentIndex;
    if (sort == 1) [items sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSNumber *ad = [a[@"delay"] isKindOfClass:[NSNumber class]] && [a[@"delay"] doubleValue] > 0 ? a[@"delay"] : @(DBL_MAX);
        NSNumber *bd = [b[@"delay"] isKindOfClass:[NSNumber class]] && [b[@"delay"] doubleValue] > 0 ? b[@"delay"] : @(DBL_MAX);
        return [ad compare:bd];
    }];
    if (sort == 2) [items sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) { return [MLString(a[@"name"]) localizedCaseInsensitiveCompare:MLString(b[@"name"])]; }];
    NSMutableArray *rows = [NSMutableArray array];
    for (NSDictionary *node in items) {
        NSString *name = MLString(node[@"name"]);
        id delay = node[@"delay"];
        NSString *latency = [delay isKindOfClass:[NSNumber class]] && [delay doubleValue] > 0 ? [NSString stringWithFormat:@"%@ ms", delay] : @"—";
        if ([node[@"health"] isEqual:@"timeout"]) latency = @"超时";
        if ([node[@"health"] isEqual:@"testing"]) latency = @"测速中";
        if ([node[@"health"] isEqual:@"failed"]) latency = @"连接失败";
        MLRow *row = [MLRow title:name detail:[NSString stringWithFormat:@"%@ · %@ · %@", MLString(node[@"type"]), latency, MLString(node[@"health"])] action:^{
            if ([MLString(node[@"type"]) isEqualToString:@"group"]) { [weakSelf push:[[MLProxies alloc] initWithGroup:name selected:nil]]; return; }
            if(![weakSelf.parentGroup[@"manualSelectable"] boolValue]) { [weakSelf showJSON:node title:@"节点详情"];return; }
            [weakSelf mutate:@"group.select" params:@{@"group":weakSelf.group, @"proxy":name} completion:^(NSDictionary *result) {
                weakSelf.selectedProxy = [result[@"selected"] isKindOfClass:[NSString class]] ? result[@"selected"] : name;
                [weakSelf refresh];
            }];
        }];
        row.selected = [node[@"selected"] boolValue] || [self.selectedProxy isEqualToString:name];
        row.longAction = ^{
            MLScreen *detail = [MLScreen new]; detail.title = @"节点详情";
            __weak MLScreen *weakDetail = detail;
            detail.sectionTitles = @[@"节点", @"操作"];
            NSMutableArray *actions = [NSMutableArray array];
            if ([node[@"type"] isEqual:@"group"]&&[weakSelf.parentGroup[@"manualSelectable"] boolValue]) {
                [actions addObject:[MLRow title:@"选为当前策略组出口" detail:name action:^{
                    [weakDetail mutate:@"group.select" params:@{@"group":weakSelf.group,@"proxy":name}
                            completion:^(NSDictionary *result) { [weakSelf refresh]; [weakDetail message:@"已选中"]; }];
                }]];
            } else if(![node[@"type"] isEqual:@"group"]) {
                [actions addObject:[MLRow title:@"单节点测速" detail:@"结果由本机核心测量" action:^{
                    [weakDetail mutate:@"proxy.test" params:@{@"group":weakSelf.group,@"proxy":name}
                            completion:^(NSDictionary *result) { [weakSelf pollProbeResults:3]; [weakDetail message:@"测速已提交，返回列表查看延迟"]; }];
                }]];
            }
            detail.sections = @[@[[MLRow title:name detail:MLString(node[@"type"]) action:^{ [weakDetail showJSON:node title:@"节点属性"]; }]], actions];
            [weakSelf push:detail];
        };
        [rows addObject:row];
    }
    self.sections = rows.count ? @[rows] : @[];
    NSString *type=MLString(self.parentGroup[@"type"]), *actual=MLString(self.parentGroup[@"actual"]);
    self.sectionTitles = @[[NSString stringWithFormat:@"%@ · 实际 %@\n%@",type,actual,[self.parentGroup[@"manualSelectable"] boolValue]?@"点选切换 · 长按详情和测速":@"自动选路 · 点选详情 · 长按测速"]];
    if (!rows.count && !self.busy) self.problem = query.length ? @"没有匹配的节点。" : @"此策略组尚未提供节点。";
    else if (!self.busy) self.problem = nil;
    [self reloadRows];
}
@end

@implementation MLProviders
- (void)viewDidLoad {
    [super viewDidLoad];self.title=@"Provider";
    self.navigationItem.rightBarButtonItem=[[UIBarButtonItem alloc]initWithCustomView:MLButton(@"更新",self,@selector(updateAll))];
}
- (void)updateAll {
    __weak typeof(self) weakSelf=self;
    [self mutate:@"provider.update" params:nil completion:^(NSDictionary *result){[weakSelf refresh];}];
}
- (void)refresh {
    __weak typeof(self) weakSelf=self;
    [self request:@"provider.list" params:nil completion:^(NSDictionary *result){
        if(!result)return;
        NSMutableArray *rows=[NSMutableArray array];
        for(NSDictionary *provider in MLArray(result[@"items"])) {
            NSString *name=MLString(provider[@"name"]), *kind=[provider[@"kind"] isEqual:@"proxy"]?@"节点":@"规则";
            NSString *state=[provider[@"status"] isEqual:@"cached"]?@"更新失败，使用缓存":@"已就绪";
            NSString *source=(@{@"http":@"远程",@"file":@"本地文件",@"inline":@"内联"})[MLString(provider[@"type"])] ?: @"";
            MLRow *row=[MLRow title:name detail:[NSString stringWithFormat:@"%@ · %@ 条 · %@\n%@",kind,provider[@"count"] ?: @0,source,state] action:^{
                MLScreen *detail=[MLScreen new];detail.title=name;__weak MLScreen *weakDetail=detail;
                NSMutableArray *actions=[NSMutableArray array];
                if(![provider[@"type"] isEqual:@"inline"])[actions addObject:[MLRow title:@"手动更新" detail:@"准备成功后切换，失败继续使用缓存" action:^{
                    [weakDetail mutate:@"provider.update" params:@{@"name":name} completion:^(NSDictionary *updated){[weakSelf refresh];[weakDetail message:@"后台已确认更新"]; }];
                }]];
                [actions addObject:[MLRow title:@"查看详情" detail:@"来源、缓存与更新诊断" action:^{[weakDetail showJSON:provider title:@"Provider 详情"];}]];
                detail.sectionTitles=@[@"当前活动配置的来源",@"操作"];
                detail.sections=@[@[[MLRow title:kind detail:state action:nil],
                    [MLRow title:@"最近成功更新" detail:MLDate(provider[@"updatedAt"]) action:nil],
                    [MLRow title:@"更新间隔" detail:[provider[@"interval"] doubleValue]>0?[NSString stringWithFormat:@"%@ 秒",provider[@"interval"]]:@"仅手动更新" action:nil]],actions];
                [weakSelf push:detail];
            }];[rows addObject:row];
        }
        MLRow *local=[MLRow title:@"导入本地 Provider 文件" detail:@"填写配置引用的相对路径及 YAML / 文本内容" action:^{[weakSelf push:[[MLInput alloc]initWithKind:@"provider" initial:@""]];}];
        weakSelf.sections=@[rows,@[local]];weakSelf.sectionTitles=@[@"当前活动配置的 Provider",@"本地文件"];
        if(!rows.count)weakSelf.problem=@"当前活动配置没有 Provider。请先应用包含 Provider 的配置。";
    }];
}
@end

@implementation MLConfigs
- (void)viewDidLoad {
    [super viewDidLoad]; self.title = @"配置";
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithCustomView:MLButton(@"导入", self, @selector(importConfig))];
}
- (void)importConfig { [self push:[MLImport new]]; }
- (void)refresh {
    __weak typeof(self) weakSelf = self;
    [self request:@"config.list" params:nil completion:^(NSDictionary *result) {
        if (!result) return;
        NSMutableArray *rows = [NSMutableArray array];
        for (NSDictionary *config in MLArray(result[@"items"])) {
            if (![config isKindOfClass:[NSDictionary class]]) continue;
            NSString *detail = [NSString stringWithFormat:@"%@ 个节点 · %@\n更新 %@ · %@", MLString(config[@"nodeCount"]), MLString(config[@"status"]), MLDate(config[@"updatedAt"]), MLSourceLabel(config[@"source"])];
            MLRow *row = [MLRow title:MLString(config[@"name"]) detail:detail action:^{ [weakSelf push:[[MLConfigDetail alloc] initWithConfig:config]]; }];
            row.selected = [config[@"active"] boolValue]; [rows addObject:row];
        }
        weakSelf.sections = rows.count ? @[rows] : @[]; weakSelf.sectionTitles = @[@"本机配置 · 勾选为后台当前配置"];
        if (!rows.count) weakSelf.problem = @"还没有配置。点右上角导入 YAML、订阅或本地文件。导入不会自动启用配置。";
    }];
}
@end

@implementation MLConfigDetail
- (instancetype)initWithConfig:(NSDictionary *)config {
    if ((self = [super init])) { self.config = config; self.title = MLString(config[@"name"]); } return self;
}
- (NSDictionary *)identifier { return @{@"id":MLString(self.config[@"id"])}; }
- (void)sourceForCheck:(BOOL)check {
    __weak typeof(self) weakSelf = self;
    [self request:@"config.source" params:[self identifier] completion:^(NSDictionary *result) {
        if (!result) { [weakSelf message:weakSelf.problem]; return; }
        NSString *yaml = result[@"yaml"];
        if (![yaml isKindOfClass:[NSString class]]) { [weakSelf message:@"后台未提供 YAML 原文。"]; return; }
        MLText *editor = [[MLText alloc] initWithTitle:@"配置源文件" text:yaml editable:YES];
        editor.configName = MLString(result[@"name"] ?: weakSelf.config[@"name"]);
        [weakSelf push:editor]; if (check) [editor check];
    }];
}
- (void)refresh {
    __weak typeof(self) weakSelf = self;
    self.sectionTitles = @[@"配置操作", @"订阅与维护"];
    self.sections = @[@[
        [MLRow title:@"应用此配置" detail:@"检查和准备成功后，由后台原子切换" action:^{
            [weakSelf mutate:@"config.apply" params:[weakSelf identifier] completion:^(NSDictionary *result) { [weakSelf message:@"配置已应用，可返回首页连接。"]; }];
        }],
        [MLRow title:@"查看与编辑 YAML" detail:@"可检查、复制原文或另存候选配置" action:^{ [weakSelf sourceForCheck:NO]; }],
        [MLRow title:@"兼容性检查" detail:@"解析错误、功能不兼容与运行警告" action:^{ [weakSelf sourceForCheck:YES]; }],
        [MLRow title:@"导出原始 YAML" detail:@"打开原文后复制；其中可能包含节点凭据" action:^{ [weakSelf sourceForCheck:NO]; }]
    ], @[
        [MLRow title:@"手动更新订阅" detail:@"后台验证新内容后保留为候选配置" action:^{ [weakSelf mutate:@"config.update" params:[weakSelf identifier] completion:^(NSDictionary *result) { [weakSelf showJSON:result title:@"订阅更新结果"]; }]; }],
        [MLRow title:@"名称与订阅地址" detail:@"提交元数据修改到后台" action:^{
            MLInput *input = [[MLInput alloc] initWithKind:@"metadata" initial:[weakSelf.config[@"source"] isKindOfClass:[NSString class]] ? weakSelf.config[@"source"] : @""];
            [input view]; input.nameField.text = MLString(weakSelf.config[@"name"]);
            input.configID = MLString(weakSelf.config[@"id"]);
            [weakSelf push:input];
        }],
        [MLRow title:@"自动更新间隔" detail:@"只有后台实现的调度能力才能启用" action:^{
            [weakSelf push:[[MLChoice alloc] initWithTitle:@"自动更新" options:@[
                @{@"title":@"关闭", @"value":@0}, @{@"title":@"每 6 小时", @"value":@21600},
                @{@"title":@"每天", @"value":@86400}] choose:^(id value) {
                    [weakSelf mutate:@"config.schedule" params:@{@"id":MLString(weakSelf.config[@"id"]), @"interval":value} completion:^(NSDictionary *result) { [weakSelf message:@"后台已确认更新计划。"]; }];
                }]];
        }],
        [MLRow title:@"Provider 管理" detail:@"当前活动配置的节点、规则来源与缓存" action:^{[weakSelf push:[MLProviders new]];}],
        [MLRow title:@"更新全部 Provider" detail:@"验证候选后原子切换，失败保留当前配置" action:^{ [weakSelf mutate:@"provider.update" params:nil completion:^(NSDictionary *result) { [weakSelf message:@"Provider 更新已完成"]; }]; }],
        [MLRow title:@"本地覆盖项" detail:@"请求后台读取独立覆盖项" action:^{ [weakSelf request:@"config.overrides" params:[weakSelf identifier] completion:^(NSDictionary *result) { if (result) [weakSelf showJSON:result title:@"本地覆盖项"]; else [weakSelf message:weakSelf.problem]; }]; }],
        [MLRow title:@"备份配置" detail:@"由后台创建受保护的配置备份" action:^{ [weakSelf mutate:@"config.backup" params:[weakSelf identifier] completion:^(NSDictionary *result) { [weakSelf showJSON:result title:@"备份结果"]; }]; }],
        [MLRow title:@"删除此配置" detail:@"后台拒绝删除仍在使用的配置" action:^{
            [weakSelf confirm:@"删除此配置？活动配置需要先切换或停止使用。" action:^{
                [weakSelf mutate:@"config.delete" params:[weakSelf identifier] completion:^(NSDictionary *result) { [weakSelf.navigationController popViewControllerAnimated:YES]; }];
            }];
        }]
    ]];
    [self reloadRows];
}
@end

@implementation MLImport
- (void)viewDidLoad { [super viewDidLoad]; self.title = @"导入配置"; }
- (void)openScannedText:(NSString *)value {
    NSString *text = [value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!text.length) { [self message:@"识别结果没有文字"]; return; }
    NSString *kind = @"uri";
    if ([text hasPrefix:@"https://"] && [text rangeOfString:@"\n"].location == NSNotFound) {
        NSURL *url = [NSURL URLWithString:text];
        if (url.host.length && !url.user && !url.password) kind = @"url";
    } else if ([text hasPrefix:@"{"] || [text hasPrefix:@"---"] ||
               [text rangeOfString:@"^([A-Za-z0-9_-]+):[ \t\r\n]" options:NSRegularExpressionSearch].location != NSNotFound) {
        kind = @"yaml";
    }
    [self push:[[MLInput alloc] initWithKind:kind initial:text]];
}
- (void)refresh {
    __weak typeof(self) weakSelf = self;
    self.sectionTitles = @[@"选择导入来源"];
    self.sections = @[@[
        [MLRow title:@"URL 订阅" detail:@"由本机后台下载并校验；保持 TLS 证书验证" action:^{ [weakSelf push:[[MLInput alloc] initWithKind:@"url" initial:@""]]; }],
        [MLRow title:@"剪贴板" detail:@"查看并确认粘贴的配置或节点" action:^{
            NSString *value = [UIPasteboard generalPasteboard].string;
            if (!value.length) { [weakSelf message:@"剪贴板没有文本。"]; return; }
            [weakSelf openScannedText:value];
        }],
        [MLRow title:@"输入 Clash YAML" detail:@"完整配置源文件" action:^{ [weakSelf push:[[MLInput alloc] initWithKind:@"yaml" initial:@""]]; }],
        [MLRow title:@"本地 YAML 文件" detail:@"选择文稿目录内文件，或输入可读路径" action:^{ [weakSelf push:[MLFiles new]]; }],
        [MLRow title:@"节点 URI / Base64" detail:@"后台必须支持相应协议与订阅格式" action:^{ [weakSelf push:[[MLInput alloc] initWithKind:@"uri" initial:@""]]; }],
        [MLRow title:@"二维码" detail:@"拍照或从相册识别，确认后导入" action:^{
            MLImport *screen = weakSelf;
            if (!screen) return;
            MLPresentQR(screen,^(NSString *text, NSString *error) {
                if (error) [weakSelf message:error];
                else if (text.length) [weakSelf openScannedText:text];
            });
        }]
    ]];
    [self reloadRows];
}
@end

@implementation MLInput
- (instancetype)initWithKind:(NSString *)kind initial:(NSString *)initial {
    if ((self = [super init])) {
        self.kind = kind;
        NSDictionary *titles = @{@"url":@"URL 订阅", @"yaml":@"导入 YAML", @"uri":@"节点 URI / Base64", @"file":@"本地文件路径", @"metadata":@"名称与订阅地址", @"dns":@"DNS 查询",@"provider":@"本地 Provider"};
        self.title = titles[kind] ?: @"输入";
        self.input = [[UITextView alloc] initWithFrame:CGRectZero]; self.input.text = initial;
    } return self;
}
- (void)viewDidLoad {
    [super viewDidLoad];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithCustomView:MLButton([self.kind isEqualToString:@"dns"] ? @"查询" : @"提交", self, @selector(submit))];
    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 320, 314)];
    header.backgroundColor = MLColor(0xF7F7F9);
    UILabel *nameLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 8, 288, 24)];
    nameLabel.text = @"名称"; nameLabel.font = [UIFont boldSystemFontOfSize:13]; nameLabel.textColor = MLTextColor(); nameLabel.backgroundColor = [UIColor clearColor]; [header addSubview:nameLabel];
    self.nameField = [[UITextField alloc] initWithFrame:CGRectMake(16, 32, 288, 44)];
    self.nameField.backgroundColor = [UIColor whiteColor]; self.nameField.contentVerticalAlignment = UIControlContentVerticalAlignmentCenter;
    self.nameField.font = [UIFont systemFontOfSize:15]; self.nameField.textColor = MLTextColor();
    self.nameField.placeholder = @"配置名称（必填）"; self.nameField.accessibilityLabel = @"配置名称";
    self.nameField.delegate = self; self.nameField.returnKeyType = UIReturnKeyNext;
    self.nameField.autoresizingMask = UIViewAutoresizingFlexibleWidth; [header addSubview:self.nameField];
    UILabel *inputLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 84, 288, 24)];
    inputLabel.font = [UIFont boldSystemFontOfSize:13]; inputLabel.textColor = MLTextColor(); inputLabel.backgroundColor = [UIColor clearColor];
    NSDictionary *labels = @{@"url":@"订阅地址（HTTPS）", @"yaml":@"YAML 原文", @"uri":@"节点链接或 Base64 文本", @"file":@"绝对文件路径", @"metadata":@"订阅地址", @"dns":@"要查询的域名",@"provider":@"Provider 的 YAML / 文本内容"};
    inputLabel.text = labels[self.kind]; [header addSubview:inputLabel];
    self.input.frame = CGRectMake(16, 110, 288, 160); self.input.backgroundColor = [UIColor whiteColor];
    self.input.font = [UIFont fontWithName:@"Courier" size:13]; self.input.textColor = MLTextColor();
    self.input.autocapitalizationType = UITextAutocapitalizationTypeNone; self.input.autocorrectionType = UITextAutocorrectionTypeNo;
    self.input.autoresizingMask = UIViewAutoresizingFlexibleWidth; self.input.accessibilityLabel = inputLabel.text;
    [header addSubview:self.input];
    UIButton *hide = MLButton(@"收起键盘", self, @selector(hideKeyboard)); hide.frame = CGRectMake(212, 270, 92, 44); [header addSubview:hide];
    self.tableView.tableHeaderView = header;
    if ([self.kind isEqualToString:@"dns"]) { self.nameField.text = @"DNS 查询"; self.nameField.enabled = NO; }
    if([self.kind isEqual:@"provider"]){nameLabel.text=@"配置引用的相对路径";self.nameField.placeholder=@"例如 ruleset/direct.yaml";self.nameField.accessibilityLabel=@"Provider 相对路径";}
}
- (void)hideKeyboard { [self.view endEditing:YES]; }
- (BOOL)textFieldShouldReturn:(UITextField *)textField { [self.input becomeFirstResponder]; return YES; }
- (void)refresh { [self reloadRows]; }
- (void)submit {
    __weak typeof(self) weakSelf = self;
    [self hideKeyboard];
    NSString *name = [self.nameField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSString *text = self.input.text ?: @"";
    if (!name.length || (!text.length && ![self.kind isEqual:@"metadata"])) { [self message:@"请填写名称与内容。"]; return; }
    if ([text lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 512 * 1024) { [self message:@"输入过大。配置最多支持 512 KiB UTF-8 文本，请缩小后重试。"]; return; }
    NSString *method = @"config.import";
    NSDictionary *params = @{@"name":name, @"yaml":text};
    if ([self.kind isEqualToString:@"url"]) {
        NSURL *url = [NSURL URLWithString:text];
        if (!url.host.length || ![[url.scheme lowercaseString] isEqual:@"https"]) { [self message:@"请输入有效的 HTTPS 订阅地址。"]; return; }
        method = @"config.importURL"; params = @{@"name":name, @"url":text};
    } else if ([self.kind isEqualToString:@"uri"]) {
        method = @"config.importNodes"; params = @{@"name":name, @"text":text};
    } else if ([self.kind isEqualToString:@"metadata"]) {
        method = @"config.metadata"; params = @{@"id":self.configID ?: @"", @"name":name, @"source":text};
    } else if ([self.kind isEqualToString:@"dns"]) {
        method = @"dns.query"; params = @{@"name":text};
    } else if([self.kind isEqual:@"provider"]) {
        method=@"provider.import";params=@{@"path":name,@"text":text};
    } else if ([self.kind isEqualToString:@"file"]) {
        [self importFile:text name:name]; return;
    }
    [self mutate:method params:params completion:^(NSDictionary *result) {
        if ([weakSelf.kind isEqualToString:@"dns"]) [weakSelf showJSON:result title:@"DNS 查询结果"];
        else [weakSelf showJSON:result title:@"后台确认结果"];
    }];
}
- (void)importFile:(NSString *)path name:(NSString *)name {
    __weak typeof(self) weakSelf = self;
    if (![path isAbsolutePath]) { [self message:@"请输入绝对文件路径。"]; return; }
    self.busy = YES; self.problem = @"正在读取本地文件…"; [self reloadRows];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            NSError *error = nil;
            NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:&error];
            NSString *failure = error.localizedDescription;
            NSString *yaml = nil;
            if (![attributes[NSFileType] isEqualToString:NSFileTypeRegular]) failure = @"只能读取普通文件。";
            else if ([attributes[NSFileSize] unsignedLongLongValue] > 512 * 1024) failure = @"配置文件超过 512 KiB 大小限制。";
            else { yaml = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:&error]; if (!yaml) failure = error.localizedDescription ?: @"文件不是 UTF-8 文本。"; }
            dispatch_async(dispatch_get_main_queue(), ^{
                weakSelf.busy = NO;
                if (!yaml) { weakSelf.problem = failure; [weakSelf reloadRows]; [weakSelf message:failure]; return; }
                [weakSelf mutate:@"config.import" params:@{@"name":name, @"yaml":yaml, @"source":[[NSURL fileURLWithPath:path] absoluteString]} completion:^(NSDictionary *result) { [weakSelf showJSON:result title:@"文件导入结果"]; }];
            });
        }
    });
}
@end

@implementation MLFiles
- (void)viewDidLoad { [super viewDidLoad]; self.title = @"本地 YAML 文件"; }
- (void)refresh {
    __weak typeof(self) weakSelf = self;
    NSMutableArray *rows = [NSMutableArray array];
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSMutableArray *directories = [NSMutableArray arrayWithArray:paths];
    [directories addObject:@"/var/mobile/Documents/MuyuClash"];
    for (NSString *directory in directories) {
        NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:directory error:NULL];
        for (NSString *file in files) {
            NSString *extension = [file.pathExtension lowercaseString];
            if (![@[@"yaml", @"yml"] containsObject:extension]) continue;
            NSString *path = [directory stringByAppendingPathComponent:file];
            [rows addObject:[MLRow title:file detail:directory action:^{
                MLInput *input = [[MLInput alloc] initWithKind:@"file" initial:path]; [input view];
                input.nameField.text = [file stringByDeletingPathExtension]; [weakSelf push:input];
            }]];
        }
    }
    [rows addObject:[MLRow title:@"输入文件路径" detail:@"读取当前应用身份有权访问的 UTF-8 YAML 文件" action:^{ [weakSelf push:[[MLInput alloc] initWithKind:@"file" initial:@""]]; }]];
    self.sections = @[rows]; self.sectionTitles = @[@"文稿目录中的配置文件"];
    self.problem = @"可将 YAML 放入应用文稿目录或 /var/mobile/Documents/MuyuClash。导入后仍需检查并单独应用。";
    [self reloadRows];
}
@end

@implementation MLText
- (instancetype)initWithTitle:(NSString *)title text:(NSString *)text editable:(BOOL)editable {
    if ((self = [super init])) { self.title = title; self.content = text ?: @""; self.editable = editable; } return self;
}
- (void)viewDidLoad {
    [super viewDidLoad]; self.view.backgroundColor = [UIColor whiteColor];
    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc] initWithCustomView:MLButton(@"‹ 返回", self, @selector(back))];
    UIView *toolbar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, self.view.bounds.size.width, 44)];
    toolbar.autoresizingMask = UIViewAutoresizingFlexibleWidth; toolbar.backgroundColor = MLColor(0xF0EDF4);
    UIButton *copy = MLButton(@"复制", self, @selector(copyText)); copy.frame = CGRectMake(8, 0, 64, 44); [toolbar addSubview:copy];
    if (self.editable) {
        UIButton *check = MLButton(@"检查", self, @selector(check)); check.frame = CGRectMake(88, 0, 64, 44); [toolbar addSubview:check];
        UIButton *save = MLButton(@"另存", self, @selector(save)); save.frame = CGRectMake(168, 0, 64, 44); [toolbar addSubview:save];
        UIButton *hide = MLButton(@"收起", self, @selector(hideKeyboard)); hide.frame = CGRectMake(248, 0, 64, 44); [toolbar addSubview:hide];
    }
    [self.view addSubview:toolbar];
    self.textView = [[UITextView alloc] initWithFrame:CGRectMake(8, 44, self.view.bounds.size.width - 16, self.view.bounds.size.height - 44)];
    self.textView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.textView.font = [UIFont fontWithName:@"Courier" size:13]; self.textView.textColor = MLTextColor();
    self.textView.text = self.content; self.textView.editable = self.editable;
    self.textView.autocapitalizationType = UITextAutocapitalizationTypeNone; self.textView.autocorrectionType = UITextAutocorrectionTypeNo;
    self.textView.accessibilityLabel = self.editable ? @"YAML 配置编辑器" : self.title;
    [self.view addSubview:self.textView];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(keyboard:) name:UIKeyboardWillShowNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(keyboard:) name:UIKeyboardWillHideNotification object:nil];
}
- (void)dealloc { [[NSNotificationCenter defaultCenter] removeObserver:self]; }
- (void)back { [self.navigationController popViewControllerAnimated:YES]; }
- (void)hideKeyboard { [self.view endEditing:YES]; }
- (void)keyboard:(NSNotification *)notification {
    CGRect frame = [notification.userInfo[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    frame = [self.view convertRect:frame fromView:nil];
    CGFloat overlap = [notification.name isEqualToString:UIKeyboardWillHideNotification] ? 0 : MAX(0, CGRectGetMaxY(self.view.bounds) - CGRectGetMinY(frame));
    self.textView.contentInset = UIEdgeInsetsMake(0, 0, overlap, 0); self.textView.scrollIndicatorInsets = self.textView.contentInset;
}
- (void)copyText {
    [UIPasteboard generalPasteboard].string = self.textView.text;
    [[[UIAlertView alloc] initWithTitle:@"已复制" message:self.editable ? @"已复制 YAML 原文；原文可能包含节点凭据，请妥善保管。" : @"已复制当前文本。" delegate:nil cancelButtonTitle:@"知道了" otherButtonTitles:nil] show];
}
- (void)run:(NSString *)method params:(NSDictionary *)params completion:(void (^)(NSDictionary *))completion {
    __weak typeof(self) weakSelf = self;
    if (self.busy) return;
    [self hideKeyboard]; self.busy = YES; self.view.userInteractionEnabled = NO;
    NSString *previousTitle = self.title;
    self.title = [method isEqualToString:@"config.check"] ? @"正在检查…" : @"正在保存…";
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            NSError *error = nil; NSDictionary *result = MLIPCRequest(MLSocket, method, params, &error);
            NSString *failure = error.localizedDescription ?: @"后台未返回有效结果";
            dispatch_async(dispatch_get_main_queue(), ^{
                MLText *screen = weakSelf; if (!screen) return;
                screen.busy = NO; screen.view.userInteractionEnabled = YES;
                screen.title = previousTitle;
                if (!result) { [[[UIAlertView alloc] initWithTitle:@"操作未完成" message:failure delegate:nil cancelButtonTitle:@"知道了" otherButtonTitles:nil] show]; return; }
                if (completion) completion(result);
            });
        }
    });
}
- (void)check {
    __weak typeof(self) weakSelf = self;
    [self view];
    [self run:@"config.check" params:@{@"yaml":self.textView.text ?: self.content} completion:^(NSDictionary *report) {
        NSDictionary *previous = weakSelf.previousReport; weakSelf.previousReport = report;
        MLReport *screen = [[MLReport alloc] initWithReport:report previous:previous editor:weakSelf];
        [weakSelf.navigationController pushViewController:screen animated:YES];
    }];
}
- (void)save {
    __weak typeof(self) weakSelf = self;
    NSString *name = self.configName.length && ![self.configName isEqualToString:@"—"] ? [self.configName stringByAppendingString:@"（编辑副本）"] : @"编辑的配置";
    [self run:@"config.import" params:@{@"name":name, @"yaml":self.textView.text ?: @""} completion:^(NSDictionary *result) {
        MLText *screen = [[MLText alloc] initWithTitle:@"另存结果" text:[@"后台已确认另存请求。原配置不变，新候选仍需单独应用。\n\n" stringByAppendingString:MLJSON(MLRedact(result))] editable:NO];
        [weakSelf.navigationController pushViewController:screen animated:YES];
    }];
}
- (void)jumpToLine:(NSUInteger)line column:(NSUInteger)column {
    [self view]; NSString *text = self.textView.text;
    NSUInteger location = 0, current = 1;
    while (location < text.length && current < MAX((NSUInteger)1, line)) { if ([text characterAtIndex:location++] == '\n') current++; }
    NSUInteger end = location;
    while (end < text.length && [text characterAtIndex:end] != '\n') end++;
    location = MIN(end, location + (column > 0 ? column - 1 : 0));
    self.textView.selectedRange = NSMakeRange(location, MIN((NSUInteger)1, text.length - location));
    [self.textView scrollRangeToVisible:self.textView.selectedRange];
    if (self.editable) [self.textView becomeFirstResponder];
}
@end

static NSString *MLCategory(id category) {
    NSString *key = MLString(category);
    if ([@[@"parse", @"parsing", @"parse-error", @"syntax"] containsObject:key]) return @"解析错误";
    if ([@[@"compatibility", @"incompatible", @"unsupported"] containsObject:key]) return @"功能不兼容";
    if ([@[@"runtime", @"warning", @"runtime-warning"] containsObject:key]) return @"运行警告";
    return key;
}
static NSString *MLSeverity(id severity) {
    NSString *key = MLString(severity);
    return (@{@"block":@"阻断", @"blocking":@"阻断", @"blocker":@"阻断", @"error":@"阻断", @"confirm":@"需要确认",
              @"confirmation":@"需要确认", @"warning":@"提醒", @"notice":@"提醒", @"unverified":@"未验证"})[key] ?: key;
}
@implementation MLReport
- (instancetype)initWithReport:(NSDictionary *)report previous:(NSDictionary *)previous editor:(MLText *)editor {
    if ((self = [super init])) { self.report = report; self.previousReport = previous; self.editor = editor; self.title = @"配置检查"; } return self;
}
- (void)viewDidLoad {
    [super viewDidLoad];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithCustomView:MLButton(@"重查", self, @selector(recheck))];
    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 320, 60)];
    self.filter = [[UISegmentedControl alloc] initWithItems:@[@"全部", @"解析", @"兼容", @"警告"]];
    self.filter.frame = CGRectMake(12, 8, 296, 44); self.filter.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    self.filter.selectedSegmentIndex = 0; MLStyleSegments(self.filter);
    [self.filter addTarget:self action:@selector(build) forControlEvents:UIControlEventValueChanged];
    [header addSubview:self.filter]; self.tableView.tableHeaderView = header; [self build];
}
- (void)refresh { [self build]; }
- (void)recheck {
    MLText *editor = self.editor;
    if (!editor) { [self message:@"配置编辑器已关闭，返回配置重新读取原文后检查。"]; return; }
    [self.navigationController popToViewController:editor animated:YES]; [editor check];
}
- (void)issue:(NSDictionary *)issue {
    __weak typeof(self) weakSelf = self;
    MLScreen *detail = [MLScreen new]; detail.title = MLString(issue[@"id"]);
    __weak MLScreen *weakDetail = detail;
    NSMutableArray *rows = [NSMutableArray array];
    NSArray *fields = @[@[@"编号", @"id"], @[@"类别", @"category"], @[@"严重程度", @"severity"], @[@"配置字段", @"field"], @[@"行", @"line"], @[@"列", @"column"], @[@"原因", @"reason"], @[@"实际影响", @"impact"], @[@"修复建议", @"suggestion"]];
    for (NSArray *field in fields) {
        NSString *value = [field[1] isEqualToString:@"category"] ? MLCategory(issue[field[1]]) : ([field[1] isEqualToString:@"severity"] ? MLSeverity(issue[field[1]]) : MLString(issue[field[1]]));
        [rows addObject:[MLRow title:field[0] detail:value action:^{ [weakDetail push:[[MLText alloc] initWithTitle:field[0] text:value editable:NO]]; }]];
    }
    detail.sectionTitles = @[@"问题详情 · 点击查看完整内容", @"修复操作"];
    detail.sections = @[rows, @[
        [MLRow title:@"跳转编辑" detail:@"定位到后台报告的行列" action:^{
            MLText *editor = weakSelf.editor;
            if (!editor) { [weakDetail message:@"编辑器不可用，请返回配置读取原文。"]; return; }
            [weakSelf.navigationController popToViewController:editor animated:YES]; [editor jumpToLine:[issue[@"line"] unsignedIntegerValue] column:[issue[@"column"] unsignedIntegerValue]];
        }],
        [MLRow title:@"复制问题" detail:@"复制编号、原因、影响与建议" action:^{ [UIPasteboard generalPasteboard].string = MLJSON(issue); [weakDetail message:@"已复制问题详情。"]; }],
        [MLRow title:@"重新检查" detail:@"重新检查当前编辑内容并比较问题变化" action:^{ [weakSelf recheck]; }]
    ]];
    [self push:detail];
}
- (void)build {
    __weak typeof(self) weakSelf = self;
    NSArray *issues = MLArray(self.report[@"issues"]);
    id uncheckedValue = self.report[@"unchecked"];
    NSArray *unchecked = MLArray(uncheckedValue);
    BOOL hasUnchecked = unchecked.count > 0 || ([uncheckedValue isKindOfClass:[NSNumber class]] && [uncheckedValue boolValue]);
    NSString *verdict = self.report[@"valid"] ? ([self.report[@"valid"] boolValue] ? @"后台判定：未发现阻断项" : @"后台判定：存在阻断项") : @"后台未提供可用性结论";
    NSString *scope = hasUnchecked ? @"存在后续未检查项目" : (uncheckedValue ? @"后台未标记后续未检查项目" : @"后台未提供检查范围");
    NSMutableArray *summary = [NSMutableArray arrayWithObject:[MLRow title:verdict detail:[NSString stringWithFormat:@"%lu 个问题 · %@", (unsigned long)issues.count, scope] action:nil]];
    if (self.previousReport) {
        NSMutableSet *before = [NSMutableSet set], *after = [NSMutableSet set];
        for (NSDictionary *issue in MLArray(self.previousReport[@"issues"]))
            if ([issue isKindOfClass:[NSDictionary class]]) [before addObject:MLJSON(@[MLString(issue[@"id"]), MLString(issue[@"field"]), MLString(issue[@"reason"])])];
        for (NSDictionary *issue in issues)
            if ([issue isKindOfClass:[NSDictionary class]]) [after addObject:MLJSON(@[MLString(issue[@"id"]), MLString(issue[@"field"]), MLString(issue[@"reason"])])];
        NSMutableSet *resolved = [before mutableCopy]; [resolved minusSet:after];
        NSMutableSet *added = [after mutableCopy]; [added minusSet:before];
        [summary addObject:[MLRow title:@"与上次检查比较" detail:[NSString stringWithFormat:@"解决 %lu 项 · 新增 %lu 项", (unsigned long)resolved.count, (unsigned long)added.count] action:^{ [weakSelf showJSON:@{@"before":weakSelf.previousReport, @"after":weakSelf.report} title:@"检查前后变化"]; }]];
    }
    if (hasUnchecked) [summary addObject:[MLRow title:@"后续未检查项目" detail:@"未检查项目不代表已通过" action:^{
        if (unchecked.count) [weakSelf showJSON:unchecked title:@"未检查项目"];
        else [weakSelf push:[[MLText alloc] initWithTitle:@"未检查项目" text:@"后台明确报告存在未检查内容，但没有返回项目列表。请先修复已报告的问题，再重新检查；不得将剩余内容视为通过。" editable:NO]];
    }]];
    NSMutableArray *rows = [NSMutableArray array];
    NSArray *categories = @[@"", @"解析错误", @"功能不兼容", @"运行警告"];
    NSInteger selected = self.filter ? self.filter.selectedSegmentIndex : 0;
    for (NSDictionary *issue in issues) {
        if (![issue isKindOfClass:[NSDictionary class]]) continue;
        NSString *category = MLCategory(issue[@"category"]);
        if (selected > 0 && ![category isEqualToString:categories[selected]]) continue;
        [rows addObject:[MLRow title:[NSString stringWithFormat:@"%@ · %@", MLString(issue[@"id"]), MLSeverity(issue[@"severity"])]
                             detail:[NSString stringWithFormat:@"%@ · %@:%@\n%@", category, MLString(issue[@"line"]), MLString(issue[@"column"]), MLString(issue[@"reason"])] action:^{ [weakSelf issue:issue]; }]];
    }
    self.sections = @[summary, rows]; self.sectionTitles = @[@"检查摘要", @"问题列表"];
    if (!rows.count) self.problem = @"当前分类没有已报告问题。未检查项目及未验证能力仍需单独确认。";
    else self.problem = nil;
    [self reloadRows];
}
@end

@implementation MLLogs
- (void)viewDidLoad {
    [super viewDidLoad]; self.title = @"日志";
    self.level = @"all";
    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 320, 112)];
    self.mode = [[UISegmentedControl alloc] initWithItems:@[@"日志", @"连接"]];
    self.mode.frame = CGRectMake(12, 8, 296, 44); self.mode.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    self.mode.selectedSegmentIndex = 0; MLStyleSegments(self.mode);
    [self.mode addTarget:self action:@selector(modeChanged) forControlEvents:UIControlEventValueChanged]; [header addSubview:self.mode];
    self.search = [[UISearchBar alloc] initWithFrame:CGRectMake(0, 60, 320, 52)];
    self.search.autoresizingMask = UIViewAutoresizingFlexibleWidth; self.search.delegate = self;
    self.search.placeholder = @"搜索当前已读取的记录"; self.search.tintColor = MLAccent(); [header addSubview:self.search];
    self.search.backgroundImage = MLFill(MLColor(0xF7F7F9));
    self.tableView.tableHeaderView = header;
}
- (void)modeChanged { self.items = nil; [self build]; [self refresh]; }
- (void)refresh {
    __weak typeof(self) weakSelf = self;
    NSString *method = self.mode.selectedSegmentIndex == 1 ? @"connections.list" : @"logs.list";
    [self request:method params:nil completion:^(NSDictionary *result) { if (result) { weakSelf.items = MLArray(result[@"items"]); [weakSelf build]; } }];
}
- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText { [self build]; }
- (void)searchBarSearchButtonClicked:(UISearchBar *)searchBar { [searchBar resignFirstResponder]; }
- (void)filterLevel {
    __weak typeof(self) weakSelf = self;
    NSMutableArray *options = [NSMutableArray array];
    for (NSArray *entry in @[@[@"全部等级", @"all"], @[@"调试", @"debug"], @[@"信息", @"info"], @[@"警告", @"warning"], @[@"错误", @"error"]])
        [options addObject:@{@"title":entry[0], @"value":entry[1]}];
    [self push:[[MLChoice alloc] initWithTitle:@"日志等级" options:options choose:^(id value) { weakSelf.level = value; [weakSelf build]; }]];
}
- (void)filterTime {
    __weak typeof(self) weakSelf = self;
    [self push:[[MLChoice alloc] initWithTitle:@"日志时间" options:@[
        @{@"title":@"全部已读取记录", @"value":@0}, @{@"title":@"最近 5 分钟", @"value":@300},
        @{@"title":@"最近 1 小时", @"value":@3600}] choose:^(id value) { weakSelf.sinceInterval = [value doubleValue]; [weakSelf build]; }]];
}
- (NSTimeInterval)timestamp:(NSDictionary *)entry {
    id value = entry[@"timestamp"] ?: entry[@"time"];
    if ([value isKindOfClass:[NSNumber class]]) return [value doubleValue];
    if ([value isKindOfClass:[NSString class]]) {
        NSDateFormatter *formatter = [NSDateFormatter new];
        formatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
        formatter.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
        for (NSString *format in @[@"yyyy-MM-dd'T'HH:mm:ss'Z'", @"yyyy-MM-dd HH:mm:ss", @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"]) {
            formatter.dateFormat = format; NSDate *date = [formatter dateFromString:value]; if (date) return date.timeIntervalSince1970;
        }
    }
    return 0;
}
- (void)build {
    __weak typeof(self) weakSelf = self;
    BOOL connections = self.mode.selectedSegmentIndex == 1;
    NSMutableArray *actions = [NSMutableArray array];
    if (!connections) {
        [actions addObject:[MLRow title:@"日志等级筛选" detail:self.level action:^{ [weakSelf filterLevel]; }]];
        NSString *time = self.sinceInterval == 300 ? @"最近 5 分钟" : (self.sinceInterval == 3600 ? @"最近 1 小时" : @"全部已读取记录");
        [actions addObject:[MLRow title:@"时间筛选" detail:time action:^{ [weakSelf filterTime]; }]];
        [actions addObject:[MLRow title:@"清空日志" detail:@"后台确认后重新读取" action:^{
            [weakSelf confirm:@"清空后台日志缓存？" action:^{ [weakSelf mutate:@"logs.clear" params:nil completion:^(NSDictionary *result) { [weakSelf refresh]; }]; }];
        }]];
        [actions addObject:[MLRow title:@"脱敏导出" detail:@"仅导出后台确认已脱敏的内容" action:^{
            [weakSelf request:@"logs.list" params:@{@"redact":@YES} completion:^(NSDictionary *result) {
                if (!result) { [weakSelf message:weakSelf.problem]; return; }
                if (![result[@"redacted"] boolValue] || ![result[@"items"] isKindOfClass:[NSArray class]]) { [weakSelf message:@"后台未确认返回的日志已经脱敏，无法导出。"]; return; }
                [weakSelf push:[[MLText alloc] initWithTitle:@"脱敏日志导出" text:MLJSON(result[@"items"]) editable:NO]];
            }];
        }]];
    }
    NSMutableArray *rows = [NSMutableArray array]; NSString *query = self.search.text ?: @"";
    NSTimeInterval cutoff = [NSDate date].timeIntervalSince1970 - self.sinceInterval;
    NSUInteger unknownTimes = 0;
    for (NSDictionary *entry in self.items) {
        if (![entry isKindOfClass:[NSDictionary class]]) continue;
        if (!connections && ![self.level isEqualToString:@"all"] && ![self.level isEqualToString:entry[@"level"]]) continue;
        if (!connections && self.sinceInterval > 0) {
            NSTimeInterval time = [self timestamp:entry]; if (time == 0) { unknownTimes++; continue; } if (time < cutoff) continue;
        }
        NSString *searchText = MLJSON(MLRedact(entry));
        if (query.length && [searchText rangeOfString:query options:NSCaseInsensitiveSearch].location == NSNotFound) continue;
        if (connections) {
            NSString *target = MLString(entry[@"host"] ?: entry[@"destination"]);
            NSString *detail = [NSString stringWithFormat:@"%@ · %@ → %@\n%@ · 实际 %@", MLString(entry[@"network"]), MLString(entry[@"source"]), target, MLString(entry[@"rule"]), MLString(entry[@"actual"])];
            [rows addObject:[MLRow title:target detail:detail action:^{ [weakSelf push:[[MLConnection alloc] initWithConnection:entry]]; }]];
        } else {
            NSString *title = [NSString stringWithFormat:@"%@ · %@", MLDate(entry[@"time"] ?: entry[@"timestamp"]), MLString(entry[@"level"])];
            [rows addObject:[MLRow title:title detail:MLString(entry[@"message"]) action:^{ [weakSelf showJSON:entry title:@"日志详情"]; }]];
        }
    }
    self.sections = connections ? @[rows] : @[actions, rows];
    self.sectionTitles = connections ? @[@"活动连接 · 点击查看与关闭"] : @[@"筛选与管理", @"后台日志 · 当前读取范围"];
    if (!rows.count && !self.busy) self.problem = connections ? @"当前没有已报告的活动连接。" : @"当前筛选没有已报告日志。";
    else if (!self.busy) self.problem = nil;
    if (unknownTimes) self.problem = [NSString stringWithFormat:@"%lu 条记录缺少可识别的时间，未纳入时间筛选结果。", (unsigned long)unknownTimes];
    [self reloadRows];
}
@end

@implementation MLConnection
- (instancetype)initWithConnection:(NSDictionary *)connection {
    if ((self = [super init])) { self.connection = connection; self.title = @"连接详情"; } return self;
}
- (void)refresh {
    __weak typeof(self) weakSelf = self;
    NSArray *fields = @[@[@"连接编号", @"id"], @[@"源地址 / 端口", @"source"], @[@"目标地址 / 端口", @"destination"],
        @[@"域名", @"host"], @[@"TCP / UDP", @"network"], @[@"命中规则", @"rule"], @[@"策略组", @"group"],
        @[@"实际出口", @"actual"], @[@"配置版本", @"generation"], @[@"连接时长（秒）", @"duration"], @[@"状态", @"state"]];
    NSMutableArray *rows = [NSMutableArray array];
    for (NSArray *field in fields) [rows addObject:[MLRow title:field[0] detail:MLString(self.connection[field[1]]) action:nil]];
    [rows addObject:[MLRow title:@"上传 / 下载" detail:[NSString stringWithFormat:@"%@ / %@", MLBytes(self.connection[@"uploadBytes"]), MLBytes(self.connection[@"downloadBytes"])] action:nil]];
    self.sections = @[rows, @[[MLRow title:@"关闭这条连接" detail:@"由后台确认连接编号并关闭" action:^{
        NSString *identifier = weakSelf.connection[@"id"];
        if (![identifier isKindOfClass:[NSString class]] || !identifier.length) { [weakSelf message:@"后台没有提供可关闭的连接编号。"]; return; }
        [weakSelf mutate:@"connections.close" params:@{@"id":identifier} completion:^(NSDictionary *result) { [weakSelf.navigationController popViewControllerAnimated:YES]; }];
    }]]];
    self.sectionTitles = @[@"后台连接记录 · 未提供的元数据显示为 —", @"连接控制"]; [self reloadRows];
}
@end

static NSString *MLSettingValue(id value) {
    if (!value || value == [NSNull null]) return @"后台未提供";
    if ([value isKindOfClass:[NSNumber class]]) {
        if (strcmp([value objCType], @encode(BOOL)) == 0 || CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID()) return [value boolValue] ? @"已开启" : @"已关闭";
        return [value description];
    }
    NSString *key = MLString(value);
    return (@{@"Rule":@"按规则", @"Global":@"全局代理", @"Direct":@"直连", @"restore":@"网络恢复优先",
              @"strict":@"严格阻断", @"utun":@"系统流量接管", @"unverified":@"仅本机代理端口", @"follow-config":@"跟随配置", @"redir-host":@"Redir-Host",
              @"fake-ip":@"Fake-IP", @"zh-Hans":@"简体中文", @"en":@"English", @"light":@"浅色",
              @"debug":@"调试", @"info":@"信息", @"warning":@"警告", @"error":@"错误", @"auto":@"自动选择"})[key] ?: key;
}
@implementation MLSettings
- (void)viewDidLoad { [super viewDidLoad]; self.title = @"设置"; }
- (void)refresh {
    __weak typeof(self) weakSelf = self;
    [self request:@"settings.get" params:nil completion:^(NSDictionary *result) { if (result) { weakSelf.values = MLDict(result[@"values"]); [weakSelf build]; } }];
}
- (void)setKey:(NSString *)key value:(id)value {
    __weak typeof(self) weakSelf = self;
    [self mutate:@"settings.set" params:@{@"key":key, @"value":value} completion:^(NSDictionary *result) { [weakSelf refresh]; }];
}
- (MLRow *)choice:(NSString *)title key:(NSString *)key options:(NSArray *)options {
    __weak typeof(self) weakSelf = self;
    return [MLRow title:title detail:MLSettingValue(self.values[key]) action:^{
        [weakSelf push:[[MLChoice alloc] initWithTitle:title options:options choose:^(id value) { [weakSelf setKey:key value:value]; }]];
    }];
}
- (MLRow *)toggle:(NSString *)title key:(NSString *)key {
    return [self choice:title key:key options:@[@{@"title":@"关闭", @"value":@NO}, @{@"title":@"开启", @"value":@YES}]];
}
- (void)build {
    __weak typeof(self) weakSelf = self;
    NSArray *general = @[
        [self toggle:@"开机自动运行" key:@"autoStart"], [self toggle:@"自动重连" key:@"autoReconnect"],
        [MLRow title:@"后台运行" detail:@"退出界面后保持连接" action:nil],
        [self choice:@"语言" key:@"language" options:@[@{@"title":@"简体中文", @"detail":@"当前构建已集成的界面语言", @"value":@"zh-Hans"}]],
        [self choice:@"主题" key:@"theme" options:@[@{@"title":@"浅色 · 白紫", @"value":@"light"}]]
    ];
    NSArray *network = @[
        [self choice:@"网络接管" key:@"captureBackend" options:@[@{@"title":@"系统流量接管", @"value":@"utun"}, @{@"title":@"仅本机代理端口", @"value":@"unverified"}]],
        [MLRow title:@"TCP / UDP / IPv6 覆盖" detail:@"查看各网络能力的独立验证状态" action:^{ [weakSelf push:[MLDiagnostic new]]; }],
        [MLRow title:@"局域网绕过" detail:@"局域网与链路本地地址使用系统路由" action:nil],
        [MLRow title:@"网络出口" detail:@"跟随当前物理网络，路径变化时恢复接管" action:nil],
        [self choice:@"网络异常处理" key:@"protectionMode" options:@[@{@"title":@"网络恢复优先", @"detail":@"核心失效时恢复网络，可能发生直连", @"value":@"restore"}, @{@"title":@"严格阻断", @"detail":@"仅在后台已验证阻断机制时可启用", @"value":@"strict"}]]
    ];
    NSArray *dns = @[[MLRow title:@"DNS 管理" detail:MLSettingValue(self.values[@"dnsMode"]) action:^{ [weakSelf push:[MLDNS new]]; }]];
    NSArray *advanced = @[
        [MLRow title:@"协议核心状态与能力" detail:@"仅显示本机后台报告的数据" action:^{ [weakSelf request:@"system.capabilities" params:nil completion:^(NSDictionary *result) { if (result) [weakSelf showJSON:result title:@"实际能力报告"]; else [weakSelf message:weakSelf.problem]; }]; }],
        [MLRow title:@"监听端口" detail:@"读取后台当前监听端口" action:^{ [weakSelf request:@"system.listeners" params:nil completion:^(NSDictionary *result) { if (result) [weakSelf showJSON:result title:@"监听端口"]; else [weakSelf message:weakSelf.problem]; }]; }],
        [self choice:@"同时测速数量" key:@"maxProbeConcurrency" options:@[@{@"title":@"1", @"value":@1}, @{@"title":@"2", @"value":@2}, @{@"title":@"3", @"value":@3}]],
        [self choice:@"日志等级" key:@"logLevel" options:@[@{@"title":@"调试", @"value":@"debug"}, @{@"title":@"信息", @"value":@"info"}, @{@"title":@"警告", @"value":@"warning"}, @{@"title":@"错误", @"value":@"error"}]],
        [MLRow title:@"网络诊断" detail:@"能力、运行状态与覆盖检查" action:^{ [weakSelf push:[MLDiagnostic new]]; }],
        [MLRow title:@"诊断导出" detail:@"要求后台输出已脱敏诊断" action:^{ [weakSelf request:@"diagnostics.export" params:@{@"redact":@YES} completion:^(NSDictionary *result) {
            if (!result) { [weakSelf message:weakSelf.problem]; return; }
            if (![result[@"redacted"] boolValue]) { [weakSelf message:@"后台没有确认诊断已经脱敏，无法导出。"]; return; }
            [weakSelf showJSON:result title:@"诊断导出"];
        }]; }],
        [MLRow title:@"恢复网络设置" detail:@"仅恢复 MuyuClash 管理的网络状态" action:^{ [weakSelf confirm:@"停止接管并请求后台恢复 MuyuClash 保存的网络状态？" action:^{ [weakSelf mutate:@"network.restore" params:nil completion:^(NSDictionary *result) { [weakSelf showJSON:result title:@"网络恢复结果"]; }]; }]; }],
        [MLRow title:@"关于 MuyuClash" detail:@"软件版本、依赖与兼容性信息" action:^{
            NSDictionary *bundle = [[NSBundle mainBundle] infoDictionary];
            NSString *text = [NSString stringWithFormat:@"MuyuClash Legacy\n版本 %@\n标识 %@\n最低系统 iOS 6.0 · ARMv7\n\n内部工程构建。协议、DNS、系统接管与后台能力必须以实时能力报告和目标设备验收为准。\n\n第三方依赖信息由后台 system.dependencies 接口提供。", MLString(bundle[@"CFBundleShortVersionString"]), MLString(bundle[@"CFBundleIdentifier"])];
            MLScreen *about = [MLScreen new]; about.title = @"关于";
            __weak MLScreen *weakAbout = about;
            about.sectionTitles = @[@"软件信息", @"实际依赖"];
            about.sections = @[@[[MLRow title:@"MuyuClash Legacy" detail:MLString(bundle[@"CFBundleShortVersionString"]) action:^{ [weakAbout push:[[MLText alloc] initWithTitle:@"软件信息" text:text editable:NO]]; }]],
                @[[MLRow title:@"依赖与许可证" detail:@"读取后台已打包的依赖清单" action:^{ [weakAbout request:@"system.dependencies" params:nil completion:^(NSDictionary *result) { if (result) [weakAbout showJSON:result title:@"依赖与许可证"]; else [weakAbout message:weakAbout.problem]; }]; }]]];
            [weakSelf push:about];
        }]
    ];
    self.sections = @[general, network, dns, advanced]; self.sectionTitles = @[@"通用", @"网络", @"DNS", @"高级"];
    self.problem = @"设置以后台确认值为准。能力尚未实现或未验证时，后台会明确拒绝启用。";
    [self reloadRows];
}
@end

@implementation MLDNS
- (void)viewDidLoad { [super viewDidLoad]; self.title = @"DNS 管理"; }
- (void)refresh {
    __weak typeof(self) weakSelf = self;
    self.sectionTitles = @[@"模式与上游", @"缓存与诊断"];
    self.sections = @[@[
        [MLRow title:@"DNS 模式" detail:@"跟随配置 / Redir-Host / Fake-IP" action:^{
            [weakSelf push:[[MLChoice alloc] initWithTitle:@"DNS 模式" options:@[@{@"title":@"跟随配置", @"value":@"follow-config"}, @{@"title":@"Redir-Host", @"value":@"redir-host"}, @{@"title":@"Fake-IP", @"detail":@"需要已验证的流量映射和接管能力", @"value":@"fake-ip"}] choose:^(id value) {
                [weakSelf mutate:@"settings.set" params:@{@"key":@"dnsMode", @"value":value} completion:^(NSDictionary *result) { [weakSelf showJSON:result title:@"DNS 设置结果"]; }];
            }]];
        }],
        [MLRow title:@"DNS 上游与加密 DNS" detail:@"显示当前配置生效的解析策略" action:^{ [weakSelf request:@"dns.status" params:nil completion:^(NSDictionary *result) { if (result) [weakSelf showJSON:result title:@"DNS 状态"]; else [weakSelf message:weakSelf.problem]; }]; }]
    ], @[
        [MLRow title:@"DNS 缓存" detail:@"读取后台缓存统计" action:^{ [weakSelf request:@"dns.cache" params:nil completion:^(NSDictionary *result) { if (result) [weakSelf showJSON:result title:@"DNS 缓存"]; else [weakSelf message:weakSelf.problem]; }]; }],
        [MLRow title:@"清空 DNS 缓存" detail:@"等待后台确认" action:^{ [weakSelf mutate:@"dns.clear" params:nil completion:^(NSDictionary *result) { [weakSelf showJSON:result title:@"DNS 缓存结果"]; }]; }],
        [MLRow title:@"DNS 查询诊断" detail:@"由本机 DNS 引擎查询并报告来源与出口" action:^{ [weakSelf push:[[MLInput alloc] initWithKind:@"dns" initial:@""]]; }]
    ]];
    [self reloadRows];
}
@end

@implementation MLDiagnostic
- (void)viewDidLoad { [super viewDidLoad]; self.title = @"网络诊断"; }
- (void)refresh {
    __weak typeof(self) weakSelf = self;
    [self request:@"diagnostics.run" params:nil completion:^(NSDictionary *result) {
        if (!result) return;
        NSMutableArray *rows = [NSMutableArray array];
        for (NSString *key in [[result allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
            id value = result[key];
            NSString *detail = [value isKindOfClass:[NSDictionary class]] || [value isKindOfClass:[NSArray class]] ? @"点击查看后台报告的完整数据" : MLString(value);
            [rows addObject:[MLRow title:key detail:detail action:^{ [weakSelf showJSON:value title:key]; }]];
        }
        [rows addObject:[MLRow title:@"实际能力报告" detail:@"协议、网络后端与已验证边界" action:^{ [weakSelf request:@"system.capabilities" params:nil completion:^(NSDictionary *capabilities) { if (capabilities) [weakSelf showJSON:capabilities title:@"实际能力报告"]; else [weakSelf message:weakSelf.problem]; }]; }]];
        weakSelf.sections = @[rows]; weakSelf.sectionTitles = @[@"本机后台诊断结果"];
    }];
}
@end

@interface MLAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic,strong) UIWindow *window;
@end
@implementation MLAppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    UITabBarController *tabs = [UITabBarController new];
    NSArray *controllers = @[[MLHome new], [MLGroups new], [MLConfigs new], [MLLogs new]];
    NSArray *titles = @[@"首页", @"代理", @"配置", @"日志"];
    NSMutableArray *navigationControllers = [NSMutableArray array];
    for (NSUInteger index = 0; index < controllers.count; index++) {
        UIViewController *controller = controllers[index]; controller.title = titles[index];
        UINavigationController *navigation = [[UINavigationController alloc] initWithRootViewController:controller];
        navigation.navigationBar.translucent = NO; navigation.navigationBar.tintColor = MLAccent();
        [navigation.navigationBar setBackgroundImage:MLFill([UIColor whiteColor]) forBarMetrics:UIBarMetricsDefault];
        navigation.navigationBar.shadowImage = MLFill(MLColor(0xE5E1E9));
        navigation.navigationBar.titleTextAttributes = @{UITextAttributeTextColor:MLTextColor(), UITextAttributeTextShadowOffset:[NSValue valueWithUIOffset:UIOffsetZero], UITextAttributeFont:[UIFont boldSystemFontOfSize:17]};
        navigation.tabBarItem = [[UITabBarItem alloc] initWithTitle:titles[index] image:MLTabIcon(index) tag:index];
        [navigation.tabBarItem setTitleTextAttributes:@{UITextAttributeTextColor:MLMuted(), UITextAttributeTextShadowOffset:[NSValue valueWithUIOffset:UIOffsetZero]} forState:UIControlStateNormal];
        [navigation.tabBarItem setTitleTextAttributes:@{UITextAttributeTextColor:MLAccent()} forState:UIControlStateSelected];
        [navigationControllers addObject:navigation];
    }
    tabs.viewControllers = navigationControllers;
    tabs.tabBar.backgroundImage = MLFill([UIColor whiteColor]);
    tabs.tabBar.shadowImage = MLFill(MLColor(0xE5E1E9));
    tabs.tabBar.selectionIndicatorImage = MLFill(MLColor(0xF0EDF4));
    tabs.tabBar.selectedImageTintColor = MLAccent(); tabs.tabBar.tintColor = MLAccent();
    self.window.rootViewController = tabs; self.window.backgroundColor = MLColor(0xF7F7F9);
    [self.window makeKeyAndVisible]; return YES;
}
@end
