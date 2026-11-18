// Optional per-app SpringBoard extension for iOS 6.1.6.
// Private selectors and _shadow ivar match the linked iOS 6 class-dump headers.
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>

static id (*originalShadowImage)(id, SEL);
static void (*originalUpdateShadow)(id, SEL);
static void (*originalSetIcon)(id, SEL, id);
static void (*originalSetLocation)(id, SEL, int);
static Ivar shadowIvar;
static UIImage *cachedShadowSource;
static UIImage *cachedClearShadow;
static void *substrateHandle;

static void recordStatus(NSString *state) {
    // A small, non-sensitive marker makes activation inspectable without syslog.
    // Written once at injection; never includes app configuration or node data.
    NSDictionary *status = @{ @"state":state, @"pid":@(getpid()),
        @"bundle":@"com.muyu.clashlegacy", @"updatedAt":[NSDate date] };
    [status writeToFile:@"/var/mobile/Library/Caches/com.muyu.clashlegacy.icon-no-shadow.plist" atomically:YES];
}

static BOOL isMuyuHomeIcon(id view) {
    // iOS 6 header locations: home screen 0, dock 1, switcher 2.
    int location = ((int (*)(id, SEL))objc_msgSend)(view, @selector(location));
    if (location != 0 && location != 1) return NO;
    id icon = ((id (*)(id, SEL))objc_msgSend)(view, @selector(icon));
    if (![icon respondsToSelector:@selector(applicationBundleID)]) return NO;
    id identifier = ((id (*)(id, SEL))objc_msgSend)(icon, @selector(applicationBundleID));
    return [identifier isKindOfClass:[NSString class]] &&
        [identifier isEqualToString:@"com.muyu.clashlegacy"];
}

static id shadowImage(id view, SEL command) {
    id image = originalShadowImage(view, command);
    if (!isMuyuHomeIcon(view) || ![image isKindOfClass:[UIImage class]]) return image;
    UIImage *source = image;
    if (source.size.width <= 0 || source.size.height <= 0) return image;
    if (cachedShadowSource != source) {
        // Preserve the stock shadow geometry and give SpringBoard a valid image.
        UIGraphicsBeginImageContextWithOptions(source.size, NO, source.scale);
        UIImage *clearImage = [UIGraphicsGetImageFromCurrentImageContext() retain];
        UIGraphicsEndImageContext();
        if (!clearImage) return image;
        [cachedShadowSource release];
        [cachedClearShadow release];
        cachedShadowSource = [source retain];
        cachedClearShadow = clearImage;
    }
    return cachedClearShadow;
}

static void refreshShadowImage(id view) {
    id shadow = object_getIvar(view, shadowIvar);
    if ([shadow isKindOfClass:[UIImageView class]]) {
        id image = ((id (*)(id, SEL))objc_msgSend)(view, @selector(_shadowImage));
        [shadow setImage:image];
    }
}

static void updateShadow(id view, SEL command) {
    originalUpdateShadow(view, command);
    if (isMuyuHomeIcon(view)) {
        // Change the separate image shadow only. Leave label, bezel, gloss,
        // reflection, drop glow, and visibility flags under SpringBoard control.
        refreshShadowImage(view);
    }
}

static void setIcon(id view, SEL command, id icon) {
    BOOL previouslyTarget = isMuyuHomeIcon(view);
    originalSetIcon(view, command, icon);
    // Reused views must regain their normal shadow when they represent another app.
    if (previouslyTarget || isMuyuHomeIcon(view)) {
        ((void (*)(id, SEL))objc_msgSend)(view, @selector(_updateShadow));
        refreshShadowImage(view);
    }
}

static void setLocation(id view, SEL command, int location) {
    BOOL previouslyTarget = isMuyuHomeIcon(view);
    originalSetLocation(view, command, location);
    if (previouslyTarget || isMuyuHomeIcon(view)) {
        ((void (*)(id, SEL))objc_msgSend)(view, @selector(_updateShadow));
        refreshShadowImage(view);
    }
}

static BOOL methodMatches(Class cls, SEL selector, const char *returnType,
                          unsigned argumentCount, const char *lastArgumentType) {
    Method method = class_getInstanceMethod(cls, selector);
    if (!method || method_getNumberOfArguments(method) != argumentCount) return NO;
    char actual[16] = {0};
    method_getReturnType(method, actual, sizeof actual);
    if (strcmp(actual, returnType)) return NO;
    if (lastArgumentType) {
        method_getArgumentType(method, argumentCount - 1, actual, sizeof actual);
        if (strcmp(actual, lastArgumentType)) return NO;
    }
    return YES;
}

__attribute__((constructor)) static void initializeMuyuClashIconNoShadow(void) {
    @autoreleasepool {
        if (![[[NSBundle mainBundle] bundleIdentifier] isEqualToString:@"com.apple.springboard"] ||
            ![[[UIDevice currentDevice] systemVersion] isEqualToString:@"6.1.6"]) return;
        Class cls = objc_getClass("SBIconView");
        if (!cls) { recordStatus(@"inactive: SBIconView unavailable"); return; }
        shadowIvar = class_getInstanceVariable(cls, "_shadow");
        const char *ivarType = shadowIvar ? ivar_getTypeEncoding(shadowIvar) : NULL;
        if (!cls || !ivarType || ivarType[0] != '@' ||
            !methodMatches(cls, @selector(icon), "@", 2, NULL) ||
            !methodMatches(cls, @selector(location), "i", 2, NULL) ||
            !methodMatches(cls, @selector(_shadowImage), "@", 2, NULL) ||
            !methodMatches(cls, @selector(_updateShadow), "v", 2, NULL) ||
            !methodMatches(cls, @selector(setIcon:), "v", 3, "@") ||
            !methodMatches(cls, @selector(setLocation:), "v", 3, "i")) {
            NSLog(@"MuyuClashIconNoShadow: inactive; iOS 6 private interface mismatch");
            recordStatus(@"inactive: private interface mismatch");
            return;
        }
        void (*hook)(Class, SEL, IMP, IMP *) =
            (void (*)(Class, SEL, IMP, IMP *))dlsym(RTLD_DEFAULT, "MSHookMessageEx");
        if (!hook) {
            // Some legacy injection loaders keep Substrate's symbols local.
            // Resolve through the installed public API library in that case.
            substrateHandle = dlopen("/usr/lib/libsubstrate.dylib", RTLD_NOW | RTLD_LOCAL);
            if (substrateHandle) hook = (void (*)(Class, SEL, IMP, IMP *))
                dlsym(substrateHandle, "MSHookMessageEx");
        }
        if (!hook) {
            NSLog(@"MuyuClashIconNoShadow: inactive; Substrate hook API unavailable");
            recordStatus(@"inactive: hook API unavailable");
            return;
        }
        hook(cls, @selector(_shadowImage), (IMP)shadowImage, (IMP *)&originalShadowImage);
        hook(cls, @selector(_updateShadow), (IMP)updateShadow, (IMP *)&originalUpdateShadow);
        hook(cls, @selector(setIcon:), (IMP)setIcon, (IMP *)&originalSetIcon);
        hook(cls, @selector(setLocation:), (IMP)setLocation, (IMP *)&originalSetLocation);
        recordStatus(@"active");
        NSLog(@"MuyuClashIconNoShadow: active for com.muyu.clashlegacy home/dock icon only");
    }
}
