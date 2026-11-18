#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#include <TargetConditionals.h>
#include <stdlib.h>
#include <string.h>
#include <zbar.h>

static const size_t MLQRLongestSide = 1280;
static const size_t MLQRMaximumInputPixels = 16 * 1024 * 1024;

static NSString *MLQRFailure(NSString **error, NSString *message) {
    if (error) *error = message;
    return nil;
}

static NSString *MLScanQRBitmap(const uint8_t *pixels, size_t width, size_t height, NSString **error) {
    zbar_image_scanner_t *scanner = zbar_image_scanner_create();
    zbar_image_t *image = zbar_image_create();
    NSString *text = nil;
    NSString *failure = @"二维码解码器无法启动。";
    if (scanner && image && zbar_image_scanner_set_config(scanner, ZBAR_QRCODE, ZBAR_CFG_BINARY, 1) == 0) {
        zbar_image_set_format(image, zbar_fourcc('Y', '8', '0', '0'));
        zbar_image_set_size(image, (unsigned)width, (unsigned)height);
        zbar_image_set_data(image, pixels, width * height, NULL);
        int count = zbar_scan_image(scanner, image);
        if (count < 0) {
            failure = @"二维码解码失败。";
        } else if (count == 0) {
            failure = @"没有识别到二维码。请使用清晰、完整的二维码图片。";
        } else {
            const zbar_symbol_t *code = zbar_image_first_symbol(image);
            if (count != 1 || !code || zbar_symbol_next(code) ||
                zbar_symbol_get_type(code) != ZBAR_QRCODE || zbar_symbol_get_components(code)) {
                failure = @"请使用只含一张独立二维码的图片。";
            } else {
                const char *payload = zbar_symbol_get_data(code);
                size_t length = zbar_symbol_get_data_length(code);
                if (payload && length > 0 && !memchr(payload, '\0', length)) {
                    text = [[NSString alloc] initWithBytes:payload length:length encoding:NSUTF8StringEncoding];
                }
                failure = @"二维码内容须为有效的 UTF-8 文本。";
            }
        }
    }
    if (image) zbar_image_destroy(image);
    if (scanner) zbar_image_scanner_destroy(scanner);
    return text ?: MLQRFailure(error, failure);
}

static NSString *MLReadQRImage(CGImageRef image, NSString **error) {
    if (error) *error = nil;
    if (!image) return MLQRFailure(error, @"无法读取所选图片。");
    size_t width = CGImageGetWidth(image), height = CGImageGetHeight(image);
    if (!width || !height || width > MLQRMaximumInputPixels / height) {
        return MLQRFailure(error, @"所选图片过大或无法读取。请裁剪到二维码区域后重试。");
    }
    size_t longest = MAX(width, height);
    if (longest > MLQRLongestSide) {
        width = MAX(1UL, (size_t)((uint64_t)width * MLQRLongestSide / longest));
        height = MAX(1UL, (size_t)((uint64_t)height * MLQRLongestSide / longest));
    }
    uint8_t *pixels = malloc(width * height);
    if (!pixels) return MLQRFailure(error, @"可用内存不足，无法处理图片。");
    CGColorSpaceRef gray = CGColorSpaceCreateDeviceGray();
    CGContextRef context = gray ? CGBitmapContextCreate(pixels, width, height, 8, width, gray, (CGBitmapInfo)kCGImageAlphaNone) : NULL;
    if (gray) CGColorSpaceRelease(gray);
    if (!context) {
        free(pixels);
        return MLQRFailure(error, @"无法处理所选图片。");
    }
    CGRect rect = CGRectMake(0, 0, width, height);
    CGContextSetGrayFillColor(context, 1, 1);
    CGContextFillRect(context, rect);
    CGContextSetInterpolationQuality(context, kCGInterpolationLow);
    CGContextDrawImage(context, rect, image);
    CGContextRelease(context);
    NSString *text = MLScanQRBitmap(pixels, width, height, error);
    free(pixels);
    return text;
}

#if TARGET_OS_IPHONE
#import "MLQR.h"
#include <dispatch/dispatch.h>
#include <objc/runtime.h>

static char MLQRImportKey;

@interface MLQRImport : NSObject <UIActionSheetDelegate, UIImagePickerControllerDelegate, UINavigationControllerDelegate>
@property(nonatomic, weak) UIViewController *owner;
@property(nonatomic, copy) void (^result)(NSString *, NSString *);
- (void)begin;
@end

static BOOL MLQRSourceAvailable(UIImagePickerControllerSourceType source) {
    return [UIImagePickerController isSourceTypeAvailable:source] &&
        [[UIImagePickerController availableMediaTypesForSourceType:source] containsObject:@"public.image"];
}

@implementation MLQRImport

- (void)complete:(NSString *)text error:(NSString *)error {
    void (^result)(NSString *, NSString *) = self.result;
    self.result = nil;
    UIViewController *owner = self.owner;
    if (owner && objc_getAssociatedObject(owner, &MLQRImportKey) == self) {
        objc_setAssociatedObject(owner, &MLQRImportKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    if (result) result(text, error);
}

- (void)chooseSource:(UIImagePickerControllerSourceType)source {
    UIViewController *owner = self.owner;
    if (!owner || !owner.view.window || owner.presentedViewController || !MLQRSourceAvailable(source)) {
        [self complete:nil error:@"无法打开所选图片来源。"];
        return;
    }
    UIImagePickerController *picker = [[UIImagePickerController alloc] init];
    picker.sourceType = source;
    picker.mediaTypes = @[@"public.image"];
    picker.delegate = self;
    if (source == UIImagePickerControllerSourceTypeCamera &&
        ![UIImagePickerController isCameraDeviceAvailable:UIImagePickerControllerCameraDeviceRear]) {
        picker.cameraDevice = UIImagePickerControllerCameraDeviceFront;
    }
    [owner presentViewController:picker animated:YES completion:nil];
}

- (void)begin {
    BOOL camera = MLQRSourceAvailable(UIImagePickerControllerSourceTypeCamera);
    BOOL library = MLQRSourceAvailable(UIImagePickerControllerSourceTypePhotoLibrary);
    if (camera && library) {
        UIActionSheet *sheet = [[UIActionSheet alloc] initWithTitle:@"导入二维码" delegate:self
            cancelButtonTitle:@"取消" destructiveButtonTitle:nil otherButtonTitles:@"拍照", @"从照片选择", nil];
        [sheet showInView:self.owner.view];
    } else if (camera || library) {
        [self chooseSource:camera ? UIImagePickerControllerSourceTypeCamera : UIImagePickerControllerSourceTypePhotoLibrary];
    } else {
        [self complete:nil error:@"没有可用的相机或照片图库。"];
    }
}

- (void)actionSheet:(UIActionSheet *)sheet didDismissWithButtonIndex:(NSInteger)buttonIndex {
    if (buttonIndex == sheet.firstOtherButtonIndex) {
        [self chooseSource:UIImagePickerControllerSourceTypeCamera];
    } else if (buttonIndex == sheet.firstOtherButtonIndex + 1) {
        [self chooseSource:UIImagePickerControllerSourceTypePhotoLibrary];
    } else {
        [self complete:nil error:nil];
    }
}

- (void)imagePickerControllerDidCancel:(UIImagePickerController *)picker {
    picker.delegate = nil;
    [picker dismissViewControllerAnimated:YES completion:^{ [self complete:nil error:nil]; }];
}

- (void)imagePickerController:(UIImagePickerController *)picker didFinishPickingMediaWithInfo:(NSDictionary *)info {
    UIImage *image = info[UIImagePickerControllerOriginalImage];
    CGImageRef pixels = [image isKindOfClass:[UIImage class]] ? image.CGImage : NULL;
    if (pixels) CGImageRetain(pixels);
    picker.delegate = nil;
    [picker dismissViewControllerAnimated:YES completion:^{
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            @autoreleasepool {
                NSString *error = nil;
                NSString *text = MLReadQRImage(pixels, &error);
                if (pixels) CGImageRelease(pixels);
                dispatch_async(dispatch_get_main_queue(), ^{ [self complete:text error:error]; });
            }
        });
    }];
}
@end

void MLPresentQR(UIViewController *owner, void (^result)(NSString *, NSString *)) {
    if (!result) return;
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ MLPresentQR(owner, result); });
        return;
    }
    if (!owner || !owner.isViewLoaded || !owner.view.window || owner.presentedViewController) {
        result(nil, @"当前页面无法打开二维码导入。");
        return;
    }
    if (objc_getAssociatedObject(owner, &MLQRImportKey)) {
        result(nil, @"正在处理另一张二维码。");
        return;
    }
    MLQRImport *operation = [[MLQRImport alloc] init];
    operation.owner = owner;
    operation.result = result;
    objc_setAssociatedObject(owner, &MLQRImportKey, operation, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [operation begin];
}
#endif
