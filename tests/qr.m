#import <CoreImage/CoreImage.h>
#import "../app/MLQR.m"
#include <assert.h>

static CGImageRef symbol(NSData *bytes) {
    CIFilter *filter = [CIFilter filterWithName:@"CIQRCodeGenerator"];
    [filter setValue:bytes forKey:@"inputMessage"];
    CIImage *image = filter.outputImage;
    assert(image);
    CIContext *context = [CIContext contextWithOptions:@{kCIContextUseSoftwareRenderer:@YES}];
    CGImageRef result = [context createCGImage:image fromRect:image.extent];
    assert(result);
    return result;
}

static CGImageRef page(NSData *first, NSData *second, size_t width) {
    CGColorSpaceRef gray = CGColorSpaceCreateDeviceGray();
    CGContextRef canvas = CGBitmapContextCreate(NULL, width, width, 8, width, gray, (CGBitmapInfo)kCGImageAlphaNone);
    CGColorSpaceRelease(gray);
    assert(canvas);
    CGContextSetGrayFillColor(canvas, 1, 1);
    CGContextFillRect(canvas, CGRectMake(0, 0, width, width));
    CGContextSetInterpolationQuality(canvas, kCGInterpolationNone);
    if (first) {
        CGImageRef code = symbol(first);
        CGContextDrawImage(canvas, CGRectMake(width / 20, width / 4, width / 3, width / 3), code);
        CGImageRelease(code);
    }
    if (second) {
        CGImageRef code = symbol(second);
        CGContextDrawImage(canvas, CGRectMake(width / 2, width / 4, width / 3, width / 3), code);
        CGImageRelease(code);
    }
    CGImageRef image = CGBitmapContextCreateImage(canvas);
    CGContextRelease(canvas);
    return image;
}

static NSString *scan(NSData *first, NSData *second, size_t width, NSString **error) {
    CGImageRef image = page(first, second, width);
    NSString *decoded = MLReadQRImage(image, error);
    CGImageRelease(image);
    return decoded;
}

int main(void) {
    @autoreleasepool {
        NSString *source = @"https://example.test/config?q=暮雨";
        NSData *valid = [source dataUsingEncoding:NSUTF8StringEncoding];
        NSData *other = [@"https://example.test/other" dataUsingEncoding:NSUTF8StringEncoding];
        NSString *error = nil;
        assert([scan(valid, nil, 1920, &error) isEqualToString:source]);
        assert(error == nil);
        assert(scan(valid, other, 480, &error) == nil && error.length);
        assert(scan(valid, valid, 480, &error) == nil && error.length);
        assert(scan(nil, nil, 480, &error) == nil && error.length);
        uint8_t invalid[] = {0xFF, 0xFE, 'a'};
        uint8_t withNUL[] = {'a', 0, 'b'};
        assert(scan([NSData dataWithBytes:invalid length:sizeof(invalid)], nil, 480, &error) == nil && error.length);
        assert(scan([NSData dataWithBytes:withNUL length:sizeof(withNUL)], nil, 480, &error) == nil && error.length);
        puts("PASS QR: downscaled UTF-8, multiple codes, no code, invalid bytes and embedded NUL");
    }
    return 0;
}
