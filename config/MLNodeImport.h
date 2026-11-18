#import <Foundation/Foundation.h>

// Convert one proxy share URI or a list of URI lines to a Clash configuration.
// A list can be plain UTF-8 or wrapped once in standard or URL-safe Base64.
FOUNDATION_EXPORT NSString *MLImportNodeText(NSString *text, NSError **error);
