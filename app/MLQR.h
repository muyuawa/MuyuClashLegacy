#import <UIKit/UIKit.h>

// Called on the main queue. Cancel returns nil text and nil error.
FOUNDATION_EXPORT void MLPresentQR(UIViewController *owner, void (^result)(NSString *text, NSString *error));
