#import <Foundation/Foundation.h>
// Read-only discovery for the Supervisor and the default CLI invocation.
FOUNDATION_EXPORT NSDictionary *MLCaptureProbe(void);
// Opt-in root device probe. Its private utun detaches when the control socket closes.
FOUNDATION_EXPORT NSDictionary *MLCaptureUTunLifecycleProbe(void);
FOUNDATION_EXPORT NSDictionary *MLCaptureCoverage(void);
