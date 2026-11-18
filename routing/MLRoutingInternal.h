#import <Foundation/Foundation.h>

NSArray *MLRouteRuleFields(NSString *line);
NSString *MLRouteRuleOperandIssue(NSString *type, NSString *operand);
NSString *MLPolicyStatusIssue(NSString *expectedStatus);
NSArray *MLRouteConditionChildren(NSString *type, NSString *operand);
