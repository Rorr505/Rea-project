#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, DumpKind) {
    DumpFieldOffset,
    DumpMethodPtr,
    DumpStaticField,
    DumpCollection,
    DumpString,
    DumpTransform,
    DumpMatrixCamera,
    DumpClassPointer,
    DumpVTable,
    DumpAnalyze,
    DumpFullScan,
    DumpGOTPLT,
};

@interface Dumper : NSObject
+ (BOOL)attach;
+ (NSString *)run:(DumpKind)kind filter:(NSString *)f;
+ (NSString *)fullScanJSON:(NSString *)f;
+ (NSString *)jsonFromText:(NSString *)text kindName:(NSString *)kn filter:(NSString *)f;
@end
