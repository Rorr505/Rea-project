#import "Dumper.h"
#import <UIKit/UIKit.h>

static UIViewController *topVC(void) {
    UIWindow *win = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if (![s isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *w in ((UIWindowScene *)s).windows) if (w.isKeyWindow) { win = w; break; }
        if (win) break;
    }
    if (!win) win = UIApplication.sharedApplication.windows.firstObject;
    UIViewController *vc = win.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

// ทำงานอัตโนมัติเมื่อ dylib ถูกโหลด: รอ Unity พร้อม → dump → เด้ง Share Sheet ให้ส่งออกไฟล์
__attribute__((constructor))
static void OffsetDumperInit(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        // เขียนลง tmp เพื่อไม่ยุ่งกับ Documents ของเกม และให้ Share Sheet อ่านได้แน่นอน
        NSString *dir = NSTemporaryDirectory();
        NSString *tp = [dir stringByAppendingPathComponent:@"dump.txt"];
        NSString *jp = [dir stringByAppendingPathComponent:@"dump.json"];
        [[Dumper run:DumpFullScan filter:@""] writeToFile:tp atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [[Dumper fullScanJSON:@""] writeToFile:jp atomically:YES encoding:NSUTF8StringEncoding error:nil];

        dispatch_async(dispatch_get_main_queue(), ^{
            UIViewController *vc = topVC();
            if (!vc) return;
            UIActivityViewController *a = [[UIActivityViewController alloc]
                initWithActivityItems:@[[NSURL fileURLWithPath:tp], [NSURL fileURLWithPath:jp]]
                applicationActivities:nil];
            a.popoverPresentationController.sourceView = vc.view;
            a.popoverPresentationController.sourceRect = CGRectMake(vc.view.bounds.size.width / 2, vc.view.bounds.size.height / 2, 1, 1);
            [vc presentViewController:a animated:YES completion:nil];
        });
    });
}
