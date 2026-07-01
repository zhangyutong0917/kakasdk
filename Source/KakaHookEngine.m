//
//  KakaHookEngine.m
//  全新方案：把 KakaSDK 当功能库，主动调用其内部函数
//  不修改 KakaSDK 的任何逻辑
//
//  核心流程：
//  1. dylib +load → swizzle bootstrapWorker + setupFloatWindow + presentViewController
//  2. bootstrapWorker 被拦截 → 执行我们的网络验证
//  3. 验证通过 → 直接调用 KakaAuthManager 设置 authStatus=Success
//  4. 发送 KakaAuthDidSucceedNotification → KakaMenuHandler 自动初始化 UI
//  5. 验证失败 → 弹出我们自己的卡密输入框
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <sys/mman.h>
#import <dlfcn.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/sysctl.h>
#include <stdarg.h>
#import "fishhook/fishhook.h"

#define PT_DENY_ATTACH 31
#ifndef _CADDR_T
typedef char *caddr_t;
#endif

// ==========================================
// 网络验证配置
// ==========================================
#define kServerUrl      @"https://authsoft.top"
#define kAppKey         @"b6ec090aa0e8beabd6bf444831f2f818"
#define kAppSecret      @"7a15b8f5c8f47e7cc4bc7bcaf771bbaa4218a1b4dc50a1e940d0a7169db8a17b"

#define KEYCHAIN_SERVICE    @"com.kakahookengine.auth"
#define KEYCHAIN_CARD_KEY   @"card_key"
#define KEYCHAIN_DEVICE_ID  @"persistent_device_id"

// ==========================================
// 全局状态
// ==========================================
typedef NS_ENUM(NSInteger, AuthState) {
    AuthStateUnCheck = 0,
    AuthStateChecking,
    AuthStatePass,
    AuthStateBan
};

static AuthState g_authState = AuthStateUnCheck;
static BOOL g_ourVerificationPassed = NO;

// ==========================================
// Keychain 工具
// ==========================================

static NSString *_saveToKeychain(NSString *key, NSString *value) {
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *deleteQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: key
    };
    SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
    
    NSDictionary *addQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecValueData: data,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    };
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    return (status == errSecSuccess) ? value : nil;
}

static NSString *_readFromKeychain(NSString *key) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecSuccess && result) {
        NSData *data = (__bridge_transfer NSData *)result;
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return nil;
}

static void _clearFromKeychain(NSString *key) {
    NSDictionary *deleteQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: key
    };
    SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
}

static NSString *_getPersistentDeviceID(void) {
    NSString *saved = _readFromKeychain(KEYCHAIN_DEVICE_ID);
    if (saved) return saved;
    NSString *newID = [[NSUUID UUID] UUIDString];
    _saveToKeychain(KEYCHAIN_DEVICE_ID, newID);
    return newID;
}

// ==========================================
// 网络验证器
// ==========================================

@interface NetworkVerifier : NSObject
@property (nonatomic, assign) NSInteger serverTimeOffset;
- (void)verifyWithCard:(NSString *)card completion:(void(^)(BOOL success, NSDictionary *data, NSString *msg))completion;
@end

@implementation NetworkVerifier

- (instancetype)init {
    self = [super init];
    if (self) { _serverTimeOffset = 0; }
    return self;
}

- (void)verifyWithCard:(NSString *)card completion:(void(^)(BOOL, NSDictionary*, NSString*))completion {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
        NSString *deviceId = _getPersistentDeviceID();
        long localTs = (long)[[NSDate date] timeIntervalSince1970] + self.serverTimeOffset;
        NSString *tsStr = [NSString stringWithFormat:@"%ld", localTs];
        NSString *nonce = [[NSUUID UUID] UUIDString];
        
        NSString *rawSign = [NSString stringWithFormat:@"%@%@%@", kAppKey, kAppSecret, tsStr];
        NSMutableString *sign = [NSMutableString string];
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(rawSign.UTF8String, (CC_LONG)rawSign.length, digest);
        for(int i=0; i<CC_SHA256_DIGEST_LENGTH; i++){
            [sign appendFormat:@"%02x", digest[i]];
        }
        
        NSDictionary *reqBody = @{
            @"card_code": card,
            @"device_id": deviceId,
            @"app_key": kAppKey,
            @"timestamp": tsStr,
            @"sign": sign,
            @"nonce": nonce
        };
        
        NSString *fullUrl = [NSString stringWithFormat:@"%@/api/init", kServerUrl];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:fullUrl]];
        req.HTTPMethod = @"POST";
        req.timeoutInterval = 8.0;
        [req setValue:@"application/json;charset=utf-8" forHTTPHeaderField:@"Content-Type"];
        [req setValue:@"AuthSoft-iOS-Client" forHTTPHeaderField:@"User-Agent"];
        
        NSError *jsonErr;
        NSData *bodyData = [NSJSONSerialization dataWithJSONObject:reqBody options:0 error:&jsonErr];
        if (jsonErr || !bodyData) {
            dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, nil, @"JSON序列化失败"); });
            return;
        }
        req.HTTPBody = bodyData;
        
        NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req
            completionHandler:^(NSData *responseData, NSURLResponse *response, NSError *error) {
                if (error) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        completion(NO, nil, [NSString stringWithFormat:@"网络错误: %@", error.localizedDescription]);
                    });
                    return;
                }
                NSError *parseErr;
                NSDictionary *resJson = [NSJSONSerialization JSONObjectWithData:responseData options:0 error:&parseErr];
                if (parseErr || ![resJson isKindOfClass:[NSDictionary class]] || !resJson[@"code"]) {
                    dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, nil, @"服务端返回数据格式错误"); });
                    return;
                }
                if(resJson[@"server_time"]){
                    self.serverTimeOffset = [resJson[@"server_time"] longValue] - localTs;
                }
                dispatch_async(dispatch_get_main_queue(), ^{
                    NSInteger code = [resJson[@"code"] integerValue];
                    if(code == 0){ completion(YES, resJson[@"data"], resJson[@"msg"] ?: @"成功"); }
                    else{ completion(NO, nil, resJson[@"msg"] ?: @"授权校验失败"); }
                });
            }];
        [task resume];
    });
}

@end

// ==========================================
// Swizzle 原始指针
// ==========================================
static IMP orig_bootstrapWorker = NULL;
static IMP orig_setupFloatWindow = NULL;
static IMP orig_presentViewController = NULL;
static void (*orig_bootstrapWorker_func)(id, SEL) = NULL;

// ==========================================
// NSUserDefaults 配置注入
// ==========================================
static IMP orig_floatForKey = NULL;
static IMP orig_boolForKey = NULL;
static IMP orig_integerForKey = NULL;
static IMP orig_objectForKey = NULL;
static NSDictionary *g_overrideFloats = nil;
static NSDictionary *g_overrideBools = nil;
static NSDictionary *g_overrideIntegers = nil;

// ==========================================
// 前向声明
// ==========================================
static void _swizzleBootstrapWorker(Class authClass);
static void _swizzleSetupFloatWindow(Class menuHandlerClass);
static void _swizzlePresentViewController(void);
static void _swizzleNSUserDefaults(void);
static UIAlertController *_createActivationAlert(NSString *errorMsg, NetworkVerifier *verifier);

// ==========================================
// 对抗层：fishhook ptrace
// ==========================================
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int fake_ptrace(int req, pid_t pid, caddr_t addr, int data) {
    if (req == PT_DENY_ATTACH || req == 31) return 0;
    return orig_ptrace(req, pid, addr, data);
}

// ==========================================
// NSUserDefaults Swizzle 实现
// ==========================================
static void _swizzleNSUserDefaults(void) {
    Class defaultsClass = [NSUserDefaults class];
    
    g_overrideFloats = @{
        @"KakaHookFloatX": @100.0, @"KakaHookFloatY": @100.0,
        @"KakaPanelOpacity": @0.9,
        @"KakaDrawLogOffsetX": @0.0, @"KakaDrawLogOffsetY": @0.0,
        @"KakaDrawLogFontScale": @1.0, @"KakaDrawIdentityOffsetX": @0.0,
        @"KakaDrawIdentityOffsetY": @0.0, @"KakaDrawIdentityFontScale": @1.0,
        @"KakaDrawPlayerFontScale": @1.0, @"KakaShortMovePanelScale": @1.0,
        @"KakaSniperPanelScale": @1.0, @"KakaTeleportPanelScale": @1.0,
    };
    g_overrideBools = @{
        @"KakaSpeedSwitch": @YES, @"KakaRoofSwitch": @NO,
        @"KakaInstantTaskSwitch": @NO, @"KakaBroadcastSwitch": @NO,
        @"KakaShortMoveSwitch": @NO, @"KakaRangeBoostSwitch": @NO,
        @"KakaDeathMicSwitch": @NO, @"KakaTeleportSwitch": @NO,
        @"KakaVoiceWallSwitch": @NO, @"KakaEggBreakerSwitch": @NO,
        @"KakaPeerDetectSwitch": @NO, @"KakaMonitorPanelSwitch": @NO,
        @"KakaIgnoreImmobilizeSwitch": @NO, @"KakaMeetingExitSwitch": @NO,
        @"KakaDrawSwitch": @NO,
    };
    g_overrideIntegers = @{ @"KakaDrawLogVisibleCount": @5 };
    
    Method m1 = class_getInstanceMethod(defaultsClass, @selector(floatForKey:));
    if (m1) {
        orig_floatForKey = method_getImplementation(m1);
        IMP fakeFloat = imp_implementationWithBlock(^float(id self, NSString *key) {
            NSNumber *v = g_overrideFloats[key];
            if (v) return [v floatValue];
            return ((float(*)(id, SEL, NSString *))orig_floatForKey)(self, @selector(floatForKey:), key);
        });
        method_setImplementation(m1, fakeFloat);
    }
    
    Method m2 = class_getInstanceMethod(defaultsClass, @selector(boolForKey:));
    if (m2) {
        orig_boolForKey = method_getImplementation(m2);
        IMP fakeBool = imp_implementationWithBlock(^BOOL(id self, NSString *key) {
            NSNumber *v = g_overrideBools[key];
            if (v) return [v boolValue];
            return ((BOOL(*)(id, SEL, NSString *))orig_boolForKey)(self, @selector(boolForKey:), key);
        });
        method_setImplementation(m2, fakeBool);
    }
    
    Method m3 = class_getInstanceMethod(defaultsClass, @selector(integerForKey:));
    if (m3) {
        orig_integerForKey = method_getImplementation(m3);
        IMP fakeInt = imp_implementationWithBlock(^NSInteger(id self, NSString *key) {
            NSNumber *v = g_overrideIntegers[key];
            if (v) return [v integerValue];
            return ((NSInteger(*)(id, SEL, NSString *))orig_integerForKey)(self, @selector(integerForKey:), key);
        });
        method_setImplementation(m3, fakeInt);
    }
    
    Method m4 = class_getInstanceMethod(defaultsClass, @selector(objectForKey:));
    if (m4) {
        orig_objectForKey = method_getImplementation(m4);
        IMP fakeObj = imp_implementationWithBlock(^id(id self, NSString *key) {
            if ([key isEqualToString:@"kaka.auth.local"]) return @"verified";
            return ((id(*)(id, SEL, NSString *))orig_objectForKey)(self, @selector(objectForKey:), key);
        });
        method_setImplementation(m4, fakeObj);
    }
    NSLog(@"[KakaHookEngine] ✅ NSUserDefaults 配置注入已就绪");
}

// ==========================================
// presentViewController Swizzle
// ==========================================
static void _swizzlePresentViewController(void) {
    Class vcClass = [UIViewController class];
    Method m = class_getInstanceMethod(vcClass, @selector(presentViewController:animated:completion:));
    if (!m) return;
    orig_presentViewController = method_getImplementation(m);
    IMP fakePresent = imp_implementationWithBlock(^void(id self, UIViewController *vc, BOOL animated, void(^completion)(void)) {
        NSString *cls = NSStringFromClass([vc class]);
        BOOL isKaka = [cls containsString:@"Kaka"] &&
                     ([cls containsString:@"Auth"] || [cls containsString:@"Verify"] ||
                      [cls containsString:@"Login"] || [cls containsString:@"Activation"]);
        if (isKaka && !g_ourVerificationPassed) {
            NSLog(@"[KakaHookEngine] 🛡️ 拦截 KakaSDK 验证弹窗: %@", cls);
            return;
        }
        ((void(*)(id, SEL, UIViewController *, BOOL, void(^)(void)))orig_presentViewController)(self, @selector(presentViewController:animated:completion:), vc, animated, completion);
    });
    method_setImplementation(m, fakePresent);
    NSLog(@"[KakaHookEngine] ✅ presentViewController 已拦截");
}

// ==========================================
// setupFloatWindow Swizzle
// ==========================================
static void _swizzleSetupFloatWindow(Class menuHandlerClass) {
    Method m = class_getInstanceMethod(menuHandlerClass, NSSelectorFromString(@"setupFloatWindow"));
    if (!m) return;
    orig_setupFloatWindow = method_getImplementation(m);
    IMP fake = imp_implementationWithBlock(^void(id self) {
        if (!g_ourVerificationPassed) {
            NSLog(@"[KakaHookEngine] 🛡️ setupFloatWindow 被拦截");
            return;
        }
        ((void(*)(id, SEL))orig_setupFloatWindow)(self, @selector(setupFloatWindow));
    });
    method_setImplementation(m, fake);
    NSLog(@"[KakaHookEngine] ✅ setupFloatWindow 已拦截");
}

// ==========================================
// bootstrapWorker Swizzle（核心）
// ==========================================
static void _swizzleBootstrapWorker(Class authClass) {
    Method m = class_getInstanceMethod(authClass, NSSelectorFromString(@"bootstrapWorker"));
    if (!m) return;
    orig_bootstrapWorker = method_getImplementation(m);
    orig_bootstrapWorker_func = (void(*)(id, SEL))orig_bootstrapWorker;
    
    IMP fake = imp_implementationWithBlock(^void(id self) {
        NSLog(@"[KakaHookEngine] 🛡️ bootstrapWorker 被拦截");
        
        if (g_ourVerificationPassed) {
            NSLog(@"[KakaHookEngine] ✓ 验证已通过，执行原始 bootstrapWorker");
            orig_bootstrapWorker_func(self, @selector(bootstrapWorker));
            return;
        }
        
        // 执行网络验证
        NetworkVerifier *verifier = [[NetworkVerifier alloc] init];
        NSString *savedCard = _readFromKeychain(KEYCHAIN_CARD_KEY);
        
        if (savedCard) {
            NSLog(@"[KakaHookEngine] 检测到本地卡密，自动验证...");
            [verifier verifyWithCard:savedCard completion:^(BOOL success, NSDictionary *data, NSString *msg) {
                if (success && [data[@"status"] isEqualToString:@"active"]) {
                    g_authState = AuthStatePass;
                    g_ourVerificationPassed = YES;
                    NSLog(@"[KakaHookEngine] ✓ 自动验证通过");
                    
                    [self setValue:@3 forKey:@"authStatus"];
                    [[NSNotificationCenter defaultCenter] postNotificationName:@"KakaAuthDidSucceedNotification" object:nil];
                    [[NSNotificationCenter defaultCenter] postNotificationName:@"KakaAuthStatusDidChangeNotification" object:nil];
                    NSLog(@"[KakaHookEngine] ✓ 已发送认证通知");
                } else {
                    g_authState = AuthStateBan;
                    _clearFromKeychain(KEYCHAIN_CARD_KEY);
                    UIAlertController *alert = _createActivationAlert(msg, verifier);
                    UIWindow *win = [UIApplication sharedApplication].windows.lastObject;
                    UIViewController *vc = win.rootViewController;
                    while (vc.presentedViewController) vc = vc.presentedViewController;
                    [vc presentViewController:alert animated:YES completion:nil];
                }
            }];
        } else {
            NSLog(@"[KakaHookEngine] 未检测到卡密，弹出激活窗口");
            g_authState = AuthStateChecking;
            dispatch_async(dispatch_get_main_queue(), ^{
                UIAlertController *alert = _createActivationAlert(nil, verifier);
                UIWindow *win = [UIApplication sharedApplication].windows.lastObject;
                UIViewController *vc = win.rootViewController;
                while (vc.presentedViewController) vc = vc.presentedViewController;
                [vc presentViewController:alert animated:YES completion:nil];
            });
        }
    });
    method_setImplementation(m, fake);
    NSLog(@"[KakaHookEngine] ✅ bootstrapWorker 已拦截");
}

// ==========================================
// 激活弹窗
// ==========================================
static UIAlertController *_createActivationAlert(NSString *errorMsg, NetworkVerifier *verifier) {
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"激活提示"
        message:(errorMsg ?: @"请输入卡密激活")
        preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"请输入卡密";
        textField.secureTextEntry = NO;
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"激活" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *card = alert.textFields.firstObject.text;
        if (card.length == 0) {
            UIAlertController *retry = _createActivationAlert(@"卡密不能为空", verifier);
            UIWindow *win = [UIApplication sharedApplication].windows.lastObject;
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;
            [vc presentViewController:retry animated:YES completion:nil];
            return;
        }
        
        [verifier verifyWithCard:card completion:^(BOOL success, NSDictionary *data, NSString *msg) {
            if (success && [data[@"status"] isEqualToString:@"active"]) {
                g_authState = AuthStatePass;
                g_ourVerificationPassed = YES;
                _saveToKeychain(KEYCHAIN_CARD_KEY, card);
                
                // 设置 KakaAuthManager authStatus = Success
                Class authClass = NSClassFromString(@"KakaAuthManager");
                if (authClass) {
                    id manager = [authClass performSelector:@selector(sharedManager)];
                    if (manager) {
                        [manager setValue:@3 forKey:@"authStatus"];
                        [[NSNotificationCenter defaultCenter] postNotificationName:@"KakaAuthDidSucceedNotification" object:nil];
                        [[NSNotificationCenter defaultCenter] postNotificationName:@"KakaAuthStatusDidChangeNotification" object:nil];
                    }
                }
                
                // 显示成功提示
                UIAlertController *ok = [UIAlertController alertControllerWithTitle:@"✅ 验证成功" message:@"功能已激活" preferredStyle:UIAlertControllerStyleAlert];
                [ok addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
                UIWindow *win = [UIApplication sharedApplication].windows.lastObject;
                UIViewController *vc = win.rootViewController;
                while (vc.presentedViewController) vc = vc.presentedViewController;
                [vc presentViewController:ok animated:YES completion:nil];
            } else {
                g_authState = AuthStateBan;
                _clearFromKeychain(KEYCHAIN_CARD_KEY);
                UIAlertController *retry = _createActivationAlert(msg, verifier);
                UIWindow *win = [UIApplication sharedApplication].windows.lastObject;
                UIViewController *vc = win.rootViewController;
                while (vc.presentedViewController) vc = vc.presentedViewController;
                [vc presentViewController:retry animated:YES completion:nil];
            }
        }];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"清除卡密" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        _clearFromKeychain(KEYCHAIN_CARD_KEY);
        UIAlertController *cleared = _createActivationAlert(@"已清除卡密，请重新输入", verifier);
        UIWindow *win = [UIApplication sharedApplication].windows.lastObject;
        UIViewController *vc = win.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        [vc presentViewController:cleared animated:YES completion:nil];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"退出" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        exit(0);
    }]];
    
    return alert;
}

// ==========================================
// dyld 回调
// ==========================================
static void kakaSDKImageCallback(const struct mach_header *header, intptr_t slide) {
    const char *name = _dyld_get_image_name(_dyld_image_count() - 1);
    NSLog(@"[KakaHookEngine] 📦 新镜像加载: %s", name ? name : "(null)");
    
    if (name && strstr(name, "KakaSDK")) {
        NSLog(@"[KakaHookEngine] ✓ 检测到 KakaSDK: %s", name);
        
        // 打印所有 Kaka 开头的类
        unsigned int classCount = 0;
        Class *classes = objc_copyClassList(&classCount);
        for (unsigned int i = 0; i < classCount; i++) {
            const char *className = class_getName(classes[i]);
            if (className && strstr(className, "Kaka")) {
                NSLog(@"[KakaHookEngine]  找到 Kaka 类: %s", className);
            }
        }
        free(classes);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            Class authClass = NSClassFromString(@"KakaAuthManager");
            NSLog(@"[KakaHookEngine] KakaAuthManager: %@", authClass ? @"存在" : @"不存在");
            if (authClass) _swizzleBootstrapWorker(authClass);
            
            Class menuClass = NSClassFromString(@"KakaMenuHandler");
            NSLog(@"[KakaHookEngine] KakaMenuHandler: %@", menuClass ? @"存在" : @"不存在");
            if (menuClass) _swizzleSetupFloatWindow(menuClass);
        });
    }
}

// ==========================================
// 主入口
// ==========================================
__attribute__((constructor))
static void kakaHookEngine_init(void) {
    NSLog(@"[KakaHookEngine] ========================================");
    NSLog(@"[KakaHookEngine] KakaHookEngine Loaded (constructor)");
    NSLog(@"[KakaHookEngine] ========================================");
    
    // 打印所有已加载的镜像
    NSLog(@"[KakaHookEngine]  当前已加载镜像 (%u 个):", _dyld_image_count());
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && (strstr(name, "Kaka") || strstr(name, "Goose") || strstr(name, "Duck"))) {
            NSLog(@"[KakaHookEngine]   [%u] %s", i, name);
        }
    }
    
    // 1. 立即执行不需要依赖 KakaSDK 的 swizzle
    _swizzleNSUserDefaults();
    _swizzlePresentViewController();
    
    // 2. Hook ptrace
    struct rebinding ptraceRebind = {"ptrace", fake_ptrace, (void *)&orig_ptrace};
    rebind_symbols(&ptraceRebind, 1);
    NSLog(@"[KakaHookEngine] ✅ ptrace 已屏蔽");
    
    // 3. 检查 KakaSDK 是否已加载
    BOOL kakaLoaded = NO;
    const char *kakaSDKPath = NULL;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "KakaSDK")) { 
            kakaLoaded = YES; 
            kakaSDKPath = name;
            break; 
        }
    }
    
    if (kakaLoaded) {
        NSLog(@"[KakaHookEngine] ✓ KakaSDK 已存在: %s", kakaSDKPath);
        Class authClass = NSClassFromString(@"KakaAuthManager");
        NSLog(@"[KakaHookEngine] KakaAuthManager: %@", authClass ? @"存在" : @"不存在");
        if (authClass) _swizzleBootstrapWorker(authClass);
        Class menuClass = NSClassFromString(@"KakaMenuHandler");
        NSLog(@"[KakaHookEngine] KakaMenuHandler: %@", menuClass ? @"存在" : @"不存在");
        if (menuClass) _swizzleSetupFloatWindow(menuClass);
    } else {
        NSLog(@"[KakaHookEngine] ⏳ 等待 KakaSDK 加载...");
        _dyld_register_func_for_add_image(kakaSDKImageCallback);
        
        // 延迟 5 秒后重试（防止 KakaSDK 加载太晚）
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            NSLog(@"[KakaHookEngine] 延迟 5 秒后重新检查 KakaSDK...");
            BOOL retryLoaded = NO;
            const char *retryPath = NULL;
            for (uint32_t i = 0; i < _dyld_image_count(); i++) {
                const char *name = _dyld_get_image_name(i);
                if (name && strstr(name, "KakaSDK")) {
                    retryLoaded = YES;
                    retryPath = name;
                    break;
                }
            }
            if (retryLoaded && !g_authState) {
                NSLog(@"[KakaHookEngine] ✓ 延迟重试：KakaSDK 已加载: %s", retryPath);
                Class authClass = NSClassFromString(@"KakaAuthManager");
                if (authClass) _swizzleBootstrapWorker(authClass);
                Class menuClass = NSClassFromString(@"KakaMenuHandler");
                if (menuClass) _swizzleSetupFloatWindow(menuClass);
            } else if (!retryLoaded) {
                NSLog(@"[KakaHookEngine] ❌ 延迟 5 秒后仍未检测到 KakaSDK");
                // 打印所有镜像
                NSLog(@"[KakaHookEngine] 所有镜像列表:");
                for (uint32_t i = 0; i < _dyld_image_count(); i++) {
                    const char *name = _dyld_get_image_name(i);
                    if (name) NSLog(@"[KakaHookEngine]   [%u] %s", i, name);
                }
            }
        });
    }
}
