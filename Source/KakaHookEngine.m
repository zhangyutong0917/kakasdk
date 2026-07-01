//
//  KakaHookEngine.m → 输出为 KKEngine.dylib
//  新方案：底层Hook authStatus getter + 定时器重试 + 强制调用菜单
//  不再依赖 bootstrapWorker 的拦截时机
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

#define KEYCHAIN_SERVICE    @"com.kkengine.auth"
#define KEYCHAIN_CARD_KEY   @"card_key"
#define KEYCHAIN_DEVICE_ID  @"persistent_device_id"

// ==========================================
// 全局状态
// ==========================================
static BOOL g_verificationPassed = NO;
static BOOL g_swizzleDone = NO;
static BOOL g_menuForced = NO;
static NetworkVerifier *g_verifier = nil;
static NSString *g_savedCard = nil;

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
static IMP orig_authStatus = NULL;
static IMP orig_bootstrapWorker = NULL;
static IMP orig_setupFloatWindow = NULL;
static IMP orig_presentViewController = NULL;
static void (*orig_bootstrapWorker_func)(id, SEL) = NULL;

// NSUserDefaults
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
static void _swizzleAuthStatus(Class authClass);
static void _swizzleBootstrapWorker(Class authClass);
static void _swizzleSetupFloatWindow(Class menuHandlerClass);
static void _swizzlePresentViewController(void);
static void _swizzleNSUserDefaults(void);
static void _forceShowMenu(void);
static void _enumerateKakaMethods(Class cls);
static UIAlertController *_createActivationAlert(NSString *errorMsg, NetworkVerifier *verifier);
static void _doAllSwizzles(void);
static void _onVerificationPassed(NSDictionary *data);

// ==========================================
// 对抗层：fishhook ptrace
// ==========================================
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int fake_ptrace(int req, pid_t pid, caddr_t addr, int data) {
    if (req == PT_DENY_ATTACH || req == 31) return 0;
    return orig_ptrace(req, pid, addr, data);
}

// ==========================================
// NSUserDefaults Swizzle
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
    NSLog(@"[KKEngine] ✅ NSUserDefaults 配置注入已就绪");
}

// ==========================================
// presentViewController Swizzle（拦截KakaSDK验证弹窗）
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
                      [cls containsString:@"Login"] || [cls containsString:@"Activation"] ||
                      [cls containsString:@"Card"] || [cls containsString:@"Input"]);
        if (isKaka && !g_verificationPassed) {
            NSLog(@"[KKEngine] 🛡️ 拦截KakaSDK验证弹窗: %@", cls);
            return;
        }
        ((void(*)(id, SEL, UIViewController *, BOOL, void(^)(void)))orig_presentViewController)(self, @selector(presentViewController:animated:completion:), vc, animated, completion);
    });
    method_setImplementation(m, fakePresent);
    NSLog(@"[KKEngine] ✅ presentViewController 已拦截");
}

// ==========================================
// ★ 核心：authStatus getter swizzle（底层Hook）
// ==========================================
static void _swizzleAuthStatus(Class authClass) {
    // 尝试多种可能的 getter 名称
    NSArray *getterNames = @[@"authStatus", @"getAuthStatus", @"status", @"authState"];
    BOOL found = NO;
    
    for (NSString *name in getterNames) {
        SEL sel = NSSelectorFromString(name);
        Method m = class_getInstanceMethod(authClass, sel);
        if (m) {
            NSLog(@"[KKEngine] 找到auth getter: %@", name);
            if (!found) {
                orig_authStatus = method_getImplementation(m);
                IMP fakeAuth = imp_implementationWithBlock(^NSInteger(id self) {
                    if (g_verificationPassed) {
                        NSLog(@"[KKEngine] authStatus 返回 3 (Success)");
                        return 3;
                    }
                    return 0;
                });
                method_setImplementation(m, fakeAuth);
                NSLog(@"[KKEngine] ✅ authStatus getter 已拦截 → 验证通过时返回3");
                found = YES;
            }
        }
    }
    
    if (!found) {
        NSLog(@"[KKEngine] ⚠️ 未找到authStatus getter，尝试枚举所有方法...");
        _enumerateKakaMethods(authClass);
    }
}

// ==========================================
// bootstrapWorker Swizzle（阻止KakaSDK自己的验证流程）
// ==========================================
static void _swizzleBootstrapWorker(Class authClass) {
    Method m = class_getInstanceMethod(authClass, NSSelectorFromString(@"bootstrapWorker"));
    if (!m) {
        NSLog(@"[KKEngine] ️ bootstrapWorker 方法不存在");
        return;
    }
    orig_bootstrapWorker = method_getImplementation(m);
    orig_bootstrapWorker_func = (void(*)(id, SEL))orig_bootstrapWorker;
    
    IMP fake = imp_implementationWithBlock(^void(id self) {
        NSLog(@"[KKEngine] ️ bootstrapWorker 被拦截");
        if (g_verificationPassed) {
            NSLog(@"[KKEngine] ✓ 验证已通过，执行原始 bootstrapWorker");
            orig_bootstrapWorker_func(self, @selector(bootstrapWorker));
        } else {
            NSLog(@"[KKEngine] ⏸️ 验证未通过，跳过 bootstrapWorker（阻止KakaSDK验证UI）");
        }
    });
    method_setImplementation(m, fake);
    NSLog(@"[KKEngine] ✅ bootstrapWorker 已拦截");
}

// ==========================================
// setupFloatWindow Swizzle
// ==========================================
static void _swizzleSetupFloatWindow(Class menuHandlerClass) {
    Method m = class_getInstanceMethod(menuHandlerClass, NSSelectorFromString(@"setupFloatWindow"));
    if (!m) {
        NSLog(@"[KKEngine] ⚠️ setupFloatWindow 方法不存在");
        return;
    }
    orig_setupFloatWindow = method_getImplementation(m);
    IMP fake = imp_implementationWithBlock(^void(id self) {
        if (!g_verificationPassed) {
            NSLog(@"[KKEngine] 🛡️ setupFloatWindow 被拦截（验证未通过）");
            return;
        }
        NSLog(@"[KKEngine] ✓ setupFloatWindow 执行（验证已通过）");
        ((void(*)(id, SEL))orig_setupFloatWindow)(self, @selector(setupFloatWindow));
    });
    method_setImplementation(m, fake);
    NSLog(@"[KKEngine] ✅ setupFloatWindow 已拦截");
}

// ==========================================
// 方法枚举（调试用）
// ==========================================
static void _enumerateKakaMethods(Class cls) {
    if (!cls) return;
    unsigned int methodCount = 0;
    Method *methods = class_copyMethodList(cls, &methodCount);
    NSLog(@"[KKEngine] %@ 共有 %u 个方法:", NSStringFromClass(cls), methodCount);
    for (unsigned int i = 0; i < methodCount; i++) {
        SEL sel = method_getName(methods[i]);
        const char *name = sel_getName(sel);
        if (name) {
            NSString *methodName = [NSString stringWithUTF8String:name];
            if ([methodName containsString:@"auth"] || [methodName containsString:@"Auth"] ||
                [methodName containsString:@"verify"] || [methodName containsString:@"Verify"] ||
                [methodName containsString:@"check"] || [methodName containsString:@"Check"] ||
                [methodName containsString:@"boot"] || [methodName containsString:@"Boot"] ||
                [methodName containsString:@"status"] || [methodName containsString:@"Status"] ||
                [methodName containsString:@"float"] || [methodName containsString:@"Float"] ||
                [methodName containsString:@"menu"] || [methodName containsString:@"Menu"] ||
                [methodName containsString:@"setup"] || [methodName containsString:@"Setup"]) {
                NSLog(@"[KKEngine]   方法: %@", methodName);
            }
        }
    }
    free(methods);
    
    // 也枚举类方法
    Method *classMethods = class_copyMethodList(object_getClass(cls), &methodCount);
    if (classMethods && methodCount > 0) {
        NSLog(@"[KKEngine] %@ 共有 %u 个类方法:", NSStringFromClass(cls), methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            SEL sel = method_getName(classMethods[i]);
            const char *name = sel_getName(sel);
            if (name) NSLog(@"[KKEngine]   类方法: %s", name);
        }
        free(classMethods);
    }
}

// ==========================================
// 强制显示菜单（验证通过后直接调用）
// ==========================================
static void _forceShowMenu(void) {
    if (g_menuForced) return;
    g_menuForced = YES;
    
    NSLog(@"[KKEngine]  强制显示菜单...");
    
    // 方式1：通过 KakaMenuHandler
    Class menuClass = NSClassFromString(@"KakaMenuHandler");
    if (menuClass) {
        // 尝试多种获取实例的方式
        id handler = nil;
        
        SEL sharedSel = NSSelectorFromString(@"sharedHandler");
        if ([menuClass respondsToSelector:sharedSel]) {
            handler = [menuClass performSelector:sharedSel];
        }
        if (!handler) {
            SEL defaultSel = NSSelectorFromString(@"defaultHandler");
            if ([menuClass respondsToSelector:defaultSel]) {
                handler = [menuClass performSelector:defaultSel];
            }
        }
        if (!handler) {
            SEL sharedManagerSel = NSSelectorFromString(@"sharedManager");
            if ([menuClass respondsToSelector:sharedManagerSel]) {
                handler = [menuClass performSelector:sharedManagerSel];
            }
        }
        if (!handler) {
            handler = [[menuClass alloc] init];
        }
        
        if (handler) {
            SEL setupSel = NSSelectorFromString(@"setupFloatWindow");
            if ([handler respondsToSelector:setupSel]) {
                NSLog(@"[KKEngine] ✓ 调用 setupFloatWindow");
                [handler performSelector:setupSel];
            }
            
            SEL showSel = NSSelectorFromString(@"showMenu");
            if ([handler respondsToSelector:showSel]) {
                NSLog(@"[KKEngine] ✓ 调用 showMenu");
                [handler performSelector:showSel];
            }
            
            SEL presentSel = NSSelectorFromString(@"presentMenu");
            if ([handler respondsToSelector:presentSel]) {
                NSLog(@"[KKEngine] ✓ 调用 presentMenu");
                [handler performSelector:presentSel];
            }
        }
    }
    
    // 方式2：通过 KakaAuthManager 发送通知
    Class authClass = NSClassFromString(@"KakaAuthManager");
    if (authClass) {
        SEL sharedSel = NSSelectorFromString(@"sharedManager");
        if ([authClass respondsToSelector:sharedSel]) {
            id manager = [authClass performSelector:sharedSel];
            if (manager) {
                // 直接设置 authStatus = 3
                [manager setValue:@3 forKey:@"authStatus"];
                NSLog(@"[KKEngine] ✓ 已设置 authStatus = 3");
                
                // 发送所有可能的通知
                [[NSNotificationCenter defaultCenter] postNotificationName:@"KakaAuthDidSucceedNotification" object:nil];
                [[NSNotificationCenter defaultCenter] postNotificationName:@"KakaAuthStatusDidChangeNotification" object:nil];
                [[NSNotificationCenter defaultCenter] postNotificationName:@"KakaMenuShouldShowNotification" object:nil];
                NSLog(@"[KKEngine] ✓ 已发送认证通知");
            }
        }
    }
    
    NSLog(@"[KKEngine] ✅ 强制显示菜单完成");
}

// ==========================================
// 验证通过后的处理
// ==========================================
static void _onVerificationPassed(NSDictionary *data) {
    g_verificationPassed = YES;
    NSLog(@"[KKEngine] ========================================");
    NSLog(@"[KKEngine] ✓✓✓ 验证通过！✓✓✓");
    NSLog(@"[KKEngine] ========================================");
    
    // 强制显示菜单
    dispatch_async(dispatch_get_main_queue(), ^{
        _forceShowMenu();
    });
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
        if (g_savedCard) textField.text = g_savedCard;
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
                g_savedCard = card;
                _saveToKeychain(KEYCHAIN_CARD_KEY, card);
                _onVerificationPassed(data);
                
                UIAlertController *ok = [UIAlertController alertControllerWithTitle:@"验证成功" message:@"功能已激活" preferredStyle:UIAlertControllerStyleAlert];
                [ok addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
                UIWindow *win = [UIApplication sharedApplication].windows.lastObject;
                UIViewController *vc = win.rootViewController;
                while (vc.presentedViewController) vc = vc.presentedViewController;
                [vc presentViewController:ok animated:YES completion:nil];
            } else {
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
        g_savedCard = nil;
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
// 显示激活弹窗
// ==========================================
static void _showActivationAlert(NSString *errorMsg) {
    if (!g_verifier) g_verifier = [[NetworkVerifier alloc] init];
    
    dispatch_async(dispatch_get_main_queue(), ^{
        // 等待 rootViewController 就绪
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            UIAlertController *alert = _createActivationAlert(errorMsg, g_verifier);
            
            UIWindow *win = nil;
            for (UIWindow *w in [UIApplication sharedApplication].windows) {
                if (w.isKeyWindow || w.windowLevel == UIWindowLevelNormal) {
                    win = w;
                    break;
                }
            }
            if (!win) win = [UIApplication sharedApplication].windows.lastObject;
            
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;
            [vc presentViewController:alert animated:YES completion:nil];
            NSLog(@"[KKEngine] ✅ 激活弹窗已显示");
        });
    });
}

// ==========================================
// 统一执行所有 swizzle
// ==========================================
static void _doAllSwizzles(void) {
    if (g_swizzleDone) return;
    g_swizzleDone = YES;
    
    NSLog(@"[KKEngine] 开始执行所有 swizzle...");
    
    Class authClass = NSClassFromString(@"KakaAuthManager");
    if (authClass) {
        NSLog(@"[KKEngine] 找到 KakaAuthManager");
        _swizzleAuthStatus(authClass);
        _swizzleBootstrapWorker(authClass);
        _enumerateKakaMethods(authClass);
    } else {
        NSLog(@"[KKEngine] ⚠️ KakaAuthManager 未找到");
    }
    
    Class menuClass = NSClassFromString(@"KakaMenuHandler");
    if (menuClass) {
        NSLog(@"[KKEngine] 找到 KakaMenuHandler");
        _swizzleSetupFloatWindow(menuClass);
        _enumerateKakaMethods(menuClass);
    } else {
        NSLog(@"[KKEngine] ⚠️ KakaMenuHandler 未找到");
    }
    
    // 检查是否有本地保存的卡密
    g_savedCard = _readFromKeychain(KEYCHAIN_CARD_KEY);
    if (g_savedCard) {
        NSLog(@"[KKEngine] 检测到本地卡密，自动验证...");
        if (!g_verifier) g_verifier = [[NetworkVerifier alloc] init];
        [g_verifier verifyWithCard:g_savedCard completion:^(BOOL success, NSDictionary *data, NSString *msg) {
            if (success && [data[@"status"] isEqualToString:@"active"]) {
                _onVerificationPassed(data);
            } else {
                _clearFromKeychain(KEYCHAIN_CARD_KEY);
                g_savedCard = nil;
                _showActivationAlert(msg);
            }
        }];
    } else {
        NSLog(@"[KKEngine] 未检测到卡密，准备显示激活窗口");
        // 等待 rootViewController 就绪后再显示
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            if (!g_verificationPassed) {
                _showActivationAlert(nil);
            }
        });
    }
}

// ==========================================
// dyld 回调
// ==========================================
static void kakaSDKImageCallback(const struct mach_header *header, intptr_t slide) {
    const char *name = _dyld_get_image_name(_dyld_image_count() - 1);
    if (name && strstr(name, "KakaSDK")) {
        NSLog(@"[KKEngine] ✓ KakaSDK 已加载: %s", name);
        dispatch_async(dispatch_get_main_queue(), ^{
            _doAllSwizzles();
        });
    }
}

// ==========================================
// 定时器重试机制
// ==========================================
static void _startRetryTimer(void) {
    __block int retryCount = 0;
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0);
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), 2 * NSEC_PER_SEC, 0);
    dispatch_source_set_event_handler(timer, ^{
        if (g_swizzleDone) {
            dispatch_source_cancel(timer);
            NSLog(@"[KKEngine] 定时器停止（swizzle已完成）");
            return;
        }
        retryCount++;
        if (retryCount > 30) {
            dispatch_source_cancel(timer);
            NSLog(@"[KKEngine] ❌ 重试30次（60秒）仍未找到KakaSDK类");
            return;
        }
        
        Class authClass = NSClassFromString(@"KakaAuthManager");
        Class menuClass = NSClassFromString(@"KakaMenuHandler");
        
        if (authClass || menuClass) {
            NSLog(@"[KKEngine] ✓ 定时器第%d次重试：找到KakaSDK类", retryCount);
            dispatch_async(dispatch_get_main_queue(), ^{
                _doAllSwizzles();
            });
        } else {
            NSLog(@"[KKEngine] 定时器第%d次重试：未找到KakaSDK类", retryCount);
        }
    });
    dispatch_resume(timer);
    NSLog(@"[KKEngine] ✅ 定时器已启动（每2秒重试，最多60秒）");
}

// ==========================================
// 主入口
// ==========================================
__attribute__((constructor))
static void kakaHookEngine_init(void) {
    NSLog(@"[KKEngine] ========================================");
    NSLog(@"[KKEngine] KKEngine Loaded (KakaSDK Hook Engine)");
    NSLog(@"[KKEngine] 方案：底层authStatus Hook + 定时器重试");
    NSLog(@"[KKEngine] ========================================");
    
    // 1. 立即执行不依赖KakaSDK的swizzle
    _swizzleNSUserDefaults();
    _swizzlePresentViewController();
    
    // 2. Hook ptrace
    struct rebinding ptraceRebind = {"ptrace", fake_ptrace, (void *)&orig_ptrace};
    rebind_symbols(&ptraceRebind, 1);
    NSLog(@"[KKEngine] ✅ ptrace 已屏蔽");
    
    // 3. 检查 KakaSDK 是否已加载
    BOOL kakaLoaded = NO;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "KakaSDK")) { kakaLoaded = YES; break; }
    }
    
    if (kakaLoaded) {
        NSLog(@"[KKEngine] ✓ KakaSDK 已存在，立即 swizzle");
        _doAllSwizzles();
    } else {
        NSLog(@"[KKEngine] ⏳ 等待 KakaSDK 加载...");
        _dyld_register_func_for_add_image(kakaSDKImageCallback);
    }
    
    // 4. 启动定时器重试（无论如何都启动，作为保底）
    _startRetryTimer();
}
