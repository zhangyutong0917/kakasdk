//
//  KakaHookEngine.m → 输出为 KKEngine.dylib
//  v3 方案：直接 Patch C 全局变量 + 正确 Keychain 格式
//  根据逆向分析：
//    - dword_1417958 (VA:0x1417958) = 1 表示验证通过
//    - qword_1417D88 (VA:0x1417D88) 必须非零
//    - 所有功能检查：if (!dword_1417958 || qword_1417D88 == 0)
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <sys/mman.h>
#import <dlfcn.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/sysctl.h>
#include <stdarg.h>
#import "fishhook/fishhook.h"

@class NetworkVerifier;

#define PT_DENY_ATTACH 31
#ifndef _CADDR_T
typedef char *caddr_t;
#endif

// ==========================================
// KakaSDK 关键地址（IDA 虚拟地址）
// ==========================================
#define KAKA_AUTH_PASSED_VA     0x1417958   // dword_1417958: 验证通过标志
#define KAKA_DATA_PTR_VA        0x1417D88   // qword_1417D88: 数据指针（必须非零）
#define KAKA_INIT_FUNC_VA       0x325BC     // InitFunc_0: 初始化函数
#define KAKA_VERIFY_FUNC_VA     0x32818     // sub_32818: 验证函数

// ==========================================
// 功能开关 Key（统一管理，避免拼写错误）
// ==========================================
static NSString *const kFeatureDraw        = @"draw";
static NSString *const kFeatureBroadcast   = @"broadcast";
static NSString *const kFeatureTeleport    = @"teleport";
static NSString *const kFeatureShortMove   = @"shortmove";
static NSString *const kFeatureRoof        = @"roof";
static NSString *const kFeatureMeetingExit = @"meeting_exit";
static NSString *const kFeatureVoiceWall   = @"voice_wall";
static NSString *const kFeatureEggBreaker  = @"egg_breaker";
static NSString *const kFeaturePeerDetect  = @"peer_detect";
static NSString *const kFeatureImmobilize  = @"immobilize";
static NSString *const kFeatureRangeBoost  = @"range_boost";
static NSString *const kFeatureDeathMic    = @"death_mic";
static NSString *const kFeatureMonitor     = @"monitor";

// 服务器下发的功能配置（验证通过后填充）
static NSDictionary *g_serverFeatures = nil;

// ==========================================
// 网络验证配置
// ==========================================
#define kServerUrl      @"https://authsoft.top"
#define kAppKey         @"b6ec090aa0e8beabd6bf444831f2f818"
#define kAppSecret      @"7a15b8f5c8f47e7cc4bc7bcaf771bbaa4218a1b4dc50a1e940d0a7169db8a17b"

#define KEYCHAIN_SERVICE    @"kaka.auth.local"
#define KEYCHAIN_CARD_KEY   @"card_key"
#define KEYCHAIN_DEVICE_ID  @"persistent_device_id"

// ==========================================
// 全局状态
// ==========================================
static BOOL g_verificationPassed = NO;
static BOOL g_patchDone = NO;
static NSString *g_savedCard = nil;

// KakaSDK 运行时基地址
static uintptr_t g_kakaSDKBase = 0;

// ==========================================
// ★ 日志系统：存储到 NSUserDefaults（沙盒允许）
// ==========================================
static NSMutableArray *_getLogArray(void) {
    static NSMutableArray *logs = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSData *data = [[NSUserDefaults standardUserDefaults] objectForKey:@"kkengine_logs"];
        if (data) {
            logs = [NSKeyedUnarchiver unarchiveObjectWithData:data];
        }
        if (!logs) {
            logs = [NSMutableArray array];
        }
    });
    return logs;
}

static void _saveLogs(void) {
    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:_getLogArray()];
    [[NSUserDefaults standardUserDefaults] setObject:data forKey:@"kkengine_logs"];
}

static void _addLog(NSString *msg) {
    NSArray *parts = [msg componentsSeparatedByString:@"\n"];
    for (NSString *part in parts) {
        if (part.length > 0) {
            [_getLogArray() addObject:part];
        }
    }
    // 只保留最近 500 条
    if (_getLogArray().count > 500) {
        [_getLogArray() removeObjectsInRange:NSMakeRange(0, _getLogArray().count - 500)];
    }
    _saveLogs();
    // 同时输出到系统日志
    NSLog(@"%@", msg);
}

#define KLOG(fmt, ...) _addLog([NSString stringWithFormat:@"[KKEngine] " fmt, ##__VA_ARGS__])

// ==========================================
// 前向声明
// ==========================================
static BOOL _setMemoryWritable(void *address, size_t size);
static void _write_int(uintptr_t offset, int value);
static void _enableAllFeatures(void);
static void _activateAll(void);
static void _callInitFunc(void);
static void _writeKakaAuthToKeychain(NSString *cardCode);
static void _saveCard(NSString *card);
static NSString *_readSavedCard(void);
static void _clearSavedCard(void);
static void _clearFromKeychain(NSString *key);
static NSString *_getPersistentDeviceID(void);
static void _findKakaSDK(void);
static void _patchAuthOnly(void);
static void _hookPresentViewController(void);
static void _doMainLogic(void);
static void _startRetryTimer(void);
static void _onVerificationPassed(NSDictionary *data, NSString *card);

// ==========================================
// Keychain 工具
// ==========================================

static void _clearFromKeychain(NSString *key) {
    NSDictionary *deleteQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: key
    };
    SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
}

static NSString *_getPersistentDeviceID(void) {
    // 使用 NSUserDefaults 存储设备 ID（简化）
    NSString *saved = [[NSUserDefaults standardUserDefaults] stringForKey:@"kkengine_device_id"];
    if (saved) return saved;
    NSString *newID = [[NSUUID UUID] UUIDString];
    [[NSUserDefaults standardUserDefaults] setObject:newID forKey:@"kkengine_device_id"];
    return newID;
}

// ==========================================
// ★ 关键：写入 KakaSDK 期望的 Keychain 格式
// ==========================================
// KakaSDK 期望的 Keychain 账户名（从逆向报告获取）
#define KAKA_KEYCHAIN_ACCOUNT @".kaka.lock.00000000333F3E99"

static void _writeKakaAuthToKeychain(NSString *cardCode) {
    // 构造 KakaSDK 期望的 JSON 结构
    long ts = (long)[[NSDate date] timeIntervalSince1970];
    NSDictionary *authDict = @{
        @"v": @1,
        @"mask": @0,
        @"ts": @(ts),
        @"card_code": cardCode,
        @"device_id": _getPersistentDeviceID()
    };
    
    NSError *err;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:authDict options:0 error:&err];
    if (err || !jsonData) {
        KLOG("❌ JSON 序列化失败");
        return;
    }
    
    // 写入 Keychain（使用 KakaSDK 期望的账户名）
    NSDictionary *deleteQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: KAKA_KEYCHAIN_ACCOUNT
    };
    SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
    
    NSDictionary *addQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: KAKA_KEYCHAIN_ACCOUNT,
        (__bridge id)kSecValueData: jsonData,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    };
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    if (status == errSecSuccess) {
        KLOG("✅ 已写入 KakaSDK 认证数据到 Keychain (account: %@)", KAKA_KEYCHAIN_ACCOUNT);
    } else {
        KLOG("❌ Keychain 写入失败: %d", (int)status);
    }
}

// 读取本地保存的卡密（从 NSUserDefaults）
static NSString *_readSavedCard(void) {
    return [[NSUserDefaults standardUserDefaults] stringForKey:KEYCHAIN_CARD_KEY];
}

// 保存卡密到 NSUserDefaults
static void _saveCard(NSString *card) {
    [[NSUserDefaults standardUserDefaults] setObject:card forKey:KEYCHAIN_CARD_KEY];
}

// 清除卡密
static void _clearSavedCard(void) {
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:KEYCHAIN_CARD_KEY];
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
            dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, nil, @"JSON 序列化失败"); });
            return;
        }
        req.HTTPBody = bodyData;
        
        NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req
            completionHandler:^(NSData *responseData, NSURLResponse *response, NSError *error) {
                if (error) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        completion(NO, nil, [NSString stringWithFormat:@"网络错误：%@", error.localizedDescription]);
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

// 网络验证器实例（必须在 NetworkVerifier 类定义之后）
static NetworkVerifier *g_verifier = nil;

// ==========================================
// 功能开关判断：服务器 > NSUserDefaults > 默认值
// ==========================================
static BOOL _isFeatureEnabled(NSString *key, BOOL defaultValue) {
    // 1. 服务器配置（最高优先级）
    if (g_serverFeatures && g_serverFeatures[key] != nil) {
        return [g_serverFeatures[key] boolValue];
    }
    
    // 2. 本地 NSUserDefaults 覆盖（用于调试或高级用户）
    NSNumber *localVal = [[NSUserDefaults standardUserDefaults] objectForKey:key];
    if (localVal != nil) {
        return [localVal boolValue];
    }
    
    // 3. 硬编码默认值（兜底）
    return defaultValue;
}

// ==========================================
// 内存写入辅助函数
// ==========================================
static void _write_int(uintptr_t offset, int value) {
    if (g_kakaSDKBase == 0) return;
    
    uintptr_t addr = g_kakaSDKBase + offset;
    if (_setMemoryWritable((void *)addr, sizeof(int))) {
        *(int *)addr = value;
    }
}

// ==========================================
// 对抗层：fishhook ptrace
// ==========================================
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int fake_ptrace(int req, pid_t pid, caddr_t addr, int data) {
    if (req == PT_DENY_ATTACH || req == 31) return 0;
    return orig_ptrace(req, pid, addr, data);
}

// ==========================================
// ★ 核心：Patch KakaSDK C 全局变量
// ==========================================

// 修改内存保护属性（vm_protect + mprotect 备选）
static BOOL _setMemoryWritable(void *address, size_t size) {
    vm_address_t addr = (vm_address_t)address;
    vm_size_t pageSize = vm_kernel_page_size;
    vm_address_t pageStart = addr & ~(pageSize - 1);
    vm_size_t pageOffset = addr - pageStart;
    vm_size_t totalSize = pageOffset + size;
    
    // 方式 1: vm_protect
    kern_return_t kr = vm_protect(mach_task_self(), pageStart, totalSize, NO, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr == KERN_SUCCESS) return YES;
    
    // 方式 2: vm_protect (不带 COPY)
    kr = vm_protect(mach_task_self(), pageStart, totalSize, NO, VM_PROT_READ | VM_PROT_WRITE);
    if (kr == KERN_SUCCESS) return YES;
    
    // 方式 3: mprotect
    int ret = mprotect((void *)pageStart, totalSize, PROT_READ | PROT_WRITE);
    if (ret == 0) return YES;
    
    NSLog(@"[KKEngine] ❌ 所有内存保护修改方式均失败");
    return NO;
}

// 调用 InitFunc_0 (sub_325BC) - 初始化绘制系统等
static void _callInitFunc(void) {
    if (g_kakaSDKBase == 0) return;
    
    uintptr_t initFuncAddr = g_kakaSDKBase + KAKA_INIT_FUNC_VA;
    void (*initFunc)(void) = (void (*)(void))initFuncAddr;
    
    NSLog(@"[KKEngine] 调用 InitFunc_0 (0x%lx)...", initFuncAddr);
    initFunc();
    NSLog(@"[KKEngine] ✅ InitFunc_0 调用完成");
}

// 统一激活函数
static void _activateAll(void) {
    if (g_patchDone || g_kakaSDKBase == 0) return;
    g_patchDone = YES;
    
    NSLog(@"[KKEngine] ========================================");
    NSLog(@"[KKEngine] 开始激活 KakaSDK");
    NSLog(@"[KKEngine] KakaSDK 基地址：0x%lx", g_kakaSDKBase);
    
    // 计算运行时地址
    uintptr_t authPassedAddr = g_kakaSDKBase + KAKA_AUTH_PASSED_VA;
    uintptr_t dataPtrAddr = g_kakaSDKBase + KAKA_DATA_PTR_VA;
    
    NSLog(@"[KKEngine] dword_1417958 地址：0x%lx", authPassedAddr);
    NSLog(@"[KKEngine] qword_1417D88 地址：0x%lx", dataPtrAddr);
    
    // 读取当前值
    uint32_t currentAuth = *(uint32_t *)authPassedAddr;
    uint64_t currentData = *(uint64_t *)dataPtrAddr;
    NSLog(@"[KKEngine] 当前 dword_1417958 = %u", currentAuth);
    NSLog(@"[KKEngine] 当前 qword_1417D88 = 0x%llx", (unsigned long long)currentData);
    
    // Patch dword_1417958 = 1 (验证通过)
    if (_setMemoryWritable((void *)authPassedAddr, sizeof(uint32_t))) {
        *(uint32_t *)authPassedAddr = 1;
        NSLog(@"[KKEngine] ✅ dword_1417958 已设置为 1");
    } else {
        NSLog(@"[KKEngine] ❌ 无法修改 dword_1417958");
    }
    
    // Patch qword_1417D88 - 确保非零
    if (currentData == 0) {
        if (_setMemoryWritable((void *)dataPtrAddr, sizeof(uint64_t))) {
            *(uint64_t *)dataPtrAddr = 0x1;
            NSLog(@"[KKEngine] ✅ qword_1417D88 已设置为 0x1");
        } else {
            NSLog(@"[KKEngine]  无法修改 qword_1417D88");
        }
    } else {
        NSLog(@"[KKEngine] ✓ qword_1417D88 已经非零 (0x%llx)", (unsigned long long)currentData);
    }
    
    // 验证
    uint32_t newAuth = *(uint32_t *)authPassedAddr;
    uint64_t newData = *(uint64_t *)dataPtrAddr;
    NSLog(@"[KKEngine] 验证：dword_1417958 = %u, qword_1417D88 = 0x%llx", newAuth, (unsigned long long)newData);
    
    if (newAuth == 1 && newData != 0) {
        g_verificationPassed = YES;
        NSLog(@"[KKEngine] ✓✓✓ Patch 成功！所有功能已激活 ✓✓✓");
        
        // 调用 InitFunc_0 初始化绘制系统
        _callInitFunc();
        
        NSLog(@"[KKEngine] ========================================");
    } else {
        NSLog(@"[KKEngine]  Patch 失败，值未正确设置");
    }
}

// ==========================================
// 查找 KakaSDK.dylib 并获取基地址
// ==========================================
static void _findKakaSDK(void) {
    if (g_kakaSDKBase != 0) return;
    
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        
        // ★ 精确匹配：只匹配 KakaSDK.dylib，不匹配主程序 kaka.app ★
        const char *basename = strrchr(name, '/');
        if (basename) {
            basename++; // 跳过 '/'
        } else {
            basename = name;
        }
        
        // 检查文件名是否以 "KakaSDK" 开头（匹配 KakaSDK.dylib）
        if (strncmp(basename, "KakaSDK", 7) == 0) {
            const struct mach_header *header = _dyld_get_image_header(i);
            g_kakaSDKBase = (uintptr_t)header;
            NSLog(@"[KKEngine] ✓ 找到 KakaSDK: %s", name);
            NSLog(@"[KKEngine]   基地址：0x%lx", g_kakaSDKBase);
            return;
        }
    }
    NSLog(@"[KKEngine]  未找到 KakaSDK.dylib");
}

// ==========================================
// ★ 第一层防御：预Patch认证标志（同步执行，不等网络）
// ==========================================
static void _patchAuthOnly(void) {
    if (g_kakaSDKBase == 0) return;
    
    uintptr_t authPassedAddr = g_kakaSDKBase + KAKA_AUTH_PASSED_VA;
    uintptr_t dataPtrAddr = g_kakaSDKBase + KAKA_DATA_PTR_VA;
    
    // Patch dword_1417958 = 1（让 KakaSDK 认为已授权，抑制弹窗逻辑）
    if (_setMemoryWritable((void *)authPassedAddr, sizeof(uint32_t))) {
        *(uint32_t *)authPassedAddr = 1;
        KLOG("✅ 认证标志已预置 (dword_1417958=1)，KakaSDK 弹窗已被抑制");
    } else {
        KLOG("❌ 预Patch dword_1417958 失败");
    }
    
    // Patch qword_1417D88 != 0
    uint64_t currentData = *(uint64_t *)dataPtrAddr;
    if (currentData == 0) {
        if (_setMemoryWritable((void *)dataPtrAddr, sizeof(uint64_t))) {
            *(uint64_t *)dataPtrAddr = 0x1;
            KLOG("✅ qword_1417D88 已预置为 0x1");
        }
    } else {
        KLOG("✓ qword_1417D88 已非零 (0x%llx)", (unsigned long long)currentData);
    }
}

// ==========================================
// ★ 第三层防御：Hook presentViewController 拦截 KakaSDK 弹窗
// ==========================================
static void (*orig_presentViewController)(id, SEL, UIViewController *, BOOL, void(^)(void));

static void _hookPresentViewController(void) {
    Class vcClass = [UIViewController class];
    SEL presentSEL = @selector(presentViewController:animated:completion:);
    Method method = class_getInstanceMethod(vcClass, presentSEL);
    if (!method) {
        KLOG("❌ 未找到 presentViewController 方法");
        return;
    }
    
    orig_presentViewController = (void (*)(id, SEL, UIViewController *, BOOL, void(^)(void)))method_getImplementation(method);
    
    IMP newImp = imp_implementationWithBlock(^(id self, UIViewController *vc, BOOL animated, void(^completion)(void)) {
        // 检查是否是 KakaSDK 的验证/激活弹窗
        if ([vc isKindOfClass:[UIAlertController class]]) {
            UIAlertController *alert = (UIAlertController *)vc;
            NSString *title = alert.title ?: @"";
            NSString *message = alert.message ?: @"";
            
            KLOG("🔍 presentViewController: title='%@' message='%@'", title, message);
            
            if ([title containsString:@"激活"] || [title containsString:@"授权"] || [title containsString:@"验证"] ||
                [message containsString:@"激活"] || [message containsString:@"授权"] || [message containsString:@"验证"] ||
                [message containsString:@"卡密"] || [title containsString:@"卡密"]) {
                KLOG("🚫 拦截 KakaSDK 弹窗：title='%@' message='%@'", title, message);
                if (completion) completion();
                return; // 直接丢弃，不显示
            }
        }
        // 非 KakaSDK 弹窗，正常放行
        orig_presentViewController(self, presentSEL, vc, animated, completion);
    });
    
    method_setImplementation(method, newImp);
    KLOG("✅ presentViewController Hook 已安装（第三层防御就绪）");
}

// ==========================================
// ★ 扩展 Hook：拦截 UIWindow makeKeyAndVisible
// ==========================================
static void (*orig_makeKeyAndVisible)(id, SEL);
static void fake_makeKeyAndVisible(id self, SEL _cmd) {
    UIWindow *window = (UIWindow *)self;
    
    // 检查是否是 KakaSDK 的窗口（通过 windowLevel 或其他特征）
    if (window.windowLevel > UIWindowLevelNormal && window.windowLevel < UIWindowLevelStatusBar + 50) {
        // 可能是 KakaSDK 的弹窗窗口，检查其内容
        if (window.rootViewController) {
            NSString *vcClass = NSStringFromClass([window.rootViewController class]);
            KLOG("🔍 UIWindow makeKeyAndVisible: %@ (level=%.0f)", vcClass, window.windowLevel);
            
            // 如果是 UIAlertController 或类似弹窗，拦截
            if ([vcClass containsString:@"Alert"] || [vcClass containsString:@"Dialog"]) {
                KLOG("🚫 拦截 KakaSDK UIWindow 弹窗");
                return; // 不显示
            }
        }
    }
    
    orig_makeKeyAndVisible(self, _cmd);
}

static void _hookUIWindow(void) {
    Class windowClass = [UIWindow class];
    SEL sel = @selector(makeKeyAndVisible);
    Method method = class_getInstanceMethod(windowClass, sel);
    if (!method) return;
    
    orig_makeKeyAndVisible = (void (*)(id, SEL))method_getImplementation(method);
    IMP newImp = imp_implementationWithBlock(^(id self) {
        fake_makeKeyAndVisible(self, sel);
    });
    method_setImplementation(method, newImp);
    KLOG("✅ UIWindow makeKeyAndVisible Hook 已安装");
}

// ==========================================
// ★ 扩展 Hook：拦截 UIApplication sendEvent（事件分发）
// ==========================================
static void (*orig_sendEvent)(id, SEL, UIEvent *);
static void fake_sendEvent(id self, SEL _cmd, UIEvent *event) {
    // 检查是否有新的窗口出现
    if (event.type == UIEventTypeTouches) {
        // 可以在这里检测并拦截 KakaSDK 的弹窗
    }
    orig_sendEvent(self, _cmd, event);
}

static void _hookSendEvent(void) {
    Class appClass = [UIApplication class];
    SEL sel = @selector(sendEvent:);
    Method method = class_getInstanceMethod(appClass, sel);
    if (!method) return;
    
    orig_sendEvent = (void (*)(id, SEL, UIEvent *))method_getImplementation(method);
    IMP newImp = imp_implementationWithBlock(^(id self, UIEvent *event) {
        fake_sendEvent(self, sel, event);
    });
    method_setImplementation(method, newImp);
    KLOG("✅ UIApplication sendEvent Hook 已安装");
}

// ==========================================
// ★ 自定义弹窗视图（不依赖 UIAlertController）
// ==========================================
static UIWindow *g_alertWindow = nil;
static UITextField *g_cardTextField = nil;

@interface KKEngineAlertView : UIView
@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UILabel *messageLabel;
@property (nonatomic, strong) UITextField *cardTextField;
@property (nonatomic, strong) UIButton *activateBtn;
@property (nonatomic, strong) UIButton *logBtn;
@property (nonatomic, strong) UIButton *clearBtn;
@property (nonatomic, strong) UIButton *exitBtn;
@property (nonatomic, strong) UITextView *logTextView;
@end

@implementation KKEngineAlertView

- (instancetype)initWithMessage:(NSString *)msg {
    self = [super initWithFrame:CGRectMake(0, 0, 300, 400)];
    if (self) {
        self.backgroundColor = [UIColor whiteColor];
        self.layer.cornerRadius = 12;
        self.layer.masksToBounds = YES;
        
        CGFloat y = 15;
        
        // 标题
        _titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(15, y, 270, 25)];
        _titleLabel.text = @"激活提示";
        _titleLabel.font = [UIFont boldSystemFontOfSize:18];
        _titleLabel.textAlignment = NSTextAlignmentCenter;
        [self addSubview:_titleLabel];
        y += 30;
        
        // 消息
        _messageLabel = [[UILabel alloc] initWithFrame:CGRectMake(15, y, 270, 40)];
        _messageLabel.text = msg ?: @"请输入卡密激活";
        _messageLabel.font = [UIFont systemFontOfSize:14];
        _messageLabel.textAlignment = NSTextAlignmentCenter;
        _messageLabel.numberOfLines = 2;
        _messageLabel.textColor = [UIColor grayColor];
        [self addSubview:_messageLabel];
        y += 45;
        
        // 输入框
        _cardTextField = [[UITextField alloc] initWithFrame:CGRectMake(20, y, 260, 36)];
        _cardTextField.borderStyle = UITextBorderStyleRoundedRect;
        _cardTextField.placeholder = @"请输入卡密";
        _cardTextField.font = [UIFont systemFontOfSize:14];
        NSString *saved = _readSavedCard();
        if (saved) _cardTextField.text = saved;
        g_cardTextField = _cardTextField;
        [self addSubview:_cardTextField];
        y += 45;
        
        // 激活按钮
        _activateBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        _activateBtn.frame = CGRectMake(20, y, 260, 36);
        [_activateBtn setTitle:@"激活" forState:UIControlStateNormal];
        _activateBtn.backgroundColor = [UIColor colorWithRed:0 green:0.5 blue:1 alpha:1];
        [_activateBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        _activateBtn.layer.cornerRadius = 8;
        _activateBtn.titleLabel.font = [UIFont boldSystemFontOfSize:16];
        [_activateBtn addTarget:self action:@selector(onActivate) forControlEvents:UIControlEventTouchUpInside];
        [self addSubview:_activateBtn];
        y += 42;
        
        // 查看日志按钮
        _logBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        _logBtn.frame = CGRectMake(20, y, 125, 32);
        [_logBtn setTitle:@"查看日志" forState:UIControlStateNormal];
        _logBtn.backgroundColor = [UIColor lightGrayColor];
        [_logBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        _logBtn.layer.cornerRadius = 6;
        _logBtn.titleLabel.font = [UIFont systemFontOfSize:13];
        [_logBtn addTarget:self action:@selector(onShowLog) forControlEvents:UIControlEventTouchUpInside];
        [self addSubview:_logBtn];
        
        // 清除卡密按钮
        _clearBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        _clearBtn.frame = CGRectMake(155, y, 125, 32);
        [_clearBtn setTitle:@"清除卡密" forState:UIControlStateNormal];
        _clearBtn.backgroundColor = [UIColor redColor];
        [_clearBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        _clearBtn.layer.cornerRadius = 6;
        _clearBtn.titleLabel.font = [UIFont systemFontOfSize:13];
        [_clearBtn addTarget:self action:@selector(onClearCard) forControlEvents:UIControlEventTouchUpInside];
        [self addSubview:_clearBtn];
        y += 38;
        
        // 退出按钮
        _exitBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        _exitBtn.frame = CGRectMake(20, y, 260, 32);
        [_exitBtn setTitle:@"退出" forState:UIControlStateNormal];
        _exitBtn.backgroundColor = [UIColor darkGrayColor];
        [_exitBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        _exitBtn.layer.cornerRadius = 6;
        _exitBtn.titleLabel.font = [UIFont systemFontOfSize:13];
        [_exitBtn addTarget:self action:@selector(onExit) forControlEvents:UIControlEventTouchUpInside];
        [self addSubview:_exitBtn];
    }
    return self;
}

- (void)onActivate {
    NSString *card = _cardTextField.text;
    if (card.length == 0) {
        _messageLabel.text = @"卡密不能为空";
        _messageLabel.textColor = [UIColor redColor];
        return;
    }
    
    KLOG("📢 开始验证卡密...");
    _activateBtn.enabled = NO;
    [_activateBtn setTitle:@"验证中..." forState:UIControlStateNormal];
    
    if (!g_verifier) g_verifier = [[NetworkVerifier alloc] init];
    [g_verifier verifyWithCard:card completion:^(BOOL success, NSDictionary *data, NSString *msg) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (success && [data[@"status"] isEqualToString:@"active"]) {
                KLOG("✅ 验证通过");
                _onVerificationPassed(data, card);
                
                // ★ 关闭目标插件的弹窗 ★
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                    [self _dismissTargetPluginAlerts];
                });
                
                [g_alertWindow setHidden:YES];
                g_alertWindow = nil;
            } else {
                KLOG("❌ 验证失败: %@", msg);
                _clearSavedCard();
                _clearFromKeychain(@"auth_data");
                _messageLabel.text = msg;
                _messageLabel.textColor = [UIColor redColor];
                _activateBtn.enabled = YES;
                [_activateBtn setTitle:@"激活" forState:UIControlStateNormal];
            }
        });
    }];
}

- (void)onShowLog {
    NSMutableArray *logs = _getLogArray();
    NSString *logText = [logs componentsJoinedByString:@"\n"];
    if (logText.length == 0) logText = @"(无日志)";
    
    if (!_logTextView) {
        _logTextView = [[UITextView alloc] initWithFrame:CGRectMake(15, 15, 270, 370)];
        _logTextView.font = [UIFont systemFontOfSize:10];
        _logTextView.editable = NO;
        _logTextView.backgroundColor = [UIColor colorWithWhite:0.95 alpha:1];
        _logTextView.layer.cornerRadius = 6;
    }
    _logTextView.text = logText;
    
    // 替换内容显示日志
    for (UIView *v in self.subviews) {
        v.hidden = YES;
    }
    [self addSubview:_logTextView];
    _logTextView.hidden = NO;
    
    // 添加关闭按钮
    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    closeBtn.frame = CGRectMake(20, 390, 260, 36);
    [closeBtn setTitle:@"复制并关闭" forState:UIControlStateNormal];
    closeBtn.backgroundColor = [UIColor blueColor];
    [closeBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    closeBtn.layer.cornerRadius = 8;
    [closeBtn addTarget:self action:@selector(onCopyAndCloseLog) forControlEvents:UIControlEventTouchUpInside];
    closeBtn.tag = 999;
    [self addSubview:closeBtn];
}

- (void)onCopyAndCloseLog {
    [UIPasteboard generalPasteboard].string = _logTextView.text;
    
    UIView *closeBtn = [self viewWithTag:999];
    [closeBtn removeFromSuperview];
    [_logTextView removeFromSuperview];
    _logTextView = nil;
    
    for (UIView *v in self.subviews) {
        v.hidden = NO;
    }
}

- (void)onClearCard {
    _clearSavedCard();
    _clearFromKeychain(@"auth_data");
    _messageLabel.text = @"已清除卡密，请重新输入";
    _messageLabel.textColor = [UIColor orangeColor];
    _cardTextField.text = @"";
}

- (void)onExit {
    exit(0);
}

// ★ 关闭目标插件的弹窗 ★
- (void)_dismissTargetPluginAlerts {
    KLOG("🔍 开始关闭目标插件弹窗...");
    
    UIApplication *app = [UIApplication sharedApplication];
    int dismissedCount = 0;
    
    for (UIWindow *window in app.windows) {
        // 跳过我们的窗口
        if (window == g_alertWindow) continue;
        
        // 检查窗口层级（目标插件弹窗通常层级较高）
        if (window.windowLevel > UIWindowLevelNormal && window.windowLevel < 2100) {
            KLOG("🔍 发现高层级窗口: level=%.0f, class=%@", 
                 window.windowLevel, NSStringFromClass([window class]));
            
            // 检查窗口内容
            if (window.rootViewController) {
                UIViewController *vc = window.rootViewController;
                NSString *vcClass = NSStringFromClass([vc class]);
                KLOG("🔍 窗口 ViewController: %@", vcClass);
                
                // 如果是普通 UIViewController 且在高层级窗口，很可能是目标插件弹窗
                // 直接隐藏整个窗口
                if (![vcClass containsString:@"KKEngine"]) {
                    KLOG("🚫 隐藏目标插件窗口: level=%.0f, class=%@", 
                         window.windowLevel, vcClass);
                    [window setHidden:YES];
                    window.alpha = 0;
                    dismissedCount++;
                }
            }
        }
    }
    
    KLOG("✅ 关闭目标弹窗完成，共关闭 %d 个", dismissedCount);
}

@end

// ==========================================
// ★ 显示激活弹窗（使用自定义 UIView）
// ==========================================
static void _showActivationAlert(NSString *errorMsg) {
    KLOG("_showActivationAlert 被调用: %@", errorMsg ?: @"无错误信息");
    
    dispatch_async(dispatch_get_main_queue(), ^{
        // 如果已有窗口，先关闭
        if (g_alertWindow) {
            [g_alertWindow setHidden:YES];
            g_alertWindow = nil;
        }
        
        KLOG("📢 创建窗口...");
        
        // 创建窗口
        g_alertWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        g_alertWindow.windowLevel = UIWindowLevelAlert + 100;
        g_alertWindow.backgroundColor = [UIColor colorWithWhite:0 alpha:0.6];
        
        // 创建自定义弹窗视图
        CGRect screenBounds = [UIScreen mainScreen].bounds;
        KKEngineAlertView *alertView = [[KKEngineAlertView alloc] initWithMessage:errorMsg];
        alertView.center = CGPointMake(screenBounds.size.width / 2, screenBounds.size.height / 2);
        
        // 创建根 ViewController
        UIViewController *rootVC = [[UIViewController alloc] init];
        rootVC.view.backgroundColor = [UIColor clearColor];
        [rootVC.view addSubview:alertView];
        g_alertWindow.rootViewController = rootVC;
        
        // 显示窗口
        [g_alertWindow makeKeyAndVisible];
        
        KLOG("✅ 自定义弹窗已显示");
    });
}

// ==========================================
// 验证通过后的处理
// ==========================================
static void _onVerificationPassed(NSDictionary *data, NSString *card) {
    g_verificationPassed = YES;
    
    // 保存卡密
    _saveCard(card);
    
    // ★★★ 核心：保存服务器返回的功能配置 ★★★
    if (data[@"features"] && [data[@"features"] isKindOfClass:[NSDictionary class]]) {
        g_serverFeatures = data[@"features"];
        NSLog(@"[KKEngine]  服务器功能配置：%@", g_serverFeatures);
    } else {
        g_serverFeatures = nil;
        NSLog(@"[KKEngine] ⚠️ 服务器未下发功能配置，使用本地默认值");
    }
    
    // 写入 Keychain（让 KakaSDK 自检通过）
    _writeKakaAuthToKeychain(card);
    
    // ★ 如果基址已找到，立即执行 Patch ★
    if (g_kakaSDKBase != 0) {
        _patchAuthOnly();
        _activateAll();
        _enableAllFeatures();
        NSLog(@"[KKEngine] ✅ 补丁应用成功");
    } else {
        // ★ 基址未找到，后台等待（最多 60 秒）★
        NSLog(@"[KKEngine] ⏳ 验证通过但 KakaSDK 未加载，后台等待基址...");
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            __block int waitCount = 0;
            while (g_kakaSDKBase == 0 && waitCount < 30) {
                [NSThread sleepForTimeInterval:2.0];
                waitCount++;
                _findKakaSDK();
                NSLog(@"[KKEngine] 等待基址... (%d/30)", waitCount);
            }
            
            dispatch_async(dispatch_get_main_queue(), ^{
                if (g_kakaSDKBase != 0) {
                    _patchAuthOnly();
                    _activateAll();
                    _enableAllFeatures();
                    NSLog(@"[KKEngine] ✅ 补丁应用成功（等待后）");
                } else {
                    NSLog(@"[KKEngine] ❌ 超时：未找到 KakaSDK，功能无法激活");
                }
            });
        });
    }
    
    NSLog(@"[KKEngine] ========================================");
    NSLog(@"[KKEngine] ✓✓✓ 网络验证通过！所有功能已激活 ✓✓✓");
    NSLog(@"[KKEngine] ========================================");
}

// ==========================================
// 应用所有功能开关
// ==========================================
static void _enableAllFeatures(void) {
    if (g_kakaSDKBase == 0) return;
    
    NSLog(@"[KKEngine] 🚀 正在根据配置开启功能...");
    
    // 核心绘制（默认开启，因为它是其他功能的基础）
    if (_isFeatureEnabled(kFeatureDraw, YES)) {
        _write_int(0x14153F0, 1);
        NSLog(@"[KKEngine] ✅ 绘制已开启");
    }
    
    // 无线广播（默认关闭）
    if (_isFeatureEnabled(kFeatureBroadcast, NO)) {
        _write_int(0x141537C, 1);
        NSLog(@"[KKEngine] ✅ 无限广播已开启");
    }
    
    // 传送（默认关闭）
    if (_isFeatureEnabled(kFeatureTeleport, NO)) {
        _write_int(0x14192A4, 1);
        NSLog(@"[KKEngine] ✅ 传送已开启");
    }
    
    // 短距位移（默认关闭）
    if (_isFeatureEnabled(kFeatureShortMove, NO)) {
        _write_int(0x1417638, 1);
        NSLog(@"[KKEngine] ✅ 短距位移已开启");
    }
    
    // 去屋顶（默认关闭）
    if (_isFeatureEnabled(kFeatureRoof, NO)) {
        _write_int(0x14154FC, 1);
        NSLog(@"[KKEngine] ✅ 去屋顶已开启");
    }
    
    // 退出会议（默认关闭）
    if (_isFeatureEnabled(kFeatureMeetingExit, NO)) {
        _write_int(0x14153C8, 1);
        NSLog(@"[KKEngine] ✅ 退出会议已开启");
    }
    
    // 隔墙有耳（默认关闭）
    if (_isFeatureEnabled(kFeatureVoiceWall, NO)) {
        _write_int(0x14153D8, 1);
        NSLog(@"[KKEngine] ✅ 隔墙有耳已开启");
    }
    
    // 全图碎蛋（默认关闭）
    if (_isFeatureEnabled(kFeatureEggBreaker, NO)) {
        _write_int(0x142A120, 1);
        NSLog(@"[KKEngine] ✅ 全图碎蛋已开启");
    }
    
    // 同行检测（默认关闭）
    if (_isFeatureEnabled(kFeaturePeerDetect, NO)) {
        _write_int(0x142A11C, 1);
        NSLog(@"[KKEngine] ✅ 同行检测已开启");
    }
    
    // 无视定身（默认关闭）
    if (_isFeatureEnabled(kFeatureImmobilize, NO)) {
        _write_int(0x1415398, 1);
        NSLog(@"[KKEngine] ✅ 无视定身已开启");
    }
    
    // 范围增幅（默认关闭）
    if (_isFeatureEnabled(kFeatureRangeBoost, NO)) {
        _write_int(0x14153A8, 1);
        NSLog(@"[KKEngine] ✅ 范围增幅已开启");
    }
    
    // 死亡开麦（默认关闭）
    if (_isFeatureEnabled(kFeatureDeathMic, NO)) {
        _write_int(0x14153B8, 1);
        NSLog(@"[KKEngine] ✅ 死亡开麦已开启");
    }
    
    // 监控面板（默认关闭）
    if (_isFeatureEnabled(kFeatureMonitor, NO)) {
        _write_int(0x1415388, 1);
        NSLog(@"[KKEngine] ✅ 监控面板已开启");
    }
    
    // 绘制子选项（全部跟随主绘制开关，但也可以单独控制）
    // 这里简化：如果绘制总开关开了，就全开子项
    if (_isFeatureEnabled(kFeatureDraw, YES)) {
        _write_int(0x140AF84, 1);   // 人物信息
        _write_int(0x140AF94, 1);   // 全局身份
        _write_int(0x140AF7C, 1);   // 事件日志
        _write_int(0x140AF8C, 1);   // 射线
        _write_int(0x140AF90, 1);   // 状态标记
        _write_int(0x140AF88, 1);   // 尸体
        _write_int(0x140B088, 1);   // 狙击镜
    }
    
    NSLog(@"[KKEngine] ✅ 功能配置应用完成");
}

// ==========================================
// 主逻辑：Patch + 验证
// ==========================================
static void _doMainLogic(void) {
    // 1. 查找 KakaSDK（不阻塞后续逻辑）
    _findKakaSDK();
    
    // ★ 第一层防御：如果找到基址，立即预Patch认证标志 ★
    if (g_kakaSDKBase != 0) {
        _patchAuthOnly();
        _activateAll();  // 完整 Patch（包含 InitFunc）
    } else {
        NSLog(@"[KKEngine] ⏳ KakaSDK 未加载，弹窗和网络验证独立运行");
    }
    
    // 2. 检查是否有本地卡密（独立于基址）
    NSString *savedCard = _readSavedCard();
    if (savedCard) {
        NSLog(@"[KKEngine] 检测到本地卡密，自动验证...");
        if (!g_verifier) g_verifier = [[NetworkVerifier alloc] init];
        [g_verifier verifyWithCard:savedCard completion:^(BOOL success, NSDictionary *data, NSString *msg) {
            if (success && [data[@"status"] isEqualToString:@"active"]) {
                _onVerificationPassed(data, savedCard);
            } else {
                _clearSavedCard();
                _clearFromKeychain(@"auth_data");
                _showActivationAlert(msg);
            }
        }];
    }
    // 如果没有卡密，弹窗已由 constructor 独立触发，这里不需要再显示
}

// ==========================================
// dyld 回调
// ==========================================
static void kakaSDKImageCallback(const struct mach_header *header, intptr_t slide) {
    const char *name = _dyld_get_image_name(_dyld_image_count() - 1);
    if (!name) return;
    
    // ★ 精确匹配：只匹配 KakaSDK.dylib ★
    const char *basename = strrchr(name, '/');
    if (basename) {
        basename++;
    } else {
        basename = name;
    }
    
    if (strncmp(basename, "KakaSDK", 7) == 0) {
        NSLog(@"[KKEngine] ✓ KakaSDK 已加载 (callback): %s", name);
        g_kakaSDKBase = (uintptr_t)header;
        
        // ★ 安全启动：延迟执行 Patch，确保 KakaSDK 内存完全映射 ★
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            _patchAuthOnly();
            _doMainLogic();
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
        if (g_patchDone) {
            dispatch_source_cancel(timer);
            NSLog(@"[KKEngine] 定时器停止（Patch 已完成）");
            return;
        }
        retryCount++;
        if (retryCount > 30) {
            dispatch_source_cancel(timer);
            NSLog(@"[KKEngine] ❌ 重试 30 次（60 秒）仍未找到 KakaSDK");
            return;
        }
        
        if (g_kakaSDKBase == 0) {
            _findKakaSDK();
        }
        if (g_kakaSDKBase != 0) {
            NSLog(@"[KKEngine] ✓ 定时器第%d次重试：执行 Patch", retryCount);
            dispatch_async(dispatch_get_main_queue(), ^{
                _doMainLogic();
            });
        } else {
            NSLog(@"[KKEngine] 定时器第%d次重试：未找到 KakaSDK", retryCount);
        }
    });
    dispatch_resume(timer);
    NSLog(@"[KKEngine] ✅ 定时器已启动（每 2 秒重试，最多 60 秒）");
}

// ==========================================
// 主入口
// ==========================================
__attribute__((constructor))
static void kakaHookEngine_init(void) {
    // 清空旧日志
    remove("/tmp/KKEngine.log");
    
    KLOG("========================================");
    KLOG("KKEngine v8 Loaded (扩展 Hook + 日志修复)");
    KLOG("Hook 列表: presentViewController, UIWindow, sendEvent");
    KLOG("========================================");
    
    // 1. Hook ptrace（反调试）
    struct rebinding ptraceRebind = {"ptrace", fake_ptrace, (void *)&orig_ptrace};
    rebind_symbols(&ptraceRebind, 1);
    KLOG("✅ ptrace 已屏蔽");
    
    // 2. ★ 安装所有 Hook ★
    _hookPresentViewController();
    _hookUIWindow();
    _hookSendEvent();
    KLOG("✅ 所有 Hook 安装完成");
    
    // 3. ★ 关键：立即显示弹窗（独立于 KakaSDK 基址）★
    KLOG("📢 0.5秒后将显示激活弹窗...");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            KLOG("📢 开始显示激活弹窗...");
            _showActivationAlert(nil);
        });
    });
    
    // 4. ★ 安全启动：不在 constructor 中直接调用 _activateAll ★
    KLOG("🔍 开始查找 KakaSDK...");
    _findKakaSDK();
    if (g_kakaSDKBase != 0) {
        KLOG("✓ KakaSDK 已找到，基地址: %p", (void *)g_kakaSDKBase);
        // 延迟 0.1 秒再执行，确保 KakaSDK 内存完全映射
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            KLOG("⏱ 开始执行 Patch...");
            _patchAuthOnly();
            _doMainLogic();
        });
    } else {
        KLOG("⏳ 等待 KakaSDK 加载...");
        _dyld_register_func_for_add_image(kakaSDKImageCallback);
    }
    
    // 5. 启动定时器重试（保底）
    _startRetryTimer();
    KLOG("✅ 初始化完成");
}
