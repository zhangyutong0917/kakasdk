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
static void _doMainLogic(void);
static void _startRetryTimer(void);
static void _onVerificationPassed(NSDictionary *data, NSString *card);
static void _showActivationAlert(NSString *errorMsg);
static UIAlertController *_createActivationAlert(NSString *errorMsg, id verifier);

// ==========================================
// Keychain 工具
// ==========================================

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
        NSLog(@"[KKEngine] ❌ JSON 序列化失败");
        return;
    }
    
    // 写入 Keychain
    NSDictionary *deleteQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: @"auth_data"
    };
    SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
    
    NSDictionary *addQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: @"auth_data",
        (__bridge id)kSecValueData: jsonData,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    };
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    if (status == errSecSuccess) {
        NSLog(@"[KKEngine] ✅ 已写入 KakaSDK 认证数据到 Keychain");
    } else {
        NSLog(@"[KKEngine] ❌ Keychain 写入失败: %d", (int)status);
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
        if (name && strstr(name, "KakaSDK")) {
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
// 显示激活弹窗
// ==========================================
static void _showActivationAlert(NSString *errorMsg) {
    if (!g_verifier) g_verifier = [[NetworkVerifier alloc] init];
    
    dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            UIAlertController *alert = _createActivationAlert(errorMsg, g_verifier);
            
            // 创建新窗口确保显示
            UIWindow *alertWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            alertWindow.windowLevel = UIWindowLevelAlert + 1;
            
            UIViewController *rootVC = [[UIViewController alloc] init];
            rootVC.view.backgroundColor = [UIColor clearColor];
            alertWindow.rootViewController = rootVC;
            [alertWindow makeKeyAndVisible];
            
            [rootVC presentViewController:alert animated:YES completion:nil];
            NSLog(@"[KKEngine] ✅ 激活弹窗已显示");
        });
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
        // 如果服务器没返回 features，则全部使用 NSUserDefaults 或默认值
        g_serverFeatures = nil;
        NSLog(@"[KKEngine] ⚠️ 服务器未下发功能配置，使用本地默认值");
    }
    
    // 写入 Keychain（让 KakaSDK 自检通过）
    _writeKakaAuthToKeychain(card);
    
    // 执行 Patch
    _activateAll();
    
    // 应用功能开关
    _enableAllFeatures();
    
    NSLog(@"[KKEngine] ========================================");
    NSLog(@"[KKEngine] ✓✓✓ 网络验证通过！所有功能已激活 ✓✓✓");
    NSLog(@"[KKEngine] ========================================");
}

// ==========================================
// 激活弹窗实现
// ==========================================
static UIAlertController *_createActivationAlert(NSString *errorMsg, id verifier) {
    NetworkVerifier *v = (NetworkVerifier *)verifier;
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"激活提示"
        message:(errorMsg ?: @"请输入卡密激活")
        preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"请输入卡密";
        textField.secureTextEntry = NO;
        NSString *saved = _readSavedCard();
        if (saved) textField.text = saved;
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"激活" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *card = alert.textFields.firstObject.text;
        if (card.length == 0) {
            UIAlertController *retry = _createActivationAlert(@"卡密不能为空", verifier);
            for (UIWindow *w in [UIApplication sharedApplication].windows) {
                if (w.windowLevel > UIWindowLevelNormal && w.rootViewController) {
                    [w.rootViewController presentViewController:retry animated:YES completion:nil];
                    break;
                }
            }
            return;
        }
        
        [v verifyWithCard:card completion:^(BOOL success, NSDictionary *data, NSString *msg) {
            if (success && [data[@"status"] isEqualToString:@"active"]) {
                _onVerificationPassed(data, card);
            } else {
                _clearSavedCard();
                _clearFromKeychain(@"auth_data");
                UIAlertController *retry = _createActivationAlert(msg, verifier);
                for (UIWindow *w in [UIApplication sharedApplication].windows) {
                    if (w.windowLevel > UIWindowLevelNormal && w.rootViewController) {
                        [w.rootViewController presentViewController:retry animated:YES completion:nil];
                        break;
                    }
                }
            }
        }];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"清除卡密" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        _clearSavedCard();
        _clearFromKeychain(@"auth_data");
        UIAlertController *cleared = _createActivationAlert(@"已清除卡密，请重新输入", verifier);
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w.windowLevel > UIWindowLevelNormal && w.rootViewController) {
                [w.rootViewController presentViewController:cleared animated:YES completion:nil];
                break;
            }
        }
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"退出" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        exit(0);
    }]];
    
    return alert;
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
    // 1. 查找 KakaSDK
    _findKakaSDK();
    
    if (g_kakaSDKBase == 0) {
        NSLog(@"[KKEngine] ⏳ KakaSDK 未加载，等待...");
        return;
    }
    
    // 2. 立即 Patch 全局变量（让功能可用）
    _activateAll();
    
    // 3. 检查是否有本地卡密
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
    } else {
        NSLog(@"[KKEngine] 未检测到卡密，准备显示激活窗口");
        _showActivationAlert(nil);
    }
}

// ==========================================
// dyld 回调
// ==========================================
static void kakaSDKImageCallback(const struct mach_header *header, intptr_t slide) {
    const char *name = _dyld_get_image_name(_dyld_image_count() - 1);
    if (name && strstr(name, "KakaSDK")) {
        NSLog(@"[KKEngine] ✓ KakaSDK 已加载 (callback): %s", name);
        g_kakaSDKBase = (uintptr_t)header;
        dispatch_async(dispatch_get_main_queue(), ^{
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
    NSLog(@"[KKEngine] ========================================");
    NSLog(@"[KKEngine] KKEngine v3 Loaded (C 全局变量 Patch 方案)");
    NSLog(@"[KKEngine] 目标：dword_1417958=1, qword_1417D88!=0");
    NSLog(@"[KKEngine] ========================================");
    
    // 1. Hook ptrace
    struct rebinding ptraceRebind = {"ptrace", fake_ptrace, (void *)&orig_ptrace};
    rebind_symbols(&ptraceRebind, 1);
    NSLog(@"[KKEngine] ✅ ptrace 已屏蔽");
    
    // 2. 立即尝试查找和 Patch
    _findKakaSDK();
    if (g_kakaSDKBase != 0) {
        NSLog(@"[KKEngine] ✓ KakaSDK 已存在，立即 Patch");
        _doMainLogic();
    } else {
        NSLog(@"[KKEngine]  等待 KakaSDK 加载...");
        _dyld_register_func_for_add_image(kakaSDKImageCallback);
    }
    
    // 3. 启动定时器重试（保底）
    _startRetryTimer();
}
