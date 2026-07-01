//
//  KakaSDK.m
//  KakaHookEngine
//
//  SDK 主入口
//  基于逆向分析还原的框架代码
//
//  [推测]: 该文件是 dylib 的入口点，包含 __attribute__((constructor))
//         自动初始化函数。原始二进制中约 158 行逻辑对应 ~2KB 代码段。
//

#import "KakaSDK.h"
#import "KakaMenuHandler.h"
#import "MetalContext.h"
#import "KakaPinnedSessionDelegate.h"
#import <UIKit/UIKit.h>

// MARK: - 配置键常量
// [推测]: 以下常量对应 __DATA,__const 段中的字符串字面量

// Original Addr: 0x10000100 [推测]: 配置常量段起始地址
NSString * const kKakaConfigHookFloatX = @"KakaHookFloatX";
NSString * const kKakaConfigHookFloatY = @"KakaHookFloatY";

NSString * const kKakaConfigPanelOpacity = @"KakaPanelOpacity";

NSString * const kKakaConfigDrawLogOffsetX = @"KakaDrawLogOffsetX";
NSString * const kKakaConfigDrawLogOffsetY = @"KakaDrawLogOffsetY";
NSString * const kKakaConfigDrawLogFontScale = @"KakaDrawLogFontScale";
NSString * const kKakaConfigDrawLogVisibleCount = @"KakaDrawLogVisibleCount";

NSString * const kKakaConfigDrawIdentityOffsetX = @"KakaDrawIdentityOffsetX";
NSString * const kKakaConfigDrawIdentityOffsetY = @"KakaDrawIdentityOffsetY";
NSString * const kKakaConfigDrawIdentityFontScale = @"KakaDrawIdentityFontScale";

NSString * const kKakaConfigDrawPlayerFontScale = @"KakaDrawPlayerFontScale";
NSString * const kKakaConfigDrawPlayerTextBold = @"KakaDrawPlayerTextBold";

NSString * const kKakaConfigShortMovePanelScale = @"KakaShortMovePanelScale";
NSString * const kKakaConfigSniperPanelScale = @"KakaSniperPanelScale";
NSString * const kKakaConfigTeleportPanelScale = @"KakaTeleportPanelScale";

NSString * const kKakaConfigShortMoveStep = @"KakaShortMoveStep";

// 功能开关
NSString * const kKakaConfigSpeedSwitch = @"KakaSpeedSwitch";
NSString * const kKakaConfigRoofSwitch = @"KakaRoofSwitch";
NSString * const kKakaConfigInstantTaskSwitch = @"KakaInstantTaskSwitch";
NSString * const kKakaConfigBroadcastSwitch = @"KakaBroadcastSwitch";
NSString * const kKakaConfigShortMoveSwitch = @"KakaShortMoveSwitch";
NSString * const kKakaConfigRangeBoostSwitch = @"KakaRangeBoostSwitch";
NSString * const kKakaConfigDeathMicSwitch = @"KakaDeathMicSwitch";
NSString * const kKakaConfigTeleportSwitch = @"KakaTeleportSwitch";
NSString * const kKakaConfigVoiceWallSwitch = @"KakaVoiceWallSwitch";
NSString * const kKakaConfigEggBreakerSwitch = @"KakaEggBreakerSwitch";
NSString * const kKakaConfigPeerDetectSwitch = @"KakaPeerDetectSwitch";
NSString * const kKakaConfigMonitorPanelSwitch = @"KakaMonitorPanelSwitch";
NSString * const kKakaConfigIgnoreImmobilizeSwitch = @"KakaIgnoreImmobilizeSwitch";
NSString * const kKakaConfigMeetingExitSwitch = @"KakaMeetingExitSwitch";
NSString * const kKakaConfigDrawSwitch = @"KakaDrawSwitch";

// 认证相关
NSString * const kKakaAuthLocal = @"kaka.auth.local";
NSString * const kKakaAuthLocalUDID = @"kaka_auth_local_udid";
NSString * const kKakaFeatureBundleRSAv1 = @"kaka-feature-bundle-rsa-v1";
NSString * const kKakaClientSealv2 = @"kaka-client-seal-v2";
NSString * const kKakaPeerEnvelopev1 = @"kaka-peer-envelope-v1";
NSString * const kKakaHeartbeatv2 = @"kaka-heartbeat-v2";

// MARK: - 全局状态

static KakaMenuHandler *g_menuHandler = nil;
static MetalContext *g_metalContext = nil;
static BOOL g_initialized = NO;

// MARK: - SDK 初始化

// Original Addr: 0x10000C00 [推测]: SDK 初始化入口函数
void KakaSDKInitialize(void) {
    if (g_initialized) {
        return;
    }
    
    NSLog(@"[KakaHookEngine] loaded; auth bootstrap pending");
    
    // 初始化认证系统
    // TODO: 实现认证引导逻辑
    
    // 初始化配置
    [KakaSDK setupDefaultConfig];
    
    // 初始化菜单处理器
    g_menuHandler = [[KakaMenuHandler alloc] init];
    
    // 初始化 Metal 上下文
    // 注意：Metal 初始化需要在主线程进行
    dispatch_async(dispatch_get_main_queue(), ^{
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (device) {
            g_metalContext = [[MetalContext alloc] initWithDevice:device];
        }
    });
    
    // 安装 Hook
    // TODO: 实现 Hook 安装逻辑
    
    g_initialized = YES;
}

// MARK: - 默认配置

+ (void)setupDefaultConfig {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    
    // 设置默认值
    if ([defaults objectForKey:kKakaConfigHookFloatX] == nil) {
        [defaults setFloat:100.0 forKey:kKakaConfigHookFloatX];
    }
    if ([defaults objectForKey:kKakaConfigHookFloatY] == nil) {
        [defaults setFloat:100.0 forKey:kKakaConfigHookFloatY];
    }
    if ([defaults objectForKey:kKakaConfigPanelOpacity] == nil) {
        [defaults setFloat:0.9 forKey:kKakaConfigPanelOpacity];
    }
    
    [defaults synchronize];
}

// MARK: - 获取单例

KakaMenuHandler *KakaGetMenuHandler(void) {
    return g_menuHandler;
}

MetalContext *KakaGetMetalContext(void) {
    return g_metalContext;
}

// MARK: - Hook 函数（框架）

BOOL KakaInstallHook(void *target, void *replacement, void **original) {
    // TODO: 实现 Hook 安装逻辑
    // 支持 substrate 和 libhooker
    
    // 检查是否已 Hook
    // 检查目标是否可执行
    // 安装 Hook
    // 注册到 Hook 注册表
    
    return NO;
}

BOOL KakaUninstallHook(void *target) {
    // TODO: 实现 Hook 卸载逻辑
    return NO;
}

// MARK: - 构造函数

// Original Addr: 0x10000E00 [推测]: dylib 加载时的自动构造函数
// [推测]: 对应 Mach-O __mod_init_func 段中的初始化函数指针
__attribute__((constructor))
static void kaka_sdk_constructor(void) {
    // 库加载时自动初始化
    // [推测]: 原始代码中可能包含更多的初始化检查逻辑
    KakaSDKInitialize();
}
