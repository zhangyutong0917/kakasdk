//
//  KakaSDK.h
//  KakaHookEngine
//
//  基于逆向分析还原的头文件
//  注意：这是推测性还原，不保证与原始代码完全一致
//

#ifndef KakaSDK_h
#define KakaSDK_h

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Metal/Metal.h>
#import <MetalKit/MetalKit.h>

// MARK: - 配置键常量

// 悬浮球位置
extern NSString * const kKakaConfigHookFloatX;
extern NSString * const kKakaConfigHookFloatY;

// 面板透明度
extern NSString * const kKakaConfigPanelOpacity;

// 绘制日志配置
extern NSString * const kKakaConfigDrawLogOffsetX;
extern NSString * const kKakaConfigDrawLogOffsetY;
extern NSString * const kKakaConfigDrawLogFontScale;
extern NSString * const kKakaConfigDrawLogVisibleCount;

// 身份绘制配置
extern NSString * const kKakaConfigDrawIdentityOffsetX;
extern NSString * const kKakaConfigDrawIdentityOffsetY;
extern NSString * const kKakaConfigDrawIdentityFontScale;

// 玩家绘制配置
extern NSString * const kKakaConfigDrawPlayerFontScale;
extern NSString * const kKakaConfigDrawPlayerTextBold;

// 面板尺寸配置
extern NSString * const kKakaConfigShortMovePanelScale;
extern NSString * const kKakaConfigSniperPanelScale;
extern NSString * const kKakaConfigTeleportPanelScale;

// 短距移动配置
extern NSString * const kKakaConfigShortMoveStep;

// 功能开关键
extern NSString * const kKakaConfigSpeedSwitch;
extern NSString * const kKakaConfigRoofSwitch;
extern NSString * const kKakaConfigInstantTaskSwitch;
extern NSString * const kKakaConfigBroadcastSwitch;
extern NSString * const kKakaConfigShortMoveSwitch;
extern NSString * const kKakaConfigRangeBoostSwitch;
extern NSString * const kKakaConfigDeathMicSwitch;
extern NSString * const kKakaConfigTeleportSwitch;
extern NSString * const kKakaConfigVoiceWallSwitch;
extern NSString * const kKakaConfigEggBreakerSwitch;
extern NSString * const kKakaConfigPeerDetectSwitch;
extern NSString * const kKakaConfigMonitorPanelSwitch;
extern NSString * const kKakaConfigIgnoreImmobilizeSwitch;
extern NSString * const kKakaConfigMeetingExitSwitch;
extern NSString * const kKakaConfigDrawSwitch;

// MARK: - 认证相关常量

extern NSString * const kKakaAuthLocal;
extern NSString * const kKakaAuthLocalUDID;
extern NSString * const kKakaFeatureBundleRSAv1;
extern NSString * const kKakaClientSealv2;
extern NSString * const kKakaPeerEnvelopev1;
extern NSString * const kKakaHeartbeatv2;

// MARK: - 字体数据

// 导出的字体数据
extern const unsigned char *kaka_font_data;
extern const unsigned char *kaka_font_data_end;

// MARK: - 类声明

@class KakaMenuHandler;
@class KakaImGuiDrawViewController;
@class KakaDrawOverlayView;
@class KakaDrawTickHandler;
@class KakaPassthroughWindow;
@class KakaImGuiPassthroughWindow;
@class KakaImGuiTouchPassthroughView;
@class KakaAuthUIHandler;
@class KakaPinnedSessionDelegate;
@class MetalContext;
@class MetalBuffer;
@class FramebufferDescriptor;

// MARK: - 全局函数

// SDK 初始化
void KakaSDKInitialize(void);

// 获取共享实例
KakaMenuHandler *KakaGetMenuHandler(void);
MetalContext *KakaGetMetalContext(void);

// Hook 相关
BOOL KakaInstallHook(void *target, void *replacement, void **original);
BOOL KakaUninstallHook(void *target);

#endif /* KakaSDK_h */
