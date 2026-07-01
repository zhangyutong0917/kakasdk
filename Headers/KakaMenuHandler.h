//
//  KakaMenuHandler.h
//  KakaHookEngine
//
//  菜单事件处理器
//  基于逆向分析还原
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface KakaMenuHandler : NSObject

// 单例
+ (instancetype)sharedHandler;

// MARK: - 菜单控制
- (void)toggleMenu;
- (void)closeMenu;

// MARK: - 游戏设置
- (void)openGameSettingTapped;

// MARK: - 导航
- (void)navTapped:(UIButton *)sender;

// MARK: - 滑块事件
- (void)sliderChanged:(UISlider *)sender;

// MARK: - 功能开关事件
- (void)speedSwitchChanged:(UISwitch *)sender;
- (void)roofSwitchChanged:(UISwitch *)sender;
- (void)instantTaskSwitchChanged:(UISwitch *)sender;
- (void)broadcastSwitchChanged:(UISwitch *)sender;
- (void)shortMoveSwitchChanged:(UISwitch *)sender;
- (void)rangeBoostSwitchChanged:(UISwitch *)sender;
- (void)deathMicSwitchChanged:(UISwitch *)sender;
- (void)teleportSwitchChanged:(UISwitch *)sender;
- (void)voiceWallSwitchChanged:(UISwitch *)sender;
- (void)eggBreakerSwitchChanged:(UISwitch *)sender;
- (void)peerDetectSwitchChanged:(UISwitch *)sender;
- (void)monitorPanelSwitchChanged:(UISwitch *)sender;
- (void)ignoreImmobilizeSwitchChanged:(UISwitch *)sender;
- (void)meetingExitSwitchChanged:(UISwitch *)sender;
- (void)drawSwitchChanged:(UISwitch *)sender;

// MARK: - 语音相关
- (void)voiceAllTapped;
- (void)voiceClearAllTapped;
- (void)voicePlayerTapped:(UIButton *)sender;

// MARK: - 推理系统
- (void)addInferenceClueTapped;
- (void)addInferenceNotCampTapped;
- (void)removeInferenceClueTapped;
- (void)selectInferencePlayerTapped;
- (void)selectInferenceCareerTapped;
- (void)inferencePlayerPrevTapped;
- (void)inferencePlayerNextTapped;
- (void)inferencePrevTapped;
- (void)inferenceNextTapped;

// MARK: - 设置微调
- (void)settingsNudgeTapped:(UIButton *)sender;

// MARK: - 配置变更
- (void)menuOpacityChanged:(UISlider *)sender;
- (void)logCountChanged:(UISlider *)sender;
- (void)logFontChanged:(UISlider *)sender;
- (void)identityFontChanged:(UISlider *)sender;
- (void)playerFontChanged:(UISlider *)sender;
- (void)playerFontBoldChanged:(UISwitch *)sender;
- (void)shortMoveStepChanged:(UISlider *)sender;
- (void)shortMovePanelSizeChanged:(UISlider *)sender;
- (void)sniperPanelSizeChanged:(UISlider *)sender;
- (void)teleportPanelSizeChanged:(UISlider *)sender;

// MARK: - 其他
- (void)selfUnbindTapped;
- (void)dragFloat:(UIPanGestureRecognizer *)gesture;

// MARK: - 认证 UI
- (void)activateTapped;
- (void)pasteTapped;
- (void)blockTouch;

@end
