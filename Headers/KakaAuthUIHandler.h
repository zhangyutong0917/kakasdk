//
//  KakaAuthUIHandler.h
//  KakaHookEngine
//
//  认证 UI 处理器
//  基于逆向分析还原
//
//  [推测]: 该类负责管理认证相关的 UI 展示，包括激活码输入框、
//         认证状态显示等。基于 KakaSDK.h 中的类前向声明推断。
//

#import <UIKit/UIKit.h>

@class KakaAuthManager;

// MARK: - 认证 UI 状态
typedef NS_ENUM(NSInteger, KakaAuthUIState) {
    KakaAuthUIStateHidden = 0,
    KakaAuthUIStateInputCode = 1,     // 输入激活码
    KakaAuthUIStateVerifying = 2,     // 验证中
    KakaAuthUIStateSuccess = 3,       // 认证成功
    KakaAuthUIStateFailed = 4,        // 认证失败
    KakaAuthUIStateBanned = 5,        // 被封禁
};

@interface KakaAuthUIHandler : NSObject

// 单例
+ (instancetype)sharedHandler;

// MARK: - 属性
@property (nonatomic, assign) KakaAuthUIState currentState;
@property (nonatomic, strong, readonly) UIWindow *authWindow;
@property (nonatomic, strong, readonly) UITextField *codeInputField;
@property (nonatomic, strong, readonly) UILabel *statusLabel;
@property (nonatomic, assign) BOOL isVisible;

// MARK: - UI 控制
- (void)showAuthUI;
- (void)hideAuthUI;
- (void)updateAuthStatus;

// MARK: - 认证操作
- (void)activateWithCode:(NSString *)code;
- (void)pasteFromClipboard;
- (void)dismissAuthUI;

// MARK: - 通知处理
- (void)handleAuthStatusChange:(NSNotification *)notification;
- (void)handleAuthSuccess:(NSNotification *)notification;
- (void)handleAuthFailure:(NSNotification *)notification;

@end
