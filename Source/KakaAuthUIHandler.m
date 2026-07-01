//
//  KakaAuthUIHandler.m
//  KakaHookEngine
//
//  认证 UI 处理器实现
//  基于逆向分析还原的框架代码
//
//  [推测]: 基于 KakaAuth 模块的通知机制和 KakaMenuHandler 中的
//         activateTapped / pasteTapped 方法推断实现。
//

#import "KakaAuthUIHandler.h"
#import "KakaAuth.h"

@interface KakaAuthUIHandler ()

@property (nonatomic, strong) UIWindow *authWindow;
@property (nonatomic, strong) UITextField *codeInputField;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UIButton *activateButton;
@property (nonatomic, strong) UIButton *pasteButton;

// 私有方法声明
- (void)activateTapped;

@end

@implementation KakaAuthUIHandler

// MARK: - 单例

+ (instancetype)sharedHandler {
    static KakaAuthUIHandler *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[KakaAuthUIHandler alloc] init];
    });
    return shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _currentState = KakaAuthUIStateHidden;
        _isVisible = NO;

        // 监听认证状态变化通知
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(handleAuthStatusChange:)
                                                     name:KakaAuthStatusDidChangeNotification
                                                   object:nil];
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(handleAuthSuccess:)
                                                     name:KakaAuthDidSucceedNotification
                                                   object:nil];
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(handleAuthFailure:)
                                                     name:KakaAuthDidFailNotification
                                                   object:nil];
    }
    return self;
}

// MARK: - UI 控制

- (void)showAuthUI {
    // Original Addr: 0x10005000 [推测]
    if (self.isVisible) {
        return;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        CGRect screenBounds = [UIScreen mainScreen].bounds;
        CGFloat width = MIN(screenBounds.size.width, 320);
        CGFloat height = 200;
        CGFloat x = (screenBounds.size.width - width) / 2.0;
        CGFloat y = (screenBounds.size.height - height) / 2.0;

        self.authWindow = [[UIWindow alloc] initWithFrame:CGRectMake(x, y, width, height)];
        self.authWindow.windowLevel = UIWindowLevelAlert + 100;
        self.authWindow.backgroundColor = [UIColor colorWithWhite:0.1 alpha:0.95];
        self.authWindow.layer.cornerRadius = 12;
        self.authWindow.layer.masksToBounds = YES;

        UIViewController *rootVC = [[UIViewController alloc] init];
        rootVC.view.backgroundColor = [UIColor clearColor];
        self.authWindow.rootViewController = rootVC;

        // 标题
        UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 15, width - 40, 30)];
        titleLabel.text = @"激活认证";
        titleLabel.textColor = [UIColor whiteColor];
        titleLabel.font = [UIFont boldSystemFontOfSize:18];
        titleLabel.textAlignment = NSTextAlignmentCenter;
        [rootVC.view addSubview:titleLabel];

        // 输入框
        self.codeInputField = [[UITextField alloc] initWithFrame:CGRectMake(20, 55, width - 40, 40)];
        self.codeInputField.placeholder = @"请输入激活码";
        self.codeInputField.backgroundColor = [UIColor colorWithWhite:0.2 alpha:1.0];
        self.codeInputField.textColor = [UIColor whiteColor];
        self.codeInputField.layer.cornerRadius = 8;
        self.codeInputField.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 10, 40)];
        self.codeInputField.leftViewMode = UITextFieldViewModeAlways;
        self.codeInputField.clearButtonMode = UITextFieldViewModeWhileEditing;
        [rootVC.view addSubview:self.codeInputField];

        // 激活按钮
        self.activateButton = [UIButton buttonWithType:UIButtonTypeSystem];
        self.activateButton.frame = CGRectMake(20, 110, (width - 60) / 2.0, 40);
        [self.activateButton setTitle:@"激活" forState:UIControlStateNormal];
        [self.activateButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        self.activateButton.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:1.0];
        self.activateButton.layer.cornerRadius = 8;
        [self.activateButton addTarget:self action:@selector(activateTapped) forControlEvents:UIControlEventTouchUpInside];
        [rootVC.view addSubview:self.activateButton];

        // 粘贴按钮
        self.pasteButton = [UIButton buttonWithType:UIButtonTypeSystem];
        self.pasteButton.frame = CGRectMake(width / 2.0 + 10, 110, (width - 60) / 2.0, 40);
        [self.pasteButton setTitle:@"粘贴" forState:UIControlStateNormal];
        [self.pasteButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        self.pasteButton.backgroundColor = [UIColor colorWithRed:0.4 green:0.4 blue:0.4 alpha:1.0];
        self.pasteButton.layer.cornerRadius = 8;
        [self.pasteButton addTarget:self action:@selector(pasteFromClipboard) forControlEvents:UIControlEventTouchUpInside];
        [rootVC.view addSubview:self.pasteButton];

        // 状态标签
        self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 160, width - 40, 30)];
        self.statusLabel.textColor = [UIColor grayColor];
        self.statusLabel.font = [UIFont systemFontOfSize:12];
        self.statusLabel.textAlignment = NSTextAlignmentCenter;
        [rootVC.view addSubview:self.statusLabel];

        [self.authWindow makeKeyAndVisible];
        self.isVisible = YES;
        self.currentState = KakaAuthUIStateInputCode;
    });
}

- (void)hideAuthUI {
    // Original Addr: 0x10005200 [推测]
    dispatch_async(dispatch_get_main_queue(), ^{
        self.authWindow.hidden = YES;
        self.authWindow = nil;
        self.isVisible = NO;
        self.currentState = KakaAuthUIStateHidden;
    });
}

- (void)updateAuthStatus {
    // Original Addr: 0x10005300 [推测]
    KakaAuthManager *authManager = [KakaAuthManager sharedManager];

    dispatch_async(dispatch_get_main_queue(), ^{
        switch (authManager.authStatus) {
            case KakaAuthStatusSuccess:
                self.statusLabel.text = @"认证成功";
                self.statusLabel.textColor = [UIColor greenColor];
                self.currentState = KakaAuthUIStateSuccess;
                // 延迟隐藏
                [self performSelector:@selector(hideAuthUI) withObject:nil afterDelay:1.5];
                break;
            case KakaAuthStatusFailed:
                self.statusLabel.text = @"认证失败";
                self.statusLabel.textColor = [UIColor redColor];
                self.currentState = KakaAuthUIStateFailed;
                break;
            case KakaAuthStatusBanned:
                self.statusLabel.text = @"设备已被封禁";
                self.statusLabel.textColor = [UIColor redColor];
                self.currentState = KakaAuthUIStateBanned;
                break;
            case KakaAuthStatusPending:
            case KakaAuthStatusVerifying:
                self.statusLabel.text = @"验证中...";
                self.statusLabel.textColor = [UIColor yellowColor];
                self.currentState = KakaAuthUIStateVerifying;
                break;
            default:
                self.statusLabel.text = @"";
                break;
        }
    });
}

// MARK: - 认证操作

- (void)activateWithCode:(NSString *)code {
    // Original Addr: 0x10005400 [推测]
    if (!code || code.length == 0) {
        self.statusLabel.text = @"请输入激活码";
        self.statusLabel.textColor = [UIColor orangeColor];
        return;
    }

    self.currentState = KakaAuthUIStateVerifying;
    [self updateAuthStatus];

    [[KakaAuthManager sharedManager] applyAuthWithCode:code completion:^(BOOL success, NSError *error) {
        if (success) {
            NSLog(@"[KakaAuthUI] Activation succeeded");
        } else {
            NSLog(@"[KakaAuthUI] Activation failed: %@", error.localizedDescription);
        }
    }];
}

- (void)activateTapped {
    NSString *code = self.codeInputField.text;
    [self activateWithCode:code];
}

- (void)pasteFromClipboard {
    // Original Addr: 0x10005500 [推测]
    UIPasteboard *pasteboard = [UIPasteboard generalPasteboard];
    NSString *code = [pasteboard.string stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (code.length > 0) {
        self.codeInputField.text = code;
    }
}

- (void)dismissAuthUI {
    [self hideAuthUI];
}

// MARK: - 通知处理

- (void)handleAuthStatusChange:(NSNotification *)notification {
    [self updateAuthStatus];
}

- (void)handleAuthSuccess:(NSNotification *)notification {
    [self updateAuthStatus];
}

- (void)handleAuthFailure:(NSNotification *)notification {
    [self updateAuthStatus];
}

// MARK: - 清理

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

@end
