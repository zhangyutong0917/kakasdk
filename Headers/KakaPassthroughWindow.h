//
//  KakaPassthroughWindow.h
//  KakaHookEngine
//
//  穿透窗口
//  基于逆向分析还原
//
//  [推测]: 该类是一个透明的 UIWindow 子类，用于承载悬浮菜单。
//         "Passthrough" 意味着触摸事件会穿透到下层视图，
//         只有命中特定子视图（如菜单按钮）时才会拦截事件。
//         基于 KakaSDK.h 中的类前向声明推断。
//

#import <UIKit/UIKit.h>

@interface KakaPassthroughWindow : UIWindow

// MARK: - 属性
@property (nonatomic, assign) BOOL passthroughEnabled;
@property (nonatomic, strong) NSArray<UIView *> *hitTestViews;

// MARK: - 初始化
- (instancetype)initWithFrame:(CGRect)frame;

// MARK: - 事件穿透
- (void)addPassthroughView:(UIView *)view;
- (void)removePassthroughView:(UIView *)view;

@end
