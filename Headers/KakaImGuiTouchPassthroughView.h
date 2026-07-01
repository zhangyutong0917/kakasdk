//
//  KakaImGuiTouchPassthroughView.h
//  KakaHookEngine
//
//  ImGui 触摸穿透视图
//  基于逆向分析还原
//
//  [推测]: 该类是一个 UIView 子类，作为 ImGui 窗口的根视图。
//         触摸事件在命中 ImGui 交互区域时被拦截，否则穿透到
//         下层游戏视图。基于 KakaSDK.h 中的类前向声明推断。
//

#import <UIKit/UIKit.h>

@interface KakaImGuiTouchPassthroughView : UIView

// MARK: - 属性
@property (nonatomic, assign) BOOL touchPassthroughEnabled;
@property (nonatomic, assign) CGRect interactiveArea;
@property (nonatomic, assign) BOOL hasActiveImGuiInteraction;

// MARK: - 初始化
- (instancetype)initWithFrame:(CGRect)frame;

// MARK: - 交互区域
- (void)setInteractiveArea:(CGRect)area;
- (BOOL)isPointInInteractiveArea:(CGPoint)point;

@end
