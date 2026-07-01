//
//  KakaImGuiPassthroughWindow.h
//  KakaHookEngine
//
//  ImGui 穿透窗口
//  基于逆向分析还原
//
//  [推测]: 该类是 KakaPassthroughWindow 的变体，专门用于 ImGui
//         界面的渲染窗口。与 KakaPassthroughWindow 类似，但针对
//         ImGui 的渲染和事件处理进行了优化。
//         基于 KakaSDK.h 中的类前向声明推断。
//

#import <UIKit/UIKit.h>
#import <Metal/Metal.h>

@class KakaImGuiDrawViewController;

@interface KakaImGuiPassthroughWindow : UIWindow

// MARK: - 属性
@property (nonatomic, strong) id<MTLDevice> device;
@property (nonatomic, strong) id<MTLCommandQueue> commandQueue;
@property (nonatomic, strong) KakaImGuiDrawViewController *drawViewController;
@property (nonatomic, assign) BOOL passthroughEnabled;

// MARK: - 初始化
- (instancetype)initWithFrame:(CGRect)frame device:(id<MTLDevice>)device;

// MARK: - 渲染控制
- (void)startRendering;
- (void)stopRendering;

@end
