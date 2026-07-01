//
//  KakaImGuiPassthroughWindow.m
//  KakaHookEngine
//
//  ImGui 穿透窗口实现
//  基于逆向分析还原的框架代码
//
//  [推测]: 基于 KakaPassthroughWindow 扩展，专门用于 ImGui 渲染。
//         持有 Metal 设备和 ImGui 绘制控制器。
//

#import "KakaImGuiPassthroughWindow.h"
#import "KakaImGuiDrawViewController.h"

@implementation KakaImGuiPassthroughWindow

// MARK: - 初始化

- (instancetype)initWithFrame:(CGRect)frame device:(id<MTLDevice>)device {
    self = [super initWithFrame:frame];
    if (self) {
        _device = device;
        _commandQueue = [device newCommandQueue];
        _passthroughEnabled = YES;

        self.backgroundColor = [UIColor clearColor];
        self.opaque = NO;

        // 创建 ImGui 绘制控制器
        _drawViewController = [[KakaImGuiDrawViewController alloc] initWithFrame:frame device:device];
        self.rootViewController = _drawViewController;
    }
    return self;
}

// MARK: - 渲染控制

- (void)startRendering {
    // Original Addr: 0x10009000 [推测]
    NSLog(@"[KakaImGuiWindow] Start rendering");
    // [推测]: 启动 MTKView 的渲染循环
    if ([self.drawViewController respondsToSelector:@selector(setMetalView:)]) {
        // 确保 MTKView 已开始渲染
    }
}

- (void)stopRendering {
    // Original Addr: 0x10009100 [推测]
    NSLog(@"[KakaImGuiWindow] Stop rendering");
}

// MARK: - 触摸事件处理

- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    // Original Addr: 0x10009200 [推测]
    if (!self.passthroughEnabled) {
        return [super hitTest:point withEvent:event];
    }

    // [推测]: 检查 ImGui 是否有活跃的交互（如窗口拖拽、滑块操作等）
    // 如果 ImGui 正在处理交互，则拦截事件
    // 否则穿透到下层

    UIView *imguiView = self.drawViewController.view;
    if (imguiView) {
        CGPoint convertedPoint = [imguiView convertPoint:point fromView:self];
        UIView *result = [imguiView hitTest:convertedPoint withEvent:event];
        if (result) {
            return result;
        }
    }

    return nil;
}

@end
