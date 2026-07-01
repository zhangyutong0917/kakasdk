//
//  KakaImGuiTouchPassthroughView.m
//  KakaHookEngine
//
//  ImGui 触摸穿透视图实现
//  基于逆向分析还原的框架代码
//
//  [推测]: 作为 ImGui 窗口的根视图，控制触摸事件的穿透行为。
//

#import "KakaImGuiTouchPassthroughView.h"

@implementation KakaImGuiTouchPassthroughView

// MARK: - 初始化

- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        _touchPassthroughEnabled = YES;
        _interactiveArea = CGRectZero;
        _hasActiveImGuiInteraction = NO;

        self.backgroundColor = [UIColor clearColor];
        self.opaque = NO;
        self.multipleTouchEnabled = YES;
    }
    return self;
}

// MARK: - 交互区域

- (void)setInteractiveArea:(CGRect)area {
    _interactiveArea = area;
}

- (BOOL)isPointInInteractiveArea:(CGPoint)point {
    // Original Addr: 0x1000A000 [推测]
    if (CGRectIsEmpty(self.interactiveArea)) {
        // 如果未设置交互区域，默认全部可交互
        return YES;
    }
    return CGRectContainsPoint(self.interactiveArea, point);
}

// MARK: - 触摸事件处理

- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    // Original Addr: 0x1000A100 [推测]
    if (!self.touchPassthroughEnabled) {
        return [super hitTest:point withEvent:event];
    }

    // 如果有活跃的 ImGui 交互，拦截所有事件
    if (self.hasActiveImGuiInteraction) {
        return [super hitTest:point withEvent:event];
    }

    // 检查是否在交互区域内
    if ([self isPointInInteractiveArea:point]) {
        return [super hitTest:point withEvent:event];
    }

    // 穿透
    return nil;
}

// MARK: - 触摸事件回调

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    // Original Addr: 0x1000A200 [推测]
    // [推测]: 标记 ImGui 开始处理交互
    self.hasActiveImGuiInteraction = YES;
    [super touchesBegan:touches withEvent:event];
}

- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    // Original Addr: 0x1000A300 [推测]
    // [推测]: 检查是否所有触摸都结束
    self.hasActiveImGuiInteraction = (touches.count > 0);
    [super touchesEnded:touches withEvent:event];
}

- (void)touchesCancelled:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    // Original Addr: 0x1000A400 [推测]
    self.hasActiveImGuiInteraction = NO;
    [super touchesCancelled:touches withEvent:event];
}

@end
