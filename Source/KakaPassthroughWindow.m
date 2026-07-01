//
//  KakaPassthroughWindow.m
//  KakaHookEngine
//
//  穿透窗口实现
//  基于逆向分析还原的框架代码
//
//  [推测]: 透明 UIWindow，触摸事件穿透到下层，
//         只有命中注册的 hitTestViews 时才拦截。
//

#import "KakaPassthroughWindow.h"

@implementation KakaPassthroughWindow

// MARK: - 初始化

- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        _passthroughEnabled = YES;
        _hitTestViews = [NSArray array];

        self.backgroundColor = [UIColor clearColor];
        self.opaque = NO;
        self.hidden = NO;
    }
    return self;
}

// MARK: - 事件穿透

- (void)addPassthroughView:(UIView *)view {
    // Original Addr: 0x10008000 [推测]
    if (!view) return;

    NSMutableArray *mutableViews = [self.hitTestViews mutableCopy];
    if (![mutableViews containsObject:view]) {
        [mutableViews addObject:view];
    }
    self.hitTestViews = [mutableViews copy];
}

- (void)removePassthroughView:(UIView *)view {
    // Original Addr: 0x10008100 [推测]
    if (!view) return;

    NSMutableArray *mutableViews = [self.hitTestViews mutableCopy];
    [mutableViews removeObject:view];
    self.hitTestViews = [mutableViews copy];
}

// MARK: - 触摸事件处理

- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    // Original Addr: 0x10008200 [推测]
    // 如果穿透未启用，走默认逻辑
    if (!self.passthroughEnabled) {
        return [super hitTest:point withEvent:event];
    }

    // 检查是否命中注册的交互视图
    for (UIView *hitView in self.hitTestViews) {
        if (!hitView.isHidden && hitView.alpha > 0 && hitView.userInteractionEnabled) {
            CGPoint convertedPoint = [hitView convertPoint:point fromView:self];
            UIView *result = [hitView hitTest:convertedPoint withEvent:event];
            if (result) {
                return result;
            }
        }
    }

    // 未命中任何交互视图，返回 nil 使事件穿透
    return nil;
}

@end
