//
//  KakaDrawTickHandler.m
//  KakaHookEngine
//
//  绘制帧回调处理器实现
//  基于逆向分析还原的框架代码
//
//  [推测]: 该类通过 CADisplayLink 驱动每帧的数据更新和渲染。
//         协调 Vision 模块的数据采集和 Overlay 的绘制。
//

#import "KakaDrawTickHandler.h"
#import "KakaDrawOverlayView.h"
#import "KakaVision.h"
#import "MetalContext.h"

@interface KakaDrawTickHandler ()

@property (nonatomic, assign) CFTimeInterval frameStartTime;
@property (nonatomic, assign) NSInteger framesSinceLastCheck;

// 私有方法声明
- (void)onDisplayLinkTick:(CADisplayLink *)link;

@end

@implementation KakaDrawTickHandler

// MARK: - 单例

+ (instancetype)sharedHandler {
    static KakaDrawTickHandler *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[KakaDrawTickHandler alloc] init];
    });
    return shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _isRunning = NO;
        _frameCount = 0;
        _lastFrameTime = 0;
        _targetFPS = 60.0;
        _frameStartTime = 0;
        _framesSinceLastCheck = 0;
    }
    return self;
}

// MARK: - 生命周期

- (void)start {
    // Original Addr: 0x10007000 [推测]
    if (self.isRunning) {
        return;
    }

    self.displayLink = [CADisplayLink displayLinkWithTarget:self
                                                   selector:@selector(onDisplayLinkTick:)];
    self.displayLink.preferredFramesPerSecond = (NSInteger)self.targetFPS;
    [self.displayLink addToRunLoop:[NSRunLoop mainRunLoop] forMode:NSRunLoopCommonModes];

    self.isRunning = YES;
    self.frameStartTime = CACurrentMediaTime();
    NSLog(@"[KakaDrawTick] Started at %.0f FPS", self.targetFPS);
}

- (void)stop {
    // Original Addr: 0x10007100 [推测]
    [self.displayLink invalidate];
    self.displayLink = nil;
    self.isRunning = NO;
    NSLog(@"[KakaDrawTick] Stopped");
}

- (void)pause {
    // Original Addr: 0x10007200 [推测]
    self.displayLink.paused = YES;
}

- (void)resume {
    // Original Addr: 0x10007300 [推测]
    self.displayLink.paused = NO;
}

// MARK: - 帧回调

- (void)onDisplayLinkTick:(CADisplayLink *)link {
    // Original Addr: 0x10007400 [推测]
    self.lastFrameTime = link.timestamp;
    self.frameCount++;
    self.framesSinceLastCheck++;

    // 1. 更新 Vision 数据
    [self updateVisionData];

    // 2. 渲染帧
    [self renderFrame];
}

- (void)updateVisionData {
    // Original Addr: 0x10007500 [推测]
    // [推测]: 从游戏内存中读取玩家数据
    // 这一步通常由 KakaVisionManager 的后台线程处理
    // 这里只触发更新
    if (self.visionManager && self.visionManager.visionEnabled) {
        [self.visionManager updatePlayerList];
    }
}

- (void)renderFrame {
    // Original Addr: 0x10007600 [推测]
    if (self.overlayView) {
        [self.overlayView requestRedraw];
    }
}

// MARK: - 性能监控

- (CFTimeInterval)currentFPS {
    CFTimeInterval elapsed = CACurrentMediaTime() - self.frameStartTime;
    if (elapsed <= 0) {
        return 0;
    }
    return self.frameCount / elapsed;
}

- (void)resetFrameCounter {
    self.frameCount = 0;
    self.framesSinceLastCheck = 0;
    self.frameStartTime = CACurrentMediaTime();
}

// MARK: - 清理

- (void)dealloc {
    [self stop];
}

@end
