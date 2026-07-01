//
//  KakaDrawTickHandler.h
//  KakaHookEngine
//
//  绘制帧回调处理器
//  基于逆向分析还原
//
//  [推测]: 该类负责处理每帧绘制的定时回调，协调 Metal 渲染
//         和 Vision 模块的数据更新。基于 KakaSDK.h 中的类前向
//         声明推断，可能与 CADisplayLink 或 MTKViewDelegate 配合使用。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Metal/Metal.h>

@class KakaDrawOverlayView;
@class KakaVisionManager;
@class MetalContext;

@interface KakaDrawTickHandler : NSObject

// MARK: - 属性
@property (nonatomic, strong) CADisplayLink *displayLink;
@property (nonatomic, weak) KakaDrawOverlayView *overlayView;
@property (nonatomic, strong) KakaVisionManager *visionManager;
@property (nonatomic, strong) MetalContext *metalContext;
@property (nonatomic, assign) BOOL isRunning;
@property (nonatomic, assign) NSInteger frameCount;
@property (nonatomic, assign) CFTimeInterval lastFrameTime;
@property (nonatomic, assign) CFTimeInterval targetFPS;

// MARK: - 单例
+ (instancetype)sharedHandler;

// MARK: - 生命周期
- (void)start;
- (void)stop;
- (void)pause;
- (void)resume;

// MARK: - 帧回调
- (void)onDisplayLinkTick:(CADisplayLink *)link;
- (void)updateVisionData;
- (void)renderFrame;

// MARK: - 性能监控
- (CFTimeInterval)currentFPS;
- (void)resetFrameCounter;

@end
