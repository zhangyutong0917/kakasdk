//
//  MetalContext.h
//  KakaHookEngine
//
//  Metal 渲染上下文
//  基于逆向分析还原
//

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

@class FramebufferDescriptor;
@class MetalBuffer;

@interface MetalContext : NSObject

// MARK: - 属性
@property (nonatomic, strong) id<MTLDepthStencilState> depthStencilState;
@property (nonatomic, strong) FramebufferDescriptor *framebufferDescriptor;
@property (nonatomic, strong) NSMutableDictionary *renderPipelineStateCache;
@property (nonatomic, strong) id<MTLTexture> fontTexture;
@property (nonatomic, strong) NSMutableArray *bufferCache;
@property (nonatomic, assign) double lastBufferCachePurge;

// MARK: - 单例
+ (instancetype)sharedContext;

// MARK: - 初始化
- (instancetype)initWithDevice:(id<MTLDevice>)device;

// MARK: - 渲染管道状态
- (id<MTLRenderPipelineState>)renderPipelineStateForFramebufferDescriptor:(FramebufferDescriptor *)descriptor
                                                                     device:(id<MTLDevice>)device;

// MARK: - 缓冲区管理
- (MetalBuffer *)dequeueReusableBufferOfLength:(NSUInteger)length
                                         device:(id<MTLDevice>)device;

- (void)purgeOldBufferCache;

// MARK: - 字体纹理
- (void)setupFontTextureWithDevice:(id<MTLDevice>)device;

// MARK: - 深度模板状态
- (void)setupDepthStencilStateWithDevice:(id<MTLDevice>)device;

// MARK: - 帧缓冲描述符
- (void)setFramebufferDescriptor:(FramebufferDescriptor *)framebufferDescriptor;

@end
