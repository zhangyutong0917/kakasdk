//
//  MetalContext.m
//  KakaHookEngine
//
//  Metal 渲染上下文
//  基于逆向分析还原的框架代码
//

#import "MetalContext.h"
#import "FramebufferDescriptor.h"
#import "MetalBuffer.h"
#import "KakaSDK.h"

@interface MetalContext ()

@property (nonatomic, strong) id<MTLDevice> device;

@end

@implementation MetalContext

// MARK: - 单例

+ (instancetype)sharedContext {
    static MetalContext *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (device) {
            shared = [[MetalContext alloc] initWithDevice:device];
        }
    });
    return shared;
}

// MARK: - 初始化

- (instancetype)initWithDevice:(id<MTLDevice>)device {
    self = [super init];
    if (self) {
        _device = device;
        _renderPipelineStateCache = [NSMutableDictionary dictionary];
        _bufferCache = [NSMutableArray array];
        _lastBufferCachePurge = 0;
        
        [self setupDepthStencilStateWithDevice:device];
        [self setupFontTextureWithDevice:device];
    }
    return self;
}

// MARK: - 渲染管道状态

- (id<MTLRenderPipelineState>)renderPipelineStateForFramebufferDescriptor:(FramebufferDescriptor *)descriptor
                                                                     device:(id<MTLDevice>)device {
    // 检查缓存
    id<MTLRenderPipelineState> cached = [self.renderPipelineStateCache objectForKey:descriptor];
    if (cached) {
        return cached;
    }
    
    // 创建新的渲染管道状态
    MTLRenderPipelineDescriptor *pipelineDescriptor = [[MTLRenderPipelineDescriptor alloc] init];
    
    // 设置像素格式
    pipelineDescriptor.colorAttachments[0].pixelFormat = descriptor.colorPixelFormat;
    pipelineDescriptor.depthAttachmentPixelFormat = descriptor.depthPixelFormat;
    pipelineDescriptor.stencilAttachmentPixelFormat = descriptor.stencilPixelFormat;
    pipelineDescriptor.rasterSampleCount = descriptor.sampleCount;
    
    // TODO: 设置顶点着色器和片段着色器
    // 需要从 Metal 库中加载着色器函数
    
    // 设置混合模式
    pipelineDescriptor.colorAttachments[0].blendingEnabled = YES;
    pipelineDescriptor.colorAttachments[0].rgbBlendOperation = MTLBlendOperationAdd;
    pipelineDescriptor.colorAttachments[0].sourceRGBBlendFactor = MTLBlendFactorSourceAlpha;
    pipelineDescriptor.colorAttachments[0].destinationRGBBlendFactor = MTLBlendFactorOneMinusSourceAlpha;
    pipelineDescriptor.colorAttachments[0].alphaBlendOperation = MTLBlendOperationAdd;
    pipelineDescriptor.colorAttachments[0].sourceAlphaBlendFactor = MTLBlendFactorSourceAlpha;
    pipelineDescriptor.colorAttachments[0].destinationAlphaBlendFactor = MTLBlendFactorOneMinusSourceAlpha;
    
    // TODO: 设置顶点描述符
    
    NSError *error = nil;
    id<MTLRenderPipelineState> pipelineState = [device newRenderPipelineStateWithDescriptor:pipelineDescriptor
                                                                                      error:&error];
    if (!pipelineState) {
        NSLog(@"Failed to create render pipeline state: %@", error);
        return nil;
    }
    
    // 缓存
    [self.renderPipelineStateCache setObject:pipelineState forKey:descriptor];
    
    return pipelineState;
}

// MARK: - 缓冲区管理

- (MetalBuffer *)dequeueReusableBufferOfLength:(NSUInteger)length
                                         device:(id<MTLDevice>)device {
    // 清理过期的缓冲区
    [self purgeOldBufferCache];
    
    // 查找可复用的缓冲区
    for (MetalBuffer *buffer in self.bufferCache) {
        if (buffer.buffer.length >= length) {
            [self.bufferCache removeObject:buffer];
            return buffer;
        }
    }
    
    // 创建新缓冲区
    id<MTLBuffer> newBuffer = [device newBufferWithLength:length options:MTLResourceStorageModeShared];
    if (!newBuffer) {
        return nil;
    }
    
    return [[MetalBuffer alloc] initWithBuffer:newBuffer];
}

- (void)purgeOldBufferCache {
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    
    // 每 10 秒清理一次
    if (now - self.lastBufferCachePurge < 10.0) {
        return;
    }
    
    self.lastBufferCachePurge = now;
    
    // 移除超过 30 秒未使用的缓冲区
    NSMutableArray *toRemove = [NSMutableArray array];
    for (MetalBuffer *buffer in self.bufferCache) {
        if (now - buffer.lastReuseTime > 30.0) {
            [toRemove addObject:buffer];
        }
    }
    
    [self.bufferCache removeObjectsInArray:toRemove];
}

// MARK: - 字体纹理

- (void)setupFontTextureWithDevice:(id<MTLDevice>)device {
    // 使用导出的字体数据创建纹理
    const unsigned char *fontData = kaka_font_data;
    const unsigned char *fontDataEnd = kaka_font_data_end;
    
    if (!fontData || !fontDataEnd) {
        NSLog(@"Font data not available");
        return;
    }
    
    NSUInteger fontDataSize = fontDataEnd - fontData;
    
    // TODO: 解析字体数据并创建纹理
    // 字体数据可能是预先生成的字体纹理 atlas
    
    MTLTextureDescriptor *textureDescriptor = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
                                                                                                   width:1024
                                                                                                  height:1024
                                                                                               mipmapped:NO];
    textureDescriptor.usage = MTLTextureUsageShaderRead;
    textureDescriptor.storageMode = MTLStorageModeShared;
    
    self.fontTexture = [device newTextureWithDescriptor:textureDescriptor];
    
    // TODO: 将字体数据上传到纹理
    // [self.fontTexture replaceRegion:MTLRegionMake2D(0, 0, width, height)
    //                     mipmapLevel:0
    //                       withBytes:fontData
    //                     bytesPerRow:bytesPerRow];
    
    NSLog(@"KangView已接入 font=%s", "msyh.ttc");
}

// MARK: - 深度模板状态

- (void)setupDepthStencilStateWithDevice:(id<MTLDevice>)device {
    MTLDepthStencilDescriptor *descriptor = [[MTLDepthStencilDescriptor alloc] init];
    descriptor.depthWriteEnabled = NO;
    descriptor.depthCompareFunction = MTLCompareFunctionAlways;
    
    self.depthStencilState = [device newDepthStencilStateWithDescriptor:descriptor];
}

// MARK: - 帧缓冲描述符

- (void)setFramebufferDescriptor:(FramebufferDescriptor *)framebufferDescriptor {
    _framebufferDescriptor = framebufferDescriptor;
}

@end
