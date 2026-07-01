//
//  FramebufferDescriptor.h
//  KakaHookEngine
//
//  帧缓冲描述符
//  基于逆向分析还原
//

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

@interface FramebufferDescriptor : NSObject <NSCopying>

// MARK: - 属性
@property (nonatomic, assign) NSUInteger sampleCount;
@property (nonatomic, assign) MTLPixelFormat colorPixelFormat;
@property (nonatomic, assign) MTLPixelFormat depthPixelFormat;
@property (nonatomic, assign) MTLPixelFormat stencilPixelFormat;

// MARK: - 初始化
- (instancetype)initWithRenderPassDescriptor:(MTLRenderPassDescriptor *)descriptor;

// MARK: - NSCopying
- (id)copyWithZone:(NSZone *)zone;

// MARK: - 相等性判断
- (BOOL)isEqualToFramebufferDescriptor:(FramebufferDescriptor *)other;

@end
