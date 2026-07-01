//
//  FramebufferDescriptor.m
//  KakaHookEngine
//
//  帧缓冲描述符实现
//  基于逆向分析还原的框架代码
//
//  [推测]: 该类用于缓存 MTLRenderPipelineState，
//         基于 MetalContext.m 中 renderPipelineStateForFramebufferDescriptor:device:
//         的使用方式推断实现。实现 NSCopying 协议以支持字典键缓存。
//

#import "FramebufferDescriptor.h"

@implementation FramebufferDescriptor

// MARK: - 初始化

- (instancetype)init {
    self = [super init];
    if (self) {
        _sampleCount = 1;
        _colorPixelFormat = MTLPixelFormatBGRA8Unorm;
        _depthPixelFormat = MTLPixelFormatInvalid;
        _stencilPixelFormat = MTLPixelFormatInvalid;
    }
    return self;
}

- (instancetype)initWithRenderPassDescriptor:(MTLRenderPassDescriptor *)descriptor {
    self = [super init];
    if (self) {
        // Original Addr: 0x10003B00 [推测]: 从 MTLRenderPassDescriptor 提取帧缓冲参数
        _sampleCount = descriptor.colorAttachments[0].loadAction == MTLLoadActionLoad ? 1 : 1;
        _colorPixelFormat = descriptor.colorAttachments[0].texture.pixelFormat;
        _depthPixelFormat = descriptor.depthAttachment ? descriptor.depthAttachment.texture.pixelFormat : MTLPixelFormatInvalid;
        _stencilPixelFormat = descriptor.stencilAttachment ? descriptor.stencilAttachment.texture.pixelFormat : MTLPixelFormatInvalid;

        // [推测]: sampleCount 可能从纹理的 sampleCount 属性获取
        if (descriptor.colorAttachments[0].texture) {
            _sampleCount = descriptor.colorAttachments[0].texture.sampleCount;
        }
    }
    return self;
}

// MARK: - NSCopying

- (id)copyWithZone:(NSZone *)zone {
    FramebufferDescriptor *copy = [[FramebufferDescriptor allocWithZone:zone] init];
    copy.sampleCount = self.sampleCount;
    copy.colorPixelFormat = self.colorPixelFormat;
    copy.depthPixelFormat = self.depthPixelFormat;
    copy.stencilPixelFormat = self.stencilPixelFormat;
    return copy;
}

// MARK: - 相等性判断

- (BOOL)isEqualToFramebufferDescriptor:(FramebufferDescriptor *)other {
    if (!other) {
        return NO;
    }
    return self.sampleCount == other.sampleCount &&
           self.colorPixelFormat == other.colorPixelFormat &&
           self.depthPixelFormat == other.depthPixelFormat &&
           self.stencilPixelFormat == other.stencilPixelFormat;
}

- (BOOL)isEqual:(id)object {
    if (self == object) {
        return YES;
    }
    if (![object isKindOfClass:[FramebufferDescriptor class]]) {
        return NO;
    }
    return [self isEqualToFramebufferDescriptor:object];
}

- (NSUInteger)hash {
    return self.sampleCount ^ self.colorPixelFormat ^ self.depthPixelFormat ^ self.stencilPixelFormat;
}

// MARK: - 描述

- (NSString *)description {
    return [NSString stringWithFormat:@"<FramebufferDescriptor: samples=%lu, color=%lu, depth=%lu, stencil=%lu>",
            (unsigned long)self.sampleCount,
            (unsigned long)self.colorPixelFormat,
            (unsigned long)self.depthPixelFormat,
            (unsigned long)self.stencilPixelFormat];
}

@end
