//
//  MetalBuffer.m
//  KakaHookEngine
//
//  Metal 缓冲区封装实现
//  基于逆向分析还原的框架代码
//
//  [推测]: 该类封装 MTLBuffer，提供对象池复用机制。
//         基于 MetalContext.m 中的使用方式推断实现。
//

#import "MetalBuffer.h"

@implementation MetalBuffer

// MARK: - 初始化

- (instancetype)initWithBuffer:(id<MTLBuffer>)buffer {
    self = [super init];
    if (self) {
        _buffer = buffer;
        _lastReuseTime = [[NSDate date] timeIntervalSince1970];
    }
    return self;
}

// MARK: - 访问

- (void *)contents {
    // Original Addr: 0x10003A00 [推测]: 地址基于代码段偏移推断
    return self.buffer.contents;
}

- (NSUInteger)length {
    // Original Addr: 0x10003A20 [推测]: 地址基于代码段偏移推断
    return self.buffer.length;
}

// MARK: - 描述

- (NSString *)description {
    return [NSString stringWithFormat:@"<MetalBuffer: %p, length=%lu, lastReuse=%.1f>",
            self, (unsigned long)self.buffer.length, self.lastReuseTime];
}

@end
