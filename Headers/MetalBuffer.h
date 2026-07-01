//
//  MetalBuffer.h
//  KakaHookEngine
//
//  Metal 缓冲区封装
//  基于逆向分析还原
//

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

@interface MetalBuffer : NSObject

// MARK: - 属性
@property (nonatomic, strong) id<MTLBuffer> buffer;
@property (nonatomic, assign) double lastReuseTime;

// MARK: - 初始化
- (instancetype)initWithBuffer:(id<MTLBuffer>)buffer;

// MARK: - 访问
- (void *)contents;
- (NSUInteger)length;

@end
