//
//  KakaImGuiDrawViewController.m
//  KakaHookEngine
//
//  ImGui 绘制视图控制器实现
//  基于逆向分析还原的框架代码
//
//  [推测]: 该类是 MTKView 的视图控制器，负责 ImGui 的渲染循环。
//         实现 MTKViewDelegate 协议处理每帧绘制。基于头文件声明和
//         MetalContext 的交互推断实现。
//

#import "KakaImGuiDrawViewController.h"
#import "MetalContext.h"
#import "FramebufferDescriptor.h"
#import "MetalBuffer.h"
#import "KakaVision.h"
#import <MetalKit/MetalKit.h>

// MARK: - 内部常量
static const NSUInteger kMaxBuffersInFlight = 3;

@interface KakaImGuiDrawViewController ()

@property (nonatomic, strong) dispatch_semaphore_t inFlightSemaphore;
@property (nonatomic, strong) id<MTLRenderPipelineState> currentPipelineState;
@property (nonatomic, assign) vector_uint2 viewportSize;
@property (nonatomic, assign) BOOL isSettingUp;

@end

@implementation KakaImGuiDrawViewController

// MARK: - 初始化

- (instancetype)initWithFrame:(CGRect)frame device:(id<MTLDevice>)device {
    self = [super init];
    if (self) {
        _device = device;
        _commandQueue = [device newCommandQueue];
        _inFlightSemaphore = dispatch_semaphore_create(kMaxBuffersInFlight);
        _viewportSize = (vector_uint2){(uint)frame.size.width, (uint)frame.size.height};
        _isSettingUp = NO;
    }
    return self;
}

// MARK: - 视图生命周期

- (void)loadView {
    // Original Addr: 0x10004000 [推测]: 创建 MTKView 作为主视图
    if (!self.device) {
        self.device = MTLCreateSystemDefaultDevice();
    }

    CGRect frame = [UIScreen mainScreen].bounds;
    MTKView *metalView = [[MTKView alloc] initWithFrame:frame device:self.device];
    metalView.delegate = self;
    metalView.colorPixelFormat = MTLPixelFormatBGRA8Unorm;
    metalView.clearColor = MTLClearColorMake(0.0, 0.0, 0.0, 0.0);
    metalView.framebufferOnly = NO;
    metalView.drawableSize = frame.size;
    metalView.autoResizeDrawable = YES;
    metalView.enableSetNeedsDisplay = NO;
    metalView.preferredFramesPerSecond = 60;

    self.metalView = metalView;
    self.view = metalView;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Original Addr: 0x10004100 [推测]

    self.view.backgroundColor = [UIColor clearColor];

    // [推测]: 初始化 ImGui 上下文
    // ImGui::CreateContext();
    // ImGuiIO& io = ImGui::GetIO();
    // io.DisplaySize = ImVec2(self.view.bounds.size.width, self.view.bounds.size.height);

    NSLog(@"[KakaImGui] viewDidLoad - Metal view configured");
}

// MARK: - MTKViewDelegate

- (void)mtkView:(MTKView *)view drawableSizeWillChange:(CGSize)size {
    // Original Addr: 0x10004200 [推测]: 更新视口尺寸
    self.viewportSize = (vector_uint2){(uint)size.width, (uint)size.height};

    // [推测]: 同步更新 ImGui 的显示尺寸
    // ImGuiIO& io = ImGui::GetIO();
    // io.DisplaySize = ImVec2(size.width, size.height);
}

- (void)drawInMTKView:(MTKView *)view {
    // Original Addr: 0x10004300 [推测]: 主渲染循环
    // 等待之前的帧完成
    dispatch_semaphore_wait(self.inFlightSemaphore, DISPATCH_TIME_FOREVER);

    @autoreleasepool {
        // 创建命令缓冲区
        id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];

        __block dispatch_semaphore_t blockSemaphore = self.inFlightSemaphore;
        [commandBuffer addCompletedHandler:^(id<MTLCommandBuffer> buffer) {
            dispatch_semaphore_signal(blockSemaphore);
        }];

        // 获取渲染通道描述符
        MTLRenderPassDescriptor *renderPass = view.currentRenderPassDescriptor;
        if (!renderPass) {
            return;
        }

        // 设置清除颜色（透明背景）
        renderPass.colorAttachments[0].clearColor = MTLClearColorMake(0.0, 0.0, 0.0, 0.0);
        renderPass.colorAttachments[0].loadAction = MTLLoadActionClear;
        renderPass.colorAttachments[0].storeAction = MTLStoreActionStore;

        // 创建渲染编码器
        id<MTLRenderCommandEncoder> encoder = [commandBuffer renderCommandEncoderWithDescriptor:renderPass];
        if (!encoder) {
            return;
        }

        // [推测]: 设置视口
        [encoder setViewport:(MTLViewport){
            0.0, 0.0,
            (double)self.viewportSize.x, (double)self.viewportSize.y,
            0.0, 1.0
        }];

        // [推测]: 设置混合状态
        // ImGui 渲染需要 alpha 混合
        // 实际实现中会调用 ImGui::Render() 并将绘制数据编码到 encoder

        // [推测]: 调用 ImGui 渲染
        // ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(), commandBuffer, renderPass);

        [encoder endEncoding];

        // 提交命令缓冲区
        id<CAMetalDrawable> drawable = view.currentDrawable;
        if (drawable) {
            [commandBuffer presentDrawable:drawable];
        }
        [commandBuffer commit];
    }
}

// MARK: - 设置 Metal 视图

- (void)setMetalView:(MTKView *)metalView {
    _metalView = metalView;
    metalView.delegate = self;
}

// MARK: - 内存管理

- (void)dealloc {
    // [推测]: 清理 ImGui 上下文
    // ImGui::DestroyContext();
    NSLog(@"[KakaImGui] dealloc");
}

@end
