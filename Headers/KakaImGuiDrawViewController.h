//
//  KakaImGuiDrawViewController.h
//  KakaHookEngine
//
//  ImGui 绘制视图控制器
//  基于逆向分析还原
//

#import <UIKit/UIKit.h>
#import <Metal/Metal.h>
#import <MetalKit/MetalKit.h>

@interface KakaImGuiDrawViewController : UIViewController <MTKViewDelegate>

// MARK: - 属性
@property (nonatomic, strong) id<MTLDevice> device;
@property (nonatomic, strong) id<MTLCommandQueue> commandQueue;
@property (nonatomic, strong) MTKView *metalView;

// MARK: - 初始化
- (instancetype)initWithFrame:(CGRect)frame device:(id<MTLDevice>)device;

// MARK: - 视图生命周期
- (void)viewDidLoad;
- (void)loadView;

// MARK: - MTKViewDelegate
- (void)mtkView:(MTKView *)view drawableSizeWillChange:(CGSize)size;
- (void)drawInMTKView:(MTKView *)view;

// MARK: - 设置 Metal 视图
- (void)setMetalView:(MTKView *)metalView;

@end
