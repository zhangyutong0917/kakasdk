//
//  KakaDrawOverlayView.h
//  KakaHookEngine
//
//  绘制覆盖视图
//  基于逆向分析还原
//
//  [推测]: 该类是一个透明的覆盖层视图，用于在游戏画面上方
//         绘制 ESP 信息（方框、名字、血条等）。基于 KakaSDK.h
//         中的类前向声明和 KakaVision 模块推断。
//

#import <UIKit/UIKit.h>
#import <Metal/Metal.h>

@class KakaVisionManager;
@class MetalContext;

@interface KakaDrawOverlayView : UIView

// MARK: - 属性
@property (nonatomic, strong) id<MTLDevice> device;
@property (nonatomic, strong) id<MTLCommandQueue> commandQueue;
@property (nonatomic, strong) MetalContext *metalContext;
@property (nonatomic, assign) BOOL isDrawing;
@property (nonatomic, assign) CGFloat drawAlpha;
@property (nonatomic, assign) NSInteger visibleLogCount;
@property (nonatomic, assign) CGFloat logFontScale;
@property (nonatomic, assign) CGFloat identityFontScale;
@property (nonatomic, assign) CGFloat playerFontScale;
@property (nonatomic, assign) BOOL playerTextBold;
@property (nonatomic, assign) CGPoint logOffset;
@property (nonatomic, assign) CGPoint identityOffset;

// MARK: - 初始化
- (instancetype)initWithFrame:(CGRect)frame device:(id<MTLDevice>)device;

// MARK: - 绘制控制
- (void)startDrawing;
- (void)stopDrawing;
- (void)requestRedraw;

// MARK: - 绘制内容
- (void)drawPlayerBoxes;
- (void)drawPlayerNames;
- (void)drawPlayerHealthBars;
- (void)drawPlayerDistances;
- (void)drawPlayerCareers;
- (void)drawPlayerSkeletons;
- (void)drawLogMessages;

// MARK: - 坐标转换
- (CGPoint)worldToScreen:(CGPoint)worldPosition;
- (BOOL)isOnScreen:(CGPoint)screenPosition;

@end
