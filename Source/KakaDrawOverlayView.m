//
//  KakaDrawOverlayView.m
//  KakaHookEngine
//
//  绘制覆盖视图实现
//  基于逆向分析还原的框架代码
//
//  [推测]: 该类是透明的 UIView 覆盖层，通过 Metal 渲染引擎
//         绘制 ESP 信息。基于 KakaVision 模块和 MetalContext 推断。
//

#import "KakaDrawOverlayView.h"
#import "KakaVision.h"
#import "MetalContext.h"

@interface KakaDrawOverlayView ()

@property (nonatomic, strong) CADisplayLink *displayLink;

// 私有方法声明
- (void)redraw;

@end

@implementation KakaDrawOverlayView

// MARK: - 初始化

- (instancetype)initWithFrame:(CGRect)frame device:(id<MTLDevice>)device {
    self = [super initWithFrame:frame];
    if (self) {
        _device = device;
        _commandQueue = [device newCommandQueue];
        _isDrawing = NO;
        _drawAlpha = 1.0;
        _visibleLogCount = 10;
        _logFontScale = 1.0;
        _identityFontScale = 1.0;
        _playerFontScale = 1.0;
        _playerTextBold = NO;
        _logOffset = CGPointZero;
        _identityOffset = CGPointZero;

        self.backgroundColor = [UIColor clearColor];
        self.opaque = NO;
        self.userInteractionEnabled = NO;
        self.clipsToBounds = NO;

        // [推测]: 初始化 Metal 上下文
        _metalContext = [MetalContext sharedContext];
    }
    return self;
}

- (instancetype)initWithFrame:(CGRect)frame {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    return [self initWithFrame:frame device:device];
}

// MARK: - 绘制控制

- (void)startDrawing {
    // Original Addr: 0x10006000 [推测]
    if (self.isDrawing) {
        return;
    }

    self.displayLink = [CADisplayLink displayLinkWithTarget:self selector:@selector(redraw)];
    self.displayLink.preferredFramesPerSecond = 60;
    [self.displayLink addToRunLoop:[NSRunLoop mainRunLoop] forMode:NSRunLoopCommonModes];

    self.isDrawing = YES;
    NSLog(@"[KakaDraw] Overlay drawing started");
}

- (void)stopDrawing {
    // Original Addr: 0x10006100 [推测]
    [self.displayLink invalidate];
    self.displayLink = nil;
    self.isDrawing = NO;
    NSLog(@"[KakaDraw] Overlay drawing stopped");
}

- (void)requestRedraw {
    [self setNeedsDisplay];
}

- (void)redraw {
    // [推测]: 每帧回调，触发重绘
    [self setNeedsDisplay];
}

// MARK: - UIView 绘制

- (void)drawRect:(CGRect)rect {
    // Original Addr: 0x10006200 [推测]
    if (!self.isDrawing) {
        return;
    }

    CGContextRef context = UIGraphicsGetCurrentContext();
    if (!context) {
        return;
    }

    KakaVisionManager *visionManager = [KakaVisionManager sharedManager];
    if (!visionManager.visionEnabled) {
        return;
    }

    // 绘制各类 ESP 信息
    if (visionManager.drawBox) {
        [self drawPlayerBoxes];
    }
    if (visionManager.drawName) {
        [self drawPlayerNames];
    }
    if (visionManager.drawHealth) {
        [self drawPlayerHealthBars];
    }
    if (visionManager.drawDistance) {
        [self drawPlayerDistances];
    }
    if (visionManager.drawCareer) {
        [self drawPlayerCareers];
    }
    if (visionManager.drawSkeleton) {
        [self drawPlayerSkeletons];
    }

    // 绘制日志信息
    [self drawLogMessages];
}

// MARK: - 绘制内容

- (void)drawPlayerBoxes {
    // Original Addr: 0x10006300 [推测]
    // [推测]: 遍历玩家列表，将世界坐标转换为屏幕坐标，绘制方框
    KakaVisionManager *vm = [KakaVisionManager sharedManager];
    int count = [vm getNearbyPlayers].count;

    for (int i = 0; i < count; i++) {
        PlayerInfo *player = [vm getPlayerAtIndex:i];
        if (!player || !player->isAlive) continue;

        CGPoint screenPos;
        if ([KakaVisionManager worldToScreen:player->position screenPos:&screenPos]) {
            // [推测]: 绘制方框
            CGRect boxRect = CGRectMake(screenPos.x - 20, screenPos.y - 40, 40, 80);
            UIColor *color = (player->camp != 0) ? vm.enemyColor : vm.friendColor;

            CGContextRef ctx = UIGraphicsGetCurrentContext();
            if (ctx) {
                CGContextSetStrokeColorWithColor(ctx, color.CGColor);
                CGContextSetLineWidth(ctx, 1.5);
                CGContextStrokeRect(ctx, boxRect);
            }
        }
    }
}

- (void)drawPlayerNames {
    // Original Addr: 0x10006400 [推测]
    KakaVisionManager *vm = [KakaVisionManager sharedManager];
    int count = [vm getNearbyPlayers].count;

    for (int i = 0; i < count; i++) {
        PlayerInfo *player = [vm getPlayerAtIndex:i];
        if (!player || !player->isAlive) continue;

        CGPoint screenPos;
        if ([KakaVisionManager worldToScreen:player->position screenPos:&screenPos]) {
            NSString *name = @(player->name);
            UIFont *font = [UIFont systemFontOfSize:12 * self.playerFontScale
                                             weight:self.playerTextBold ? UIFontWeightBold : UIFontWeightRegular];
            NSDictionary *attrs = @{NSFontAttributeName: font,
                                    NSForegroundColorAttributeName: vm.nameColor};
            CGSize size = [name sizeWithAttributes:attrs];
            [name drawAtPoint:CGPointMake(screenPos.x - size.width / 2, screenPos.y - 55) withAttributes:attrs];
        }
    }
}

- (void)drawPlayerHealthBars {
    // Original Addr: 0x10006500 [推测]
    KakaVisionManager *vm = [KakaVisionManager sharedManager];
    int count = [vm getNearbyPlayers].count;

    for (int i = 0; i < count; i++) {
        PlayerInfo *player = [vm getPlayerAtIndex:i];
        if (!player || !player->isAlive) continue;

        CGPoint screenPos;
        if ([KakaVisionManager worldToScreen:player->position screenPos:&screenPos]) {
            CGFloat barWidth = 40;
            CGFloat barHeight = 4;
            CGFloat healthRatio = (player->maxHealth > 0) ? (player->health / player->maxHealth) : 0;

            // 背景
            CGRect bgRect = CGRectMake(screenPos.x - barWidth / 2, screenPos.y - 45, barWidth, barHeight);
            [[UIColor darkGrayColor] setFill];
            UIRectFill(bgRect);

            // 血条
            CGRect healthRect = CGRectMake(screenPos.x - barWidth / 2, screenPos.y - 45, barWidth * healthRatio, barHeight);
            [vm.healthColor setFill];
            UIRectFill(healthRect);
        }
    }
}

- (void)drawPlayerDistances {
    // Original Addr: 0x10006600 [推测]
    KakaVisionManager *vm = [KakaVisionManager sharedManager];
    int count = [vm getNearbyPlayers].count;

    for (int i = 0; i < count; i++) {
        PlayerInfo *player = [vm getPlayerAtIndex:i];
        if (!player || !player->isAlive) continue;

        CGPoint screenPos;
        if ([KakaVisionManager worldToScreen:player->position screenPos:&screenPos]) {
            NSString *distText = [NSString stringWithFormat:@"%.0fm", player->distance];
            UIFont *font = [UIFont systemFontOfSize:10 * self.playerFontScale];
            NSDictionary *attrs = @{NSFontAttributeName: font,
                                    NSForegroundColorAttributeName: vm.distanceColor};
            CGSize size = [distText sizeWithAttributes:attrs];
            [distText drawAtPoint:CGPointMake(screenPos.x - size.width / 2, screenPos.y + 42) withAttributes:attrs];
        }
    }
}

- (void)drawPlayerCareers {
    // Original Addr: 0x10006700 [推测]
    // [推测]: 绘制职业信息，具体映射需要根据游戏数据推断
    KakaVisionManager *vm = [KakaVisionManager sharedManager];
    int count = [vm getNearbyPlayers].count;

    for (int i = 0; i < count; i++) {
        PlayerInfo *player = [vm getPlayerAtIndex:i];
        if (!player || !player->isAlive) continue;

        CGPoint screenPos;
        if ([KakaVisionManager worldToScreen:player->position screenPos:&screenPos]) {
            NSString *careerText = [NSString stringWithFormat:@"职业:%d", player->career];
            UIFont *font = [UIFont systemFontOfSize:9 * self.playerFontScale];
            NSDictionary *attrs = @{NSFontAttributeName: font,
                                    NSForegroundColorAttributeName: [UIColor cyanColor]};
            [careerText drawAtPoint:CGPointMake(screenPos.x - 20, screenPos.y + 50) withAttributes:attrs];
        }
    }
}

- (void)drawPlayerSkeletons {
    // Original Addr: 0x10006800 [推测]
    // [推测]: 骨架绘制需要骨骼关节点数据，当前结构体中没有骨骼数据
    // 需要额外的骨骼数据源
    NSLog(@"[KakaDraw] Skeleton drawing not yet implemented - requires bone data");
}

- (void)drawLogMessages {
    // Original Addr: 0x10006900 [推测]
    // [推测]: 绘制日志消息列表
    // 从某个日志缓冲区读取最近 N 条消息并显示
}

// MARK: - 坐标转换

- (CGPoint)worldToScreen:(CGPoint)worldPosition {
    CGPoint screenPos;
    [KakaVisionManager worldToScreen:worldPosition screenPos:&screenPos];
    return screenPos;
}

- (BOOL)isOnScreen:(CGPoint)screenPosition {
    return [KakaVisionManager isPointInScreen:screenPosition];
}

// MARK: - 清理

- (void)dealloc {
    [self stopDrawing];
}

@end
