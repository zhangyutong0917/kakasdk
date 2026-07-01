//
//  KakaVision.h
//  KakaHookEngine
//
//  视野/透视模块头文件
//  基于逆向分析还原
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// MARK: - 视野信息结构体
typedef struct {
    CGPoint position;          // 位置
    CGFloat radius;            // 视野半径
    BOOL isValid;              // 是否有效
    BOOL isWaiting;            // 等待中
    uint64_t targetPointer;    // 目标对象指针
    double lastUpdateTime;     // 上次更新时间
    int retryCount;            // 重试次数
} VisionInfo;

// MARK: - 玩家信息结构体
typedef struct {
    uint64_t playerPointer;    // 玩家对象指针
    CGPoint position;          // 位置
    float rotation;            // 旋转角度
    BOOL isAlive;              // 是否存活
    int camp;                  // 阵营
    int career;                // 职业
    char name[64];             // 名字
    float health;              // 生命值
    float maxHealth;           // 最大生命值
    float distance;            // 距离
    BOOL isCached;             // 是否缓存
} PlayerInfo;

// MARK: - 绘制项结构体
typedef struct {
    CGPoint position;          // 位置
    CGSize size;               // 大小
    UIColor *color;            // 颜色
    NSString *text;            // 文本
    int type;                  // 类型
    float alpha;               // 透明度
} DrawItem;

// MARK: - 视野模式
typedef NS_ENUM(NSInteger, KakaVisionMode) {
    KakaVisionModeOff = 0,
    KakaVisionModeNormal = 1,      // 普通透视
    KakaVisionModeFull = 2,        // 全透视
    KakaVisionModeMinimap = 3,     // 小地图
};

// MARK: - 绘制类型
typedef NS_ENUM(NSInteger, KakaDrawType) {
    KakaDrawTypeNone = 0,
    KakaDrawTypeBox = 1,           // 方框
    KakaDrawTypeSkeleton = 2,      // 骨架
    KakaDrawTypeName = 3,          // 名字
    KakaDrawTypeHealth = 4,        // 血条
    KakaDrawTypeDistance = 5,      // 距离
    KakaDrawTypeCareer = 6,        // 职业
    KakaDrawTypeAll = 7,           // 全部
};

// MARK: - 视野管理器
@interface KakaVisionManager : NSObject

// 单例
+ (instancetype)sharedManager;

// MARK: - 属性
@property (nonatomic, assign) KakaVisionMode visionMode;
@property (nonatomic, assign) CGFloat visionRadius;
@property (nonatomic, assign) BOOL visionEnabled;
@property (nonatomic, assign) BOOL autoStart;
@property (nonatomic, assign) int maxRetryCount;
@property (nonatomic, assign) NSTimeInterval retryInterval;

// MARK: - 视野信息
@property (nonatomic, assign, readonly) VisionInfo *visionInfo;
@property (nonatomic, strong, readonly) NSArray *playerList;
@property (nonatomic, assign, readonly) int playerCount;

// MARK: - 启动/停止
- (BOOL)startVision;
- (void)stopVision;
- (BOOL)isVisionRunning;

// MARK: - 目标管理
- (BOOL)setTarget:(void *)target;
- (void *)getCurrentTarget;
- (BOOL)waitForValidVisionInfo;
- (BOOL)autoResolve;

// MARK: - 玩家信息
- (NSArray *)getNearbyPlayers;
- (PlayerInfo *)getPlayerAtIndex:(int)index;
- (int)getAlivePlayerCount;
- (int)getEnemyPlayerCount;

// MARK: - 绘制配置
@property (nonatomic, assign) KakaDrawType drawType;
@property (nonatomic, assign) BOOL drawBox;
@property (nonatomic, assign) BOOL drawName;
@property (nonatomic, assign) BOOL drawHealth;
@property (nonatomic, assign) BOOL drawDistance;
@property (nonatomic, assign) BOOL drawCareer;
@property (nonatomic, assign) BOOL drawSkeleton;

// MARK: - 颜色配置
@property (nonatomic, strong) UIColor *enemyColor;
@property (nonatomic, strong) UIColor *friendColor;
@property (nonatomic, strong) UIColor *nameColor;
@property (nonatomic, strong) UIColor *healthColor;
@property (nonatomic, strong) UIColor *distanceColor;

// MARK: - 线程
@property (nonatomic, strong) NSThread *visionThread;
@property (nonatomic, assign) BOOL threadCreated;
@property (nonatomic, copy) NSString *threadCreateError;

// MARK: - 生命周期
- (void)visionThreadMain;
- (void)updateVisionInfo;
- (void)updatePlayerList;

// MARK: - 工具方法
+ (CGFloat)calculateDistance:(CGPoint)from to:(CGPoint)to;
+ (BOOL)isPointInScreen:(CGPoint)point;
+ (BOOL)worldToScreen:(CGPoint)worldPos screenPos:(CGPoint *)screenPos;

@end

// MARK: - 全局 C 函数

// 启动视野
BOOL kaka_vision_start(void);
void kaka_vision_stop(void);
BOOL kaka_vision_is_running(void);

// 设置目标
BOOL kaka_vision_set_target(void *target);
void *kaka_vision_get_target(void);

// 获取视野信息
VisionInfo *kaka_vision_get_info(void);
BOOL kaka_vision_wait_valid(void);

// 玩家列表
int kaka_vision_player_count(void);
PlayerInfo *kaka_vision_get_player(int index);

// 绘制
void kaka_vision_draw_frame(void);

// 配置
void kaka_vision_set_radius(float radius);
float kaka_vision_get_radius(void);
void kaka_vision_set_enabled(BOOL enabled);
BOOL kaka_vision_get_enabled(void);
