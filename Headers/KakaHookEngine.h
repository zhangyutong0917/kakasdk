//
//  KakaHookEngine.h
//  KakaHookEngine
//
//  Hook 引擎头文件
//  基于逆向分析还原
//

#import <Foundation/Foundation.h>

// MARK: - Hook 类型
typedef NS_ENUM(NSInteger, KakaHookType) {
    KakaHookTypeUnknown = 0,
    KakaHookTypeBranchThunk = 1,        // 分支 thunk hook
    KakaHookTypeLazyBranchLiteral = 2,  // 惰性分支字面量 hook
    KakaHookTypeSetter = 3,             // Setter hook
    KakaHookTypeVision = 4,             // Vision hook
    KakaHookTypeRuntime = 5,            // 运行时 hook (fallback)
    KakaHookTypeStatic = 6,             // 静态 hook (__HOOK_DATA)
};

// MARK: - Hook 引擎类型
typedef NS_ENUM(NSInteger, KakaHookEngineType) {
    KakaHookEngineTypeAuto = 0,         // 自动选择
    KakaHookEngineTypeSubstrate = 1,    // MobileSubstrate
    KakaHookEngineTypeLibHooker = 2,    // libhooker
};

// MARK: - Hook 注册表项
@interface KakaHookRegistryEntry : NSObject

@property (nonatomic, assign) KakaHookType hookType;
@property (nonatomic, assign) void *targetAddress;
@property (nonatomic, assign) void *replacementAddress;
@property (nonatomic, assign) void *originalAddress;
@property (nonatomic, assign) BOOL isActive;
@property (nonatomic, copy) NSString *hookName;

- (instancetype)initWithType:(KakaHookType)type
                      target:(void *)target
                 replacement:(void *)replacement
                    original:(void **)original;

@end

// MARK: - Hook 错误码
typedef NS_ENUM(NSInteger, KakaHookErrorCode) {
    KakaHookErrorNone = 0,
    KakaHookErrorAlreadyHooked = 1001,
    KakaHookErrorTargetNotExecutable = 1002,
    KakaHookErrorReplacementNotExecutable = 1003,
    KakaHookErrorInvalidArguments = 1004,
    KakaHookErrorRegistryFailed = 1005,
    KakaHookErrorTamperBlocked = 1006,
    KakaHookErrorThunkDestinationNotExecutable = 1007,
    KakaHookErrorStubsSizeMismatch = 1008,
    KakaHookErrorStaticHookMissing = 1009,
    KakaHookErrorRuntimeFallbackDisabled = 1010,
};

// MARK: - Hook 引擎
@interface KakaHookEngine : NSObject

// 单例
+ (instancetype)sharedEngine;

// MARK: - 属性
@property (nonatomic, assign, readonly) KakaHookEngineType engineType;
@property (nonatomic, strong, readonly) NSArray *registry;
@property (nonatomic, assign, readonly) BOOL isJailbreak;
@property (nonatomic, assign, readonly) BOOL runtimeFallbackEnabled;

// MARK: - 初始化
- (BOOL)initializeEngine;
- (KakaHookEngineType)detectEngineType;

// MARK: - Hook 框架检测
- (BOOL)hasSubstrateFramework;
- (BOOL)hasLibhooker;

// MARK: - 安装 Hook
- (BOOL)installHook:(void *)target
        replacement:(void *)replacement
           original:(void **)original
               type:(KakaHookType)type
              error:(NSError **)error;

- (BOOL)installBranchThunkHook:(void *)thunk
                   destination:(void *)destination
                      original:(void **)original
                         error:(NSError **)error;

- (BOOL)installLazyBranchLiteralHook:(void *)thunk
                         destination:(void *)destination
                             literal:(void *)literal
                            original:(void **)original
                               error:(NSError **)error;

- (BOOL)installSetterHook:(void *)target
                     base:(CGFloat)base
                   offset:(CGFloat)offset
                    error:(NSError **)error;

- (BOOL)installVisionHook:(void *)target
                   radius:(CGFloat)radius
                    error:(NSError **)error;

// MARK: - 卸载 Hook
- (BOOL)uninstallHook:(void *)target error:(NSError **)error;
- (BOOL)uninstallAllHooks:(NSError **)error;

// MARK: - Hook 注册表
- (BOOL)addRegistryEntry:(KakaHookRegistryEntry *)entry error:(NSError **)error;
- (KakaHookRegistryEntry *)findRegistryEntry:(void *)target;
- (BOOL)removeRegistryEntry:(void *)target error:(NSError **)error;

// MARK: - 静态 Hook
- (BOOL)hasStaticHookData;
- (void *)findStaticHookBlock:(uint64_t)rva;

// MARK: - 防篡改
- (BOOL)checkTamperProtection;
- (NSString *)getTamperReason;

// MARK: - 代码指针规范化
- (BOOL)normalizeCodePointers;

// MARK: - 分支 thunk 工具
- (BOOL)isBranchThunk:(void *)address;
- (void *)getBranchThunkDestination:(void *)thunk;
- (BOOL)isValidBranchIsland:(void *)island;

@end

// MARK: - 全局 C 函数

// 初始化 Hook 引擎
BOOL kaka_hook_engine_init(void);

// 安装 Hook
BOOL kaka_hook_install(void *target, void *replacement, void **original);

// 安装分支 thunk hook
BOOL kaka_hook_branch_thunk(void *thunk, void *destination, void **original);

// 安装惰性字面量 hook
BOOL kaka_hook_lazy_literal(void *thunk, void *destination, void *literal, void **original);

// 卸载 Hook
BOOL kaka_hook_uninstall(void *target);

// 检查是否已 Hook
BOOL kaka_hook_is_hooked(void *target);

// 获取 Hook 注册表
NSArray *kaka_hook_get_registry(void);

// MARK: - 外部 Hook 框架检测

// 检测 MobileSubstrate
BOOL kaka_hook_has_substrate(void);
const char *kaka_hook_substrate_path(void);

// 检测 libhooker
BOOL kaka_hook_has_libhooker(void);
const char *kaka_hook_libhooker_path(void);

// MARK: - 错误信息
const char *kaka_hook_error_string(KakaHookErrorCode code);
