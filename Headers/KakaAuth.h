//
//  KakaAuth.h
//  KakaHookEngine
//
//  认证系统头文件
//  基于逆向分析还原
//

#import <Foundation/Foundation.h>

// MARK: - 认证状态
typedef NS_ENUM(NSInteger, KakaAuthStatus) {
    KakaAuthStatusUnknown = 0,
    KakaAuthStatusPending = 1,      // 等待认证
    KakaAuthStatusVerifying = 2,    // 验证中
    KakaAuthStatusSuccess = 3,      // 认证成功
    KakaAuthStatusFailed = 4,       // 认证失败
    KakaAuthStatusBanned = 5,       // 被封禁
};

// MARK: - 认证类型
typedef NS_ENUM(NSInteger, KakaAuthType) {
    KakaAuthTypeLocal = 0,          // 本地认证
    KakaAuthTypeNetwork = 1,        // 网络认证
    KakaAuthTypeFeature = 2,        // 功能包认证
};

// MARK: - 认证错误码
typedef NS_ENUM(NSInteger, KakaAuthErrorCode) {
    KakaAuthErrorNone = 0,
    KakaAuthErrorInvalidUDID = 1001,
    KakaAuthErrorUDIDBanned = 1002,
    KakaAuthErrorInvalidSignature = 1003,
    KakaAuthErrorTamperDetected = 1004,
    KakaAuthErrorNetworkError = 2001,
    KakaAuthErrorServerError = 2002,
    KakaAuthErrorExpired = 3001,
};

// MARK: - 功能包信息
@interface KakaFeatureBundle : NSObject

@property (nonatomic, copy) NSString *bundleId;
@property (nonatomic, copy) NSString *featureId;
@property (nonatomic, assign) NSInteger bundleVersion;
@property (nonatomic, assign) BOOL featureEnabled;
@property (nonatomic, strong) NSData *signature;
@property (nonatomic, strong) NSData *nonce;
@property (nonatomic, strong) NSDate *expireDate;

- (instancetype)initWithDictionary:(NSDictionary *)dict;
- (BOOL)verifySignatureWithPublicKey:(NSData *)publicKey;

@end

// MARK: - 认证管理器
@interface KakaAuthManager : NSObject

// 单例
+ (instancetype)sharedManager;

// MARK: - 属性
@property (nonatomic, assign, readonly) KakaAuthStatus authStatus;
@property (nonatomic, copy, readonly) NSString *currentUDID;
@property (nonatomic, strong, readonly) NSArray *featureBundles;
@property (nonatomic, assign, readonly) KakaAuthErrorCode lastError;

// MARK: - 认证流程
- (void)startBootstrap;
- (void)startAuthSystems;

// MARK: - 本地认证
- (BOOL)verifyLocalAuth;
- (NSString *)getLocalAuthUDID;
- (BOOL)checkUDIDBanned;

// MARK: - 预认证
- (NSData *)generatePreauthSeed;
- (NSData *)generateClientIntegritySeed;

// MARK: - 功能包验证
- (BOOL)verifyFeatureBundle:(KakaFeatureBundle *)bundle;
- (BOOL)isFeatureEnabled:(NSString *)featureId;

// MARK: - 客户端密封
- (NSData *)sealClientData:(NSData *)data;
- (NSData *)sealFeatureParams:(NSDictionary *)params;

// MARK: - Kami 验证
- (BOOL)verifyKami:(NSString *)kami;
- (NSString *)generateLastKami;

// MARK: - Marker 验证
- (BOOL)verifyMarker:(NSData *)marker;
- (NSData *)generateMarkerWithVersion:(NSInteger)version;

// MARK: - 防篡改
- (BOOL)checkIntegrity;
- (BOOL)detectTamper:(NSString **)reason;

// MARK: - 网络认证
- (void)applyAuthWithCode:(NSString *)code
               completion:(void (^)(BOOL success, NSError *error))completion;

// MARK: - 通知
extern NSString * const KakaAuthStatusDidChangeNotification;
extern NSString * const KakaAuthDidSucceedNotification;
extern NSString * const KakaAuthDidFailNotification;

@end

// MARK: - 全局函数

// 认证引导入口
void kaka_auth_bootstrap(void);

// 启动认证系统
void kaka_auth_start_systems(void);

// 本地认证
BOOL kaka_auth_local_verify(void);
const char *kaka_auth_local_udid(void);

// 客户端密封
NSData *kaka_client_seal_v2(NSData *data);

// 功能包签名验证
BOOL kaka_feature_bundle_rsa_v1_verify(NSData *data, NSData *signature);
