//
//  KakaPinnedSessionDelegate.m
//  KakaHookEngine
//
//  SSL Pinning 会话委托实现
//  基于逆向分析还原的框架代码
//
//  注意：这是基于静态分析的推测性还原
//  实际实现可能有所不同
//

#import "KakaPinnedSessionDelegate.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

// MARK: - 证书指纹
// 预定义的服务器证书公钥指纹
static NSArray *g_pinnedPublicKeys = nil;
static NSArray *g_pinnedCertificates = nil;

@interface KakaPinnedSessionDelegate ()

@property (nonatomic, strong) NSArray *pinnedPublicKeys;
@property (nonatomic, strong) NSArray *pinnedCertificates;
@property (nonatomic, assign) BOOL allowInvalidCertificates;

// 私有方法声明
- (void)setupPinnedCertificates;
- (void)verifyServerTrust:(SecTrustRef)serverTrust
       forProtectionSpace:(NSURLProtectionSpace *)protectionSpace
        completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler;
- (BOOL)verifyCertificateChain:(SecTrustRef)serverTrust;
- (BOOL)verifyPublicKeyFingerprint:(SecTrustRef)serverTrust;
- (BOOL)performDefaultTrustEvaluation:(SecTrustRef)serverTrust;
- (NSData *)publicKeyDataFromCertificate:(SecCertificateRef)certificate;
- (NSString *)sha256FingerprintForData:(NSData *)data;

@end

@implementation KakaPinnedSessionDelegate

// MARK: - 单例

+ (instancetype)sharedDelegate {
    static KakaPinnedSessionDelegate *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[KakaPinnedSessionDelegate alloc] init];
    });
    return shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _allowInvalidCertificates = NO;
        [self setupPinnedCertificates];
    }
    return self;
}

// MARK: - 设置固定证书

- (void)setupPinnedCertificates {
    // 加载预定义的证书或公钥指纹
    // 这些证书/指纹应该是编译时内置的
    
    // 示例：添加公钥指纹（SHA-256）
    // 实际应该从 __DATA 段中读取
    
    NSMutableArray *publicKeys = [NSMutableArray array];
    NSMutableArray *certificates = [NSMutableArray array];
    
    // TODO: 从二进制文件中读取固定的证书数据
    // 通常会有一个或多个根证书的公钥指纹
    
    self.pinnedPublicKeys = publicKeys;
    self.pinnedCertificates = certificates;
    g_pinnedPublicKeys = publicKeys;
    g_pinnedCertificates = certificates;
}

// MARK: - NSURLSessionDelegate

- (void)URLSession:(NSURLSession *)session didBecomeInvalidWithError:(NSError *)error {
    NSLog(@"[KakaPinnedSession] Session became invalid: %@", error);
}

- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                             NSURLCredential *credential))completionHandler {
    NSLog(@"[KakaPinnedSession] Received challenge: %@", challenge.protectionSpace.authenticationMethod);
    
    // 处理服务器信任验证
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        [self verifyServerTrust:challenge.protectionSpace.serverTrust
             forProtectionSpace:challenge.protectionSpace
              completionHandler:completionHandler];
        return;
    }
    
    // 其他类型的验证，默认处理
    if (challenge.previousFailureCount == 0) {
        NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    } else {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    }
}

- (void)URLSessionDidFinishEventsForBackgroundURLSession:(NSURLSession *)session {
    NSLog(@"[KakaPinnedSession] Background session finished events");
}

// MARK: - 服务器信任验证

- (void)verifyServerTrust:(SecTrustRef)serverTrust
       forProtectionSpace:(NSURLProtectionSpace *)protectionSpace
        completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
    if (!serverTrust) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }
    
    BOOL trusted = NO;
    
    // 方法1: 验证证书链
    if (self.pinnedCertificates.count > 0) {
        trusted = [self verifyCertificateChain:serverTrust];
    }
    
    // 方法2: 验证公钥指纹
    if (!trusted && self.pinnedPublicKeys.count > 0) {
        trusted = [self verifyPublicKeyFingerprint:serverTrust];
    }
    
    // 方法3: 默认信任评估（作为后备）
    if (!trusted) {
        trusted = [self performDefaultTrustEvaluation:serverTrust];
    }
    
    if (trusted) {
        NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    } else {
        NSLog(@"[KakaPinnedSession] SSL Pinning validation failed for host: %@", protectionSpace.host);
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    }
}

// MARK: - 证书链验证

- (BOOL)verifyCertificateChain:(SecTrustRef)serverTrust {
    if (!serverTrust || self.pinnedCertificates.count == 0) {
        return NO;
    }
    
    // 获取服务器证书链
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    if (certificateCount == 0) {
        return NO;
    }
    
    // 检查每个固定证书是否在服务器证书链中
    for (NSData *certData in self.pinnedCertificates) {
        SecCertificateRef pinnedCert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData);
        if (!pinnedCert) {
            continue;
        }
        
        // 检查证书是否在链中
        for (CFIndex i = 0; i < certificateCount; i++) {
            SecCertificateRef serverCert = SecTrustGetCertificateAtIndex(serverTrust, i);
            if (CFEqual(pinnedCert, serverCert)) {
                CFRelease(pinnedCert);
                return YES;
            }
        }
        
        CFRelease(pinnedCert);
    }
    
    return NO;
}

// MARK: - 公钥指纹验证

- (BOOL)verifyPublicKeyFingerprint:(SecTrustRef)serverTrust {
    if (!serverTrust || self.pinnedPublicKeys.count == 0) {
        return NO;
    }
    
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    if (certificateCount == 0) {
        return NO;
    }
    
    // 检查每个证书的公钥指纹
    for (CFIndex i = 0; i < certificateCount; i++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        
        // 获取公钥数据
        NSData *publicKeyData = [self publicKeyDataFromCertificate:certificate];
        if (!publicKeyData) {
            continue;
        }
        
        // 计算 SHA-256 指纹
        NSString *fingerprint = [self sha256FingerprintForData:publicKeyData];
        
        // 检查是否匹配
        for (NSString *pinnedFingerprint in self.pinnedPublicKeys) {
            if ([fingerprint caseInsensitiveCompare:pinnedFingerprint] == NSOrderedSame) {
                return YES;
            }
        }
    }
    
    return NO;
}

// MARK: - 默认信任评估

- (BOOL)performDefaultTrustEvaluation:(SecTrustRef)serverTrust {
    if (!serverTrust) {
        return NO;
    }
    
    // 如果允许无效证书（调试模式）
    if (self.allowInvalidCertificates) {
        NSLog(@"[KakaPinnedSession] WARNING: Allowing invalid certificate (debug mode)");
        return YES;
    }
    
    // 使用系统默认的信任评估
    SecTrustResultType result;
    OSStatus status = SecTrustEvaluate(serverTrust, &result);
    
    if (status != errSecSuccess) {
        NSLog(@"[KakaPinnedSession] Trust evaluation failed: %d", (int)status);
        return NO;
    }
    
    // 检查结果类型
    switch (result) {
        case kSecTrustResultProceed:
        case kSecTrustResultUnspecified:
            return YES;
        case kSecTrustResultDeny:
        case kSecTrustResultFatalTrustFailure:
        case kSecTrustResultOtherError:
        case kSecTrustResultRecoverableTrustFailure:
        default:
            return NO;
    }
}

// MARK: - 辅助方法

- (NSData *)publicKeyDataFromCertificate:(SecCertificateRef)certificate {
    if (!certificate) {
        return nil;
    }
    
    // 从证书中提取公钥
    SecTrustRef trust = NULL;
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    
    OSStatus status = SecTrustCreateWithCertificates(certificate, policy, &trust);
    if (status != errSecSuccess || !trust) {
        if (policy) CFRelease(policy);
        return nil;
    }
    
    SecTrustResultType result;
    SecTrustEvaluate(trust, &result);
    
    SecKeyRef publicKey = SecTrustCopyPublicKey(trust);
    
    if (trust) CFRelease(trust);
    if (policy) CFRelease(policy);
    
    if (!publicKey) {
        return nil;
    }
    
    // 获取公钥数据
    NSData *publicKeyData = CFBridgingRelease(SecKeyCopyExternalRepresentation(publicKey, NULL));
    
    CFRelease(publicKey);
    
    return publicKeyData;
}

- (NSString *)sha256FingerprintForData:(NSData *)data {
    if (!data) {
        return nil;
    }
    
    // 计算 SHA-256 哈希
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    
    // 转换为十六进制字符串
    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [fingerprint appendFormat:@"%02x", digest[i]];
    }
    
    return [fingerprint copy];
}

// MARK: - 调试模式

+ (void)setAllowInvalidCertificates:(BOOL)allow {
    [KakaPinnedSessionDelegate sharedDelegate].allowInvalidCertificates = allow;
}

@end
