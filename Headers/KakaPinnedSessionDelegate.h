//
//  KakaPinnedSessionDelegate.h
//  KakaHookEngine
//
//  SSL Pinning 会话委托
//  基于逆向分析还原
//

#import <Foundation/Foundation.h>

@interface KakaPinnedSessionDelegate : NSObject <NSURLSessionDelegate>

// 单例
+ (instancetype)sharedDelegate;

// MARK: - NSURLSessionDelegate
- (void)URLSession:(NSURLSession *)session didBecomeInvalidWithError:(NSError *)error;

- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                             NSURLCredential *credential))completionHandler;

- (void)URLSessionDidFinishEventsForBackgroundURLSession:(NSURLSession *)session;

@end
