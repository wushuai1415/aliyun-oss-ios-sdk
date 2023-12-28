//
//  OSSV4Signer.m
//  AliyunOSSSDK
//
//  Created by ws on 2023/12/26.
//  Copyright © 2023 aliyun. All rights reserved.
//

#import "OSSV4Signer.h"
#import "NSDate+OSS.h"
#import "OSSDefine.h"
#import "OSSAllRequestNeededMessage.h"
#import "NSMutableDictionary+OSS.h"
#import "OSSSignerParams.h"
#import "OSSUtil.h"
#import "NSSet+OSS.h"
#import "NSData+OSS.h"
#import "OSSServiceSignature.h"
#import "OSSLog.h"

#define ISO8601DateTimeFormat       @"yyyyMMdd'T'HHmmss'Z'"
#define ISO8601DateFormat           @"yyyyMMdd"
#define NewLine                     @"\n"
#define SeparatorBackslash          @"/"
#define Terminator                  @"aliyun_v4_request"
#define OSS4HMacSHA256              @"OSS4-HMAC-SHA256"
#define SecretKeyPrefix             @"aliyun_v4"

@interface OSSV4Signer()

@property (nonatomic, copy) NSDate *requestDateTime;

@property (nonatomic, copy) NSSet<NSString *> *additionalSignedHeaders;

@end

@implementation OSSV4Signer

- (NSString *)getDateTime {
    return [self.requestDateTime oss_asStringValueWithDateFormat:ISO8601DateTimeFormat];
}

- (NSString *)getDate {
    return [self.requestDateTime oss_asStringValueWithDateFormat:ISO8601DateFormat];
}

- (BOOL)hasDefaultSignedHeaders:(NSString *)header {
    if ([@[OSSHttpHeaderContentType, OSSHttpHeaderContentMD5] containsObject:header]) {
        return YES;
    }
    return [header hasPrefix:OSSPrefix];
}

- (BOOL)hasSignedHeaders:(NSString *)header {
    if ([self hasDefaultSignedHeaders:header]) {
        return YES;
    }
    return [self.additionalSignedHeaders containsObject:header];
}

- (BOOL)hasAdditionalSignedHeaders {
    return self.additionalSignedHeaders != nil && self.additionalSignedHeaders.count != 0;
}

- (void)buildSortedHeadersMap:(NSDictionary *)headers {
    
}

- (void)resolveAdditionalSignedHeaders:(OSSAllRequestNeededMessage *)request
                           headerNames:(NSSet<NSString *> *)headerNames {
    
}

- (void)addSignedHeaderIfNeeded:(OSSAllRequestNeededMessage *)request {
    if ([self.additionalSignedHeaders containsObject:OSSHttpHeaderHost.lowercaseString] &&
        [request.headerParams.allKeys containsObject:OSSHttpHeaderHost.lowercaseString]) {
        [request.headerParams oss_setObject:[[[NSURL alloc] initWithString:request.endpoint] host] forKey:OSSHttpHeaderHost];
    }
}

- (void)addOSSContentSha256Header:(OSSAllRequestNeededMessage *)request {
    request.headerParams[OSSHttpHeaderContentSha256] = @"UNSIGNED-PAYLOAD";
}

- (void)addDateHeaderIfNeeded:(OSSAllRequestNeededMessage *)request {
    [self initRequestDateTime];
    [request.headerParams oss_setObject:[self getDateTime] forKey:OSSHttpHeaderDate];
}

- (void)initRequestDateTime {
    self.requestDateTime = [NSDate oss_clockSkewFixedDate];
}

- (NSString *)buildCanonicalRequest:(OSSAllRequestNeededMessage *)request {
    NSString *method = request.httpMethod;
    NSString *resourcePath = self.signerParams.resourcePath;
    
    NSMutableString *canonicalString = [NSMutableString new];
    
    //http method + "\n"
    [canonicalString appendString:method];
    [canonicalString appendString:NewLine];
    
    //Canonical URI + "\n"
    [canonicalString appendString:[resourcePath oss_urlEncodedString]];
    [canonicalString appendString:NewLine];
    
    //Canonical Query String + "\n" +
    NSMutableArray * params = [NSMutableArray new];
    [request.params enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        NSString * keyStr = [[key oss_trim] oss_urlEncodedString];
        NSString * valueStr = [[obj oss_trim] oss_urlEncodedString];
        if ([valueStr oss_isNotEmpty]) {
            [params addObject:[NSString stringWithFormat:@"%@=%@", keyStr, valueStr]];
        }
    }];
    NSArray *sortedParams = [params sortedArrayUsingSelector:@selector(compare:)];
    [canonicalString appendString:[sortedParams componentsJoinedByString:@"&"]];
    [canonicalString appendString:NewLine];

    //Canonical Headers + "\n" +
    NSMutableArray * headers = [NSMutableArray new];
    [request.headerParams enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        NSString * keyStr = [key oss_trim];
        NSString * valueStr = [obj oss_trim];
        if ([valueStr oss_isNotEmpty]) {
            [params addObject:[NSString stringWithFormat:@"%@:%@%@", keyStr, valueStr, NewLine]];
        }
    }];
    NSArray *sortedHeaders = [headers sortedArrayUsingSelector:@selector(compare:)];
    [canonicalString appendString:[sortedHeaders componentsJoinedByString:@"&"]];
    [canonicalString appendString:NewLine];

    //Additional Headers + "\n" +
    NSString *canonicalPartStr = [self.additionalSignedHeaders componentsJoinedByString:@";"];
    [canonicalString appendString:canonicalPartStr];
    [canonicalString appendString:NewLine];
    
    //Hashed PayLoad
    NSString *hashedPayLoad = request.headerParams[OSSHttpHeaderContentSha256];
    if (![hashedPayLoad oss_isNotEmpty]) {
        hashedPayLoad = @"UNSIGNED-PAYLOAD";
    }
    [canonicalString appendString:hashedPayLoad];
    
    return canonicalString;
}

- (NSString *)getSignRegion {
    if ([self.signerParams.cloudBoxId oss_isNotEmpty]) {
        return self.signerParams.cloudBoxId;
    }
    return self.signerParams.region;
}

- (NSString *)getSignProduct {
    if ([self.signerParams.cloudBoxId oss_isNotEmpty]) {
        return OSSProductCloudBox;
    }
    return OSSProductDefault;
}

- (NSString *)buildScope {
    NSString *build = [[self getDate] stringByAppendingString:SeparatorBackslash];
    build = [[build stringByAppendingString:[self getSignRegion]] stringByAppendingString:SeparatorBackslash];
    build = [[build stringByAppendingString:[self getSignProduct]] stringByAppendingString:SeparatorBackslash];
    build = [build stringByAppendingString:Terminator];
    return build;
}

- (NSString *)buildStringToSign:(NSString *)canonicalString {
    NSString *build = [OSS4HMacSHA256 stringByAppendingString:NewLine];
    build = [[build stringByAppendingString:[self getDateTime]] stringByAppendingString:NewLine];
    build = [[build stringByAppendingString:[self buildScope]] stringByAppendingString:NewLine];
    build = [build stringByAppendingString:[[[canonicalString dataUsingEncoding:NSUTF8StringEncoding] calculateSha256] hexString]];
    return build;
}

- (NSData *)buildSigningKey:(OSSFederationToken *)federationToken {
    id<OSSServiceSignature> signature = [HmacSHA256Signature new];
    NSData *signingSecret = [[SecretKeyPrefix stringByAppendingString:federationToken.tSecretKey] dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signingDate = [signature computeHash:signingSecret data:[[self getDate] dataUsingEncoding:NSUTF8StringEncoding]];
    NSData *signingRegion = [signature computeHash:signingDate data:[[self getSignRegion] dataUsingEncoding:NSUTF8StringEncoding]];
    NSData *signingService = [signature computeHash:signingRegion data:[[self getSignProduct] dataUsingEncoding:NSUTF8StringEncoding]];

    return [signature computeHash:signingService data:[Terminator dataUsingEncoding:NSUTF8StringEncoding]];
}

- (NSString *)buildSignature:(NSData *)signingKey
                stringToSign:(NSString *)stringToSign {
    NSData *result = [[HmacSHA256Signature new] computeHash:signingKey
                                                       data:[stringToSign dataUsingEncoding:NSUTF8StringEncoding]];
    return [result hexString];
}

- (NSString *)buildAuthorization:(NSString *)signature
                 federationToken:(OSSFederationToken *)federationToken {
    NSString *credential = [@"Credential=" stringByAppendingFormat:@"%@%@%@", federationToken.tAccessKey, SeparatorBackslash, [self buildScope]];
    NSString *signedHeaders = ![self hasAdditionalSignedHeaders] ? @"" : [@"" stringByAppendingString:[self.additionalSignedHeaders componentsJoinedByString:@";"]];
    NSString *sign = [@",Signature=" stringByAppendingString:signature];
    
    return [@"OSS4-HMAC-SHA256 " stringByAppendingFormat:@"%@%@%@", credential, signedHeaders, sign];
}

- (void)addAuthorizationHeader:(OSSAllRequestNeededMessage *)request
               federationToken:(OSSFederationToken *)federationToken {
    NSString *stringToSign = [self buildStringToSignWithRequest:request];
    NSData *signingKey = [self buildSigningKey:federationToken];
    NSString *signature = [self buildSignature:signingKey stringToSign:stringToSign];
    NSString *authorization = [self buildAuthorization:signature
                                       federationToken:federationToken];
    
    [request.headerParams oss_setObject:authorization forKey:OSSHttpHeaderAuthorization];
}

- (NSString *)buildStringToSignWithRequest:(OSSAllRequestNeededMessage *)request {
    NSString *canonicalRequest = [self buildCanonicalRequest:request];
    OSSLogVerbose(@"canonicalRequest: %@", canonicalRequest);
    NSString *stringToSign = [self buildStringToSign:canonicalRequest];
    return stringToSign;
}

- (OSSTask *)sign:(OSSAllRequestNeededMessage *)requestMessage {
    if (!requestMessage.isAuthenticationRequired) {
        return [OSSTask taskWithResult:nil];
    }
    
    id<OSSCredentialProvider> credentialProvider = self.signerParams.credentialProvider;
    OSSFederationToken *federationToken;
    NSError * error = nil;
    if ([credentialProvider isKindOfClass:[OSSFederationCredentialProvider class]]) {
        federationToken = [(OSSFederationCredentialProvider *)credentialProvider getToken:&error];
        if (error) {
            return [OSSTask taskWithError:error];
        }
    } else if ([credentialProvider isKindOfClass:[OSSStsTokenCredentialProvider class]]) {
        federationToken = [(OSSStsTokenCredentialProvider *)credentialProvider getToken];
    }
    
    [self addDateHeaderIfNeeded:requestMessage];
    if ([credentialProvider isKindOfClass:[OSSCustomSignerCredentialProvider class]]) {
        [self resolveAdditionalSignedHeaders:requestMessage
                                 headerNames:requestMessage.additionalHeaderNames];
        [self addSignedHeaderIfNeeded:requestMessage];
        [self addOSSContentSha256Header:requestMessage];
//        NSString *stringToSign = [self buildStringToSign:requestMessage];
        
    } else {
        if (federationToken == nil) {
            return [OSSTask taskWithError:[NSError errorWithDomain:OSSClientErrorDomain
                                                              code:OSSClientErrorCodeSignFailed
                                                          userInfo:@{OSSErrorMessageTOKEN: @"Can't get a federation token"}]];
        }
        [self resolveAdditionalSignedHeaders:requestMessage
                                 headerNames:requestMessage.additionalHeaderNames];
        [self addSignedHeaderIfNeeded:requestMessage];
        [self addSecurityTokenHeaderIfNeeded:requestMessage
                             federationToken:federationToken];
        [self addOSSContentSha256Header:requestMessage];
        [self addAuthorizationHeader:requestMessage
                     federationToken:federationToken];
    }
    
    return [OSSTask taskWithResult:nil];
}

- (OSSTask *)presign:(OSSAllRequestNeededMessage *)requestMessage {
    id<OSSCredentialProvider> credentialProvider = self.signerParams.credentialProvider;
    OSSFederationToken *federationToken;
    NSError * error = nil;
    if ([credentialProvider isKindOfClass:[OSSFederationCredentialProvider class]]) {
        federationToken = [(OSSFederationCredentialProvider *)credentialProvider getToken:&error];
        if (error) {
            return [OSSTask taskWithError:error];
        }
    } else if ([credentialProvider isKindOfClass:[OSSStsTokenCredentialProvider class]]) {
        federationToken = [(OSSStsTokenCredentialProvider *)credentialProvider getToken];
    }
    
    NSMutableDictionary *params = requestMessage.params.mutableCopy;
    // date
    [self initRequestDateTime];
    NSString *expires = [NSString stringWithFormat:@"%@", @(self.signerParams.expiration)];
    params[@"x-oss-date"] = [self getDateTime];
    params[@"x-oss-expires"] = expires;
    
    // signed header
    [self resolveAdditionalSignedHeaders:requestMessage
                             headerNames:self.signerParams.additionalHeaderNames];
    [self addSignedHeaderIfNeeded:requestMessage];
    if ([self hasAdditionalSignedHeaders]) {
        params[@"x-oss-additional-headers"] = [self.additionalSignedHeaders componentsJoinedByString:@";"];
    }
    
    params[@"x-oss-signature-version"] = @"OSS4-HMAC-SHA256";
    if ([credentialProvider isKindOfClass:[OSSCustomSignerCredentialProvider class]]) {
        
        
    } else {
        if ([federationToken useSecurityToken]) {
            params[OSSHttpHeaderSecurityToken] = federationToken.tToken;
        }
        NSString *credential = [NSString stringWithFormat:@"%@%@%@", federationToken.tAccessKey, SeparatorBackslash, [self buildScope]];
        params[@"x-oss-credential"] = credential;
        NSString *stringToSign = [self buildStringToSignWithRequest:requestMessage];
        NSData *signingKey = [self buildSigningKey:federationToken];
        NSString *signature = [self buildSignature:signingKey stringToSign:stringToSign];
        params[@"x-oss-signature"] = signature;
    }
    requestMessage.params = params;
    
    return [OSSTask taskWithResult:nil];
}

@end


