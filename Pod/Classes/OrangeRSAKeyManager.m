//
//  OrangeRSAKeyManager.m
//  OrangeTooth
//
//  Created by Jesper on 07/03/15.
//  Copyright (c) 2015 Orange Groove. All rights reserved.
//

#import "OrangeRSAKeyManager.h"

@interface OrangeRSAKeyManager ()

@property (copy, nonatomic)   NSData    *publicTag;
@property (copy, nonatomic)   NSData    *privateTag;
@property (copy, nonatomic)   NSData    *remoteTagPrefix;
@property (assign, nonatomic) SecKeyRef  localPublicKey;
@property (assign, nonatomic) SecKeyRef  localPrivateKey;

@end
@implementation OrangeRSAKeyManager

#pragma mark - Lifecycle

- (instancetype)initWithNamespace:(NSString *)namespace
{
    self = [super init];
    
    if (self)
    {
        _namespace = [namespace copy];
    }
    
    return self;
}

#pragma mark - Public

- (BOOL)generateLocalKeyPairWithKeySize:(size_t)keySize
{
    if (self.localPublicKey)
    {
        [self deleteKeyForTag:self.publicTag];
    }
    
    if (self.localPrivateKey)
    {
        [self deleteKeyForTag:self.privateTag];
    }
    
    OSStatus status      = noErr;
    self.localPublicKey  = nil;
    self.localPrivateKey = nil;
    
    NSMutableDictionary *privateKeyAttr = [NSMutableDictionary dictionary];
    NSMutableDictionary *publicKeyAttr  = [NSMutableDictionary dictionary];
    NSMutableDictionary *keyPairAttr    = [NSMutableDictionary dictionary];
    
    privateKeyAttr[(__bridge id)kSecAttrIsPermanent]    = @YES;
    privateKeyAttr[(__bridge id)kSecAttrApplicationTag] = self.privateTag;
    
    publicKeyAttr[(__bridge id)kSecAttrIsPermanent]    = @YES;
    publicKeyAttr[(__bridge id)kSecAttrApplicationTag] = self.publicTag;
    
    keyPairAttr[(__bridge id)kSecAttrKeyType]       = (__bridge id)kSecAttrKeyTypeRSA;
    keyPairAttr[(__bridge id)kSecAttrKeySizeInBits] = @(keySize);
    keyPairAttr[(__bridge id)kSecPrivateKeyAttrs]   = privateKeyAttr;
    keyPairAttr[(__bridge id)kSecPublicKeyAttrs]    = publicKeyAttr;
    
    // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
    status = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &_localPublicKey, &_localPrivateKey);
    
    return status == noErr && _localPublicKey && _localPrivateKey;
}

- (BOOL)deleteLocalKeyPair
{
    self.localPublicKey  = nil;
    self.localPrivateKey = nil;
    
    return [self deleteKeyForTag:self.publicTag] && [self deleteKeyForTag:self.privateTag];
}

- (NSData *)localPublicKeyData
{
    return [self retrieveKeyDataWithTag:self.publicTag];
}

- (SecKeyRef)remotePublicKeyForIdentifier:(NSString *)identifier
{
    NSData *tag = [self tagForRemotePublicKeyIdentifier:identifier];
    
    return [self retrieveKeyWithTag:tag];
}

- (BOOL)storeRemotePublicKey:(NSData *)keyData withIdentifier:(NSString *)identifier
{
    NSData *tag                                     = [self tagForRemotePublicKeyIdentifier:identifier];
    OSStatus status                                 = noErr;
    CFTypeRef keyType                               = NULL;
    NSMutableDictionary *attributes                 = [NSMutableDictionary dictionary];
    attributes[(__bridge id)kSecClass]              = (__bridge id)kSecClassKey;
    attributes[(__bridge id)kSecAttrKeyType]        = (__bridge id)kSecAttrKeyTypeRSA;
    attributes[(__bridge id)kSecAttrApplicationTag] = tag;
    attributes[(__bridge id)kSecValueData]          = keyData;
    attributes[(__bridge id)kSecReturnData]         = @YES;
    status                                          = SecItemAdd((__bridge CFDictionaryRef)attributes, (CFTypeRef *)&keyType);
    
    return status == noErr;
}

- (BOOL)deleteRemotePublicKeyWithIdentifier:(NSString *)identifier
{
    return [self deleteKeyForTag:[self tagForRemotePublicKeyIdentifier:identifier]];
}

#pragma mark - Private

- (SecKeyRef)retrieveKeyWithTag:(NSData *)tag
{
    SecKeyRef key                              = NULL;
    NSMutableDictionary *query                 = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass]              = (__bridge id)kSecClassKey;
    query[(__bridge id)kSecAttrKeyType]        = (__bridge id)kSecAttrKeyTypeRSA;
    query[(__bridge id)kSecReturnRef]          = @YES;
    query[(__bridge id)kSecAttrApplicationTag] = tag;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&key);
    
    if (status != noErr)
    {
        key = NULL;
    }
    
    return key;
}

- (NSData *)retrieveKeyDataWithTag:(NSData *)tag
{
    CFTypeRef buffer                           = NULL;
    NSMutableDictionary *query                 = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass]              = (__bridge id)kSecClassKey;
    query[(__bridge id)kSecAttrKeyType]        = (__bridge id)kSecAttrKeyTypeRSA;
    query[(__bridge id)kSecReturnData]         = @YES;
    query[(__bridge id)kSecAttrApplicationTag] = tag;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &buffer);
    
    if (status != noErr)
    {
        buffer = NULL;
    }
    
    return CFBridgingRelease(buffer);
}

- (NSData *)tagForRemotePublicKeyIdentifier:(NSString *)identifier
{
    NSMutableData *data = [NSMutableData data];
    
    [data appendData:self.remoteTagPrefix];
    [data appendData:[identifier dataUsingEncoding:NSUTF8StringEncoding]];
    
    return [data copy];
}

- (BOOL)deleteKeyForTag:(NSData *)tag
{
    NSMutableDictionary *query                 = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass]              = (__bridge id)kSecClassKey;
    query[(__bridge id)kSecAttrApplicationTag] = tag;
    query[(__bridge id)kSecAttrKeyType]        = (__bridge id)kSecAttrKeyTypeRSA;
    OSStatus status                            = SecItemDelete((__bridge CFDictionaryRef)query);
    
    return status == noErr;
}

#pragma mark - Accessors

- (SecKeyRef)localPublicKey
{
    if (_localPublicKey) return _localPublicKey;
    
    _localPublicKey = [self retrieveKeyWithTag:self.publicTag];
    
    return _localPublicKey;
}

- (SecKeyRef)localPrivateKey
{
    if (_localPrivateKey) return _localPrivateKey;
    
    _localPrivateKey = [self retrieveKeyWithTag:self.privateTag];
    
    return _localPrivateKey;
}

- (NSData *)privateTag
{
    if (_privateTag) return _privateTag;
    
    _privateTag = [[self.namespace stringByAppendingString:@".localprivatekey"] dataUsingEncoding:NSUTF8StringEncoding];
    
    return _privateTag;
}

- (NSData *)publicTag
{
    if (_publicTag) return _publicTag;
    
    _publicTag = [[self.namespace stringByAppendingString:@".localpublickey"] dataUsingEncoding:NSUTF8StringEncoding];
    
    return _publicTag;
}

- (NSData *)remoteTagPrefix
{
    if (_remoteTagPrefix) return _remoteTagPrefix;
    
    _remoteTagPrefix = [[self.namespace stringByAppendingString:@".remotepublickey."] dataUsingEncoding:NSUTF8StringEncoding];
    
    return _remoteTagPrefix;
}

@end
