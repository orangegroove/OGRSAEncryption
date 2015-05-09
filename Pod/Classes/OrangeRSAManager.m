//
//  OrangeRSAManager.m
//  OrangeTooth
//
//  Created by Jesper on 06/03/15.
//  Copyright (c) 2015 Orange Groove. All rights reserved.
//

#import "OrangeRSAManager.h"

NSString * const kOrangeRSAManagerErrorDomain = @"OrangeRSAManagerErrorDomain";

@implementation OrangeRSAManager

#pragma mark - Lifecycle

- (instancetype)init
{
    self = [super init];
    
    if (self)
    {
        _plainBufferSize  = 1024;
        _cipherBufferSize = 1024;
        _padding          = kSecPaddingNone;
    }
    
    return self;
}

#pragma mark - Public

- (NSData *)encryptData:(NSData *)data withPublicKey:(SecKeyRef)publicKey error:(NSError *__autoreleasing *)error
{
    NSData *output    = nil;
    size_t bufferSize = self.cipherBufferSize;
    uint8_t *buffer   = (uint8_t *)calloc(bufferSize, sizeof(uint8_t));
    OSStatus status   = SecKeyEncrypt(publicKey, self.padding, data.bytes, data.length, buffer, &bufferSize);
    
    if (status == noErr)
    {
        output = [NSData dataWithBytes:buffer length:bufferSize];
    }
    else if (error)
    {
        *error = [NSError errorWithDomain:kOrangeRSAManagerErrorDomain code:status userInfo:nil];
    }
    
    free(buffer);
    
    return output;
}

- (NSData *)decryptData:(NSData *)data withPrivateKey:(SecKeyRef)privateKey error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(SecKeyGetBlockSize(privateKey) >= data.length);
    
    NSData *output    = nil;
    size_t bufferSize = self.plainBufferSize;
    uint8_t *buffer   = (uint8_t *)calloc(bufferSize, sizeof(uint8_t));
    OSStatus status   = SecKeyDecrypt(privateKey, self.padding, data.bytes, data.length, buffer, &bufferSize);
    
    if (status == noErr)
    {
        output = [NSData dataWithBytes:buffer length:bufferSize];
    }
    else if (error)
    {
        *error = [NSError errorWithDomain:kOrangeRSAManagerErrorDomain code:status userInfo:nil];
    }
    
    free(buffer);
    
    return output;
}

- (NSData *)signatureForData:(NSData *)data withPrivateKey:(SecKeyRef)privateKey error:(NSError *__autoreleasing *)error
{
    NSData *output    = nil;
    size_t bufferSize = SecKeyGetBlockSize(privateKey);
    uint8_t *buffer   = (uint8_t *)calloc(bufferSize, sizeof(uint8_t));
    OSStatus status   = SecKeyRawSign(privateKey, self.padding, data.bytes, data.length, buffer, &bufferSize);
    
    if (status == noErr)
    {
        output = [NSData dataWithBytes:buffer length:bufferSize];
    }
    else if (error)
    {
        *error = [NSError errorWithDomain:kOrangeRSAManagerErrorDomain code:status userInfo:nil];
    }
    
    free(buffer);
    
    return output;
}

- (BOOL)verifySignature:(NSData *)signature forData:(NSData *)data withPublicKey:(SecKeyRef)publicKey error:(NSError *__autoreleasing *)error
{
    OSStatus status = SecKeyRawVerify(publicKey, self.padding, data.bytes, data.length, signature.bytes, signature.length);
    
    if (status != noErr && error)
    {
        *error = [NSError errorWithDomain:kOrangeRSAManagerErrorDomain code:status userInfo:nil];
    }
    
    return status == noErr;
}

@end
