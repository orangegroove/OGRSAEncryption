//
//  OrangeRSAManager.h
//  OrangeTooth
//
//  Created by Jesper on 06/03/15.
//  Copyright (c) 2015 Orange Groove. All rights reserved.
//

/**
 Asymmetrically encrypts and decrypts, signs and verifies signatures.
 */

NS_ASSUME_NONNULL_BEGIN

@import Foundation;
@import Security;

extern NSString * const kOrangeRSAManagerErrorDomain;

@interface OrangeRSAManager : NSObject

/**
 Available buffer for decryption. Defaults to 1024.
 */
@property (nonatomic, assign) size_t plainBufferSize;

/**
 Available buffer for encryption. Defaults to 1024.
 */
@property (nonatomic, assign) size_t cipherBufferSize;

/**
 Padding. Defaults to kSecPaddingNone.
 */
@property (nonatomic, assign) SecPadding padding;

/**
 Encrypts data.
 
 @param data      Plain data to encrypt.
 @param publicKey The public key with which to encrypt.
 @param error     Error code matches OSStatus if operation fails.
 
 @return The encrypted data.
 */
- (nullable NSData *)encryptData:(NSData *)data withPublicKey:(SecKeyRef)publicKey error:(NSError * __nullable *)error;

/**
 Decrypts data.
 
 @param data       Cipher data to decrypt.
 @param privateKey The private key with which to decrypt.
 @param error      Error code matches OSStatus if operation fails.
 
 @return The decrypted data.
 */
- (nullable NSData *)decryptData:(NSData *)data withPrivateKey:(SecKeyRef)privateKey error:(NSError * __nullable *)error;

/**
 Signs data.
 
 @param data       The data to sign.
 @param privateKey The private key with which to sign.
 @param error      Error code matches OSStatus if operation fails.
 
 @return The signature.
 */
- (nullable NSData *)signatureForData:(NSData *)data withPrivateKey:(SecKeyRef)privateKey error:(NSError * __nullable *)error;

/**
 Verifies signature.
 
 @param signature The signature to verify.
 @param data      The signed data.
 @param publicKey The public key with which to verify.
 @param error     Error code matches OSStatus if operation fails.
 
 @return Whether signature matches key and data.
 */
- (BOOL)verifySignature:(NSData *)signature forData:(NSData *)data withPublicKey:(SecKeyRef)publicKey error:(NSError * __nullable *)error;

@end

NS_ASSUME_NONNULL_END
