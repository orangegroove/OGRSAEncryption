//
//  OrangeRSAKeyManager.h
//  OrangeTooth
//
//  Created by Jesper on 07/03/15.
//  Copyright (c) 2015 Orange Groove. All rights reserved.
//

/**
 Manages a keypair and an optional number of foreign public keys.
 */

NS_ASSUME_NONNULL_BEGIN

@import Foundation;
@import Security;

@interface OrangeRSAKeyManager : NSObject

/**
 The namespace under which to store keys in the keychain.
 */
@property (nonatomic, copy, readonly) NSString  *namespace;

/**
 The keypair public key, if available.
 */
@property (nonatomic, assign, nullable, readonly) SecKeyRef localPublicKey;

/**
 The keypair private key, if available.
 */
@property (nonatomic, assign, nullable, readonly) SecKeyRef localPrivateKey;

/**
 The designated initializer.
 
 @param namespace Unique prefix for use in the keychain.
 
 @return An initialized object.
 */
- (instancetype)initWithNamespace:(NSString *)namespace NS_DESIGNATED_INITIALIZER;

/**
 Generates keypair.
 
 @param keySize Must be a valid value for RSA: 512, 1024, 2048, etc.
 
 @return Whether keys were generated.
 @note Existing keypair will be overwritten.
 */
- (BOOL)generateLocalKeyPairWithKeySize:(size_t)keySize;

/**
 Deletes keypair.
 
 @return Whether both keys were successfully deleted.
 */
- (BOOL)deleteLocalKeyPair;

/**
 Converts the keypair public key for export.
 
 @return Public key as NSData.
 */
- (nullable NSData *)localPublicKeyData;

/**
 Retrieves a foreign public key.
 
 @param identifier Namespace-unique identifier for key.
 
 @return Key or nil.
 */
- (SecKeyRef)remotePublicKeyForIdentifier:(NSString *)identifier;

/**
 Stores a foreign public key.
 
 @param keyData    Key as NSData.
 @param identifier Namespace-unique identifier for key.
 
 @return Whether key was stored successfully.
 */
- (BOOL)storeRemotePublicKey:(NSData *)keyData withIdentifier:(NSString *)identifier;

/**
 Deletes stored foreign public key.
 
 @param identifier Namespace-unique identifier for key.
 
 @return Whether key was deleted successfully.
 */
- (BOOL)deleteRemotePublicKeyWithIdentifier:(NSString *)identifier;

@end

NS_ASSUME_NONNULL_END
