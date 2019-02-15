//
//  RSAManager.swift
//  Teamly
//
//  Created by User on 14/02/19.
//  https://lapo.it/asn1js/#
// https://github.com/cossacklabs/themis

import Foundation


enum DescriptionIdentifier: String {
	case publicDescr = "----- RSA PUBLIC KEY -----"
	case privateDescr = "----- RSA PRIVATE KEY -----"
}

class RSAManager {
	
	public static let accountPublicKey = "accountPublicKey"
	public static let devicePublicKey = "devicePublicKey"
	
	private static var randKey: String {
		let generated = UUID().uuidString
		return generated
	}
	
	
	//MARK:- Key-pair Generation methods
	
	// most proper native key-pair creation with save into persistent store
	@discardableResult
	public static func generatePairRSA(withTag: String) -> (Data, Data)? {
		let publicKeyAttr: [NSObject: Any] = [
			kSecAttrIsPermanent		: true, // store in keychain
			kSecAttrApplicationTag	: withTag.data(using: String.Encoding.utf8)!,
			kSecClass				: kSecClassKey,		// ?
			kSecReturnData			: true
		]
		let privateKeyAttr: [NSObject: Any] = [
			kSecAttrIsPermanent		: true,
			kSecAttrApplicationTag	: withTag.data(using: String.Encoding.utf8)!,
			kSecClass				: kSecClassKey,
			kSecReturnData			: true
		]
		let keyPairAttr: [NSObject: Any] = [
			kSecAttrKeyType 		: kSecAttrKeyTypeRSA,
			kSecAttrKeySizeInBits 	: 2048 as NSObject,
			kSecPublicKeyAttrs		: publicKeyAttr,
			kSecPrivateKeyAttrs		: privateKeyAttr,
			kSecAttrCanDecrypt		: true
		]
		var pubSecKey: SecKey?
		var privSecKey: SecKey?
		let statusGenerate = SecKeyGeneratePair(keyPairAttr as CFDictionary, &pubSecKey, &privSecKey)
		guard statusGenerate == errSecSuccess else {
			print("Error: \(statusGenerate)")
			return nil
		}
		// convert SecKey -> Data
		var pubDataKey: AnyObject?
		var privDataKey: AnyObject?
		let statusPublicKey = SecItemCopyMatching(publicKeyAttr as CFDictionary, &pubDataKey)
		let statusPrivateKey = SecItemCopyMatching(privateKeyAttr as CFDictionary, &privDataKey)
		
		guard let publicKey = pubDataKey, let  privateKey = privDataKey else { return nil }
		guard statusPublicKey == errSecSuccess, statusPrivateKey == errSecSuccess else {
			print("Error in: \(statusPublicKey) or \(statusPrivateKey)")
			return nil
		}
		let some = (publicKey as! Data).base64EncodedString()
		RSAManager.smartPrint(string: some, identifier: .publicDescr)
		
		return (publicKey as! Data, privateKey as! Data)
	}
	
	
	// native random key-pair creation with save into persistent store
	public static func generateRandomPairRSA(withTag: String) {
		let attributes: [NSObject: Any] = [
			kSecAttrKeyType			: kSecAttrKeyTypeRSA,
			kSecAttrKeySizeInBits	: 2048,
			kSecPrivateKeyAttrs 	: [
				kSecAttrIsPermanent 	: true,
				kSecAttrApplicationTag	: withTag.data(using: .utf8)!
			]
		]
		var error: Unmanaged<CFError>?
		if let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) {
			// Gets the public key associated with the given private key.
			let publicKey = SecKeyCopyPublicKey(privateKey)!
			var error: Unmanaged<CFError>?
			let data = SecKeyCopyExternalRepresentation(publicKey, &error)! as Data
			RSAManager.smartPrint(string: data.base64EncodedString(), identifier: .publicDescr)
		}
		else {
			print(error!.takeRetainedValue() as Error)
		}
	}
	
	
	
	//MARK:- other...
	
	public static func getPublicKeyData(withTag: String) -> Data? {
		let parameters:[String : Any]  = [
			String(kSecClass)				: kSecClassKey,
			String(kSecAttrKeyType)			: kSecAttrKeyTypeRSA,
			String(kSecAttrApplicationTag)	: withTag,
			String(kSecAttrKeyClass)		: kSecAttrKeyClassPublic,
			String(kSecReturnData)			: true
		]
		var data: AnyObject?
		let status = SecItemCopyMatching(parameters as CFDictionary, &data)
		if status == errSecSuccess {
			return data as? Data
		}
		else { return nil }
	}
	
	public static func getPublicSecKey(withTag: String) -> SecKey? {
		let parameters:[String : Any]  = [
			String(kSecClass)				: kSecClassKey,
			String(kSecAttrKeyType)			: kSecAttrKeyTypeRSA,
			String(kSecAttrApplicationTag)	: withTag,
			String(kSecAttrKeyClass)		: kSecAttrKeyClassPublic,
			String(kSecReturnRef)			: true
		]
		var data: AnyObject?
		let status = SecItemCopyMatching(parameters as CFDictionary, &data)
		if status == errSecSuccess {
			return data! as! SecKey
		}
		else { return nil }
	}
	
	
	public static func getPrivateKeyData(withTag: String) -> Data? {
		let parameters:[String : Any] = [
			String(kSecClass)				: kSecClassKey,
			String(kSecAttrKeyClass) 		: kSecAttrKeyClassPrivate,
			String(kSecAttrApplicationTag)	: withTag,
			String(kSecReturnData)			: true
		]
		var data: AnyObject?
		let status = SecItemCopyMatching(parameters as CFDictionary, &data)
		if status == errSecSuccess {
			return data as! Data?
		}
		else { return nil }
	}
	
	
	public static func isKeyPairExists(withTag: String) -> Bool {
		return RSAManager.getPrivateKeyData(withTag: withTag) != nil
	}
	
	
	public static func deleteSecureKeyPair(withTag: String, _ completion: ((_ success: Bool) -> Void)?) {
		// private query dictionary
		let deleteQuery: [String : Any] = [
			kSecClass as String				: kSecClassKey,
			kSecAttrApplicationTag as String: withTag,
			]
		DispatchQueue.global(qos: .default).async {
			let status = SecItemDelete(deleteQuery as CFDictionary) // delete private key
			DispatchQueue.main.async {
				completion?(status == errSecSuccess)
			}
		}
	}
	
	
	public static func smartPrint(string: String, identifier: DescriptionIdentifier) {
		let prefix = identifier.rawValue
		let suffix: String = "\n"
		print("\(prefix)\n\(string)\(suffix)")
	}
	
}



