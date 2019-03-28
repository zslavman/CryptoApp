//
//  RSAManager.swift
//  Teamly
//
//  Created by User on 14/02/19.
//

import Foundation
import CommonCrypto


enum DescriptionIdentifier: String {
	case publicDescr  = "----- PUBLIC KEY ------"
	case privateDescr = "----- PRIVATE KEY -----"
}
enum KeyTag: String {
	case accountKey = "accountPublicKey"// for crypt/decrypt
	case deviceKey = "devicePublicKey" 	// for register another device
}
enum AccessIdentif {
	case publicA
	case privateA
}

struct KeyPairRSA {
	let privateSecKey: SecKey
	let publicSecKey: SecKey
	var privateDataKey: Data {
		return Cipher.convertSecKeyToData(secKey: privateSecKey)!
	}
	var publicDataKey: Data {
		return Cipher.convertSecKeyToData(secKey: publicSecKey)!
	}
}


class Cipher {
	
	private static var privSecKey: SecKey? {
		return getSecKeyFromKeychain(withTag: .accountKey, access: .privateA)
	}
	private static let cryptoSecKeyAlgorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA1 // works lower then 224 bytes only
	public static let suiteName = "group.com.teamyIntermodules"
	private static let defaults = UserDefaults(suiteName: suiteName)!

	
	//MARK:- RSA Key-pair Generation methods
	
	/*
	* Most proper native key-pair creation
	*/
	@discardableResult
	public static func generatePair_RSA(withTag: KeyTag) -> KeyPairRSA? {
		//deleteSecureKeyPair(withTag: withTag)
		
		let publicKeyAttr: [NSObject: Any] = [
			//kSecAttrIsPermanent	: true, // store in keychain
			//kSecAttrApplicationTag: withTag.rawValue.data(using: String.Encoding.utf8)!,
			kSecClass				: kSecClassKey,
			kSecReturnData			: true
		]
		let privateKeyAttr: [NSObject: Any] = [
			//kSecAttrIsPermanent	: true,
			//kSecAttrApplicationTag: withTag.rawValue.data(using: String.Encoding.utf8)!,
			kSecClass				: kSecClassKey,
			kSecReturnData			: true
		]
		let keyPairAttr: [NSObject: Any] = [
			kSecAttrKeyType 		: kSecAttrKeyTypeRSA,
			kSecAttrKeySizeInBits 	: 2048,
			kSecPublicKeyAttrs		: publicKeyAttr,
			kSecPrivateKeyAttrs		: privateKeyAttr,
			kSecAttrCanDecrypt		: true
		]
		var pubSecKey: SecKey?
		var privSecKey: SecKey?
		// generate keys & save it into keychain
		let statusGenerate = SecKeyGeneratePair(keyPairAttr as CFDictionary, &pubSecKey, &privSecKey)
		guard statusGenerate == errSecSuccess else {
			print("Error while generate pair: \(statusGenerate)")
			return nil
		}
		guard let pubKey = pubSecKey, let privKey = privSecKey else { return nil }
		let pair = KeyPairRSA(privateSecKey: privKey, publicSecKey: pubKey)
		return pair
	}
	
	
	/// native random key-pair creation with save into persistent store (return: public key)
	@discardableResult
	public static func generatePair_RSA2(withTag: KeyTag) -> Data? {
		deleteSecureKeyPair(withTag: withTag)
		
		let attributes: [NSObject: Any] = [
			kSecAttrKeyType			: kSecAttrKeyTypeRSA,
			kSecAttrKeySizeInBits	: 2048,
			kSecPrivateKeyAttrs 	: [
				kSecAttrIsPermanent 	: true,
				kSecAttrApplicationTag	: withTag.rawValue.data(using: String.Encoding.utf8)!
			]
		]
		var error: Unmanaged<CFError>?
		if let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) {
			// Gets the public key associated with the given private key.
			let publicKey = SecKeyCopyPublicKey(privateKey)!
			// save to keychain
			addSecKeyToKeychain(secKey: privateKey, access: .privateA, tagName: withTag)
			addSecKeyToKeychain(secKey: publicKey, access: .publicA, tagName: withTag)
			// printKeys()
			print("Keys successfully generated!")
			return getKeyData(withTag: .accountKey, access: .publicA)
		}
		else {
			print(error!.takeRetainedValue() as Error)
			return nil
		}
	}
	
	/*----------------------------------------------------------------------*/
	
	
	//MARK:- RSA-Encrypt/Decrypt
	
	// use this method
	public static func encrypt_RSA(data: Data, rsaPublicKeyRef: SecKey) -> Data? {
		guard let encrData = SecKeyCreateEncryptedData(rsaPublicKeyRef,
													   cryptoSecKeyAlgorithm,
													   data as CFData,
													   nil) else {
														print("Error encrypting")
														return nil
		}
		return encrData as Data
	}
	
	
	public static func encrypt_RSA(str: String, rsaPublicKeyRef: SecKey) -> Data? {
		guard let messageData = str.data(using: String.Encoding.utf8) else {
			print("Bad text to encrypt")
			return nil
		}
		return encrypt_RSA(data: messageData, rsaPublicKeyRef: rsaPublicKeyRef)
	}
	
	/// convert DataKey into SecKey (for local use only)
	public static func encrypt_RSA(data: Data, rsaPublicKeyData: Data) -> Data? {
		guard let pubSecKey = convertPublicKeyData(pubKey: rsaPublicKeyData) else {
			return nil
		}
		return encrypt_RSA(data: data, rsaPublicKeyRef: pubSecKey)
	}
	
	
	public static func decrypt_RSA(data: Data) -> Data? {
		guard let privSecKey = privSecKey else { return nil }
		guard let decryptData = SecKeyCreateDecryptedData(privSecKey,
														  cryptoSecKeyAlgorithm,
														  data as CFData,
														  nil) else {
															print("Error decrypting. Bad key for decryption!")
															return nil
		}
		print("Successfully decrypted!")
		return decryptData as Data
	}
	
	
	public static func decrypt_RSA(str: String) -> Data? {
		guard let messageData = Data(base64Encoded: str) else {
			print("Bad message to decrypt")
			return nil
		}
		return decrypt_RSA(data: messageData)
	}
	
	/*----------------------------------------------------------------------*/
	
	
	//MARK:- other (for RSA)
	
	public static func deleteCommonSecKeys() {
		let secItemClasses = [
			kSecClassGenericPassword,
			kSecClassInternetPassword,
			kSecClassCertificate,
			kSecClassKey,
			kSecClassIdentity
		]
		for secItemClass in secItemClasses {
			let dictionary = [kSecClass as String:secItemClass]
			let status = SecItemDelete(dictionary as CFDictionary)
			if status == errSecSuccess {
				print("Successfully deletre SecKey for \(secItemClass)")
			}
		}
	}
	
	
	public static func getSecKeyFromKeychain(withTag: KeyTag, access: AccessIdentif, printExists: Bool = true) -> SecKey? {
		let parameters:[NSObject : Any]  = [
			kSecClass				: kSecClassKey,
			kSecAttrKeyClass		: (access == .publicA) ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
			kSecAttrKeyType			: (withTag == .accountKey) ? kSecAttrKeyTypeRSA : kSecAttrKeyTypeEC,
			kSecAttrApplicationTag	: withTag.rawValue,
			kSecReturnRef			: true
		]
		var ref: AnyObject?
		let status = SecItemCopyMatching(parameters as CFDictionary, &ref)
		if status == errSecSuccess {
			return ref as! SecKey?
		}
		if printExists {
			print("Error: key '\(access)' not found!")
		}
		return nil
	}
	
	
	/// convert DataKey -> SecKey
	public static func convertPublicKeyData(pubKey: Data, tagName: String = "777") -> SecKey? {
		guard let pubkeyData = stripPublicKeyHeader(pubKey) else {
			return nil
		}
		let queryFilter: [NSObject : Any] = [
			kSecClass             	: kSecClassKey,
			kSecAttrKeyType       	: kSecAttrKeyTypeRSA,
			kSecAttrApplicationTag	: tagName,
			kSecAttrKeyClass        : kSecAttrKeyClassPublic,
			kSecReturnPersistentRef	: false
		]
		if let secKeyPublic = SecKeyCreateWithData(pubkeyData as CFData, queryFilter as CFDictionary, nil) {
			return secKeyPublic
		}
		print("Error can't create SecKey WithData!")
		return nil
	}
	
	
	
	/// convert SecKey -> DataKey
	public static func convertSecKeyToData(secKey: SecKey) -> Data? {
		var error: Unmanaged<CFError>?
		if let dataKey = SecKeyCopyExternalRepresentation(secKey, &error) {
			return dataKey as Data
		}
		print(error!.takeRetainedValue() as Error)
		return nil
	}
	
	
	
	/*
	* Verifies that the supplied key is in fact a X509 public key, and strips its header.
	*/
	/// Returns the RSA public key with stripped header
	/// - Parameter pubkey: X509 public key
	private static func stripPublicKeyHeader(_ pubkey: Data) -> Data? {
		if pubkey.count == 0 {
			return nil
		}
		var keyAsArray = [UInt8](repeating: 0, count: pubkey.count / MemoryLayout<UInt8>.size)
		(pubkey as NSData).getBytes(&keyAsArray, length: pubkey.count)
		
		var idx = 0
		if (keyAsArray[idx] != 0x30) {
			print("Error: provided key doesn't have a valid ASN.1 structure (first byte should be 0x30)")
			return nil
		}
		idx += 1
		
		if (keyAsArray[idx] > 0x80) {
			idx += Int(keyAsArray[idx]) - 0x80 + 1
		}
		else {
			idx += 1
		}
		/*
		* If current byte is 0x02, it means the key doesn't have a X509 header (it contains only modulo & public exponent).
		* In this case, we can just return the provided DER data as is
		*/
		if (Int(keyAsArray[idx]) == 0x02) {
			return pubkey
		}
		
		let seqiod = [UInt8](arrayLiteral: 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00)
		for i in idx..<idx+seqiod.count {
			if (keyAsArray[i] != seqiod[i - idx]) {
				print("Error: provided key doesn't have a valid X509 header.")
				return nil
			}
		}
		idx += seqiod.count
		if (keyAsArray[idx] != 0x03) {
			print("Error: invalid byte at index \(idx) (\(keyAsArray[idx])) for public key header.")
			return nil
		}
		idx += 1
		if (keyAsArray[idx] > 0x80) {
			idx += Int(keyAsArray[idx]) - 0x80 + 1;
		}
		else {
			idx += 1
		}
		if (keyAsArray[idx] != 0x00) {
			print("Error: invalid byte at index \(idx) (\(keyAsArray[idx])) for public key header.")
			return nil
		}
		idx += 1
		return pubkey.subdata(in: idx..<keyAsArray.count)
		//return pubkey.subdata(in: NSMakeRange(idx, keyAsArray.count - idx).toRange()!)
	}
	
	
	
	public static func getKeyData(withTag: KeyTag, access: AccessIdentif) -> Data? {
		let parameters:[NSObject : Any]  = [
			kSecClass				: kSecClassKey,
			kSecAttrKeyClass		: (access == .publicA) ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
			kSecAttrKeyType			: kSecAttrKeyTypeRSA,
			kSecAttrApplicationTag	: withTag.rawValue.data(using: String.Encoding.utf8)!,
			kSecReturnData			: true
		]
		var data: AnyObject?
		let status = SecItemCopyMatching(parameters as CFDictionary, &data)
		if status == errSecSuccess {
			return data as? Data
		}
		else {
			print("Error: key '\(withTag.rawValue)' not found!")
			return nil
		}
	}
	
	
	public static func isKeyPairExists(withTag: KeyTag) -> Bool {
		return Cipher.getSecKeyFromKeychain(withTag: withTag, access: .privateA, printExists: false) != nil
	}
	
	
	public static func deleteSecureKeyPair(withTag: KeyTag) {
		let deleteQuery: [NSObject : Any] = [
			kSecClass				: kSecClassKey,
			kSecAttrKeyType 		: kSecAttrKeyTypeRSA,
		]
		let status = SecItemDelete(deleteQuery as CFDictionary)
		if status == errSecSuccess {
			print("Keys with tag \(withTag.rawValue) successfully deleted!")
		}
		//		else {
		//			print("Nothing to delete!")
		//		}
	}
	
	
	// Add RSA-key into keychain storage
	@discardableResult
	private static func addSecKeyToKeychain(secKey: SecKey, access: AccessIdentif, tagName: KeyTag) -> SecKey? {
		let queryFilter: [NSObject : Any] = [
			kSecClass            	: kSecClassKey,
			kSecAttrKeyType      	: kSecAttrKeyTypeRSA,
			kSecAttrApplicationTag 	: tagName.rawValue.data(using: String.Encoding.utf8)!,
			//kSecAttrAccessible    : kSecAttrAccessibleWhenUnlocked,
			kSecValueRef         	: secKey,
			kSecAttrKeyClass      	: access == .privateA ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic,
			kSecReturnPersistentRef	: true
		]
		let result = SecItemAdd(queryFilter as CFDictionary, nil)
		if (result != noErr && result != errSecDuplicateItem) {
			print("Error, can't add key to keychain, status \(result)")
			return nil
		}
		return Cipher.getSecKeyFromKeychain(withTag: tagName, access: .privateA)
	}
	
	
	
	
	/*
	* Verifies that the supplied key is in fact a PEM RSA private key, and strips its header.
	* If the supplied key is PKCS#8, its ASN.1 header should be stripped. Otherwise (PKCS#1), the whole key data is left intact.
	*/
	/// Returns the private RSA key with stripped header
	///
	/// - Parameter privkey: RSA private key (PKCS#1 or PKCS#8)
	/// - Throws: Error if the input key is not a valid RSA PKCS#8 private key
	private static func stripPrivateKeyHeader(_ privkey: Data) -> Data? {
		if privkey.count == 0 {
			return nil
		}
		var keyAsArray = [UInt8](repeating: 0, count: privkey.count / MemoryLayout<UInt8>.size)
		(privkey as NSData).getBytes(&keyAsArray, length: privkey.count)
		
		//PKCS#8: magic byte at offset 22, check if it's actually ASN.1
		var idx = 22
		if keyAsArray[idx] != 0x04 {
			return privkey
		}
		idx += 1
		
		//now we need to find out how long the key is, so we can extract the correct hunk
		//of bytes from the buffer.
		var len = Int(keyAsArray[idx])
		idx += 1
		let det = len & 0x80 //check if the high bit set
		if (det == 0) {
			//no? then the length of the key is a number that fits in one byte, (< 128)
			len = len & 0x7f
		}
		else {
			//otherwise, the length of the key is a number that doesn't fit in one byte (> 127)
			var byteCount = Int(len & 0x7f)
			if (byteCount + idx > privkey.count) {
				return nil
			}
			//so we need to snip off byteCount bytes from the front, and reverse their order
			var accum: UInt = 0
			var idx2 = idx
			idx += byteCount
			while (byteCount > 0) {
				//after each byte, we shove it over, accumulating the value into accum
				accum = (accum << 8) + UInt(keyAsArray[idx2])
				idx2 += 1
				byteCount -= 1
			}
			// now we have read all the bytes of the key length, and converted them to a number,
			// which is the number of bytes in the actual key.  we use this below to extract the
			// key bytes and operate on them
			len = Int(accum)
		}
		return privkey.subdata(in: idx..<idx + len)
	}
	
	
	public static func smartPrint(string: String, identifier: DescriptionIdentifier) {
		let prefix = identifier.rawValue
		let suffix: String = "\n"
		print("\(prefix)\n\(string)\(suffix)")
	}
	
	
	private static func printKeys() {
		let pubKey = getKeyData(withTag: .accountKey, access: .publicA)
		let privKey = getKeyData(withTag: .accountKey, access: .privateA)
		guard let pubData = pubKey, let privData = privKey else { return }
		print(pubData)
		smartPrint(string: pubData.base64EncodedString(), identifier: .publicDescr)
		print(privData)
		smartPrint(string: privData.base64EncodedString(), identifier: .privateDescr)
	}
	
	/*----------------------------------------------------------------------*/
	
	
	//MARK:- AES-CBC
	
	public static func encrypt_AES(data: Data, keyData: Data) -> Data? {
		return cryptAES_CBC(data: data, keyData: keyData, kCCMethod: kCCEncrypt)
	}
	
	
	public static func decrypt_AES(data: Data, keyData: Data) -> Data? {
		return cryptAES_CBC(data: data, keyData: keyData, kCCMethod: kCCDecrypt)
	}
	
	
	/// Encrypt/Decrypt message with AES-key
	///
	/// - Parameters:
	///   - data: data witch will be encrypted/decrypted
	///   - keyData: binary AES-key
	///   - kCCMethod: kCCEncrypt - encrypt, kCCDecrypt - decrypt
	private static func cryptAES_CBC(data: Data, keyData: Data, kCCMethod: Int) -> Data? {
		guard keyData.count == kCCKeySizeAES128 else { // kCCKeySizeAES128 = 16 (bytes)
			print("Invalid key length: ", keyData.count)
			return nil
		}
		let ivData = Data(bytes: [UInt8](repeating: 0, count: 16)) // salt
		let dataLength = data.count
		let cryptLength = size_t(dataLength + kCCBlockSizeAES128)
		var cryptData = Data(count: cryptLength)
		
		let keyLength = size_t(kCCKeySizeAES128)
		let options = CCOptions(kCCOptionPKCS7Padding) // 0
		var numBytesEncrypted: size_t = 0
		
		let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
			data.withUnsafeBytes {dataBytes in
				ivData.withUnsafeBytes {ivBytes in
					keyData.withUnsafeBytes {keyBytes in
						CCCrypt(CCOperation(kCCMethod),
								CCAlgorithm(kCCAlgorithmAES),
								options,
								keyBytes, keyLength,
								ivBytes,
								dataBytes, dataLength,
								cryptBytes, cryptLength,
								&numBytesEncrypted)
					}
				}
			}
		}
		if UInt32(cryptStatus) == UInt32(kCCSuccess) {
			cryptData.removeSubrange(numBytesEncrypted..<cryptData.count)
			//--------------
			if let crypt = String(data: cryptData, encoding: .utf8){
				let prefix = (kCCMethod == kCCEncrypt) ? "encrypted" : "decrypted"
				print("\(prefix)Data = \(crypt)")
			}
			//--------------
			generateKeyAES_CBC()
			return cryptData
		}
		else {
			print("AES crypt error with status: \(cryptStatus)")
			return nil
		}
	}
	
	@discardableResult
	public static func generateKeyAES_CBC() -> Data {
		var bytes = [UInt8](repeating: 0, count: kCCKeySizeAES128) // 16 elements
		let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
		if status == errSecSuccess {
			let data = Data(bytes: bytes)
			return data
		}
		else {
			fatalError("Error while generating AES-key, status: \(status)")
		}
	}
	
	/*----------------------------------------------------------------------*/
	
}









