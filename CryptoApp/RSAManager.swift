//
//  RSAManager.swift
//  Teamly
//
//  Created by User on 14/02/19.
//  lapo.it/asn1js/#
//  github.com/cossacklabs/themis
//  linkedin.com/pulse/ios-10-how-use-secure-enclave-touch-id-protect-your-keys-satyam-tyagi/

import Foundation
import CommonCrypto


enum DescriptionIdentifier: String {
	case publicDescr = "----- PUBLIC KEY -----"
	case privateDescr = "----- PRIVATE KEY -----"
}
enum KeyTag: String {
	case accountKey = "accountPublicKey"// for crypt/decrypt
	case deviceKey = "devicePublicKey" 	// for signing/verify
}
enum AccessIdentif {
	case publicA
	case privateA
}
enum AESError: Error {
	case KeyError(String, Int)
	case IVError(String, Int)
	case CryptorError(String, Int)
}


class RSAManager {
	
	private static var privSecKey: SecKey? {
		return getSecKeyFromKeychain(withTag: .accountKey, access: .privateA)
	}
	/*
	* RSA encryption or decryption, data is padded using OAEP padding scheme internally using SHA256. Input data must be at most
	* "key block size - 66" bytes long and returned block has always the same size as block size, as returned
	* by SecKeyGetBlockSize().  Use kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM to be able to encrypt and decrypt arbitrary long data
	*/
	// private static let secKeyAlgorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA1 				// works lower 224 bytes only
	// private static let secKeyAlgorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA1AESGCM 		// GOOG for all sizes
	private static let cryptoSecKeyAlgorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA1			// GOOD for all sizes
	private static let signSecKeyAlgorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
	private static let keySizeRSA = 2048
	private static let keySizeEC = 256
	
	//MARK:- Key-pair Generation methods
	
	// most proper native key-pair creation with save into persistent store
	@discardableResult
	public static func generatePairKeys(withTag: KeyTag) -> Data? {
		deleteSecureKeyPair(withTag: withTag, nil)
		
		let publicKeyAttr: [NSObject: Any] = [
			kSecAttrIsPermanent		: true, // store in keychain
			kSecAttrApplicationTag	: withTag.rawValue.data(using: String.Encoding.utf8)!,
			kSecClass				: kSecClassKey,
			kSecReturnData			: true
		]
		let privateKeyAttr: [NSObject: Any] = [
			kSecAttrIsPermanent		: true,
			kSecAttrApplicationTag	: withTag.rawValue.data(using: String.Encoding.utf8)!,
			kSecClass				: kSecClassKey,
			kSecReturnData			: true
		]
		let keyPairAttr: [NSObject: Any] = [
			kSecAttrKeyType 		: kSecAttrKeyTypeRSA,
			kSecAttrKeySizeInBits 	: keySizeRSA,
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
		// convert SecKey -> Data
		guard let pubKey = pubSecKey, let _ = privSecKey else { return nil }
		var error: Unmanaged<CFError>?
		let pubData = SecKeyCopyExternalRepresentation(pubKey, &error)! as Data
		//printKeys()
		print("RSA keys successfully generated!")
		return (pubData)
	}
	
	
	// native random key-pair creation with save into persistent store
	@discardableResult
	public static func generatePairRSA(withTag: KeyTag) -> Data? {
		deleteSecureKeyPair(withTag: withTag, nil)
		
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
	
	
	//MARK:- Encrypt
	
	public static func encryptWithSecKey(data: Data, rsaPublicKeyRef: SecKey) -> Data? {
		guard let encrData = SecKeyCreateEncryptedData(rsaPublicKeyRef,
														  cryptoSecKeyAlgorithm,
														  data as CFData,
														  nil) else {
			print("Error encrypting")
			return nil
		}
		return encrData as Data
	}
	
	
	public static func encryptWithSecKey(str: String, rsaPublicKeyRef: SecKey) -> Data? {
		guard let messageData = str.data(using: String.Encoding.utf8) else {
			print("Bad text to encrypt")
			return nil
		}
		return encryptWithSecKey(data: messageData, rsaPublicKeyRef: rsaPublicKeyRef)
	}
	
	
	public static func encryptWithDataKey(data: Data, rsaPublicKeyData: Data) -> Data? {
		guard let pubSecKey = convertPublicKeyData(pubKey: rsaPublicKeyData) else {
			return nil
		}
		return encryptWithSecKey(data: data, rsaPublicKeyRef: pubSecKey)
	}
	
	/*----------------------------------------------------------------------*/
	
	
	//MARK:- Decrypt
	
	
	public static func decrypt(data: Data) -> Data? {
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
	
	
	public static func decrypt(str: String) -> Data? {
		guard let messageData = Data(base64Encoded: str) else {
			print("Bad message to decrypt")
			return nil
		}
		return decrypt(data: messageData)
	}
	
	
	/*----------------------------------------------------------------------*/
	
	
	//MARK:- Signing and Verification
	
	public static func signMessage(str: String) -> String? {
		guard let messageData = str.data(using: String.Encoding.utf8) else {
				print("Bad message to sign")
				return nil
		}
		guard let privSecKey = getSecKeyFromKeychain(withTag: .deviceKey, access: .privateA) else { return nil }
		var error: Unmanaged<CFError>?
		guard let signedData = SecKeyCreateSignature(privSecKey, // finger print proteted
												   signSecKeyAlgorithm,
												   messageData as CFData,
												   &error) else {
			print(error!.takeRetainedValue() as Error)
			return nil
		}
		//convert signed to base64 string
		let signedStr = (signedData as Data).base64EncodedString()
		return signedStr
	}
	
	
	
	public static func verifySign(messageStr: String, signatueStr: String, notMySecKey: SecKey) -> Bool {
		guard let messageData = messageStr.data(using: String.Encoding.utf8) else {
				print("Bad message to verify")
				return false
		}
		let pubEncKey = signatueStr // there is is small problem in this place
		guard let signatureData = Data(base64Encoded: pubEncKey) else {
				print("Bad signature to verify")
				return false
		}
		let verify = SecKeyVerifySignature(notMySecKey,
										   signSecKeyAlgorithm,
										   messageData as CFData,
										   signatureData as CFData,
										   nil)
		print(verify ? "Signature matches for key" : "Signature DOESN'T matches")
		return verify
	}
	
	
	
	/*----------------------------------------------------------------------*/
	
	
	//MARK:- other...
	
	
	/// execution speed measurement
	public static func timeMeasuringCodeRunning(title: String, operationBlock: () -> ()) {
		let start = CFAbsoluteTimeGetCurrent()
		operationBlock()
		let finish = CFAbsoluteTimeGetCurrent()
		let timeElapsed = finish - start
		let roundedTime = String(format: "%.3f", timeElapsed)
		print ("Время выполнения \(title) = \(roundedTime) секунд")
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
		let parameters:[String : Any]  = [
			String(kSecClass)				: kSecClassKey,
			String(kSecAttrKeyClass)		: (access == .publicA) ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
			String(kSecAttrKeyType)			: kSecAttrKeyTypeRSA,
			String(kSecAttrApplicationTag)	: withTag.rawValue.data(using: String.Encoding.utf8)!,
			String(kSecReturnData)			: true
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
		return RSAManager.getSecKeyFromKeychain(withTag: withTag, access: .privateA, printExists: false) != nil
	}
	
	
	public static func deleteSecureKeyPair(withTag: KeyTag, _ completion: ((_ success: Bool) -> Void)?) {
		// private query dictionary
		let deleteQuery: [NSObject : Any] = [
			kSecClass				: kSecClassKey,
			kSecAttrApplicationTag 	: withTag.rawValue,
		]
		//DispatchQueue.global(qos: .default).async {
			let status = SecItemDelete(deleteQuery as CFDictionary) // delete private key
			//DispatchQueue.main.async {
				completion?(status == errSecSuccess)
				if status == errSecSuccess {
					print("Keys successfully deleted!")
				}
				else {
					//print("Nothing to delete!")
				}
			//}
		//}
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
		return RSAManager.getSecKeyFromKeychain(withTag: tagName, access: .privateA)
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
		let pubKey = getKeyData(withTag: .accountKey, access: .publicA) 	// 270 bytes
		let privKey = getKeyData(withTag: .accountKey, access: .privateA) 	// 1090 - 1093 bytes
		guard let pubData = pubKey, let privData = privKey else { return }
		print(pubData)
		smartPrint(string: pubData.base64EncodedString(), identifier: .publicDescr)
		print(privData)
		smartPrint(string: privData.base64EncodedString(), identifier: .privateDescr)
	}
	
	/*----------------------------------------------------------------------*/
	
	
	//MARK:- AES-CBC
	
	// The iv is prefixed to the encrypted data
	public static func encryptAES_CBC(data: Data, keyData: Data) -> Data? {
		let keyLength = keyData.count
		let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES256]
		if !validKeyLengths.contains(keyLength) {
			print("Invalid key length:", keyLength)
			return nil
		}
		let ivSize = kCCBlockSizeAES128
		let cryptLength = size_t(ivSize + data.count + kCCBlockSizeAES128)
		var cryptData = Data(count: cryptLength)
		
		let status = cryptData.withUnsafeMutableBytes {
			(ivBytes) in
			SecRandomCopyBytes(kSecRandomDefault, kCCBlockSizeAES128, ivBytes)
		}
		if (status != 0) {
			print("IV generation failed with status: ", Int(status))
			return nil
		}
		var numBytesEncrypted: size_t = 0
		let options = CCOptions(kCCOptionPKCS7Padding)
		
		let cryptStatus = cryptData.withUnsafeMutableBytes {
			(cryptBytes) in
			data.withUnsafeBytes {
				(dataBytes) in
				keyData.withUnsafeBytes {
					(keyBytes) in
					CCCrypt(CCOperation(kCCEncrypt),
							CCAlgorithm(kCCAlgorithmAES),
							options,
							keyBytes, keyLength,
							cryptBytes,
							dataBytes, data.count,
							cryptBytes + kCCBlockSizeAES128, cryptLength,
							&numBytesEncrypted)
				}
			}
		}
		if UInt32(cryptStatus) == UInt32(kCCSuccess) {
			cryptData.count = numBytesEncrypted + ivSize
			print("Successfully encrypted!")
			return cryptData
		}
		else {
			print("Encryption failed with status: ", Int(cryptStatus))
			return nil
		}
	}
	

	public static func decryptAES_CBC(data: Data, keyData: Data) -> Data? {
		let keyLength = keyData.count
		let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES256]
		if !validKeyLengths.contains(keyLength) {
			print("Invalid key length:", keyLength)
			return nil
		}
		let ivSize = kCCBlockSizeAES128
		let clearLength = size_t(data.count - ivSize)
		var clearData = Data(count: clearLength)
		
		var numBytesDecrypted: size_t = 0
		let options = CCOptions(kCCOptionPKCS7Padding)
		
		let cryptStatus = clearData.withUnsafeMutableBytes {
			(cryptBytes) in
			data.withUnsafeBytes {
				(dataBytes) in
				keyData.withUnsafeBytes {
					(keyBytes) in
					CCCrypt(CCOperation(kCCDecrypt),
							CCAlgorithm(kCCAlgorithmAES128),
							options,
							keyBytes, keyLength,
							dataBytes,
							dataBytes + kCCBlockSizeAES128, clearLength,
							cryptBytes, clearLength,
							&numBytesDecrypted)
				}
			}
		}
		if UInt32(cryptStatus) == UInt32(kCCSuccess) {
			clearData.count = numBytesDecrypted
			print("Successfully decrypted!")
			return clearData
		}
		else {
			print("Decryption failed with status:", Int(cryptStatus))
			return nil
		}
	}
	
	/*----------------------------------------------------------------------*/
	
}
















