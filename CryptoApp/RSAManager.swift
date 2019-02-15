//
//  RSAManager.swift
//  Teamly
//
//  Created by User on 14/02/19.
//  https://lapo.it/asn1js/#
// https://github.com/cossacklabs/themis
// https://www.linkedin.com/pulse/ios-10-how-use-secure-enclave-touch-id-protect-your-keys-satyam-tyagi/

import Foundation


enum DescriptionIdentifier: String {
	case publicDescr = "----- RSA PUBLIC KEY -----"
	case privateDescr = "----- RSA PRIVATE KEY -----"
}
enum KeyIdentifier: String {
	case accountPublicKey = "accountPublicKey"
	case devicePublicKey = "devicePublicKey"
}
enum AccessIdentif {
	case publicA
	case privateA
}



class RSAManager {
	
	private static var randKey: String {
		let generated = UUID().uuidString
		return generated
	}
	
	
	//MARK:- Key-pair Generation methods
	
	// most proper native key-pair creation with save into persistent store
	@discardableResult
	public static func generatePairRSA(withTag: KeyIdentifier) -> (Data, Data)? {
		let publicKeyAttr: [NSObject: Any] = [
			kSecAttrIsPermanent		: true, // store in keychain
			kSecAttrApplicationTag	: withTag.rawValue.data(using: String.Encoding.utf8)!,
			kSecClass				: kSecClassKey,		// ?
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
	
	//MARK:- Crypt/Decrypt
	
	
	
	//MARK:- other...
	
	public static func getSecKeyFromKeychain(withTag: KeyIdentifier, access: AccessIdentif) -> SecKey? {
		let parameters:[NSObject : Any]  = [
			kSecClass				: kSecClassKey,
			kSecAttrKeyClass		: (access == .publicA) ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
			kSecAttrKeyType			: kSecAttrKeyTypeRSA,
			kSecAttrApplicationTag	: withTag.rawValue,
			kSecReturnRef			: true
		]
		var ref: AnyObject?
		let status = SecItemCopyMatching(parameters as CFDictionary, &ref)
		if status == errSecSuccess {
			return ref as! SecKey?
		}
		else { return nil }
	}
	
	
	// Add private RSA-key into keychain storage
	@discardableResult
	public static func addPrivateKeyRSAtoKeychain(privkey: Data, tagName: KeyIdentifier) throws -> SecKey? {
		RSAManager.deleteSecureKeyPair(withTag: tagName, nil)
		
		let privkeyData = try stripPrivateKeyHeader(privkey)
		if privkeyData == nil {
			return nil
		}
		let queryFilter: [NSObject : Any] = [
			kSecClass            	: kSecClassKey,
			kSecAttrKeyType      	: kSecAttrKeyTypeRSA,
			kSecAttrApplicationTag 	: tagName,
			//kSecAttrAccessible    : kSecAttrAccessibleWhenUnlocked,
			kSecValueData         	: privkeyData!,
			kSecAttrKeyClass      	: kSecAttrKeyClassPrivate,
			kSecReturnPersistentRef	: true
		]
		let result = SecItemAdd(queryFilter as CFDictionary, nil)
		if ((result != noErr) && (result != errSecDuplicateItem)) {
			print("Cannot add key to keychain, status \(result)")
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
	private static func stripPrivateKeyHeader(_ privkey: Data) throws -> Data? {
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
		return privkey.subdata(in: idx..<idx+len)
		//return privkey.subdata(in: NSMakeRange(idx, len).toRange()!)
	}
	
	
	
	public static func convertKeyPublicData(_ pubkey: Data, tagName: String) throws -> SecKey? {
		guard let pubkeyData = stripPublicKeyHeader(pubkey) else {
			return nil
		}
		let queryFilter: [NSObject : Any] = [
			kSecClass             	: kSecClassKey,
			kSecAttrKeyType       	: kSecAttrKeyTypeRSA,
			kSecAttrApplicationTag	: tagName,
			kSecValueData    		: pubkeyData,
			kSecAttrKeyClass        : kSecAttrKeyClassPublic,
			kSecReturnPersistentRef	: true
		]
		let result = SecItemAdd(queryFilter as CFDictionary, nil)
		if ((result != noErr) && (result != errSecDuplicateItem)) {
			return nil
		}
		//TODO: convert Data -> SecKey
		return nil
	}
	

	
	/*
	* Verifies that the supplied key is in fact a X509 public key, and strips its header.
	*/
	/// Returns the RSA public key with stripped header
	///
	/// - Parameter pubkey: X509 public key
	private static func stripPublicKeyHeader(_ pubkey: Data) -> Data? {
		if pubkey.count == 0 {
			return nil
		}
		var keyAsArray = [UInt8](repeating: 0, count: pubkey.count / MemoryLayout<UInt8>.size)
		(pubkey as NSData).getBytes(&keyAsArray, length: pubkey.count)
		
		var idx = 0
		if (keyAsArray[idx] != 0x30) {
			//throw Error
			print("Provided key doesn't have a valid ASN.1 structure (first byte should be 0x30)")
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
				print("Provided key doesn't have a valid X509 header.")
				return nil
			}
		}
		idx += seqiod.count
		if (keyAsArray[idx] != 0x03) {
			print("Invalid byte at index \(idx) (\(keyAsArray[idx])) for public key header.")
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
			print("Invalid byte at index \(idx) (\(keyAsArray[idx])) for public key header.")
			return nil
		}
		idx += 1
		return pubkey.subdata(in: idx..<keyAsArray.count)
		//return pubkey.subdata(in: NSMakeRange(idx, keyAsArray.count - idx).toRange()!)
	}
	
	

	public static func getKeyData(withTag: String, access: AccessIdentif) -> Data? {
		let parameters:[String : Any]  = [
			String(kSecClass)				: kSecClassKey,
			String(kSecAttrKeyClass)		: (access == .publicA) ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
			String(kSecAttrKeyType)			: kSecAttrKeyTypeRSA,
			String(kSecAttrApplicationTag)	: withTag,
			String(kSecReturnData)			: true
		]
		var data: AnyObject?
		let status = SecItemCopyMatching(parameters as CFDictionary, &data)
		if status == errSecSuccess {
			return data as? Data
		}
		else { return nil }
	}
	
	
	
	public static func isKeyPairExists(withTag: KeyIdentifier) -> Bool {
		return RSAManager.getSecKeyFromKeychain(withTag: withTag, access: .privateA) != nil
	}
	
	
	public static func deleteSecureKeyPair(withTag: KeyIdentifier, _ completion: ((_ success: Bool) -> Void)?) {
		// private query dictionary
		let deleteQuery: [NSObject : Any] = [
			kSecClass				: kSecClassKey,
			kSecAttrApplicationTag 	: withTag.rawValue,
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



