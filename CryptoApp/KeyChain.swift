//
//  KeyChain.swift
//  Teamly
//
//  Created by User on 20/03/19.
//

import Foundation

class KeyChain {
	
	public static let accessGroup = "8RTU5H2QPQ.com.CryptoApp7718"
	public static let accountName = "vasya01"
	
	public static func readKey(sessionID: String) -> Data? {
		var query = createQuery(service: sessionID)
		query[kSecMatchLimit] 		= kSecMatchLimitOne
		query[kSecReturnAttributes] = kCFBooleanTrue
		query[kSecReturnData] 		= kCFBooleanTrue
		
		// Try to fetch the existing keychain item that matches the query
		var queryResult: AnyObject?
		let status = withUnsafeMutablePointer(to: &queryResult) {
			SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
		}
		// Check the return status
		guard status != errSecItemNotFound else {
			//print("KeyChain reading error - no keyitem found")
			return nil
		}
		guard status == noErr else {
			print("KeyChain reading error with status \(status)")
			return nil
		}
		// Parse the password string from the query result
		if let existingItem = queryResult as? [String: AnyObject]{
			let dataKey = existingItem[kSecValueData as String] as? Data
			// let version = existingItem[kSecAttrLabel as String] as? String
			print("KeyChain reading sucess")
			return dataKey
		}
		else {
			print("KeyChain reading error - unexpected password data!")
			return nil
		}
	}
	
	
	
	public static func saveKey(sessionID: String, dataKey: Data, ver: Int32 = 0) {
		var query = createQuery(service: sessionID)
		
		// Check for an existing item in the keychain
		if keyIsExists(sessionID: sessionID) {
			// Update the existing item with the new data
			let attributesToUpdate: [NSObject: Any] = [
				kSecValueData 		: dataKey,
				kSecAttrLabel 		: String(ver)
			]
			let status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
			if status != noErr {
				print("KeyChain saving error with status \(status)")
			}
			else {
				print("KeyChain update success!")
			}
		}
		// If no keyitem found
		else {
			// Add a the new item to the keychain
			query[kSecValueData] 		= dataKey
			query[kSecAttrAccessible] 	= kSecAttrAccessibleAlways
			let status = SecItemAdd(query as CFDictionary, nil)
			if status != noErr {
				print("KeyChain saving error with status \(status)")
			}
			else {
				print("KeyChain saving success!")
			}
		}
	}
	
	
	private static func createQuery(service: String) -> [NSObject: Any] {
		let query: [NSObject: Any] = [
			kSecClass 			: kSecClassGenericPassword,
			kSecAttrService 	: service,
			kSecAttrAccount		: accountName,
			kSecAttrAccessGroup	: accessGroup,
			//kSecReturnAttributes: kCFBooleanTrue,
			//kSecReturnData 		: kCFBooleanTrue,
			//kSecAttrAccessible	: kSecAttrAccessibleAlwaysThisDeviceOnly,
		]
		return query
	}
	
	
	
	public static func keyIsExists(sessionID: String) -> Bool {
		return readKey(sessionID: sessionID) != nil
	}
	
	
	private static func deleteKey(sessionID: String) {
		let query = createQuery(service: sessionID)
		let resultCodeDelete = SecItemDelete(query as CFDictionary)
		
		if resultCodeDelete != noErr {
			print("Error deleting from Keychain: \(resultCodeDelete)")
			return
		}
		print("Key successfully deleted!")
	}
	
	//-------------
	
	public static func savePairRSAtoKeychain(keys: KeyPairRSA, tagName: KeyTag, ver: Int32, accountName: String) {
		let commonQuery: [NSObject : Any] = [
			kSecClass            	: kSecClassKey,
			kSecAttrKeyType      	: kSecAttrKeyTypeRSA,
			kSecReturnPersistentRef	: false,
			kSecAttrAccessGroup		: KeyChain.accessGroup,
			kSecAttrApplicationTag 	: (tagName == .accountKey) ? String(ver) : accountName,	// 123  | search atag
			kSecAttrLabel			: (tagName == .accountKey) ? accountName : "",			// John | search labl
			kSecAttrApplicationLabel: tagName.rawValue, 									// accountKey	 klbl(binData)
		]
		var privQuery = commonQuery
		privQuery[kSecValueData] 	= keys.privateDataKey
		privQuery[kSecAttrKeyClass] = kSecAttrKeyClassPrivate				//	1
		var pubQuery = commonQuery
		pubQuery[kSecValueData]		= keys.publicDataKey
		pubQuery[kSecAttrKeyClass]	= kSecAttrKeyClassPublic				// 	0
		
		let privResult = SecItemAdd(privQuery as CFDictionary, nil)
		let pubResult = SecItemAdd(pubQuery as CFDictionary, nil)
		
		if privResult != errSecSuccess || pubResult != errSecSuccess {
			print("Error \(privResult) while save KeyPair")
			return
		}
		print("KeyPair successfully saved")
	}
	
	
	/// Forming base query for reading RSA-key
	private static func readQueryRSA() -> [NSObject : Any] {
		let query: [NSObject : Any] = [
			kSecClass            	: kSecClassKey,			// class
			kSecAttrKeyType      	: kSecAttrKeyTypeRSA,	// type
			kSecAttrAccessGroup		: KeyChain.accessGroup,
			kSecReturnAttributes	: true,
			kSecReturnData 			: true,					// r_Data
			kSecMatchLimit 			: kSecMatchLimitOne,
			kSecAttrKeyClass		: kSecAttrKeyClassPrivate,
			kSecAttrLabel			: "john01" 		// accauntName
		]
		return query
	}
	
	
	/// Get RSA-key on specific request
	public static func readRSA(access: AccessIdentif, type: KeyTag, ver: String? = nil) -> Data? {
		var query = readQueryRSA()
		if access == .publicA {
			query[kSecAttrKeyClass] = kSecAttrKeyClassPublic
		}
		if let version = ver {
			query[kSecAttrApplicationTag] = version
		}
		// Try to fetch the existing keychain item that matches the query
		var queryResult: AnyObject?
		let status = withUnsafeMutablePointer(to: &queryResult) {
			SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
		}
		// Check the return status
		guard status != errSecItemNotFound else {
			print("KeyChain reading error - no keyitem found"); return nil
		}
		guard status == noErr else {
			print("KeyChain reading error with status \(status)"); return nil
		}
		// Parse the password string from the query result
		if let existingItem = queryResult as? [String: AnyObject]{
			let dataKey = existingItem[kSecValueData as String] as? Data
			// let version = existingItem[kSecAttrLabel as String] as? String
			print("KeyChain reading sucess")
			return dataKey
		}
		else {
			print("KeyChain reading error - unexpected password data!")
			return nil
		}
	}
	
	
	
	/// Get all private RSA-keys for current account
	public static func readAllprivateRSA() -> [Int32 : Data]?{
		var query = readQueryRSA()
		query[kSecMatchLimit] = kSecMatchLimitAll
		var queryResult: AnyObject?
		var keys = [Int32 : Data]()
		
		let status = withUnsafeMutablePointer(to: &queryResult) {
			SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
		}
		guard status != errSecItemNotFound else {
			print("KeyChain reading error - no keyitem found"); return nil
		}
		guard status == noErr else {
			print("KeyChain reading error with status \(status)"); return nil
		}
		if let keysArray = queryResult as? [[String: AnyObject]] {
			for itemKey in keysArray {
				let ver = itemKey[kSecAttrApplicationTag as String] as? String
				let data = itemKey[kSecValueData as String] as? Data
				if let version = ver, let keyData = data {
					if let versionInt = Int32(version) {
						keys[versionInt] = keyData
					}
				}
			}
			print("KeyChain reading sucess")
			return keys.isEmpty ? nil : keys
		}
		else {
			print("KeyChain reading error - unexpected password data!")
			return nil
		}
	}
	
	
	
}
