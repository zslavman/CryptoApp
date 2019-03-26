//
//  KeyChain.swift
//  Teamly
//
//  Created by User on 20/03/19.
//

import Foundation

class KeyChain {
	
	public static let accessGroup = "LC7P3687MC.com.CryptoApp7718"
	public static let accountName = "drgth6678"
	
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
	
	
}
