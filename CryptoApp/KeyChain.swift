//
//  KeyChain.swift
//  Teamly
//
//  Created by User on 20/03/19.
//

import Foundation

class KeyChain {
	
	
	public static func readKey(sessionID: String) -> Data? {
		let query = createQuery(sessionID: sessionID)
		
		var data: AnyObject?
		let status = SecItemCopyMatching(query as CFDictionary, &data)
//		let status = withUnsafeMutablePointer(to: &data) {
//			SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
//		}
		if status == errSecSuccess {
			let receivedKey = data as! Data
			print("receivedKey = ", String(data: receivedKey, encoding: .utf8)!)
			return receivedKey
		}
		print("Error \(status) key for session '\(sessionID)' not found!")
		return nil
	}
	
	
	public static func writeKey(sessionID: String, dataKey: Data) {
		var query = createQuery(sessionID: sessionID)
		//deleteKey(sessionID: sessionID)
		query[kSecValueData] = dataKey
		// To enable Keychain Sharing, select a Development Team to use for provisioning
		let result = SecItemAdd(query as CFDictionary, nil)
		if (result != noErr && result != errSecDuplicateItem) {
			print("Error, can't add key to keychain, status \(result)")
		}
		else {
			print("Succesfully add new key")
		}
	}
	
	
	private static func createQuery(sessionID: String) -> [NSObject: Any] {
		let email 		= "22golcom" //TODO: get email from userPayload
		let prefix		= ""
//		let accessGroup = "\(prefix).CryptoAppKeyChainGroup1"// com.CryptoApp7718
		let accessGroup = "\(prefix).com.CryptoApp7718"
		let version 	= "18"
		
		let query: [NSObject: Any] = [
//			kSecAttrService 	: sessionID,
			kSecAttrAccount 	: email,
			kSecAttrAccessGroup : accessGroup,
//			kSecAttrLabel		: version,
			kSecClass 			: kSecClassGenericPassword,
			kSecMatchLimit		: kSecMatchLimitOne,
			kSecReturnAttributes: kCFBooleanTrue,
//			kSecReturnData 		: kCFBooleanTrue,
			kSecAttrAccessible	: kSecAttrAccessibleAlways,
//			kSecAttrAccessible	: kSecAttrAccessibleAlwaysThisDeviceOnly,
		]
		return query
	}
	
	
	
	public static func keyIsExists(sessionID: String) -> Bool {
		return readKey(sessionID: sessionID) != nil
	}
	
	
	private static func deleteKey(sessionID: String) {
		let query = createQuery(sessionID: sessionID)
		let resultCodeDelete = SecItemDelete(query as CFDictionary)
		
		if resultCodeDelete != noErr {
			print("Error deleting from Keychain: \(resultCodeDelete)")
			return
		}
		print("Key successfully deleted!")
	}
	
}
