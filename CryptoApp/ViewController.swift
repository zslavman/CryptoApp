//
//  ViewController.swift
//  CryptoApp
//
//  Created by User on 15/02/19.
//  Copyright © 2019 com.user. All rights reserved.
//

import UIKit

class ViewController: UIViewController {


	@IBOutlet weak var inp_Field: UITextView!
	@IBOutlet weak var out_Field: UITextView!
	
	
	override func viewDidLoad() {
		super.viewDidLoad()
		view.backgroundColor = #colorLiteral(red: 0.4620226622, green: 0.8382837176, blue: 1, alpha: 1)
		navigationItem.title = "Crypto Tests"
		navigationItem.leftBarButtonItem = UIBarButtonItem(title: "Gen Kyes", style: .plain, target: self, action: #selector(onLeftClick))
		navigationItem.rightBarButtonItem = UIBarButtonItem(title: "Del Keys", style: .plain, target: self, action: #selector(onRightClick))
		
		view.addGestureRecognizer(UITapGestureRecognizer(target: self, action: #selector(onBackingClick)))
	}
	
	@objc private func onBackingClick(){
		view.endEditing(true)
	}
	
	@objc private func onLeftClick(){
		if RSAManager.isKeyPairExists(withTag: .accountKey) {
			print("Already have keys")
			return
		}
		RSAManager.generatePairRSA(withTag: .accountKey)
		print("Keys successfully generated!")
	}
	@objc private func onRightClick(){
		RSAManager.deleteSecureKeyPair(withTag: .accountKey) {
			(success: Bool) in
			let toPrint = success ? "Keys successfully deleted!" : "No keys found!"
			print(toPrint)
		}
	}
	
	@IBAction private func onEncryptClick(sender: UIButton) {
		guard !inp_Field.text.isEmpty, let str = inp_Field.text else { return }
		guard let rsaKeyRef = RSAManager.getSecKeyFromKeychain(withTag: .accountKey, access: .publicA) else { return }
		guard let encryptedData = RSAManager.encryptSimple(str: str, rsaKeyRef: rsaKeyRef) else { return }
		print("Successfully encrypted, length: \(encryptedData.count) bytes")
		out_Field.text = encryptedData.base64EncodedString()
		
		// ----------------------------------------
//		guard let rsaKeyRef = RSAManager.getSecKeyFromKeychain(withTag: .accountKey, access: .publicA) else {
//			return
//		}
//		guard let encryptedData = RSAManager.encryptWithRSAKey(data: str.data(using: String.Encoding.utf8)!,
//															   rsaKeyRef: rsaKeyRef) else { return }
//		out_Field.text = encryptedData.base64EncodedString()
	}
	
	
	
	@IBAction private func onDecryptClick(sender: UIButton){
		guard !out_Field.text.isEmpty, let str = out_Field.text else { return }
		guard let messageData = Data(base64Encoded: str) else {
			print("Bad message to decrypt")
			return
		}
		guard let privKey = RSAManager.getSecKeyFromKeychain(withTag: .accountKey, access: .privateA) else {
			print("Private key not found!")
			return
		}
		guard let decryptData = SecKeyCreateDecryptedData(privKey,
														  SecKeyAlgorithm.rsaEncryptionPKCS1,
														  messageData as CFData,
														  nil) else {
			print("Error decrypting. Bad key for decryption!")
			return
		}
		let decryptedData = decryptData as Data
		guard let decryptedString = String(data: decryptedData, encoding: String.Encoding.utf8) else {
			print("Decrypt error: could not get string")
			return
		}
		out_Field.text = decryptedString
		
		
		// ----------------------------------------
//		guard let decryptedData = RSAManager.decrypt(encryptedData: str.data(using: String.Encoding.utf8)!) else { return }
//		out_Field.text = decryptedData.base64EncodedString()
		
//		guard let decryptedString = RSAManager.decprypt(encrpted: str.data(using: String.Encoding.utf8)!) else { return }
//		out_Field.text = decryptedString
		
//		guard let decryptedString = RSAManager.decrypt(source: str.data(using: String.Encoding.utf8)!) else { return }
//		out_Field.text = decryptedString
	}
		
	
	

}



















