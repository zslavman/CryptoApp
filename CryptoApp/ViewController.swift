//
//  ViewController.swift
//  CryptoApp
//
//  Created by User on 15/02/19.
//  Copyright © 2019 com.user. All rights reserved.
//

import UIKit
import CommonCrypto

class ViewController: UIViewController {


	@IBOutlet weak var inp_Field: UITextView!
	@IBOutlet weak var out_Field: UITextView!
	private let keyData = "1234567890123456".data(using: String.Encoding.utf8)! // 16 bytes for AES128
	private let ivData 	= "abcdefghijklmnop".data(using: String.Encoding.utf8)! // 16 bytes for AES128
	
	override func viewDidLoad() {
		super.viewDidLoad()
		view.backgroundColor = #colorLiteral(red: 0.4620226622, green: 0.8382837176, blue: 1, alpha: 1)
		navigationItem.title = "Crypto Tests"
		navigationItem.leftBarButtonItem = UIBarButtonItem(title: "Gen Kyes", style: .plain, target: self, action: #selector(onLeftClick))
		navigationItem.rightBarButtonItem = UIBarButtonItem(title: "Del Keys", style: .plain, target: self, action: #selector(onRightClick))
		
		view.addGestureRecognizer(UITapGestureRecognizer(target: self, action: #selector(onBackingClick)))
		inp_Field.text = "123"
	}
	
	
	
	
	@objc private func onBackingClick(){
		view.endEditing(true)
	}
	
	@objc private func onLeftClick(){
		if RSAManager.isKeyPairExists(withTag: .accountKey) {
			print("Already have keys")
			return
		}
		//RSAManager.generatePairKeys(withTag: .accountKey, algorithm: .EC)
		RSAManager.generateAllKeys()
	}
	
	
	@objc private func onRightClick(){
		RSAManager.deleteSecureKeyPair(withTag: .accountKey, nil)
	}
	
	
	@IBAction private func onEncryptClick(sender: UIButton) {
		//----------------- RSA -----------------
//		guard !inp_Field.text.isEmpty, let str = inp_Field.text else { return }
//		guard let rsaKeyData = RSAManager.getKeyData(withTag: .accountKey, access: .publicA) else { return }
//		guard let encryptedData = RSAManager.encryptWithDataKey(data: str.data(using: String.Encoding.utf8)!,
//																rsaPublicKeyData: rsaKeyData) else { return }
//		print("Successfully encrypted, length: \(encryptedData.count) bytes")
//		out_Field.text = encryptedData.base64EncodedString()
		
		//----------------- AES CBC -----------------
//		guard !inp_Field.text.isEmpty, let str = inp_Field.text else { return }
//		guard let strData = str.data(using: String.Encoding.utf8) else { return }
//
//		guard let cryptedData = RSAManager.encryptAES_CBC(dataToEncrypt: strData, keyData: keyData) else { return }
//		out_Field.text = cryptedData.base64EncodedString()
//		print(cryptedData)
		
		//----------------- AES CBC (extension) -----------------
		guard !inp_Field.text.isEmpty, let str = inp_Field.text else { return }
		guard let strData = str.data(using: String.Encoding.utf8) else { return }

		if let encryptedData = strData.aesCrypt(keyData: keyData, ivData: ivData, operation: kCCEncrypt) {
			out_Field.text = encryptedData.base64EncodedString()
		}
	}
	
	
	@IBAction private func onDecryptClick(sender: UIButton) {
		//----------------- RSA -----------------
//		guard !out_Field.text.isEmpty, let str = out_Field.text else { return }
//		guard let decryptedData = RSAManager.decrypt(str: str) else { return }
//		guard let decryptedString = String(data: decryptedData, encoding: String.Encoding.utf8) else {
//			print("Decrypt error: could't get string")
//			return
//		}
//		out_Field.text = decryptedString
		
		//----------------- AES CBC -----------------
//		guard !out_Field.text.isEmpty, let str = out_Field.text else { return }
//		guard let cryptedData = str.data(using: String.Encoding.utf8) else { return }
//		
//		guard let decryptedData = RSAManager.decryptAES_CBC(dataToDecrypt: cryptedData, keyData: keyData) else { return }
//		out_Field.text = decryptedData.base64EncodedString()
//		print(decryptedData)
		
		//----------------- AES CBC (extension) -----------------
		guard !out_Field.text.isEmpty, let str = out_Field.text else { return }
		guard let cryptedData = str.data(using: String.Encoding.utf8) else { return }
		
		if let decryptedData = cryptedData.aesCrypt(keyData: keyData, ivData: ivData, operation: kCCDecrypt){
			out_Field.text = decryptedData.base64EncodedString()
			//out_Field.text = String(bytes: decryptedData, encoding: .utf8) // does'nt work
		}
	}
	

}



















