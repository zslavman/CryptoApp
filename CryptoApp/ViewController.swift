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
	@IBOutlet weak var segmentedControl: UISegmentedControl!
	@IBOutlet weak var encryptBttn: UIButton!
	@IBOutlet weak var decryptBttn: UIButton!
	private let keyData = "1234567890123456".data(using: .utf8)! 		// 16 bytes for AES128
	
	
	
	
	override func viewDidLoad(){
		super.viewDidLoad()
		view.backgroundColor = #colorLiteral(red: 0.4620226622, green: 0.8382837176, blue: 1, alpha: 1)
		navigationItem.title = "Crypto Tests"
		navigationItem.leftBarButtonItem = UIBarButtonItem(title: "Gen Kyes", style: .plain, target: self, action: #selector(onLeftClick))
		navigationItem.rightBarButtonItem = UIBarButtonItem(title: "Del Keys", style: .plain, target: self, action: #selector(onRightClick))
		
		view.addGestureRecognizer(UITapGestureRecognizer(target: self, action: #selector(onBackingClick)))
		inp_Field.text = "123"
		configureUI()
	}
	
	
	private func configureUI(){
		inp_Field.contentInset = UIEdgeInsets(top: 0, left: 10, bottom: 0, right: 10)
		out_Field.contentInset = UIEdgeInsets(top: 0, left: 10, bottom: 0, right: 10)
		let elements = [inp_Field, out_Field, encryptBttn, decryptBttn]
		elements.forEach {
			(element) in
			element?.layer.cornerRadius = 12
			element?.clipsToBounds = true
		}
	}
	
	
	@objc private func onBackingClick(){
		view.endEditing(true)
	}
	
	@objc private func onLeftClick(){
		if Cipher.isKeyPairExists(withTag: .accountKey) {
			print("Already have keys")
			return
		}
		Cipher.generatePair_RSA(withTag: .accountKey)
	}
	
	
	@objc private func onRightClick(){
		Cipher.deleteSecureKeyPair(withTag: .accountKey)
	}
	
	
	@IBAction private func onEncryptClick(sender: UIButton) {
		guard !inp_Field.text.isEmpty, let str = inp_Field.text else { return }
//		//----------------- RSA-SKCS-1 -----------------
//		if segmentedControl.selectedSegmentIndex == 0 {
//			guard let rsaKeyData = RSAManager.getKeyData(withTag: .accountKey, access: .publicA) else { return }
//			guard let encryptedData = RSAManager.encryptWithDataKey(data: str.data(using: String.Encoding.utf8)!,
//																	rsaPublicKeyData: rsaKeyData) else { return }
//			print("Successfully encrypted, length: \(encryptedData.count) bytes")
//			out_Field.text = encryptedData.base64EncodedString()
//		}
//		//----------------- AES-CBC -----------------
//		else {
//			guard let strData = str.data(using: .utf8) else { return }
//			guard let cryptedData = RSAManager.encryptAES_CBC(data: strData, keyData: keyData) else { return }
//			out_Field.text = cryptedData.base64EncodedString()
//		}
		let dataKey = str.data(using: .utf8)!
		KeyChain.saveKey(sessionID: "123456", dataKey: dataKey)
	}
	
	
	@IBAction private func onDecryptClick(sender: UIButton) {
		//guard !out_Field.text.isEmpty, let str = out_Field.text else { return }
//		//----------------- RSA-SKCS-1 -----------------
//		if segmentedControl.selectedSegmentIndex == 0 {
//			guard let decryptedData = RSAManager.decrypt(str: str) else { return }
//			guard let decryptedString = String(data: decryptedData, encoding: String.Encoding.utf8) else {
//				print("Decrypt error: could't get string")
//				return
//			}
//			out_Field.text = decryptedString
//		}
//		//----------------- AES-CBC -----------------
//		else {
//			guard let cryptedData = Data(base64Encoded: str) else { return } 	// VERY IMPORTANT to encode using this method!
//			guard let decryptedData = RSAManager.decryptAES_CBC(data: cryptedData, keyData: keyData) else { return }
//			out_Field.text = String(data: decryptedData, encoding: .utf8) 		// VERY IMPORTANT to encode using this method!
//		}
		if let loadedKey = KeyChain.readKey(sessionID: "123456"){
			out_Field.text = String(data: loadedKey, encoding: .utf8)
		}
	}
	

}



















