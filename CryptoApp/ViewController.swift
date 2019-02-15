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
		
		setup()
	}
	
	private func setup(){
		
	}
	
	@objc private func onLeftClick(){
		if RSAManager.isKeyPairExists(withTag: RSAManager.accountPublicKey) {
			print("Already have keys")
			return
		}
		RSAManager.generatePairRSA(withTag: RSAManager.accountPublicKey)
		print("Keys successfully generated!")
	}
	@objc private func onRightClick(){
		RSAManager.deleteSecureKeyPair(withTag: RSAManager.accountPublicKey) {
			(success: Bool) in
			let toPrint = success ? "Keys successfully deleted!" : "No keys found!"
			print(toPrint)
		}
	}
	
	@IBAction private func onEncryptClick(sender: UIButton){
		guard !inp_Field.text.isEmpty, let str = inp_Field.text else { return }
		guard let messageData = str.data(using: String.Encoding.utf8) else {
				print("ECC bad message to encrypt")
				return
		}
		
		guard let pubKey = RSAManager.getPublicSecKey(withTag: RSAManager.accountPublicKey) else { return }
		
		guard let encryptData = SecKeyCreateEncryptedData(pubKey,
														  SecKeyAlgorithm.rsaEncryptionOAEPSHA256,
														  messageData as CFData,
														  nil) else {
			print("pub ECC error encrypting")
			return
		}
		let encryptedData = encryptData as Data
		print("\(encryptedData.count) bytes")
		let encryptedString = encryptedData.base64EncodedString()
		out_Field.text = encryptedString
	}
	
	
	
	@IBAction private func onDecryptClick(sender: UIButton){
		//guard !out_Field.text.isEmpty, let str = out_Field.text else { return }
		
	}
	
	

}

