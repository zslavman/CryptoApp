//
//  OTPScreenController.swift
//  CryptoApp
//
//  Created by Zinko Viacheslav on 02.04.2019.
//  Copyright © 2019 com.user. All rights reserved.
//

import Foundation
import UIKit

class OTPScreenController: UIViewController {
	
	@IBOutlet weak var dig1: UITextView!
	@IBOutlet weak var dig2: UITextView!
	@IBOutlet weak var dig3: UITextView!
	@IBOutlet weak var dig4: UITextView!
	@IBOutlet weak var dig5: UITextView!
	@IBOutlet weak var dig6: UITextView!
	private lazy var digits:[UITextView] = [dig1, dig2, dig3, dig4, dig5, dig6]
	
	
	override func viewDidLoad() {
		super.viewDidLoad()
		
		configureDigits()
	}
	
	private func configureDigits() {
		digits.forEach { (digit) in
			digit.layer.cornerRadius = 6
			digit.delegate = self
			digit.text = ""
		}
		dig1.becomeFirstResponder()
	}
	
}

extension OTPScreenController: UITextViewDelegate {
	
	func textView(_ textView: UITextView,
				  shouldChangeTextIn range: NSRange,
				  replacementText text: String) -> Bool {
		
		guard let extractedText = textView.text else { return false }
		guard let textViewNumber = digits.firstIndex(of: textView) else { return false }
		
		if extractedText.count < 1 && text.count > 0 {
			if textViewNumber < digits.count - 1 {
				digits[textViewNumber + 1].becomeFirstResponder()
				digits[textViewNumber + 1].text = ""
			}
			else {
				digits[textViewNumber].resignFirstResponder()
			}
			textView.text = text
			return false
		}
//		else if extractedText.count >= 1 && text.count == 0 {
//			if textViewNumber < digits.count - 1 {
//				digits[textViewNumber + 1].becomeFirstResponder()
//			}
//			else {
//				digits[textViewNumber].resignFirstResponder()
//			}
//			textView.text = ""
//			return false
//		}
		else if extractedText.count >= 1 {
			textView.text = text
			return false
		}
		return true
	}
	
}
