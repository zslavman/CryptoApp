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
	
	@IBOutlet weak var dig1: UnderlinedTextView!
	@IBOutlet weak var dig2: UnderlinedTextView!
	@IBOutlet weak var dig3: UnderlinedTextView!
	@IBOutlet weak var dig4: UnderlinedTextView!
	@IBOutlet weak var dig5: UnderlinedTextView!
	@IBOutlet weak var dig6: UnderlinedTextView!
	private lazy var digits:[UnderlinedTextView] = [dig1, dig2, dig3, dig4, dig5, dig6]
	@IBOutlet weak var topInfoLabel: UITextView!
	
	
	override func viewDidLoad() {
		super.viewDidLoad()
		digits.forEach{$0.delegate = self}
	}
	
	override func viewWillAppear(_ animated: Bool) {
		super.viewWillAppear(animated)
		digits.forEach{$0.text = ""}
	}
	
	override func viewDidAppear(_ animated: Bool) {
		super.viewDidAppear(animated)
		dig1.becomeFirstResponder()
	}
	
	@IBAction func onMagicLinkClick(_ sender: UIButton) {
		let plistDictionary = Bundle.main.infoDictionary!
		let appName = plistDictionary["CFBundleName"] as? String ?? "Teamy"
		let message = "This will re-generate your account keys, so you may lose history of previos conversations."
		
		let alertController = UIAlertController(title: appName, message: message, preferredStyle: .alert)
		
		let OK_action = UIAlertAction(title: "OK", style: .default, handler: {
			[weak self] (action) in
			self?.checkPhraze()
		})
		let CANCEL_action = UIAlertAction(title: "Cancel", style: .default, handler: nil)
		
		alertController.addAction(OK_action)
		alertController.addAction(CANCEL_action)
		present(alertController, animated: true, completion: nil)
	}
	
}

extension OTPScreenController: UITextViewDelegate {
	
	func textView(_ textView: UITextView,
				  shouldChangeTextIn range: NSRange,
				  replacementText text: String) -> Bool {
		
		guard let textViewNumber = digits.firstIndex(of: textView as! UnderlinedTextView) else { return false }
		
		if let char = text.cString(using: String.Encoding.utf8) {
			let isBackSpace = strcmp(char, "\\b")
			if (isBackSpace == -92) { // detecting backspace tap
				if textViewNumber - 1 >= 0 {
					textView.resignFirstResponder()
					digits[textViewNumber - 1].becomeFirstResponder()
					digits[textViewNumber - 1].text = ""
				}
			}
			else if textViewNumber < digits.count - 1 {
				digits[textViewNumber + 1].becomeFirstResponder()
				digits[textViewNumber + 1].text = ""
			}
		}
		textView.text = text
		checkPhraze()
		return true
	}
	
	private func checkPhraze(){
		var codePhraze = ""
		digits.forEach {
			(digit) in
			if let character = digit.text, character != "" {
				codePhraze.append(character)
			}
		}
		if codePhraze.count == digits.count {
			view.endEditing(true)
			// TODO: send request
		}
		print("Code: \(codePhraze)")
	}
	
}


class UnderlinedTextView: UITextView {
	
	private var offsetY: CGFloat = -1
	private let lineHeight: CGFloat = 3
	private var dashBackWard = CALayer()
	private var dashForward = CALayer()
	
	
	override func awakeFromNib() {
		super.awakeFromNib()
		layer.cornerRadius = 5
	}
	
	override func layoutSubviews() {
		super.layoutSubviews()
		if offsetY == -1 {
			offsetY = centerVertically()
			addUnderline()
		}
	}
	
	public func centerVertically() -> CGFloat {
		let fittingSize = CGSize(width: bounds.width, height: CGFloat.greatestFiniteMagnitude)
		let size = sizeThatFits(fittingSize)
		let topOffset = (bounds.size.height - size.height * zoomScale) / 2
		let positiveTopOffset = max(1, topOffset)
//		self.contentInset.top = positiveTopOffset
		contentOffset = CGPoint(x: 0, y: -positiveTopOffset)
		return positiveTopOffset
	}
	
	private func addUnderline() {
		dashBackWard.backgroundColor = #colorLiteral(red: 0, green: 0, blue: 0, alpha: 0.3).cgColor
		dashBackWard.frame = CGRect(x: 0, y: frame.size.height - lineHeight - offsetY, width: frame.width, height: lineHeight)
		layer.addSublayer(dashBackWard)
		
		dashForward.backgroundColor = #colorLiteral(red: 0.07, green: 0.42, blue: 0.83, alpha: 1).cgColor
		dashForward.frame = CGRect(x: 0, y: frame.size.height - lineHeight - offsetY, width: frame.width, height: lineHeight)
		layer.addSublayer(dashForward)
		dashForward.isHidden = true
	}
	
	@discardableResult
	override func resignFirstResponder() -> Bool {
		super.resignFirstResponder()
		dashForward.isHidden = true
		return true
	}
	
	@discardableResult
	override func becomeFirstResponder() -> Bool {
		super.becomeFirstResponder()
		dashForward.isHidden = false
		return true
	}
	
}
