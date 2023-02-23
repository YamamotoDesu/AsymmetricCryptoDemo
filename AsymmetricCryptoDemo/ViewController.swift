//
//  ViewController.swift
//  AsymmetricCryptoDemo
//
//  Created by 山本響 on 2023/02/23.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        encryptDecrypt()
    }

    private func encryptDecrypt() {
        let facade = KeychainFacade()
        
        let text = "Super secret text"
        
        do {
            if let encryptedData = try facade.encrypt(text: text) {
                print("Text encryption successful")
                
                if let decryptedData = try facade.decrypt(data: encryptedData) {
                    print("Data decrypted successfully")
                    print(String(data: decryptedData, encoding: .utf8) ?? "")
                }
            }
        } catch {
            print(error)
        }
    }

}

