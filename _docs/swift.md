---
title: Swift
tags: 
 - swift
description: Swift Vulnerabilities
---

# Swift




## آسیب پذیری Improper Platform Usage


##### 🐞 کد آسیب پذیر




{% highlight php %}

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let urlString = "http://example.com/api/data"
        let url = URL(string: urlString)!
        let request = URLRequest(url: url)
        
        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            if let error = error {
                print("Error: \(error.localizedDescription)")
                return
            }
            
            if let data = data {
                let json = try? JSONSerialization.jsonObject(with: data, options: [])
                print("Response: \(json ?? "")")
            }
        }
        
        task.resume()
    }
}
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
import UIKit

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let urlString = "https://example.com/api/data"
        
        guard let urlComponents = URLComponents(string: urlString),
              let host = urlComponents.host,
              let scheme = urlComponents.scheme,
              scheme.lowercased().hasPrefix("https") else {
            print("Invalid URL or scheme")
            return
        }
        
        // Perform additional validation checks if required, such as verifying the domain or certificate
        
        guard let url = urlComponents.url else {
            print("Failed to create URL")
            return
        }
        
        let request = URLRequest(url: url)
        
        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            if let error = error {
                print("Error: \(error.localizedDescription)")
                return
            }
            
            if let data = data {
                let json = try? JSONSerialization.jsonObject(with: data, options: [])
                print("Response: \(json ?? "")")
            }
        }
        
        task.resume()
    }
}
{% endhighlight %}





## آسیب پذیری Insecure Data Storage


##### 🐞 کد آسیب پذیر


{% highlight php %}
import UIKit

class ViewController: UIViewController {
    
    let password = "myPassword"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Saving password to UserDefaults
        UserDefaults.standard.set(password, forKey: "password")
        
        // Reading password from UserDefaults
        let storedPassword = UserDefaults.standard.string(forKey: "password")
        print("Stored Password: \(storedPassword ?? "")")
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 



{% highlight php %}
import UIKit
import KeychainAccess

class ViewController: UIViewController {
    
    let password = "myPassword"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        do {
            // Saving password to Keychain
            let keychain = Keychain(service: "com.example.app")
            try keychain.set(password, key: "password")
            
            // Reading password from Keychain
            let storedPassword = try keychain.get("password")
            print("Stored Password: \(storedPassword ?? "")")
        } catch {
            print("Error: \(error.localizedDescription)")
        }
    }
}
{% endhighlight %}






## آسیب پذیری Insecure Communication

##### 🐞 کد آسیب پذیر


{% highlight php %}
import UIKit

class ViewController: UIViewController {
    
    let apiUrl = "http://example.com/api"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Insecurely sending a request to the API
        if let url = URL(string: apiUrl) {
            let request = URLRequest(url: url)
            let session = URLSession.shared
            
            let task = session.dataTask(with: request) { (data, response, error) in
                if let error = error {
                    print("Error: \(error.localizedDescription)")
                } else if let data = data {
                    let responseString = String(data: data, encoding: .utf8)
                    print("Response: \(responseString ?? "")")
                }
            }
            
            task.resume()
        }
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 



{% highlight php %}
import UIKit

class ViewController: UIViewController {
    
    let apiUrl = "https://example.com/api"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Securely sending a request to the API
        if let url = URL(string: apiUrl) {
            let request = URLRequest(url: url)
            let session = URLSession(configuration: .default)
            
            let task = session.dataTask(with: request) { (data, response, error) in
                if let error = error {
                    print("Error: \(error.localizedDescription)")
                } else if let data = data {
                    let responseString = String(data: data, encoding: .utf8)
                    print("Response: \(responseString ?? "")")
                }
            }
            
            task.resume()
        }
    }
}
{% endhighlight %}





## آسیب پذیری Insecure Authentication

##### 🐞 کد آسیب پذیر


{% highlight php %}
import UIKit

class LoginViewController: UIViewController {
    
    @IBOutlet weak var usernameTextField: UITextField!
    @IBOutlet weak var passwordTextField: UITextField!
    
    @IBAction func loginButtonTapped(_ sender: UIButton) {
        let username = usernameTextField.text ?? ""
        let password = passwordTextField.text ?? ""
        
        // Noncompliant code: Insecurely sending username and password over HTTP
        let apiUrl = "http://example.com/login"
        let requestUrl = URL(string: apiUrl)!
        
        var request = URLRequest(url: requestUrl)
        request.httpMethod = "POST"
        
        let body = "username=\(username)&password=\(password)"
        request.httpBody = body.data(using: .utf8)
        
        let session = URLSession.shared
        let task = session.dataTask(with: request) { (data, response, error) in
            // Handle response
        }
        
        task.resume()
    }
}
{% endhighlight %}









##### ✅ کد اصلاح شده 


{% highlight php %}
import UIKit

class LoginViewController: UIViewController {
    
    @IBOutlet weak var usernameTextField: UITextField!
    @IBOutlet weak var passwordTextField: UITextField!
    
    @IBAction func loginButtonTapped(_ sender: UIButton) {
        let username = usernameTextField.text ?? ""
        let password = passwordTextField.text ?? ""
        
        // Compliant code: Securely sending username and password over HTTPS
        let apiUrl = "https://example.com/login"
        let requestUrl = URL(string: apiUrl)!
        
        var request = URLRequest(url: requestUrl)
        request.httpMethod = "POST"
        
        let body = "username=\(username)&password=\(password)"
        request.httpBody = body.data(using: .utf8)
        
        let session = URLSession(configuration: .default)
        let task = session.dataTask(with: request) { (data, response, error) in
            // Handle response
        }
        
        task.resume()
    }
}
{% endhighlight %}






## آسیب پذیری Insufficient Cryptography

##### 🐞 کد آسیب پذیر


{% highlight php %}
import CommonCrypto

func encryptData(data: Data, key: String) -> Data? {
    let keyData = key.data(using: .utf8)!
    let algorithm: CCAlgorithm = CCAlgorithm(kCCAlgorithmAES)
    let options: CCOptions = CCOptions(kCCOptionECBMode)
    let keyLength = size_t(kCCKeySizeAES256)
    let bufferSize = data.count + kCCBlockSizeAES128
    var buffer = Data(count: bufferSize)
    
    let status = keyData.withUnsafeBytes { keyBytes in
        data.withUnsafeBytes { dataBytes in
            buffer.withUnsafeMutableBytes { bufferBytes in
                CCCrypt(CCOperation(kCCEncrypt),
                        algorithm,
                        options,
                        keyBytes.baseAddress,
                        keyLength,
                        nil,
                        dataBytes.baseAddress,
                        data.count,
                        bufferBytes.baseAddress,
                        bufferSize,
                        nil)
            }
        }
    }
    
    return (status == kCCSuccess) ? buffer : nil
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
import CommonCrypto

func encryptData(data: Data, key: Data) -> Data? {
    let algorithm: CCAlgorithm = CCAlgorithm(kCCAlgorithmAES)
    let options: CCOptions = CCOptions(kCCOptionPKCS7Padding)
    let keyLength = size_t(kCCKeySizeAES256)
    let ivSize = kCCBlockSizeAES128
    let bufferSize = data.count + ivSize
    var buffer = Data(count: bufferSize)
    var numBytesEncrypted: size_t = 0
    
    let status = key.withUnsafeBytes { keyBytes in
        CCCrypt(CCOperation(kCCEncrypt),
                algorithm,
                options,
                keyBytes.baseAddress,
                keyLength,
                nil,
                data.withUnsafeBytes { dataBytes in
                    dataBytes.baseAddress
                },
                data.count,
                buffer.withUnsafeMutableBytes { bufferBytes in
                    bufferBytes.baseAddress
                },
                bufferSize,
                &numBytesEncrypted)
    }
    
    return (status == kCCSuccess) ? buffer.prefix(numBytesEncrypted) : nil
}
{% endhighlight %}




## آسیب پذیری Insecure Authorization


##### 🐞 کد آسیب پذیر


{% highlight php %}
func checkPermission(user: User, permission: String) -> Bool {
    let userPermissions = user.permissions
    return userPermissions.contains(permission)
}
{% endhighlight %}








##### ✅ کد اصلاح شده 


{% highlight php %}
func checkPermission(user: User, permission: String) -> Bool {
    guard let userPermissions = retrieveUserPermissions(user: user) else {
        return false
    }
    
    return userPermissions.contains(permission)
}

func retrieveUserPermissions(user: User) -> [String]? {
    // Fetch user permissions from a secure and trusted data source
    // Implement proper authentication and authorization mechanisms
    // Apply appropriate access control policies
    // Validate and sanitize user input
    // Perform necessary checks to ensure the user is authorized to access the permissions data
    
    return user.permissions
}
{% endhighlight %}






## آسیب پذیری Client Code Quality


##### 🐞 کد آسیب پذیر


{% highlight php %}
class ViewController: UIViewController {
    @IBOutlet weak var label: UILabel!
    
    func updateLabel(text: String) {
        label.text = text
    }
    
    func showAlert() {
        let alert = UIAlertController(title: "Alert", message: "This is an alert message.", preferredStyle: .alert)
        let action = UIAlertAction(title: "OK", style: .default)
        alert.addAction(action)
        self.present(alert, animated: true, completion: nil)
    }
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
class ViewController: UIViewController {
    @IBOutlet weak var label: UILabel!
    
    func updateLabel(text: String) {
        DispatchQueue.main.async { [weak self] in
            self?.label.text = text
        }
    }
}

class AlertHelper {
    static func showAlert(on viewController: UIViewController, title: String, message: String) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        let action = UIAlertAction(title: "OK", style: .default)
        alert.addAction(action)
        viewController.present(alert, animated: true, completion: nil)
    }
}
{% endhighlight %}






## آسیب پذیری Code Tampering


##### 🐞 کد آسیب پذیر


{% highlight php %}
class ViewController: UIViewController {
    @IBOutlet weak var label: UILabel!
    
    func updateLabel(text: String) {
        label.text = text
    }
}

class DataProcessor {
    func processData(data: String) -> String {
        // Some data processing logic
        return data.uppercased()
    }
}

class MainViewController: UIViewController {
    let dataProcessor = DataProcessor()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let viewController = ViewController()
        viewController.updateLabel(text: dataProcessor.processData(data: "Hello, World!"))
    }
}
{% endhighlight %}










##### ✅ کد اصلاح شده 


{% highlight php %}
class ViewController: UIViewController {
    @IBOutlet weak var label: UILabel!
    
    func updateLabel(text: String) {
        label.text = text
    }
}

class DataProcessor {
    func processData(data: String) -> String {
        // Some data processing logic
        return data.uppercased()
    }
}

class MainViewController: UIViewController {
    let dataProcessor = DataProcessor()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let processedData = dataProcessor.processData(data: "Hello, World!")
        let viewController = ViewController()
        viewController.updateLabel(text: processedData)
    }
}
{% endhighlight %}






## آسیب پذیری Reverse Engineering


##### 🐞 کد آسیب پذیر


{% highlight php %}
class SecretManager {
    private let secretKey = "mySecretKey"
    
    func getSecretKey() -> String {
        return secretKey
    }
}

class ViewController: UIViewController {
    let secretManager = SecretManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let secretKey = secretManager.getSecretKey()
        print("Secret Key: \(secretKey)")
    }
}
{% endhighlight %}












##### ✅ کد اصلاح شده 


{% highlight php %}
class SecretManager {
    private let secretKey = "mySecretKey"
    
    func getSecretKey() -> String {
        return secretKey
    }
}

class ViewController: UIViewController {
    let secretManager = SecretManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        printSecretKey()
    }
    
    func printSecretKey() {
        let secretKey = secretManager.getSecretKey()
        print("Secret Key: \(secretKey)")
    }
}
{% endhighlight %}






## آسیب پذیری Extraneous Functionality


##### 🐞 کد آسیب پذیر


{% highlight php %}
class DataManager {
    func saveData(data: String) {
        // Code to save data
    }
    
    func deleteData(data: String) {
        // Code to delete data
    }
    
    func processData(data: String) {
        // Code to process data
    }
    
    func sendDataToServer(data: String) {
        // Code to send data to the server
    }
}

class ViewController: UIViewController {
    let dataManager = DataManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let data = "Sample data"
        
        dataManager.saveData(data: data)
        dataManager.deleteData(data: data)
        dataManager.processData(data: data)
        dataManager.sendDataToServer(data: data)
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
class DataManager {
    func saveData(data: String) {
        // Code to save data
    }
    
    func deleteData(data: String) {
        // Code to delete data
    }
}

class ViewController: UIViewController {
    let dataManager = DataManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let data = "Sample data"
        
        dataManager.saveData(data: data)
        dataManager.deleteData(data: data)
    }
}
{% endhighlight %}


