---
title: C#
tags: 
 - csharp
description: C# Vulnerabilities
---

# C#





## آسیب پذیری Exposure of sensitive information


##### 🐞 کد آسیب پذیر




{% highlight php %}
using System;

class Program
{
    static void Main()
    {
        try
        {
            // Simulating an error
            throw new Exception("An error occurred: Sensitive information");
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
using System;

class Program
{
    static void Main()
    {
        try
        {
            // Simulating an error
            throw new Exception("An error occurred");
        }
        catch (Exception ex)
        {
            Console.WriteLine("An unexpected error occurred");
            // Log the exception for debugging or monitoring purposes
            LogException(ex);
        }
    }

    static void LogException(Exception ex)
    {
        // Log the exception to a secure log file or logging service
        // Include necessary information for debugging, but avoid sensitive data
        Console.WriteLine("Error occurred: " + ex.ToString());
    }
}
{% endhighlight %}





Semgrep:


{% highlight php %}
rules:
  - id: sensitive-information-exposure
    patterns:
      - pattern: 'catch \(Exception ex\)\n\s+Console\.WriteLine\(ex\.Message\);'
    message: "Sensitive information exposure in exception handling"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from TryCatchStatement tryCatch
where exists(CatchClause catchClause |
  catchClause.getParameter().getType().toString() = "System.Exception" and
  exists(MethodInvocation println |
    println.getTarget().toString() = "System.Console.WriteLine" and
    println.getArgument(0).toString().indexOf("ex.Message") >= 0
  )
)
select tryCatch
{% endhighlight %}



## آسیب پذیری Insertion of Sensitive Information Into Sent Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.Net;
using System.Net.Mail;

class Program
{
    static void Main()
    {
        string username = "user";
        string password = "password";
        string recipient = "example@example.com";
        string sensitiveData = "Sensitive information";

        using (var client = new SmtpClient("smtp.example.com", 587))
        {
            client.EnableSsl = true;
            client.Credentials = new NetworkCredential(username, password);

            var message = new MailMessage("sender@example.com", recipient, "Subject", "Body: " + sensitiveData);

            client.Send(message);
        }
    }
}
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Net;
using System.Net.Mail;

class Program
{
    static void Main()
    {
        string username = "user";
        string password = "password";
        string recipient = "example@example.com";
        string sensitiveData = "Sensitive information";

        using (var client = new SmtpClient("smtp.example.com", 587))
        {
            client.EnableSsl = true;
            client.Credentials = new NetworkCredential(username, password);

            var message = new MailMessage("sender@example.com", recipient, "Subject", "Body");

            // Attach the sensitive data as a secure attachment
            var attachment = new Attachment(sensitiveData);
            message.Attachments.Add(attachment);

            client.Send(message);
        }
    }
}
{% endhighlight %}





Semgrep:


{% highlight php %}
rules:
  - id: sensitive-information-exposure
    patterns:
      - pattern: 'new MailMessage\(.+\, ".+"\, ".+"\, "Body: .+"\)'
    message: "Sensitive information exposure in email communication"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from ObjectCreation messageCreation
where messageCreation.getType().toString() = "System.Net.Mail.MailMessage" and
  messageCreation.getArgument(3).toString().indexOf("Body:") >= 0
select messageCreation
{% endhighlight %}




## آسیب پذیری  Cross-Site Request Forgery (CSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.Web.UI;

public partial class MyPage : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        // Noncompliant code: No CSRF protection implemented
        if (Request.QueryString["action"] == "delete")
        {
            string id = Request.QueryString["id"];
            // Delete the record with the given ID
            // ...
        }
    }
}
{% endhighlight %}



##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Web.UI;

public partial class MyPage : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        if (IsPostBack)
        {
            // Verify CSRF token
            if (ValidateCsrfToken())
            {
                // Process the request
                if (Request.QueryString["action"] == "delete")
                {
                    string id = Request.QueryString["id"];
                    // Delete the record with the given ID
                    // ...
                }
            }
            else
            {
                // CSRF token validation failed, handle the error
                // ...
            }
        }
        else
        {
            // Generate and store CSRF token in session or view state
            GenerateCsrfToken();
        }
    }

    private bool ValidateCsrfToken()
    {
        // Retrieve CSRF token from session or view state
        string csrfToken = Session["CsrfToken"] as string;

        // Compare the CSRF token from the request with the stored token
        string requestToken = Request.Form["__RequestVerificationToken"];
        return csrfToken == requestToken;
    }

    private void GenerateCsrfToken()
    {
        // Generate a unique CSRF token
        string csrfToken = Guid.NewGuid().ToString();

        // Store the CSRF token in session or view state
        Session["CsrfToken"] = csrfToken;

        // Include the CSRF token in the rendered HTML
        Page.ClientScript.RegisterHiddenField("__RequestVerificationToken", csrfToken);
    }
}
{% endhighlight %}




Semgrep:


{% highlight php %}
rules:
  - id: csrf-vulnerability
    patterns:
      - pattern: 'if \(Request\.QueryString\["action"\] == "delete"\)'
    message: "Potential CSRF vulnerability"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from MethodDeclaration method
where method.getName() = "Page_Load" and
  exists(BinaryExpression binaryExpr |
    binaryExpr.getOperator().toString() = "==" and
    binaryExpr.getLeftOperand().toString() = "Request.QueryString[\"action\"]" and
    binaryExpr.getRightOperand().toString() = "\"delete\""
  )
select method
{% endhighlight %}




## آسیب پذیری  Use of Hard-coded Password

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.Data.SqlClient;

public class DatabaseConnector
{
    private string connectionString = "Server=myServerAddress;Database=myDatabase;User Id=myUsername;Password=myPassword;";

    public void Connect()
    {
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            // Connect to the database
            connection.Open();
            // Perform database operations
            // ...
        }
    }
}
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Configuration;
using System.Data.SqlClient;

public class DatabaseConnector
{
    private string connectionString = ConfigurationManager.ConnectionStrings["MyConnectionString"].ConnectionString;

    public void Connect()
    {
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            // Connect to the database
            connection.Open();
            // Perform database operations
            // ...
        }
    }
}
{% endhighlight %}




Semgrep:


{% highlight php %}
rules:
  - id: sensitive-information-exposure
    patterns:
      - pattern: 'private string connectionString = "Server=.+;Database=.+;User Id=.+;Password=.+;"'
    message: "Sensitive information exposure in database connection string"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from FieldDeclaration field
where field.getType().toString() = "System.String" and
  field.getInitializer().toString().indexOf("Server=") >= 0 and
  field.getInitializer().toString().indexOf("Database=") >= 0 and
  field.getInitializer().toString().indexOf("User Id=") >= 0 and
  field.getInitializer().toString().indexOf("Password=") >= 0
select field
{% endhighlight %}




## آسیب پذیری  Broken or Risky Crypto Algorithm

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.Security.Cryptography;

public class CryptoUtils
{
    public string Encrypt(string data, string key)
    {
        byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
        byte[] keyBytes = System.Text.Encoding.UTF8.GetBytes(key);

        TripleDESCryptoServiceProvider desCryptoProvider = new TripleDESCryptoServiceProvider();
        desCryptoProvider.Key = keyBytes;
        desCryptoProvider.Mode = CipherMode.ECB; // Using ECB mode, which is insecure
        desCryptoProvider.Padding = PaddingMode.PKCS7;

        ICryptoTransform encryptor = desCryptoProvider.CreateEncryptor();
        byte[] encryptedData = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
        encryptor.Dispose();
        desCryptoProvider.Clear();

        return Convert.ToBase64String(encryptedData);
    }
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Security.Cryptography;

public class CryptoUtils
{
    public string Encrypt(string data, string key)
    {
        byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
        byte[] keyBytes = System.Text.Encoding.UTF8.GetBytes(key);

        using (AesCryptoServiceProvider aesCryptoProvider = new AesCryptoServiceProvider())
        {
            aesCryptoProvider.Key = keyBytes;
            aesCryptoProvider.Mode = CipherMode.CBC;
            aesCryptoProvider.Padding = PaddingMode.PKCS7;

            ICryptoTransform encryptor = aesCryptoProvider.CreateEncryptor();
            byte[] encryptedData = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
            encryptor.Dispose();
            aesCryptoProvider.Clear();

            return Convert.ToBase64String(encryptedData);
        }
    }
}
{% endhighlight %}



Semgrep:


{% highlight php %}
rules:
  - id: insecure-encryption-mode
    patterns:
      - pattern: 'desCryptoProvider.Mode = CipherMode\.ECB'
    message: "Insecure encryption mode (ECB) detected"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from Assignment assignment
where assignment.getRightOperand().toString() = "CipherMode.ECB"
select assignment
{% endhighlight %}



## آسیب پذیری  Insufficient Entropy

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;

public class RandomNumberGenerator
{
    public int GenerateRandomNumber(int minValue, int maxValue)
    {
        Random random = new Random();
        return random.Next(minValue, maxValue);
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Security.Cryptography;

public class RandomNumberGenerator
{
    public int GenerateRandomNumber(int minValue, int maxValue)
    {
        using (RNGCryptoServiceProvider rngCryptoProvider = new RNGCryptoServiceProvider())
        {
            byte[] randomBytes = new byte[4];
            rngCryptoProvider.GetBytes(randomBytes);
            int randomNumber = BitConverter.ToInt32(randomBytes, 0);

            return Math.Abs(randomNumber % (maxValue - minValue + 1)) + minValue;
        }
    }
}
{% endhighlight %}






Semgrep:


{% highlight php %}
rules:
  - id: random-without-seed
    patterns:
      - pattern: 'new Random\(\)'
    message: "Random number generator initialized without a specified seed"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from ObjectCreation randomCreation, MethodAccess randomNextAccess
where randomCreation.getType().toString() = "System.Random" and
  randomNextAccess.getTarget().toString() = randomCreation.toString() and
  not exists(Expression seedArg |
    randomCreation.getArguments() = seedArg and
    seedArg.toString().startsWith("new Random(")
  )
select randomCreation
{% endhighlight %}



## آسیب پذیری  XSS

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;

public class UserInputProcessor
{
    public string ProcessUserInput(string userInput)
    {
        string sanitizedInput = userInput.Replace("<", "&lt;").Replace(">", "&gt;");
        return sanitizedInput;
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Web;

public class UserInputProcessor
{
    public string ProcessUserInput(string userInput)
    {
        string sanitizedInput = HttpUtility.HtmlEncode(userInput);
        return sanitizedInput;
    }
}
{% endhighlight %}



Semgrep:


{% highlight php %}
rules:
  - id: xss-sanitization
    patterns:
      - pattern: 'Replace\(\"<\"'
    message: "Potential XSS vulnerability: User input not properly sanitized"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from MethodInvocation replaceMethod
where replaceMethod.getTarget().toString() = "userInput.Replace"
select replaceMethod
{% endhighlight %}




## آسیب پذیری  SQL Injection

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.Data.SqlClient;

public class UserLogin
{
    public bool AuthenticateUser(string username, string password)
    {
        string query = "SELECT COUNT(*) FROM Users WHERE Username='" + username + "' AND Password='" + password + "'";
        using (SqlConnection connection = new SqlConnection("Data Source=example.com;Initial Catalog=MyDB;User ID=sa;Password=pass123"))
        {
            SqlCommand command = new SqlCommand(query, connection);
            connection.Open();
            int count = (int)command.ExecuteScalar();
            return count > 0;
        }
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Data.SqlClient;

public class UserLogin
{
    public bool AuthenticateUser(string username, string password)
    {
        string query = "SELECT COUNT(*) FROM Users WHERE Username=@Username AND Password=@Password";
        using (SqlConnection connection = new SqlConnection("Data Source=example.com;Initial Catalog=MyDB;User ID=sa;Password=pass123"))
        {
            SqlCommand command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Username", username);
            command.Parameters.AddWithValue("@Password", password);
            connection.Open();
            int count = (int)command.ExecuteScalar();
            return count > 0;
        }
    }
}
{% endhighlight %}




Semgrep:


{% highlight php %}
rules:
  - id: sql-injection
    patterns:
      - pattern: 'SELECT .* FROM .* WHERE .*'
    message: "Potential SQL injection vulnerability: User input not properly parameterized"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from BinaryExpression binaryExpr
where binaryExpr.getLeftOperand().toString().startsWith("\"SELECT ") and
  binaryExpr.getOperator().toString() = "+" and
  binaryExpr.getRightOperand().toString().contains("\"")
select binaryExpr
{% endhighlight %}



## آسیب پذیری  External Control of File Name or Path

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.IO;

public class FileProcessor
{
    public void ProcessFile(string fileName)
    {
        string filePath = "C:\\Temp\\" + fileName;
        if (File.Exists(filePath))
        {
            // Process the file
        }
        else
        {
            Console.WriteLine("File not found.");
        }
    }
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.IO;

public class FileProcessor
{
    private readonly string baseDirectory = "C:\\Temp\\";

    public void ProcessFile(string fileName)
    {
        string sanitizedFileName = Path.GetFileName(fileName);
        string filePath = Path.Combine(baseDirectory, sanitizedFileName);
        if (File.Exists(filePath))
        {
            // Process the file
        }
        else
        {
            Console.WriteLine("File not found.");
        }
    }
}
{% endhighlight %}





Semgrep:


{% highlight php %}
rules:
  - id: path-traversal
    patterns:
      - pattern: 'C:\\Temp\\\\'
    message: "Potential path traversal vulnerability: Unsanitized file path concatenation"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from Addition addExpr
where addExpr.getLeftOperand().toString() = "\"C:\\Temp\\" and
  addExpr.getOperator().toString() = "+" and
  addExpr.getRightOperand().toString().contains("\"")
select addExpr
{% endhighlight %}



## آسیب پذیری  Generation of Error Message Containing Sensitive Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;

public class UserController
{
    public void AuthenticateUser(string username, string password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Invalid username or password.");
        }

        // Authenticate the user
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
using System;

public class UserController
{
    public void AuthenticateUser(string username, string password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Invalid credentials.");
        }

        // Authenticate the user
    }
}
{% endhighlight %}




Semgrep:


{% highlight php %}
rules:
  - id: empty-username-password
    patterns:
      - pattern: 'string.IsNullOrEmpty\({{ _ }}\)'
    message: "Potential issue: Empty or null username or password"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from Invocation invocation
where invocation.getTarget().toString() = "string.IsNullOrEmpty" and
  invocation.getArgument(0).toString() = "{{ _ }}"
select invocation
{% endhighlight %}


## آسیب پذیری  unprotected storage of credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;

public class UserController
{
    private string _username;
    private string _password;

    public void SetCredentials(string username, string password)
    {
        _username = username;
        _password = password;
    }

    public void AuthenticateUser()
    {
        // Authenticate the user using the stored credentials
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Security.Cryptography;

public class UserController
{
    private byte[] _encryptedCredentials;

    public void SetCredentials(string username, string password)
    {
        byte[] encryptedUsername = EncryptData(username);
        byte[] encryptedPassword = EncryptData(password);

        _encryptedCredentials = CombineArrays(encryptedUsername, encryptedPassword);
    }

    public void AuthenticateUser()
    {
        // Decrypt and use the stored credentials for user authentication
        string decryptedUsername = DecryptData(GetUsernameFromEncryptedCredentials());
        string decryptedPassword = DecryptData(GetPasswordFromEncryptedCredentials());

        // Authenticate the user using the decrypted credentials
    }

    private byte[] EncryptData(string data)
    {
        // Use a secure encryption algorithm (e.g., AES) to encrypt the data
        // and return the encrypted byte array
        // ...
    }

    private string DecryptData(byte[] encryptedData)
    {
        // Use the same encryption algorithm and decryption process
        // to decrypt the data and return the plaintext
        // ...
    }

    private byte[] CombineArrays(byte[] array1, byte[] array2)
    {
        // Combine two byte arrays into one
        // ...
    }

    private byte[] GetUsernameFromEncryptedCredentials()
    {
        // Extract and return the encrypted username from the stored credentials
        // ...
    }

    private byte[] GetPasswordFromEncryptedCredentials()
    {
        // Extract and return the encrypted password from the stored credentials
        // ...
    }
}
{% endhighlight %}




Semgrep:


{% highlight php %}
rules:
  - id: insecure-credentials-storage
    patterns:
      - pattern: '_username = {{ _ }}'
      - pattern: '_password = {{ _ }}'
    message: "Potential security issue: Credentials stored in memory"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

class StoredCredentials extends FieldAccess {
  StoredCredentials() {
    this.getTarget().toString().matches("_username") or
    this.getTarget().toString().matches("_password")
  }
}

from StoredCredentials access
select access
{% endhighlight %}


## آسیب پذیری  Trust Boundary Violation

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;

public class PaymentController
{
    private string _creditCardNumber;

    public void ProcessPayment(string creditCardNumber)
    {
        _creditCardNumber = creditCardNumber;
        // Process the payment using the credit card number
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
using System;

public class PaymentController
{
    public void ProcessPayment(string creditCardNumber)
    {
        // Perform input validation and sanitization of the credit card number
        if (IsValidCreditCardNumber(creditCardNumber))
        {
            // Process the payment using the credit card number
        }
        else
        {
            // Handle the case when an invalid credit card number is provided
        }
    }

    private bool IsValidCreditCardNumber(string creditCardNumber)
    {
        // Implement proper credit card number validation logic
        // to ensure the input meets the required format and integrity
        // ...
    }
}
{% endhighlight %}





Semgrep:


{% highlight php %}
rules:
  - id: insecure-credit-card-storage
    patterns:
      - pattern: '_creditCardNumber = {{ _ }}'
    message: "Potential security issue: Credit card number stored in memory"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

class StoredCreditCardNumber extends FieldAccess {
  StoredCreditCardNumber() {
    this.getTarget().toString().matches("_creditCardNumber")
  }
}

from StoredCreditCardNumber access
select access
{% endhighlight %}



## آسیب پذیری  Insufficiently Protected Credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;

public class LoginController
{
    private string _username;
    private string _password;

    public bool Authenticate(string username, string password)
    {
        _username = username;
        _password = password;
        
        // Perform authentication logic
        // ...
        
        return true;
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Security.Cryptography;

public class LoginController
{
    public bool Authenticate(string username, string password)
    {
        string hashedPassword = HashPassword(password);
        
        // Perform authentication logic using the hashed password
        // ...
        
        return true;
    }

    private string HashPassword(string password)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] hashedBytes = sha256.ComputeHash(passwordBytes);
            return Convert.ToBase64String(hashedBytes);
        }
    }
}
{% endhighlight %}








Semgrep:


{% highlight php %}
rules:
  - id: insecure-sensitive-data-storage
    patterns:
      - pattern: '_username = {{ _ }}'
      - pattern: '_password = {{ _ }}'
    message: "Potential security issue: Sensitive data stored in memory"
{% endhighlight %}

CodeQL:



{% highlight php %}
rules:
  - id: insecure-sensitive-data-storage
    patterns:
      - pattern: '_username = {{ _ }}'
      - pattern: '_password = {{ _ }}'
    message: "Potential security issue: Sensitive data stored in memory"
{% endhighlight %}




## آسیب پذیری  Restriction of XML External Entity Reference

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.Xml;

public class XmlParser
{
    public void ParseXml(string xmlContent)
    {
        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.LoadXml(xmlContent);
        
        // Process the XML document
        // ...
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Xml;

public class XmlParser
{
    public void ParseXml(string xmlContent)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;

        using (XmlReader reader = XmlReader.Create(new System.IO.StringReader(xmlContent), settings))
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(reader);

            // Process the XML document
            // ...
        }
    }
}
{% endhighlight %}






Semgrep:


{% highlight php %}
rules:
  - id: xml-parsing-insecure
    pattern: |
      XmlDocument xmlDoc = new XmlDocument();
      xmlDoc.LoadXml({{ _ }});
    message: "Potential security issue: Insecure XML parsing"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

class InsecureXmlParsing extends MethodCall {
  InsecureXmlParsing() {
    this.getTarget().toString().matches("XmlDocument.LoadXml")
  }
}

from InsecureXmlParsing call
select call
{% endhighlight %}



## آسیب پذیری  Vulnerable and Outdated Components


##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using Newtonsoft.Json;

public class UserData
{
    public string Name { get; set; }
    public string Email { get; set; }
}

public class UserController
{
    public void GetUserDetails()
    {
        // Fetch user data from the database
        UserData user = Database.GetUserDetails();

        // Convert user data to JSON
        string json = JsonConvert.SerializeObject(user);

        // Send the JSON response to the client
        HttpResponse.Write(json);
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Text.Json;

public class UserData
{
    public string Name { get; set; }
    public string Email { get; set; }
}

public class UserController
{
    public void GetUserDetails()
    {
        // Fetch user data from the database
        UserData user = Database.GetUserDetails();

        // Convert user data to JSON
        string json = JsonSerializer.Serialize(user);

        // Send the JSON response to the client
        HttpResponse.Write(json);
    }
}
{% endhighlight %}






Semgrep:


{% highlight php %}
rules:
  - id: json-serialization-insecure
    pattern: |
      JsonConvert.SerializeObject({{ _ }});
    message: "Potential security issue: Insecure JSON serialization"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

class InsecureJsonSerialization extends MethodCall {
  InsecureJsonSerialization() {
    this.getTarget().toString().matches("JsonConvert.SerializeObject")
  }
}

from InsecureJsonSerialization call
select call
{% endhighlight %}



## آسیب پذیری  Improper Validation of Certificate with Host Mismatch

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.Net.Http;

public class HttpClientExample
{
    public void SendRequest()
    {
        // Create HttpClient instance
        HttpClient client = new HttpClient();

        // Disable SSL certificate validation
        ServicePointManager.ServerCertificateValidationCallback +=
            (sender, certificate, chain, sslPolicyErrors) => true;

        // Send a request to a remote server
        HttpResponseMessage response = client.GetAsync("https://example.com").Result;

        // Process the response
        if (response.IsSuccessStatusCode)
        {
            // Do something with the successful response
            Console.WriteLine("Request succeeded!");
        }
        else
        {
            // Handle the error response
            Console.WriteLine("Request failed!");
        }
    }
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Net.Http;

public class HttpClientExample
{
    public void SendRequest()
    {
        // Create HttpClient instance
        HttpClient client = new HttpClient();

        // Enable SSL certificate validation
        ServicePointManager.ServerCertificateValidationCallback +=
            (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (sslPolicyErrors == SslPolicyErrors.None)
                    return true;
                
                // Check if the certificate matches the host
                string requestedHost = new Uri("https://example.com").Host;
                return certificate.Subject.Equals($"CN={requestedHost}", StringComparison.OrdinalIgnoreCase);
            };

        // Send a request to a remote server
        HttpResponseMessage response = client.GetAsync("https://example.com").Result;

        // Process the response
        if (response.IsSuccessStatusCode)
        {
            // Do something with the successful response
            Console.WriteLine("Request succeeded!");
        }
        else
        {
            // Handle the error response
            Console.WriteLine("Request failed!");
        }
    }
}
{% endhighlight %}




Semgrep:


{% highlight php %}
rules:
  - id: disable-ssl-certificate-validation
    pattern: |
      ServicePointManager.ServerCertificateValidationCallback += {{ _ }};
    message: "Potential security issue: Disabling SSL certificate validation"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

class DisableSSLCertificateValidation extends MethodCall {
  DisableSSLCertificateValidation() {
    this.getTarget().toString().matches("ServicePointManager.ServerCertificateValidationCallback +=")
  }
}

from DisableSSLCertificateValidation call
select call
{% endhighlight %}





## آسیب پذیری  Improper Authentication

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.Data.SqlClient;

public class AuthenticationExample
{
    public bool AuthenticateUser(string username, string password)
    {
        string connectionString = "Data Source=...;Initial Catalog=...;User ID=...;Password=...";

        // Construct the SQL query with user-provided input
        string query = $"SELECT * FROM Users WHERE Username = '{username}' AND Password = '{password}'";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            SqlCommand command = new SqlCommand(query, connection);

            // Open the connection
            connection.Open();

            // Execute the query
            SqlDataReader reader = command.ExecuteReader();

            // Check if the user exists
            bool userExists = reader.HasRows;

            // Close the connection
            connection.Close();

            return userExists;
        }
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Data.SqlClient;

public class AuthenticationExample
{
    public bool AuthenticateUser(string username, string password)
    {
        string connectionString = "Data Source=...;Initial Catalog=...;User ID=...;Password=...";

        // Construct the parameterized SQL query
        string query = "SELECT * FROM Users WHERE Username = @username AND Password = @password";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            SqlCommand command = new SqlCommand(query, connection);

            // Add parameters to the command
            command.Parameters.AddWithValue("@username", username);
            command.Parameters.AddWithValue("@password", password);

            // Open the connection
            connection.Open();

            // Execute the query
            SqlDataReader reader = command.ExecuteReader();

            // Check if the user exists
            bool userExists = reader.HasRows;

            // Close the connection
            connection.Close();

            return userExists;
        }
    }
}
{% endhighlight %}





Semgrep:


{% highlight php %}
rules:
  - id: sql-injection
    pattern: |
      SqlCommand command = new SqlCommand({{ query }}, {{ connection }});
    message: "Potential SQL injection vulnerability"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

class SQLInjection extends MethodCall {
  SQLInjection() {
    this.getTarget().toString().matches("SqlCommand SqlCommand(SqlConnection, String)")
    or
    this.getTarget().toString().matches("SqlCommand SqlCommand(SqlConnection, String, SqlConnection)")
  }
}

from SQLInjection call, DataFlow::PathNode query
where query.asExpr().getValue().toString().matches(".*[\"'].*")
select query, call
{% endhighlight %}




## آسیب پذیری  Session Fixation

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.Web;

public class SessionFixationExample
{
    public void Login(string username)
    {
        // Create a new session
        HttpSessionState session = HttpContext.Current.Session;

        // Set the username in the session
        session["username"] = username;
    }

    public bool IsUserAuthenticated()
    {
        // Retrieve the session
        HttpSessionState session = HttpContext.Current.Session;

        // Check if the username exists in the session
        return session["username"] != null;
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Web;

public class SessionFixationExample
{
    public void Login(string username)
    {
        // Create a new session
        HttpSessionState session = HttpContext.Current.Session;

        // Set the username in the session
        session["username"] = username;

        // Regenerate the session ID
        session.RegenerateID();
    }

    public bool IsUserAuthenticated()
    {
        // Retrieve the session
        HttpSessionState session = HttpContext.Current.Session;

        // Check if the username exists in the session
        return session["username"] != null;
    }
}
{% endhighlight %}






Semgrep:


{% highlight php %}
rules:
  - id: session-fixation
    pattern: |
      HttpSessionState session = HttpContext.Current.Session;
    message: "Potential session fixation vulnerability"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

class SessionFixation extends MethodAccess {
  SessionFixation() {
    this.getTarget().toString().matches("HttpSessionState HttpSessionState(HttpContext)")
  }
}

from SessionFixation call, DataFlow::PathNode session
select session, call
{% endhighlight %}


## آسیب پذیری  Inclusion of Functionality from Untrusted Control

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.Diagnostics;
using System.IO;

public class FileUploader
{
    public void UploadFile(string filename, byte[] fileData)
    {
        // Save the uploaded file to a specified directory
        string savePath = "C:\\Uploads\\" + filename;
        File.WriteAllBytes(savePath, fileData);
        
        // Execute a command on the uploaded file
        string command = "C:\\Windows\\System32\\cmd.exe /C echo File uploaded successfully!";
        Process.Start(command, savePath);
    }
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Diagnostics;
using System.IO;

public class FileUploader
{
    public void UploadFile(string filename, byte[] fileData)
    {
        // Validate and sanitize the filename
        string sanitizedFilename = SanitizeFilename(filename);
        if (sanitizedFilename == null)
        {
            // Invalid filename, abort the upload
            return;
        }

        // Save the uploaded file to a specified directory
        string savePath = "C:\\Uploads\\" + sanitizedFilename;
        File.WriteAllBytes(savePath, fileData);
        
        // Perform other operations on the uploaded file (e.g., logging, virus scanning)

        // Notify the user about the successful upload
        Console.WriteLine("File uploaded successfully!");
    }

    private string SanitizeFilename(string filename)
    {
        // Implement proper filename validation and sanitization logic
        // Ensure that the filename conforms to your desired format and does not contain any malicious characters or path traversal sequences
        
        // Example implementation: removing any path information and disallowing specific characters
        string sanitizedFilename = Path.GetFileName(filename);
        if (sanitizedFilename.IndexOfAny(Path.GetInvalidFileNameChars()) != -1)
        {
            // Invalid filename, return null
            return null;
        }

        return sanitizedFilename;
    }
}
{% endhighlight %}





Semgrep:


{% highlight php %}
rules:
  - id: directory-traversal
    pattern: File.WriteAllBytes($savePath, $fileData)
    message: "Potential directory traversal vulnerability when saving file"
{% endhighlight %}

CodeQL:



{% highlight php %}
rules:
  - id: directory-traversal
    pattern: File.WriteAllBytes($savePath, $fileData)
    message: "Potential directory traversal vulnerability when saving file"
{% endhighlight %}



## آسیب پذیری  Download of Code Without Integrity Check

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.Net;

public class CodeDownloader
{
    public void DownloadCode(string url)
    {
        using (WebClient client = new WebClient())
        {
            string code = client.DownloadString(url);
            
            // Execute the downloaded code
            ExecuteCode(code);
        }
    }

    private void ExecuteCode(string code)
    {
        // Execute the downloaded code without performing an integrity check
        Console.WriteLine("Executing downloaded code: " + code);
        // ...
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;

public class CodeDownloader
{
    public void DownloadCode(string url)
    {
        using (WebClient client = new WebClient())
        {
            byte[] downloadedData = client.DownloadData(url);
            
            // Verify the integrity of the downloaded code
            if (IsCodeIntegrityValid(downloadedData))
            {
                string code = Encoding.UTF8.GetString(downloadedData);
                
                // Execute the downloaded code
                ExecuteCode(code);
            }
            else
            {
                Console.WriteLine("Code integrity check failed. Aborting execution.");
            }
        }
    }

    private bool IsCodeIntegrityValid(byte[] downloadedData)
    {
        // Implement integrity check logic here
        // For example, calculate the hash of the downloaded code and compare it with a trusted hash value
        
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] hash = sha256.ComputeHash(downloadedData);

            // Compare the calculated hash with the trusted hash value
            byte[] trustedHash = GetTrustedHash(); // Retrieve the trusted hash value from a secure source

            return ByteArrayEquals(hash, trustedHash);
        }
    }

    private bool ByteArrayEquals(byte[] array1, byte[] array2)
    {
        // Compare two byte arrays for equality
        if (array1.Length != array2.Length)
            return false;

        for (int i = 0; i < array1.Length; i++)
        {
            if (array1[i] != array2[i])
                return false;
        }

        return true;
    }

    private void ExecuteCode(string code)
    {
        // Execute the downloaded code
        Console.WriteLine("Executing downloaded code: " + code);
        // ...
    }
}
{% endhighlight %}






Semgrep:


{% highlight php %}
rules:
  - id: insecure-code-download
    pattern: WebClient().DownloadString($url)
    message: "Potential security risk: Insecure code download"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

class CodeDownload extends MethodCall {
  CodeDownload() {
    this.getTarget().toString().matches("WebClient().DownloadString($url)")
  }
}

from CodeDownload
select CodeDownload
{% endhighlight %}


## آسیب پذیری  Deserialization of Untrusted Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

public class DataDeserializer
{
    public object DeserializeData(byte[] data)
    {
        BinaryFormatter formatter = new BinaryFormatter();
        MemoryStream memoryStream = new MemoryStream(data);
        
        // Deserialize the untrusted data
        object deserializedData = formatter.Deserialize(memoryStream);
        
        return deserializedData;
    }
}
{% endhighlight %}






Semgrep:


{% highlight php %}
rules:
  - id: insecure-data-deserialization
    pattern: BinaryFormatter().Deserialize($stream)
    message: "Potential security risk: Insecure data deserialization"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

class DataDeserialization extends MethodCall {
  DataDeserialization() {
    this.getTarget().toString().matches("BinaryFormatter().Deserialize($stream)")
  }
}

from DataDeserialization
select DataDeserialization
{% endhighlight %}



##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

public class DataDeserializer
{
    public object DeserializeData(byte[] data)
    {
        BinaryFormatter formatter = new BinaryFormatter();
        
        // Set up a custom SerializationBinder to restrict deserialization to trusted types
        formatter.Binder = new TrustedSerializationBinder();
        
        using (MemoryStream memoryStream = new MemoryStream(data))
        {
            try
            {
                // Deserialize the data with proper validation
                object deserializedData = formatter.Deserialize(memoryStream);
                
                // Perform additional validation on the deserialized object, if required
                
                return deserializedData;
            }
            catch (SerializationException ex)
            {
                Console.WriteLine("Error occurred during deserialization: " + ex.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Unexpected error occurred: " + ex.Message);
            }
        }
        
        return null;
    }
}

// Custom SerializationBinder to restrict deserialization to trusted types
public class TrustedSerializationBinder : SerializationBinder
{
    public override Type BindToType(string assemblyName, string typeName)
    {
        // Check if the requested type is trusted
        if (IsTypeTrusted(typeName))
        {
            // Return the trusted type for deserialization
            Type trustedType = GetTypeFromTrustedAssembly(typeName);
            return trustedType;
        }
        
        // For untrusted types, throw an exception or return null to prevent deserialization
        throw new SerializationException("Attempted deserialization of untrusted type: " + typeName);
    }
    
    private bool IsTypeTrusted(string typeName)
    {
        // Implement your logic to determine if the type is trusted
        // For example, maintain a whitelist of trusted types
        
        // Return true if the type is trusted, false otherwise
        // ...
    }
    
    private Type GetTypeFromTrustedAssembly(string typeName)
    {
        // Retrieve the trusted type from a known and trusted assembly
        // For example, look up the type in a predefined assembly
        
        // Return the Type object for the trusted type
        // ...
    }
}
{% endhighlight %}





Semgrep:


{% highlight php %}
rules:
  - id: secure-data-deserialization
    pattern: BinaryFormatter().{ Deserialize($stream), Deserialize($stream, out _) }
    message: "Ensure secure data deserialization"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

class DataDeserialization extends MethodCall {
  DataDeserialization() {
    this.getTarget().toString().matches("BinaryFormatter().{ Deserialize($stream), Deserialize($stream, out _) }")
  }
}

class DeserializationExceptionHandling extends TryStatement {
  DeserializationExceptionHandling() {
    getBody() instanceof Block and
    getBody().getChildren().get(0) instanceof ThrowStatement and
    getBody().getChildren().get(1) instanceof CatchClause
  }
}

from DataDeserialization d, DeserializationExceptionHandling e
where d.getAncestor(Statement+) = e.getAncestor(Statement+)
select d, e
{% endhighlight %}





## آسیب پذیری  Insufficient Logging

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;

public class PaymentProcessor
{
    public void ProcessPayment(double amount, string creditCardNumber)
    {
        // Process the payment logic
        
        try
        {
            // Perform payment processing
            
            // Log a success message
            Console.WriteLine("Payment processed successfully.");
        }
        catch (Exception ex)
        {
            // Log the exception message only
            Console.WriteLine("Payment processing failed. Exception: " + ex.Message);
        }
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.IO;

public class PaymentProcessor
{
    private readonly ILogger logger;

    public PaymentProcessor(ILogger logger)
    {
        this.logger = logger;
    }

    public void ProcessPayment(double amount, string creditCardNumber)
    {
        try
        {
            // Perform payment processing

            // Log a success message with detailed information
            string logMessage = $"Payment processed successfully. Amount: {amount}, Credit Card: {MaskCreditCardNumber(creditCardNumber)}";
            logger.LogInfo(logMessage);
        }
        catch (Exception ex)
        {
            // Log the exception with detailed information
            string errorMessage = $"Payment processing failed. Amount: {amount}, Credit Card: {MaskCreditCardNumber(creditCardNumber)}, Exception: {ex}";
            logger.LogError(errorMessage);
        }
    }

    private string MaskCreditCardNumber(string creditCardNumber)
    {
        // Implement logic to mask sensitive information
        // For example, replace all but the last four digits with asterisks
        int maskLength = creditCardNumber.Length - 4;
        string maskedNumber = new string('*', maskLength) + creditCardNumber.Substring(maskLength);
        return maskedNumber;
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
{% endhighlight %}





Semgrep:


{% highlight php %}
rules:
  - id: secure-payment-processing
    pattern: |
      try {
        $processPaymentExpr
      } catch (Exception $ex) {
        Console.WriteLine("Payment processing failed. Exception: " + $ex.Message);
      }
    message: "Ensure secure payment processing"
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

class PaymentProcessing extends TryStatement {
  PaymentProcessing() {
    getBody() instanceof Block and
    getBody().getChildren().get(0) instanceof ExpressionStatement and
    getBody().getChildren().get(0).getChildren().get(0).toString().matches("$processPaymentExpr")
  }
}

from PaymentProcessing p
select p
{% endhighlight %}




## آسیب پذیری  Improper Output Neutralization for Logs

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;

public class LoginController
{
    private readonly ILogger logger;

    public LoginController(ILogger logger)
    {
        this.logger = logger;
    }

    public void LogUserLogin(string username)
    {
        // Log the user login
        logger.LogInfo("User login: " + username);
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
using System;

public class LoginController
{
    private readonly ILogger logger;

    public LoginController(ILogger logger)
    {
        this.logger = logger;
    }

    public void LogUserLogin(string username)
    {
        // Log the user login with neutralized output
        string logMessage = $"User login: {NeutralizeLogOutput(username)}";
        logger.LogInfo(logMessage);
    }

    private string NeutralizeLogOutput(string input)
    {
        // Implement logic to neutralize special characters or control characters in the log output
        // For example, replace newlines, carriage returns, or other potentially dangerous characters
        string neutralizedOutput = input.Replace("\r", "").Replace("\n", "");
        return neutralizedOutput;
    }
}

public interface ILogger
{
    void LogInfo(string message);
}
{% endhighlight %}





Semgrep:


{% highlight php %}
rules:
  - id: improper-output-neutralization
    pattern: |
      using System;
      
      public class LoginController
      {
          private readonly ILogger logger;
      
          public LoginController(ILogger logger)
          {
              this.logger = logger;
          }
      
          public void LogUserLogin(string username)
          {
              // Log the user login
              logger.LogInfo("User login: " + $username);
          }
      }
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from MethodAccess ma, MethodAccess ma2, StringConcatenation concat
where
  ma.getTarget().getType().getQualifiedName() = "ILogger" and
  ma.getTarget().hasQualifiedName("ILogger", "LogInfo") and
  ma2.getTarget().getType().getQualifiedName() = "LoginController" and
  ma2.getTarget().getName() = "LogUserLogin" and
  concat.getAnOperand() = ma2.getTarget() and
  concat.getParent*().getAPrimaryQlClass() instanceof ExpressionStatement
select ma2, "Improper output neutralization for logs"
{% endhighlight %}




## آسیب پذیری  Omission of Security-relevant Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;

public class PaymentController
{
    private readonly ILogger logger;

    public PaymentController(ILogger logger)
    {
        this.logger = logger;
    }

    public void ProcessPayment(decimal amount)
    {
        // Process payment logic
        try
        {
            // Payment processing code here...

            logger.LogInfo("Payment processed successfully");
        }
        catch (Exception ex)
        {
            logger.LogError("Payment processing failed");
        }
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
using System;

public class PaymentController
{
    private readonly ILogger logger;

    public PaymentController(ILogger logger)
    {
        this.logger = logger;
    }

    public void ProcessPayment(decimal amount)
    {
        // Process payment logic
        try
        {
            // Payment processing code here...

            logger.LogInfo($"Payment processed successfully. Amount: {amount}");
        }
        catch (Exception ex)
        {
            logger.LogError($"Payment processing failed. Amount: {amount}. Error: {ex.Message}");
        }
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
{% endhighlight %}







Semgrep:


{% highlight php %}
rules:
  - id: improper-output-neutralization
    pattern: |
      using System;
      
      public class PaymentController
      {
          private readonly ILogger logger;
      
          public PaymentController(ILogger logger)
          {
              this.logger = logger;
          }
      
          public void ProcessPayment(decimal amount)
          {
              // Process payment logic
              try
              {
                  // Payment processing code here...
      
                  logger.LogInfo($"Payment processed successfully: {amount}");
              }
              catch (Exception ex)
              {
                  logger.LogError("Payment processing failed");
              }
          }
      }
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from MethodAccess ma, MethodAccess ma2, StringConcatenation concat
where
  ma.getTarget().getType().getQualifiedName() = "ILogger" and
  ma.getTarget().hasQualifiedName("ILogger", "LogInfo") and
  ma2.getTarget().getType().getQualifiedName() = "PaymentController" and
  ma2.getTarget().getName() = "ProcessPayment" and
  concat.getAnOperand() = ma2.getTarget() and
  concat.getParent*().getAPrimaryQlClass() instanceof ExpressionStatement
select ma2, "Improper output neutralization for logs"
{% endhighlight %}






## آسیب پذیری  Sensitive Information into Log File

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.IO;

public class UserController
{
    private readonly ILogger logger;

    public UserController(ILogger logger)
    {
        this.logger = logger;
    }

    public void CreateUser(string username, string password)
    {
        try
        {
            // User creation logic here...

            logger.LogInfo($"User '{username}' created successfully");
        }
        catch (Exception ex)
        {
            logger.LogError($"Failed to create user '{username}'");
        }
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.IO;

public class UserController
{
    private readonly ILogger logger;

    public UserController(ILogger logger)
    {
        this.logger = logger;
    }

    public void CreateUser(string username)
    {
        try
        {
            // User creation logic here...

            logger.LogInfo($"User '{username}' created successfully");
        }
        catch (Exception ex)
        {
            logger.LogError($"Failed to create user '{username}'");
        }
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
{% endhighlight %}




Semgrep:


{% highlight php %}
rules:
  - id: improper-output-neutralization
    pattern: |
      using System;
      using System.IO;

      public class UserController
      {
          private readonly ILogger logger;

          public UserController(ILogger logger)
          {
              this.logger = logger;
          }

          public void CreateUser(string username, string password)
          {
              try
              {
                  // User creation logic here...

                  logger.LogInfo($"User '{username}' created successfully");
              }
              catch (Exception ex)
              {
                  logger.LogError($"Failed to create user '{username}'");
              }
          }
      }
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from MethodAccess ma, MethodAccess ma2, StringConcatenation concat
where
  ma.getTarget().getType().getQualifiedName() = "ILogger" and
  ma.getTarget().hasQualifiedName("ILogger", "LogInfo") and
  ma2.getTarget().getType().getQualifiedName() = "UserController" and
  ma2.getTarget().getName() = "CreateUser" and
  concat.getAnOperand() = ma2.getTarget() and
  concat.getParent*().getAPrimaryQlClass() instanceof ExpressionStatement
select ma2, "Improper output neutralization for logs"
{% endhighlight %}






## آسیب پذیری  Server-Side Request Forgery (SSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
using System;
using System.Net;

public class ImageController
{
    public void DisplayImage(string url)
    {
        WebClient client = new WebClient();
        byte[] imageData = client.DownloadData(url);

        // Display the image on the website
        // ...
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
using System;
using System.Net;

public class ImageController
{
    public void DisplayImage(string url)
    {
        if (!IsAllowedURL(url))
        {
            throw new ArgumentException("Invalid image URL");
        }

        WebClient client = new WebClient();
        byte[] imageData = client.DownloadData(url);

        // Display the image on the website
        // ...
    }

    private bool IsAllowedURL(string url)
    {
        // Implement logic to check if the URL is allowed
        // Example: Validate against a whitelist of trusted domains or patterns
        // ...
    }
}
{% endhighlight %}





Semgrep:


{% highlight php %}
metadata:
  difficulty: Easy

rules:
  - id: display-image-insecure
    message: "Insecure image display: Potential security vulnerability when displaying images from external sources."
    severity: warning
    languages:
      - csharp
    patterns:
      - pattern: "WebClient client = new WebClient();\nbyte\\[\\] imageData = client.DownloadData($url$);"
        capture:
          - variable: url
{% endhighlight %}

CodeQL:



{% highlight php %}
import csharp

from MethodAccess ma
where ma.getMethod().getName() = "DownloadData" and ma.getQualifier().getType().getName() = "WebClient"
select ma
{% endhighlight %}
