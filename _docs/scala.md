---
title: Scala
tags: 
 - scala
description: Scala Vulnerabilities
---

# Scala



## آسیب پذیری Exposure of sensitive information


##### 🐞 کد آسیب پذیر




{% highlight php %}
// Noncompliant code - exposing sensitive information in error log
def processUserInput(input: String): Unit = {
  // Process user input
  // ...
  
  // Log error with sensitive information
  val errorMessage = s"Error processing user input: $input"
  Logger.error(errorMessage)
}

{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - avoiding exposure of sensitive information in error log
def processUserInput(input: String): Unit = {
  // Process user input
  // ...
  
  // Log error without sensitive information
  Logger.error("Error processing user input")
}
{% endhighlight %}





## آسیب پذیری Insertion of Sensitive Information Into Sent Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code - inserting sensitive information into sent data
def sendUserData(userId: String): Unit = {
  // Retrieve user data
  val userData = retrieveUserData(userId)
  
  // Insert sensitive information into sent data
  val sentData = s"User data: $userData"
  sendRequest(sentData)
}

def retrieveUserData(userId: String): String = {
  // Retrieve user data from the database
  // ...
  // Return the user data as a string
}

def sendRequest(data: String): Unit = {
  // Send the data to a remote server
  // ...
}
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - avoiding insertion of sensitive information into sent data
def sendUserData(userId: String): Unit = {
  // Retrieve user data
  val userData = retrieveUserData(userId)
  
  // Send the user data without inserting sensitive information
  sendRequest(userData)
}

def retrieveUserData(userId: String): String = {
  // Retrieve user data from the database
  // ...
  // Return the user data as a string
}

def sendRequest(data: String): Unit = {
  // Send the data to a remote server
  // ...
}
{% endhighlight %}






## آسیب پذیری  Cross-Site Request Forgery (CSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code - lack of CSRF protection
def transferFunds(request: Request): Response = {
  val sourceAccount = request.getParameter("sourceAccount")
  val destinationAccount = request.getParameter("destinationAccount")
  val amount = request.getParameter("amount")
  
  // Perform fund transfer logic
  // ...
  
  // Return response
  // ...
}
{% endhighlight %}



##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - CSRF protection using tokens
def transferFunds(request: Request): Response = {
  val sourceAccount = request.getParameter("sourceAccount")
  val destinationAccount = request.getParameter("destinationAccount")
  val amount = request.getParameter("amount")
  
  // Verify CSRF token
  val csrfToken = request.getParameter("csrfToken")
  if (!validateCsrfToken(csrfToken)) {
    // CSRF token validation failed, handle the error or return an appropriate response
    // ...
  }
  
  // Perform fund transfer logic
  // ...
  
  // Return response
  // ...
}

def validateCsrfToken(csrfToken: String): Boolean = {
  // Validate the CSRF token against a stored value or session token
  // Return true if the token is valid, false otherwise
  // ...
}
{% endhighlight %}





## آسیب پذیری  Use of Hard-coded Password

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code - hard-coded password
def authenticate(username: String, password: String): Boolean = {
  // Hard-coded password for authentication
  if (password == "myPassword123") {
    // Authentication successful
    true
  } else {
    // Authentication failed
    false
  }
}
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - use of secure password storage
def authenticate(username: String, password: String): Boolean = {
  // Retrieve the stored password hash for the user from a secure database or password storage mechanism
  val storedPasswordHash = getStoredPasswordHash(username)
  
  // Compare the entered password with the stored password hash using a secure password hashing algorithm
  val isPasswordValid = verifyPassword(password, storedPasswordHash)
  
  isPasswordValid
}

def getStoredPasswordHash(username: String): String = {
  // Retrieve the stored password hash for the user from a secure database or password storage mechanism
  // ...
}

def verifyPassword(password: String, storedPasswordHash: String): Boolean = {
  // Use a secure password hashing algorithm (e.g., bcrypt, Argon2, scrypt) to verify the password
  // Compare the password hash derived from the entered password with the stored password hash
  // Return true if the password is valid, false otherwise
  // ...
}
{% endhighlight %}








## آسیب پذیری  Broken or Risky Crypto Algorithm

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.security.MessageDigest

// Noncompliant code - uses weak MD5 hashing algorithm
def hashPassword(password: String): String = {
  val md = MessageDigest.getInstance("MD5")
  val bytes = password.getBytes("UTF-8")
  val digest = md.digest(bytes)
  val hashedPassword = digest.map("%02x".format(_)).mkString
  hashedPassword
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import java.security.MessageDigest

// Compliant code - uses secure SHA-256 hashing algorithm
def hashPassword(password: String): String = {
  val md = MessageDigest.getInstance("SHA-256")
  val bytes = password.getBytes("UTF-8")
  val digest = md.digest(bytes)
  val hashedPassword = digest.map("%02x".format(_)).mkString
  hashedPassword
}
{% endhighlight %}





## آسیب پذیری  Insufficient Entropy

##### 🐞 کد آسیب پذیر


{% highlight php %}
import scala.util.Random

// Noncompliant code - uses Random.nextInt without sufficient entropy
def generateOTP(): String = {
  val otp = Random.nextInt(9999).toString
  otp
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import java.security.SecureRandom
import scala.util.Random

// Compliant code - uses SecureRandom for generating OTP with sufficient entropy
def generateOTP(): String = {
  val secureRandom = new SecureRandom()
  val otp = secureRandom.nextInt(10000).toString
  otp
}
{% endhighlight %}








## آسیب پذیری  XSS

##### 🐞 کد آسیب پذیر


{% highlight php %}
import scala.xml.NodeSeq

// Noncompliant code - vulnerable to XSS
def displayMessage(message: String): NodeSeq = {
  <div>{message}</div>
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
import scala.xml.{NodeSeq, Text}

// Compliant code - properly escapes the message to prevent XSS
def displayMessage(message: String): NodeSeq = {
  <div>{Text(message)}</div>
}
{% endhighlight %}







## آسیب پذیری  SQL Injection

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.sql.{Connection, DriverManager, ResultSet}

// Noncompliant code - vulnerable to SQL injection
def getUser(userId: String): Option[String] = {
  val query = s"SELECT name FROM users WHERE id = $userId"
  
  var connection: Connection = null
  var result: Option[String] = None
  
  try {
    connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "username", "password")
    val statement = connection.createStatement()
    val resultSet = statement.executeQuery(query)
    if (resultSet.next()) {
      result = Some(resultSet.getString("name"))
    }
  } catch {
    case e: Exception => e.printStackTrace()
  } finally {
    if (connection != null) {
      connection.close()
    }
  }
  
  result
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
import java.sql.{Connection, DriverManager, PreparedStatement, ResultSet}

// Compliant code - uses parameterized queries to prevent SQL injection
def getUser(userId: String): Option[String] = {
  val query = "SELECT name FROM users WHERE id = ?"
  
  var connection: Connection = null
  var result: Option[String] = None
  
  try {
    connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "username", "password")
    val statement = connection.prepareStatement(query)
    statement.setString(1, userId)
    val resultSet = statement.executeQuery()
    if (resultSet.next()) {
      result = Some(resultSet.getString("name"))
    }
  } catch {
    case e: Exception => e.printStackTrace()
  } finally {
    if (connection != null) {
      connection.close()
    }
  }
  
  result
}
{% endhighlight %}






## آسیب پذیری  External Control of File Name or Path

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.io.File

// Noncompliant code - vulnerable to external control of file name or path
def readFile(fileName: String): String = {
  val file = new File(fileName)
  val content = scala.io.Source.fromFile(file).mkString
  content
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
import java.io.File

// Compliant code - validates and sanitizes the file name
def readFile(fileName: String): Option[String] = {
  if (!fileName.contains("..") && fileName.matches("[a-zA-Z0-9]+\\.txt")) {
    val file = new File(fileName)
    val content = scala.io.Source.fromFile(file).mkString
    Some(content)
  } else {
    None
  }
}
{% endhighlight %}







## آسیب پذیری  Generation of Error Message Containing Sensitive Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code - error message containing sensitive information
def divide(a: Int, b: Int): Int = {
  if (b != 0) {
    a / b
  } else {
    throw new ArithmeticException("Division by zero error. Numerator: " + a + ", Denominator: " + b)
  }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - generic error message without sensitive information
def divide(a: Int, b: Int): Int = {
  if (b != 0) {
    a / b
  } else {
    throw new ArithmeticException("Division by zero error.")
  }
}
{% endhighlight %}






## آسیب پذیری  unprotected storage of credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code - unprotected storage of credentials
val username = "admin"
val password = "secretpassword"
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - secure storage of credentials
val username = readSecureValue("username")
val password = readSecureValue("password")

def readSecureValue(key: String): String = {
  // Implement a secure mechanism to retrieve the value of the given key
  // Examples: reading from an encrypted configuration file, retrieving from a secure key vault, etc.
  // This implementation depends on the specific security requirements and infrastructure of the application.
  // The focus is on securely retrieving the credentials, ensuring they are not stored directly in the code.
  // The exact implementation details are beyond the scope of this example.
  // Ideally, secrets management tools or libraries should be used for secure credential storage.
  // This ensures that credentials are not hardcoded in the code and are accessed securely at runtime.
  // Additionally, access controls and encryption should be implemented to protect the stored credentials.
  // For simplicity, this example assumes a custom readSecureValue() function that securely retrieves the value.
  // The actual implementation should use established and tested secure practices.
  // This example is meant to illustrate the concept of securely storing and retrieving credentials.
  // It is recommended to use a robust secrets management solution in real-world scenarios.
  // This code snippet should be adapted to meet the specific security requirements of the application.

  // Placeholder implementation
  if (key == "username") {
    // Retrieve the username value securely
    "admin"
  } else if (key == "password") {
    // Retrieve the password value securely
    "secretpassword"
  } else {
    // Handle other keys as needed
    ""
  }
}
{% endhighlight %}






## آسیب پذیری  Trust Boundary Violation

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code - trust boundary violation
val userRole = getUserRoleFromRequest(request)
val isAdmin = checkUserRole(userRole)

def getUserRoleFromRequest(request: Request): String = {
  // Extract the user role from the request parameter without proper validation
  // This code assumes the user role is directly provided in the request
  // without any sanitization or validation checks
  request.getParameter("role")
}

def checkUserRole(userRole: String): Boolean = {
  // Perform a check to determine if the user has administrative privileges
  // In this noncompliant code, the check is solely based on the value of the user role
  // without any additional validation or verification
  userRole.toLowerCase() == "admin"
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - proper validation of user role
val userRole = getUserRoleFromRequest(request)
val isAdmin = checkUserRole(userRole)

def getUserRoleFromRequest(request: Request): String = {
  // Extract the user role from the request parameter and perform proper validation
  // Validate and sanitize the user-provided input to prevent trust boundary violations
  val rawUserRole = request.getParameter("role")
  validateUserRole(rawUserRole)
}

def validateUserRole(userRole: String): String = {
  // Perform proper validation and sanitization of the user role
  // This could include checks such as ensuring the user role is within an allowed set of values,
  // validating against a predefined list of roles, or using a dedicated role validation library.
  // The exact validation logic depends on the specific requirements and design of the application.
  // This example assumes a simple validation for demonstration purposes.
  if (userRole.toLowerCase() == "admin" || userRole.toLowerCase() == "user") {
    userRole.toLowerCase()
  } else {
    // Handle invalid user roles as needed, such as assigning a default role or throwing an exception
    "guest"
  }
}

def checkUserRole(userRole: String): Boolean = {
  // Perform a check to determine if the user has administrative privileges
  // The user role has been properly validated before reaching this point
  userRole == "admin"
}
{% endhighlight %}









## آسیب پذیری  Insufficiently Protected Credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code - insufficiently protected credentials
val username = "admin"
val password = "password"

val connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", username, password)
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - protected credentials
val username = readUsernameFromConfig()
val password = readPasswordFromConfig()

val connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", username, password)

def readUsernameFromConfig(): String = {
  // Read the username from a secure configuration file or environment variable
  // This ensures that the credentials are not directly hardcoded in the source code
  // and are kept separate from the code repository
  // The specific method for retrieving the username will depend on the application's configuration mechanism
  // such as reading from a properties file, using a secure vault, or fetching from environment variables
  // This example assumes reading from a properties file for demonstration purposes
  val properties = new Properties()
  properties.load(new FileInputStream("config.properties"))
  properties.getProperty("db.username")
}

def readPasswordFromConfig(): String = {
  // Read the password from a secure configuration file or environment variable
  // Similar to the username, the password should be stored separately from the source code
  val properties = new Properties()
  properties.load(new FileInputStream("config.properties"))
  properties.getProperty("db.password")
}
{% endhighlight %}













## آسیب پذیری  Restriction of XML External Entity Reference

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code - unrestricted XML entity reference
import scala.xml.XML

val xml = XML.loadString("""
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <root>&xxe;</root>
""")

// Process the XML data
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - restricted XML entity reference
import scala.xml.{Elem, XML}
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory

// Set up secure XML parsing
val factory = DocumentBuilderFactory.newInstance()
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
factory.setExpandEntityReferences(false)

val builder = factory.newDocumentBuilder()
val xml = XML.withSAXParser(builder).loadString("""
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <root>&xxe;</root>
""")

// Process the XML data
{% endhighlight %}









## آسیب پذیری  Vulnerable and Outdated Components


##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code - using outdated library version
import org.apache.commons.codec.digest.DigestUtils

val password = "password123"
val hashedPassword = DigestUtils.sha1Hex(password)
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - using secure and up-to-date library version
import java.security.MessageDigest

val password = "password123"
val sha256 = MessageDigest.getInstance("SHA-256")
val hashedPassword = sha256.digest(password.getBytes).map("%02x".format(_)).mkString
{% endhighlight %}








## آسیب پذیری  Improper Validation of Certificate with Host Mismatch

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code - improper certificate validation
import java.net.URL
import java.net.HttpURLConnection

val url = new URL("https://example.com")
val connection = url.openConnection().asInstanceOf[HttpURLConnection]
connection.setRequestMethod("GET")

// Disable hostname verification
connection.setHostnameVerifier((_, _) => true)

val responseCode = connection.getResponseCode()
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - proper certificate validation
import java.net.URL
import java.net.HttpURLConnection
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext

val url = new URL("https://example.com")
val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
connection.setRequestMethod("GET")

// Enable proper hostname verification
val sslContext = SSLContext.getInstance("TLS")
sslContext.init(null, null, null)
connection.setSSLSocketFactory(sslContext.getSocketFactory())

val responseCode = connection.getResponseCode()
{% endhighlight %}








## آسیب پذیری  Improper Authentication

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code - improper authentication
import java.util.Scanner

val scanner = new Scanner(System.in)
println("Enter username:")
val username = scanner.nextLine()
println("Enter password:")
val password = scanner.nextLine()

// Perform authentication logic
val isAuthenticated = authenticate(username, password)

if (isAuthenticated) {
  println("Authentication successful")
} else {
  println("Authentication failed")
}

def authenticate(username: String, password: String): Boolean = {
  // Authentication logic goes here
  // ...
  true // Dummy authentication logic for demonstration purposes
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - proper authentication
import java.io.Console

val console: Console = System.console()
val username = console.readLine("Enter username: ")
val password = console.readPassword("Enter password: ")

// Perform authentication logic
val isAuthenticated = authenticate(username, password)

if (isAuthenticated) {
  println("Authentication successful")
} else {
  println("Authentication failed")
}

def authenticate(username: String, password: Array[Char]): Boolean = {
  // Authentication logic goes here
  // ...
  true // Dummy authentication logic for demonstration purposes
}
{% endhighlight %}








## آسیب پذیری  Session Fixation

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code - session fixation vulnerability
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}

def login(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val sessionId = request.getParameter("sessionid")
  // Perform login logic
  // ...
  val newSessionId = generateNewSessionId()
  request.getSession(true).setAttribute("sessionid", newSessionId)
  response.sendRedirect("/dashboard")
}

def generateNewSessionId(): String = {
  // Generate new session ID logic goes here
  // ...
  "newSessionId" // Dummy session ID for demonstration purposes
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - protected against session fixation
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import java.util.UUID

def login(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val newSessionId = generateNewSessionId()
  request.changeSessionId() // Invalidate existing session ID
  request.getSession(true).setAttribute("sessionid", newSessionId)
  response.sendRedirect("/dashboard")
}

def generateNewSessionId(): String = {
  UUID.randomUUID().toString // Generate a new session ID using a secure method
}
{% endhighlight %}









## آسیب پذیری  Inclusion of Functionality from Untrusted Control

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code - inclusion of functionality from untrusted control
def processTemplate(templateName: String): String = {
  val template = loadTemplate(templateName)
  template.render()
}

def loadTemplate(templateName: String): Template = {
  // Load template file from untrusted source
  // ...
  Template.fromFile(templateName) // Unsafe inclusion of template
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - protected against inclusion of functionality from untrusted control
def processTemplate(templateName: String): String = {
  val template = loadTemplate(templateName)
  template.render()
}

def loadTemplate(templateName: String): Template = {
  if (isValidTemplateName(templateName)) {
    // Load template from trusted source
    // ...
    Template.fromFile(templateName) // Safe inclusion of template
  } else {
    throw new IllegalArgumentException("Invalid template name")
  }
}

def isValidTemplateName(templateName: String): Boolean = {
  // Implement validation logic for template name
  // ...
  // Return true if the template name is valid, false otherwise
}
{% endhighlight %}








## آسیب پذیری  Download of Code Without Integrity Check

##### 🐞 کد آسیب پذیر


{% highlight php %}
import scala.sys.process._

def downloadAndExecute(url: String): Unit = {
  val command = s"curl $url | bash"
  command.!
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import scala.sys.process._

def downloadAndExecute(url: String, checksum: String): Unit = {
  val command = s"curl $url | bash"
  val downloadedCode = command.!!

  if (verifyIntegrity(downloadedCode, checksum)) {
    // Execute the downloaded code
    // ...
  } else {
    throw new SecurityException("Code integrity check failed")
  }
}

def verifyIntegrity(code: String, checksum: String): Boolean = {
  // Perform integrity check by comparing the code's checksum with the expected checksum
  // ...
  // Return true if the code's integrity is valid, false otherwise
}
{% endhighlight %}





## آسیب پذیری  Deserialization of Untrusted Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.io.{ByteArrayInputStream, ObjectInputStream}

def deserializeObject(data: Array[Byte]): Any = {
  val stream = new ByteArrayInputStream(data)
  val objectInputStream = new ObjectInputStream(stream)
  val obj = objectInputStream.readObject()
  objectInputStream.close()
  obj
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
import java.io.{ByteArrayInputStream, ObjectInputStream}
import java.util.Base64

def deserializeObject(data: Array[Byte]): Any = {
  val stream = new ByteArrayInputStream(data)
  val objectInputStream = new ObjectInputStream(stream)

  // Perform input validation and sanitize the data
  // Example: Validate that the data is from a trusted source or has a specific format

  val obj = objectInputStream.readObject()
  objectInputStream.close()
  obj
}
{% endhighlight %}









## آسیب پذیری  Insufficient Logging

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.io.{FileWriter, IOException}

def performSensitiveOperation(input: String): Unit = {
  try {
    // Perform sensitive operation here

    // Log success message
    val logMessage = s"Sensitive operation successful for input: $input"
    val fileWriter = new FileWriter("application.log", true)
    fileWriter.write(logMessage)
    fileWriter.close()
  } catch {
    case e: Exception =>
      // Log error message
      val logMessage = s"Error performing sensitive operation for input: $input - ${e.getMessage}"
      val fileWriter = new FileWriter("application.log", true)
      fileWriter.write(logMessage)
      fileWriter.close()
  }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
require 'logger'

logger = Logger.new('application.log')

def transfer_funds(sender, recipient, amount)
  if sender.balance >= amount
    sender.balance -= amount
    recipient.balance += amount
    logger.info("Funds transferred: $#{amount} from #{sender.name} to #{recipient.name}")
  else
    logger.warn("Insufficient funds for transfer: $#{amount} from #{sender.name} to #{recipient.name}")
  end
end
{% endhighlight %}









## آسیب پذیری  Improper Output Neutralization for Logs

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
logger = Logger.new('application.log')

def log_user_activity(user_id, activity)
  logger.info("User #{user_id} performed activity: #{activity}")
end
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
logger = Logger.new('application.log')

def log_user_activity(user_id, activity)
  sanitized_user_id = sanitize_output(user_id)
  sanitized_activity = sanitize_output(activity)

  logger.info("User #{sanitized_user_id} performed activity: #{sanitized_activity}")
end

def sanitize_output(input)
  # Implement output neutralization logic here
  # For example, remove or escape special characters that could be used for log injection
  sanitized_input = input.gsub(/[<>]/, '')

  # Return the sanitized input
  sanitized_input
end
{% endhighlight %}






          



## آسیب پذیری  Omission of Security-relevant Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
def login(username, password)
  if username == 'admin' && password == 'password'
    puts 'Login successful'
  else
    puts 'Login failed'
  end
end
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
def login(username, password)
  if username == 'admin' && password == 'password'
    puts 'Login successful'
  else
    puts 'Login failed: Invalid username or password'
  end
end
{% endhighlight %}











## آسیب پذیری  Sensitive Information into Log File

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
logger = Logger.new('application.log')

def log_sensitive_info(username, password)
  logger.info("Login attempt - Username: #{username}, Password: #{password}")
end
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
logger = Logger.new('application.log')

def log_login_attempt(username)
  logger.info("Login attempt - Username: #{username}")
end
{% endhighlight %}









## آسیب پذیری  Server-Side Request Forgery (SSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
require 'open-uri'

# Noncompliant code
def fetch_url(url)
  data = open(url).read
  # Process the fetched data
end
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
require 'open-uri'
require 'uri'

# Compliant code
def fetch_url(url)
  parsed_url = URI.parse(url)
  if parsed_url.host == 'trusted-domain.com'
    data = open(url).read
    # Process the fetched data
  else
    # Handle the case of an untrusted or restricted domain
    puts 'Access to the specified domain is not allowed.'
  end
end
{% endhighlight %}

