---
title: Java
tags: 
 - java
description: Java Vulnerabilities
---

# Java



## آسیب پذیری Exposure of sensitive information


##### 🐞 کد آسیب پذیر




{% highlight php %}
import java.util.logging.*;

public class UserController {
    private static final Logger LOGGER = Logger.getLogger(UserController.class.getName());

    public void loginUser(String username, String password) {
        // Perform login logic

        LOGGER.info("User logged in - username: " + username);
    }
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
import java.util.logging.*;

public class UserController {
    private static final Logger LOGGER = Logger.getLogger(UserController.class.getName());

    public void loginUser(String username, String password) {
        // Perform login logic

        LOGGER.info("User logged in - username: " + obfuscateUsername(username));
    }

    private String obfuscateUsername(String username) {
        // Implement a method to obfuscate or mask the username
        // Example: Replace characters with asterisks or hash the username
        // ...

        return username; // Return the obfuscated username
    }
}
{% endhighlight %}





## آسیب پذیری Insertion of Sensitive Information Into Sent Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStream;
import java.io.IOException;

public class PaymentService {
    private static final String API_ENDPOINT = "https://api.example.com/payments";

    public void makePayment(String cardNumber, double amount) {
        try {
            // Create a connection to the API endpoint
            URL url = new URL(API_ENDPOINT);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");

            // Set the request headers
            connection.setRequestProperty("Content-Type", "application/json");

            // Construct the request body
            String requestBody = "{\"cardNumber\": \"" + cardNumber + "\", \"amount\": " + amount + "}";

            // Send the request
            connection.setDoOutput(true);
            OutputStream outputStream = connection.getOutputStream();
            outputStream.write(requestBody.getBytes());
            outputStream.flush();
            outputStream.close();

            // Process the response...
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStream;
import java.io.IOException;

public class PaymentService {
    private static final String API_ENDPOINT = "https://api.example.com/payments";

    public void makePayment(String cardNumber, double amount) {
        try {
            // Create a connection to the API endpoint
            URL url = new URL(API_ENDPOINT);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");

            // Set the request headers
            connection.setRequestProperty("Content-Type", "application/json");

            // Construct the request body using a JSON library or object mapping
            JsonObject requestBody = new JsonObject();
            requestBody.addProperty("cardNumber", obfuscateCardNumber(cardNumber));
            requestBody.addProperty("amount", amount);

            // Send the request
            connection.setDoOutput(true);
            OutputStream outputStream = connection.getOutputStream();
            outputStream.write(requestBody.toString().getBytes());
            outputStream.flush();
            outputStream.close();

            // Process the response...
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String obfuscateCardNumber(String cardNumber) {
        // Implement a method to obfuscate or mask the card number
        // Example: Replace characters with asterisks, mask certain digits, or encrypt the card number
        // ...

        return cardNumber; // Return the obfuscated card number
    }
}
{% endhighlight %}






## آسیب پذیری  Cross-Site Request Forgery (CSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AccountService {
    public void updateEmail(HttpServletRequest request, HttpServletResponse response) {
        String newEmail = request.getParameter("email");

        // Code to update the email address in the user's account...
        // ...
    }
}
{% endhighlight %}



##### ✅ کد اصلاح شده 


{% highlight php %}
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.UUID;

public class AccountService {
    private static final String CSRF_TOKEN_SESSION_ATTR = "csrfToken";

    public void updateEmail(HttpServletRequest request, HttpServletResponse response) {
        String newEmail = request.getParameter("email");

        // Validate CSRF token
        HttpSession session = request.getSession();
        String csrfToken = (String) session.getAttribute(CSRF_TOKEN_SESSION_ATTR);
        String requestCsrfToken = request.getParameter("csrfToken");

        if (csrfToken == null || !csrfToken.equals(requestCsrfToken)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        // Code to update the email address in the user's account...
        // ...
    }

    public void generateCsrfToken(HttpServletRequest request) {
        HttpSession session = request.getSession();
        String csrfToken = UUID.randomUUID().toString();
        session.setAttribute(CSRF_TOKEN_SESSION_ATTR, csrfToken);
    }
}
{% endhighlight %}





## آسیب پذیری  Use of Hard-coded Password

##### 🐞 کد آسیب پذیر


{% highlight php %}
public class DatabaseConnection {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydatabase";
    private static final String DB_USERNAME = "root";
    private static final String DB_PASSWORD = "password123";

    public void connect() {
        // Code to establish a database connection using the hard-coded credentials
        // ...
    }
}
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
public class DatabaseConnection {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydatabase";
    private static final String DB_USERNAME = "root";
    private String dbPassword;

    public DatabaseConnection(String dbPassword) {
        this.dbPassword = dbPassword;
    }

    public void connect() {
        // Code to establish a database connection using the provided password
        // ...
    }
}
{% endhighlight %}








## آسیب پذیری  Broken or Risky Crypto Algorithm

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PasswordUtils {
    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
import org.mindrot.jbcrypt.BCrypt;

public class PasswordUtils {
    private static final int BCRYPT_COST = 12;

    public static String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(BCRYPT_COST));
    }

    public static boolean verifyPassword(String password, String hashedPassword) {
        return BCrypt.checkpw(password, hashedPassword);
    }
}
{% endhighlight %}





## آسیب پذیری  Insufficient Entropy

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.util.Random;

public class TokenGenerator {
    public static String generateToken(int length) {
        String characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            char c = characters.charAt(index);
            sb.append(c);
        }
        return sb.toString();
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import java.security.SecureRandom;
import java.util.Base64;

public class TokenGenerator {
    public static String generateToken(int length) {
        byte[] bytes = new byte[length];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
{% endhighlight %}








## آسیب پذیری  XSS

##### 🐞 کد آسیب پذیر


{% highlight php %}
public class XssExample {
    public static String getUserInput() {
        // Assume user input is obtained from an untrusted source
        String userInput = "<script>alert('XSS');</script>";
        return userInput;
    }
    
    public static String displayUserInput(String userInput) {
        String html = "<div>" + userInput + "</div>";
        return html;
    }
    
    public static void main(String[] args) {
        String userInput = getUserInput();
        String html = displayUserInput(userInput);
        System.out.println(html);
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
import org.apache.commons.text.StringEscapeUtils;

public class XssExample {
    public static String getUserInput() {
        // Assume user input is obtained from an untrusted source
        String userInput = "<script>alert('XSS');</script>";
        return userInput;
    }
    
    public static String displayUserInput(String userInput) {
        String sanitizedInput = StringEscapeUtils.escapeHtml4(userInput);
        String html = "<div>" + sanitizedInput + "</div>";
        return html;
    }
    
    public static void main(String[] args) {
        String userInput = getUserInput();
        String html = displayUserInput(userInput);
        System.out.println(html);
    }
}
{% endhighlight %}







## آسیب پذیری  SQL Injection

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class SqlInjectionExample {
    public static void main(String[] args) {
        String username = "admin'; DROP TABLE users;--";
        String password = "password";
        
        String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
        
        try {
            Connection connection = Database.getConnection();
            Statement statement = connection.createStatement();
            ResultSet resultSet = statement.executeQuery(query);
            
            // Process the result set...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SqlInjectionExample {
    public static void main(String[] args) {
        String username = "admin'; DROP TABLE users;--";
        String password = "password";
        
        String query = "SELECT * FROM users WHERE username=? AND password=?";
        
        try {
            Connection connection = Database.getConnection();
            PreparedStatement statement = connection.prepareStatement(query);
            statement.setString(1, username);
            statement.setString(2, password);
            
            ResultSet resultSet = statement.executeQuery();
            
            // Process the result set...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
{% endhighlight %}






## آسیب پذیری  External Control of File Name or Path

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.io.File;

public class FileUploadExample {
    public static void main(String[] args) {
        String fileName = getFileNameFromUserInput();
        String directory = "uploads/";

        File file = new File(directory + fileName);
        
        // Process the uploaded file...
    }
    
    private static String getFileNameFromUserInput() {
        // Code to get file name from user input
        // This could be from a user input field, request parameter, etc.
        return userInput;
    }
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileUploadExample {
    private static final String UPLOAD_DIRECTORY = "uploads/";

    public static void main(String[] args) {
        String fileName = getFileNameFromUserInput();
        
        Path filePath = Paths.get(UPLOAD_DIRECTORY, fileName).normalize();
        if (!filePath.startsWith(UPLOAD_DIRECTORY)) {
            // Invalid file name or path, handle the error
            return;
        }

        File file = filePath.toFile();
        
        // Process the uploaded file...
    }
    
    private static String getFileNameFromUserInput() {
        // Code to get file name from user input
        // This could be from a user input field, request parameter, etc.
        return userInput;
    }
}
{% endhighlight %}







## آسیب پذیری  Generation of Error Message Containing Sensitive Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
public class UserService {
    public User getUserById(String userId) {
        try {
            // Code to fetch user details from the database using the provided userId
            // ...
        } catch (Exception e) {
            String errorMessage = "An error occurred while fetching user details for userId: " + userId;
            throw new RuntimeException(errorMessage, e);
        }
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
public class UserService {
    public User getUserById(String userId) {
        try {
            // Code to fetch user details from the database using the provided userId
            // ...
        } catch (Exception e) {
            throw new RuntimeException("An error occurred while fetching user details", e);
        }
    }
}
{% endhighlight %}






## آسیب پذیری  unprotected storage of credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
public class UserService {
    private String username;
    private String password;
    
    public void login(String username, String password) {
        this.username = username;
        this.password = password;
        // Code to authenticate the user
        // ...
    }
    
    public void printCredentials() {
        System.out.println("Username: " + username);
        System.out.println("Password: " + password);
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
public class UserService {
    private char[] password;
    
    public void login(String username, char[] password) {
        // Code to authenticate the user
        // ...
        
        // Store the password securely
        this.password = Arrays.copyOf(password, password.length);
        
        // Clear the original password data
        Arrays.fill(password, ' ');
    }
    
    public void printCredentials() {
        System.out.println("Username: " + getUsername());
        System.out.println("Password: ********");
    }
    
    private String getUsername() {
        // Retrieve the username from the authenticated user session
        // ...
    }
}
{% endhighlight %}






## آسیب پذیری  Trust Boundary Violation

##### 🐞 کد آسیب پذیر


{% highlight php %}
public class UserAuthenticator {
    private boolean isAdmin;
    
    public boolean authenticateUser(String username, String password) {
        // Code to authenticate the user credentials
        // ...
        
        // Set isAdmin flag based on the authentication result
        if (username.equals("admin") && password.equals("admin123")) {
            isAdmin = true;
        }
        
        return true;
    }
    
    public void performAdminAction() {
        if (isAdmin) {
            // Code to perform administrative action
            // ...
        } else {
            System.out.println("Access denied. You are not authorized to perform this action.");
        }
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
public class UserAuthenticator {
    private boolean isAdmin;
    
    public boolean authenticateUser(String username, String password) {
        // Code to authenticate the user credentials
        // ...
        
        // Set isAdmin flag based on the authentication result
        if (username.equals("admin") && password.equals("admin123")) {
            isAdmin = true;
        } else {
            isAdmin = false;
        }
        
        return true;
    }
    
    public void performAdminAction() {
        if (checkAdminStatus()) {
            // Code to perform administrative action
            // ...
        } else {
            System.out.println("Access denied. You are not authorized to perform this action.");
        }
    }
    
    private boolean checkAdminStatus() {
        // Code to check the isAdmin flag from the authenticated user session
        // ...
        
        return isAdmin;
    }
}
{% endhighlight %}









## آسیب پذیری  Insufficiently Protected Credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
public class UserAuthenticator {
    public boolean authenticateUser(String username, String password) {
        // Code to authenticate the user credentials
        // ...
        
        // Log the username and password
        System.out.println("User credentials: " + username + ", " + password);
        
        // Continue with authentication logic
        // ...
        
        return true;
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
public class UserAuthenticator {
    public boolean authenticateUser(String username, String password) {
        // Code to authenticate the user credentials
        // ...
        
        // Log a generic message instead of the credentials
        System.out.println("User authentication attempt");
        
        // Continue with authentication logic
        // ...
        
        return true;
    }
}
{% endhighlight %}













## آسیب پذیری  Restriction of XML External Entity Reference

##### 🐞 کد آسیب پذیر


{% highlight php %}
import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

public class XMLParser {
    public Document parseXML(String xml) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new ByteArrayInputStream(xml.getBytes()));
            return document;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;

public class XMLParser {
    public Document parseXML(String xml) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new ByteArrayInputStream(xml.getBytes()));
            return document;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
{% endhighlight %}









## آسیب پذیری  Vulnerable and Outdated Components


##### 🐞 کد آسیب پذیر


{% highlight php %}
import org.apache.commons.lang.StringUtils;

public class StringHelper {
    public static String sanitizeString(String input) {
        return StringUtils.stripTags(input);
    }

    public static boolean isNullOrEmpty(String input) {
        return StringUtils.isEmpty(input);
    }

    public static boolean isNumeric(String input) {
        return StringUtils.isNumeric(input);
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
import org.apache.commons.lang3.StringUtils;

public class StringHelper {
    public static String sanitizeString(String input) {
        return StringUtils.stripTags(input);
    }

    public static boolean isNullOrEmpty(String input) {
        return StringUtils.isEmpty(input);
    }

    public static boolean isNumeric(String input) {
        return StringUtils.isNumeric(input);
    }
}
{% endhighlight %}








## آسیب پذیری  Improper Validation of Certificate with Host Mismatch

##### 🐞 کد آسیب پذیر


{% highlight php %}
import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.URL;

public class HttpClient {
    public static void sendRequest(String url) throws IOException {
        URL requestUrl = new URL(url);
        HttpsURLConnection connection = (HttpsURLConnection) requestUrl.openConnection();
        connection.setHostnameVerifier((hostname, session) -> true); // Disabling hostname verification
        connection.setRequestMethod("GET");
        int responseCode = connection.getResponseCode();
        // Process the response...
    }
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.URL;

public class HttpClient {
    public static void sendRequest(String url) throws IOException {
        URL requestUrl = new URL(url);
        HttpsURLConnection connection = (HttpsURLConnection) requestUrl.openConnection();
        connection.setRequestMethod("GET");
        try {
            connection.connect();
            SSLSession session = connection.getSSLSession();
            String peerHost = session.getPeerHost();
            if (!requestUrl.getHost().equals(peerHost)) {
                throw new SSLPeerUnverifiedException("Certificate does not match the host name");
            }
        } catch (SSLPeerUnverifiedException e) {
            // Handle certificate validation failure
        } finally {
            connection.disconnect();
        }
        int responseCode = connection.getResponseCode();
        // Process the response...
    }
}
{% endhighlight %}








## آسیب پذیری  Improper Authentication

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.util.Scanner;

public class AuthenticationExample {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        
        System.out.print("Enter password: ");
        String password = scanner.nextLine();
        
        if (username.equals("admin") && password.equals("password")) {
            System.out.println("Authentication successful");
            // Proceed with privileged operation
        } else {
            System.out.println("Authentication failed");
            // Handle authentication failure
        }
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
import java.util.Scanner;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class AuthenticationExample {
    private static final String SALT = "random_salt";
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        
        System.out.print("Enter password: ");
        String password = scanner.nextLine();
        
        if (authenticate(username, password)) {
            System.out.println("Authentication successful");
            // Proceed with privileged operation
        } else {
            System.out.println("Authentication failed");
            // Handle authentication failure
        }
    }
    
    private static boolean authenticate(String username, String password) {
        // Retrieve hashed password from a secure database or storage
        String storedPasswordHash = getStoredPasswordHash(username);
        
        // Hash the input password with a salt
        String hashedPassword = hashPassword(password);
        
        // Compare the stored hashed password with the input hashed password
        return storedPasswordHash.equals(hashedPassword);
    }
    
    private static String hashPassword(String password) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update((password + SALT).getBytes());
            byte[] hashedBytes = messageDigest.digest();
            return bytesToHexString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            // Handle the exception
            e.printStackTrace();
        }
        return null;
    }
    
    private static String bytesToHexString(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : bytes) {
            stringBuilder.append(String.format("%02x", b));
        }
        return stringBuilder.toString();
    }
    
    private static String getStoredPasswordHash(String username) {
        // Retrieve the hashed password from a secure database or storage
        // based on the given username
        // Return the stored password hash
        return "stored_password_hash";
    }
}
{% endhighlight %}








## آسیب پذیری  Session Fixation

##### 🐞 کد آسیب پذیر


{% highlight php %}
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class SessionFixationExample {
    public static void login(HttpServletRequest request, String username) {
        HttpSession session = request.getSession(true);
        session.setAttribute("username", username);
    }
    
    public static void main(String[] args) {
        HttpServletRequest request = // Obtain the request object
        
        String username = "admin";
        login(request, username);
        
        // Proceed with authenticated actions
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class SessionFixationExample {
    public static void login(HttpServletRequest request, String username) {
        HttpSession session = request.getSession();
        session.invalidate(); // Invalidate the existing session
        session = request.getSession(true); // Create a new session
        
        session.setAttribute("username", username);
    }
    
    public static void main(String[] args) {
        HttpServletRequest request = // Obtain the request object
        
        String username = "admin";
        login(request, username);
        
        // Proceed with authenticated actions
    }
}
{% endhighlight %}









## آسیب پذیری  Inclusion of Functionality from Untrusted Control

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.io.File;
import java.io.IOException;

public class UntrustedFunctionalityExample {
    public static void processFile(String filename) {
        try {
            File file = new File(filename);
            // Process the file contents
        } catch (IOException e) {
            // Handle file processing error
        }
    }
    
    public static void main(String[] args) {
        String userProvidedFilename = "userfile.txt";
        processFile(userProvidedFilename);
    }
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
import java.io.File;
import java.io.IOException;

public class UntrustedFunctionalityExample {
    public static void processFile(String filename) {
        // Validate and sanitize the filename before processing
        if (isValidFilename(filename)) {
            try {
                File file = new File(filename);
                // Process the file contents
            } catch (IOException e) {
                // Handle file processing error
            }
        } else {
            // Handle invalid filename
        }
    }
    
    public static boolean isValidFilename(String filename) {
        // Implement validation logic to ensure the filename is safe
        // e.g., restrict file path, disallow certain characters, etc.
        return true;
    }
    
    public static void main(String[] args) {
        String userProvidedFilename = "userfile.txt";
        processFile(userProvidedFilename);
    }
}
{% endhighlight %}








## آسیب پذیری  Download of Code Without Integrity Check

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class CodeDownloadExample {
    public static void downloadCode(String url, String destination) {
        try {
            URL codeUrl = new URL(url);
            Path destinationPath = Path.of(destination);
            Files.copy(codeUrl.openStream(), destinationPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            // Handle download error
        }
    }
    
    public static void main(String[] args) {
        String codeUrl = "http://example.com/malicious-code.jar";
        String destinationPath = "/path/to/save/malicious-code.jar";
        downloadCode(codeUrl, destinationPath);
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CodeDownloadExample {
    public static void downloadCode(String url, String destination) {
        try {
            URL codeUrl = new URL(url);
            Path destinationPath = Path.of(destination);
            
            // Download the code to a temporary file
            Path tempPath = Files.createTempFile("downloaded_code", ".tmp");
            Files.copy(codeUrl.openStream(), tempPath, StandardCopyOption.REPLACE_EXISTING);
            
            // Calculate the checksum of the downloaded code
            String checksum = calculateChecksum(tempPath);
            
            // Verify the integrity of the downloaded code
            if (isValidChecksum(checksum)) {
                // Move the downloaded code to the destination path
                Files.move(tempPath, destinationPath, StandardCopyOption.REPLACE_EXISTING);
            } else {
                // Handle integrity check failure
                Files.deleteIfExists(tempPath);
            }
        } catch (IOException e) {
            // Handle download error
        }
    }
    
    public static String calculateChecksum(Path filePath) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] fileBytes = Files.readAllBytes(filePath);
            byte[] checksumBytes = md.digest(fileBytes);
            StringBuilder checksumBuilder = new StringBuilder();
            for (byte b : checksumBytes) {
                checksumBuilder.append(String.format("%02x", b));
            }
            return checksumBuilder.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error calculating checksum.", e);
        }
    }
    
    public static boolean isValidChecksum(String checksum) {
        // Compare the calculated checksum with a trusted value
        String trustedChecksum = "e1a7a76c51a1024193a54f95e3dbaeaeaa01a7544c24404db4c24bdf8a34937e";
        return trustedChecksum.equals(checksum);
    }
    
    public static void main(String[] args) {
        String codeUrl = "http://example.com/malicious-code.jar";
        String destinationPath = "/path/to/save/malicious-code.jar";
        downloadCode(codeUrl, destinationPath);
    }
}
{% endhighlight %}





## آسیب پذیری  Deserialization of Untrusted Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class DeserializationExample {
    public static void main(String[] args) {
        String serializedData = "serialized_data.ser";
        
        try (FileInputStream fileIn = new FileInputStream(serializedData);
             ObjectInputStream in = new ObjectInputStream(fileIn)) {
            
            Object obj = in.readObject();
            // Process the deserialized object
            
        } catch (IOException | ClassNotFoundException e) {
            // Handle deserialization error
        }
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class DeserializationExample {
    public static void main(String[] args) {
        String serializedData = "serialized_data.ser";
        
        try (FileInputStream fileIn = new FileInputStream(serializedData);
             ObjectInputStream in = new ObjectInputStream(fileIn)) {
            
            // Perform validation on the deserialized object
            Object obj = in.readObject();
            if (isValidObject(obj)) {
                // Process the deserialized object
            } else {
                // Handle invalid or malicious object
            }
            
        } catch (IOException | ClassNotFoundException e) {
            // Handle deserialization error
        }
    }
    
    public static boolean isValidObject(Object obj) {
        // Implement validation logic based on the expected object type
        // and any additional validation criteria
        
        // Example: Ensure the deserialized object is of the expected type
        return obj instanceof MySerializableClass;
    }
}
{% endhighlight %}









## آسیب پذیری  Insufficient Logging

##### 🐞 کد آسیب پذیر


{% highlight php %}
public class PaymentService {
    private static final Logger logger = Logger.getLogger(PaymentService.class.getName());

    public void processPayment(String paymentData) {
        // Process the payment
        // ...

        // Log the payment result
        logger.info("Payment processed successfully");
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
public class PaymentService {
    private static final Logger logger = Logger.getLogger(PaymentService.class.getName());

    public void processPayment(String paymentData, User user) {
        // Process the payment
        // ...

        // Log the payment result with relevant information
        logger.info("Payment processed successfully. User: " + user.getUsername() + ", Amount: " + paymentData.getAmount());
    }
}
{% endhighlight %}









## آسیب پذیری  Improper Output Neutralization for Logs

##### 🐞 کد آسیب پذیر


{% highlight php %}
public class LoginService {
    private static final Logger logger = Logger.getLogger(LoginService.class.getName());

    public void logInvalidLogin(String username) {
        // Log the invalid login attempt
        logger.info("Invalid login attempt: " + username);
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
public class LoginService {
    private static final Logger logger = Logger.getLogger(LoginService.class.getName());

    public void logInvalidLogin(String username) {
        // Sanitize the username to prevent log injection
        String sanitizedUsername = sanitize(username);

        // Log the invalid login attempt with the sanitized username
        logger.info("Invalid login attempt: " + sanitizedUsername);
    }

    private String sanitize(String input) {
        // Implement appropriate sanitization logic
        // ...
        return input.replaceAll("[^a-zA-Z0-9]", "");
    }
}
{% endhighlight %}






          



## آسیب پذیری  Omission of Security-relevant Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
public class PaymentService {
    public void processPayment(String creditCardNumber, double amount) {
        // Process the payment

        // Log the payment without including security-relevant information
        Logger.getLogger(PaymentService.class.getName()).info("Payment processed");
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
public class PaymentService {
    public void processPayment(String creditCardNumber, double amount) {
        // Process the payment

        // Log the payment with security-relevant information
        Logger logger = Logger.getLogger(PaymentService.class.getName());
        logger.info("Payment processed - Credit Card: " + maskCreditCardNumber(creditCardNumber) + ", Amount: " + amount);
    }

    private String maskCreditCardNumber(String creditCardNumber) {
        // Mask the credit card number for security purposes
        // ...
        return "************" + creditCardNumber.substring(creditCardNumber.length() - 4);
    }
}
{% endhighlight %}











## آسیب پذیری  Sensitive Information into Log File

##### 🐞 کد آسیب پذیر


{% highlight php %}
public class UserService {
    private static final Logger logger = Logger.getLogger(UserService.class.getName());

    public void createUser(String username, String password) {
        // Create the user

        // Log the sensitive information
        logger.info("User created - Username: " + username + ", Password: " + password);
    }
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
public class UserService {
    private static final Logger logger = Logger.getLogger(UserService.class.getName());

    public void createUser(String username, String password) {
        // Create the user

        // Log a message without sensitive information
        logger.info("User created - Username: " + username);
    }
}
{% endhighlight %}









## آسیب پذیری  Server-Side Request Forgery (SSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;

public class ImageProcessor {
    public void processImage(String imageUrl) throws IOException {
        // Retrieve image from the provided URL
        URL url = new URL(imageUrl);
        BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
        // Process the image
        // ...
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;

public class ImageProcessor {
    private static final String ALLOWED_DOMAIN = "example.com";

    public void processImage(String imageUrl) throws IOException {
        // Validate the URL
        URL url = new URL(imageUrl);
        String host = url.getHost();
        
        if (!host.endsWith(ALLOWED_DOMAIN)) {
            throw new IllegalArgumentException("Invalid image URL");
        }

        // Retrieve image from the provided URL
        BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
        // Process the image
        // ...
    }
}
{% endhighlight %}
