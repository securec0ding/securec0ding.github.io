---
title: PHP
tags: 
 - php
description: PHP Vulnerabilities
---

# PHP


## آسیب پذیری Exposure of sensitive information


##### 🐞 کد آسیب پذیر




{% highlight php %}
// Noncompliant code - exposing sensitive information in error log
function processUserInput($input) {
  // Process user input
  // ...
  
  // Log error with sensitive information
  error_log("Error processing user input: $input");
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code - avoiding exposure of sensitive information in error log
function processUserInput($input) {
  // Process user input
  // ...
  
  // Log error without sensitive information
  error_log("Error processing user input"); // Log generic error message
}
{% endhighlight %}





## آسیب پذیری Insertion of Sensitive Information Into Sent Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
// This code sends a user's password to a remote API as part of a JSON payload
$payload = json_encode(array('username' => 'alice', 'password' => 's3cret'));
$response = file_get_contents('https://example.com/api', null, stream_context_create(array(
    'http' => array(
        'method' => 'POST',
        'header' => "Content-Type: application/json\r\n",
        'content' => $payload,
    ),
)));
?>
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
<?php
// This code sends a user's password to a remote API as a URL parameter using HTTPS
$username = 'alice';
$password = 's3cret';
$api_url = 'https://example.com/api?username=' . urlencode($username) . '&password=' . urlencode($password);
$response = file_get_contents($api_url, null, stream_context_create(array(
    'http' => array(
        'method' => 'GET',
    ),
)));
?>
{% endhighlight %}






## آسیب پذیری  Cross-Site Request Forgery (CSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
<form action="transfer.php" method="post">
    <input type="hidden" name="amount" value="1000">
    <input type="submit" value="Transfer Funds">
</form>
{% endhighlight %}



##### ✅ کد اصلاح شده 


{% highlight php %}
<?php
session_start();
$_SESSION['token'] = bin2hex(random_bytes(32));
?>

<form action="transfer.php" method="post">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
    <input type="submit" value="Transfer Funds">
</form>
{% endhighlight %}





## آسیب پذیری  Use of Hard-coded Password

##### 🐞 کد آسیب پذیر


{% highlight php %}
// This code includes a hard-coded password directly in the script
$password = "MyHardCodedPassword123";
$connection = mysqli_connect("localhost", "myuser", $password, "mydatabase");
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
// This code stores the password in a separate configuration file with restricted access
$config = parse_ini_file("/etc/myapp/config.ini");
$connection = mysqli_connect("localhost", "myuser", $config['db_password'], "mydatabase");
{% endhighlight %}








## آسیب پذیری  Broken or Risky Crypto Algorithm

##### 🐞 کد آسیب پذیر


{% highlight php %}
function encryptData($data, $key) {
    $iv = mcrypt_create_iv(16, MCRYPT_DEV_RANDOM);
    $encryptedData = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
    return $encryptedData;
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
function encryptData($data, $key) {
    $iv = openssl_random_pseudo_bytes(16);
    $encryptedData = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encryptedData);
}
{% endhighlight %}





## آسیب پذیری  Insufficient Entropy

##### 🐞 کد آسیب پذیر


{% highlight php %}
$token = substr(str_shuffle('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, 8);
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
$token = bin2hex(random_bytes(16));
{% endhighlight %}








## آسیب پذیری  XSS

##### 🐞 کد آسیب پذیر


{% highlight php %}
<?php
$username = $_GET['username'];
echo "Welcome " . $username . "!";
?>
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
<?php
$username = htmlspecialchars($_GET['username'], ENT_QUOTES, 'UTF-8');
echo "Welcome " . $username . "!";
?>
{% endhighlight %}







## آسیب پذیری  SQL Injection

##### 🐞 کد آسیب پذیر


{% highlight php %}
$username = $_POST['username'];
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $sql);
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
$username = mysqli_real_escape_string($conn, $_POST['username']);
$password = mysqli_real_escape_string($conn, $_POST['password']);

$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $sql);
{% endhighlight %}






## آسیب پذیری  External Control of File Name or Path

##### 🐞 کد آسیب پذیر


{% highlight php %}
$username = $_POST['username'];
$password = $_POST['password'];

$stmt = $conn->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
$result = $stmt->get_result();
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
$filename = basename($_GET['filename']);
$file = '/path/to/directory/' . $filename;
if (file_exists($file) && is_file($file)) {
  // do something with the file
} else {
  // handle error
}
{% endhighlight %}







## آسیب پذیری  Generation of Error Message Containing Sensitive Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
<?php
$username = $_POST['username'];
$password = $_POST['password'];
if ($username != 'admin' || $password != 'secretpass') {
  die('Invalid username or password!');
}
?>
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
<?php
$username = $_POST['username'];
$password = $_POST['password'];
if ($username != 'admin' || $password != 'secretpass') {
  die('Invalid username or password!');
} else {
  // Valid login
}
?>
{% endhighlight %}






## آسیب پذیری  unprotected storage of credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
$username = $_POST['username'];
$password = $_POST['password'];
$file = fopen('credentials.txt', 'w');
fwrite($file, "Username: $username, Password: $password");
fclose($file);
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
$username = $_POST['username'];
$password = $_POST['password'];
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
$dbConnection = mysqli_connect('localhost', 'user', 'password', 'mydatabase');
$query = "INSERT INTO users (username, password) VALUES ('$username', '$hashedPassword')";
mysqli_query($dbConnection, $query);
{% endhighlight %}






## آسیب پذیری  Trust Boundary Violation

##### 🐞 کد آسیب پذیر


{% highlight php %}
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = ".$user_id;
$results = mysqli_query($conn, $query);
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
$user_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($user_id === false) {
    // handle invalid input
} else {
    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $results = $stmt->get_result();
}
{% endhighlight %}









## آسیب پذیری  Insufficiently Protected Credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
$password = $_POST['password'];
$hashed_password = sha1($password);
$query = "INSERT INTO users (username, password) VALUES ('{$_POST['username']}', '{$hashed_password}')";
mysqli_query($conn, $query);
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
$password = $_POST['password'];
if (strlen($password) < 8) {
    // Handle error: password must be at least 8 characters long
}
$salt = bin2hex(random_bytes(16));
$hashed_password = password_hash($password . $salt, PASSWORD_ARGON2ID);
$stmt = $conn->prepare("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)");
$stmt->bind_param("sss", $_POST['username'], $hashed_password, $salt);
$stmt->execute();
{% endhighlight %}













## آسیب پذیری  Restriction of XML External Entity Reference

##### 🐞 کد آسیب پذیر


{% highlight php %}
$xml = simplexml_load_string($xmlstring, 'SimpleXMLElement', LIBXML_NOENT);

// use $xml here
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
$disableEntities = libxml_disable_entity_loader(true);
$xml = simplexml_load_string($xmlstring, 'SimpleXMLElement', LIBXML_NOENT);
libxml_disable_entity_loader($disableEntities);

// use $xml here
{% endhighlight %}









## آسیب پذیری  Vulnerable and Outdated Components


##### 🐞 کد آسیب پذیر


{% highlight php %}
<?php
// Example of vulnerable and outdated components
// using an old version of PHPMailer library

require_once 'PHPMailer/class.phpmailer.php';

$mail = new PHPMailer();

$mail->IsSMTP();
$mail->SMTPDebug = 1;
$mail->SMTPAuth = true;
$mail->SMTPSecure = 'ssl';

$mail->Host = 'smtp.gmail.com';
$mail->Port = 465;

$mail->Username = 'example@gmail.com';
$mail->Password = 'password';

$mail->SetFrom('from@example.com', 'From Name');
$mail->AddReplyTo('reply@example.com', 'Reply-to Name');

$mail->Subject = 'Test email';
$mail->Body = 'This is a test email';

$mail->AddAddress('recipient@example.com', 'Recipient Name');

if (!$mail->Send()) {
    echo 'Message could not be sent.';
    echo 'Mailer Error: ' . $mail->ErrorInfo;
} else {
    echo 'Message has been sent.';
}
?>
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
<?php
// Example of secure and up-to-date code
// using the latest version of PHPMailer library

require_once 'PHPMailer/src/PHPMailer.php';
require_once 'PHPMailer/src/SMTP.php';

$mail = new PHPMailer\PHPMailer\PHPMailer(true);

$mail->SMTPDebug = SMTP::DEBUG_SERVER;
$mail->isSMTP();
$mail->Host = 'smtp.gmail.com';
$mail->SMTPAuth = true;
$mail->Username = 'example@gmail.com';
$mail->Password = 'password';
$mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
$mail->Port = 587;

$mail->setFrom('from@example.com', 'From Name');
$mail->addAddress('recipient@example.com', 'Recipient Name');

$mail->isHTML(true);
$mail->Subject = 'Test email';
$mail->Body = 'This is a test email';

if (!$mail->send()) {
    echo 'Message could not be sent.';
    echo 'Mailer Error: ' . $mail->ErrorInfo;
{% endhighlight %}








## آسیب پذیری  Improper Validation of Certificate with Host Mismatch

##### 🐞 کد آسیب پذیر


{% highlight php %}
$host = $_SERVER['HTTP_HOST'];
$opts = array('ssl' => array('verify_peer' => true, 'CN_match' => $host));
$context = stream_context_create($opts);
$data = file_get_contents('https://example.com', false, $context);
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
$host = 'example.com';
$opts = array('ssl' => array('verify_peer' => true, 'CN_match' => $host));
$context = stream_context_create($opts);
$data = file_get_contents('https://'.$host, false, $context);
{% endhighlight %}








## آسیب پذیری  Improper Authentication

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Example 1: Weak Password
$password = $_POST['password'];
if ($password === 'password123') {
    // Allow access
} else {
    // Deny access
}

// Example 2: Hardcoded Credentials
$username = 'admin';
$password = 'password';
if ($_POST['username'] === $username && $_POST['password'] === $password) {
    // Allow access
} else {
    // Deny access
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
// Example 1: Strong Password
$password = $_POST['password'];
if (password_verify($password, $hashedPassword)) {
    // Allow access
} else {
    // Deny access
}

// Example 2: Stored Credentials
$username = $_POST['username'];
$password = $_POST['password'];

// Validate the user's credentials against a secure database
if (validateCredentials($username, $password)) {
    // Allow access
} else {
    // Deny access
}
{% endhighlight %}








## آسیب پذیری  Session Fixation

##### 🐞 کد آسیب پذیر


{% highlight php %}
<?php
session_start();
if (isset($_POST['username']) && isset($_POST['password'])) {
  $username = $_POST['username'];
  $password = $_POST['password'];
  if (authenticate($username, $password)) {
    $_SESSION['authenticated'] = true;
    $_SESSION['username'] = $username;
  }
}
?>
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
<?php
session_start();
if (isset($_POST['username']) && isset($_POST['password'])) {
  $username = $_POST['username'];
  $password = $_POST['password'];
  if (authenticate($username, $password)) {
    // Regenerate session ID after successful login
    session_regenerate_id();
    $_SESSION['authenticated'] = true;
    $_SESSION['username'] = $username;
  }
}
?>
{% endhighlight %}









## آسیب پذیری  Inclusion of Functionality from Untrusted Control

##### 🐞 کد آسیب پذیر


{% highlight php %}
<?php
$remoteUrl = $_GET['url'];
include($remoteUrl);
?>
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
<?php
$remoteUrl = $_GET['url'];
if (filter_var($remoteUrl, FILTER_VALIDATE_URL)) {
  include($remoteUrl);
} else {
  // handle error
}
?>
{% endhighlight %}








## آسیب پذیری  Download of Code Without Integrity Check

##### 🐞 کد آسیب پذیر


{% highlight php %}
$url = 'https://example.com/package.tar.gz';
$pkg = file_get_contents($url);
file_put_contents('/tmp/package.tar.gz', $pkg);
system('tar -xvf /tmp/package.tar.gz');
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
$url = 'https://example.com/package.tar.gz';
$hash = file_get_contents($url . '.sha256');
$pkg = file_get_contents($url);

if (hash('sha256', $pkg) === trim($hash)) {
    file_put_contents('/tmp/package.tar.gz', $pkg);
    system('tar -xvf /tmp/package.tar.gz');
} else {
    throw new Exception('Package hash does not match expected value');
}
{% endhighlight %}





## آسیب پذیری  Deserialization of Untrusted Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code for Deserialization of Untrusted Data

// unserialize() function is used to deserialize the input data from a string
$userData = unserialize($_COOKIE['user']);

// Use the data from $userData
$name = $userData['name'];
$id = $userData['id'];
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code for Deserialization of Untrusted Data

// Deserialize the input data after validating and sanitizing it
$userData = json_decode(filter_input(INPUT_COOKIE, 'user', FILTER_SANITIZE_STRING));

// Use the data from $userData
if (isset($userData->name)) {
    $name = $userData->name;
}
if (isset($userData->id)) {
    $id = $userData->id;
}
{% endhighlight %}









## آسیب پذیری  Insufficient Logging

##### 🐞 کد آسیب پذیر


{% highlight php %}
function transferMoney($amount, $recipient) {
  // some code to transfer money
  // ...
  
  // log the transaction
  file_put_contents('transaction.log', "Transfered $amount to $recipient", FILE_APPEND);
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
function transferMoney($amount, $recipient) {
  // some code to transfer money
  // ...
  
  // log the transaction with useful information
  $log = fopen('transaction.log', 'a');
  if ($log) {
    $datetime = date('Y-m-d H:i:s');
    $severity = 'INFO';
    $message = "Transfered $amount to $recipient";
    $entry = "$datetime [$severity]: $message\n";
    fwrite($log, $entry);
    fclose($log);
  } else {
    error_log('Unable to open transaction log file');
  }
}
{% endhighlight %}









## آسیب پذیری  Improper Output Neutralization for Logs

##### 🐞 کد آسیب پذیر


{% highlight php %}
$username = $_POST['username'];
$password = $_POST['password'];

// log the username and password to a file
file_put_contents('logs.txt', 'Username: '.$username.' Password: '.$password);
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
$username = $_POST['username'];
$password = $_POST['password'];

// sanitize the input using filter_var
$sanitized_username = filter_var($username, FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH);
$sanitized_password = filter_var($password, FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH);

// log the sanitized username and password to a file
file_put_contents('logs.txt', 'Username: '.$sanitized_username.' Password: '.$sanitized_password);
{% endhighlight %}






          



## آسیب پذیری  Omission of Security-relevant Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
$username = $_POST['username'];
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE username = '" . $username . "' AND password = '" . $password . "'";
$result = mysqli_query($conn, $sql);

if (mysqli_num_rows($result) > 0) {
    // user is authenticated
    // do some sensitive operation
} else {
    // user is not authenticated
    echo "Invalid credentials";
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
$username = $_POST['username'];
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE username = ? AND password = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "ss", $username, $password);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (mysqli_num_rows($result) > 0) {
    // user is authenticated
    // do some sensitive operation
} else {
    // user is not authenticated
    echo "Invalid credentials";
}
{% endhighlight %}











## آسیب پذیری  Sensitive Information into Log File

##### 🐞 کد آسیب پذیر


{% highlight php %}
// sensitive data is logged without proper redaction
$username = $_POST['username'];
$password = $_POST['password'];

error_log("Login attempt with username: ".$username." and password: ".$password);
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
// sensitive data is redacted before being logged
$username = $_POST['username'];
$password = $_POST['password'];

error_log("Login attempt with username: ".redact($username)." and password: ".redact($password));

function redact($string) {
  // replace sensitive data with asterisks
  return preg_replace('/./', '*', $string);
}
{% endhighlight %}









## آسیب پذیری  Server-Side Request Forgery (SSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
$url = $_GET['url'];
$file = file_get_contents($url);
echo $file;
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
$url = $_GET['url'];
if (filter_var($url, FILTER_VALIDATE_URL) === FALSE) {
    echo "Invalid URL";
} else {
    $file = file_get_contents($url);
    echo $file;
}
{% endhighlight %}



