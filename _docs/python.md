---
title: Python
tags: 
 - python
description: Python Vulnerabilities
---

# Python



## آسیب پذیری Exposure of sensitive information


##### 🐞 کد آسیب پذیر




{% highlight php %}
@app.route('/users/<id>', methods=['GET'])
def get_user(id):
    user = db.get_user(id)
    
    if user:
        return jsonify(user)
    else:
        return jsonify({'error': 'User not found'}), 404

{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
@app.route('/users/<id>', methods=['GET'])
def get_user(id):
    user = db.get_user(id)
    
    if user:
        sanitized_user = {
            'id': user['id'],
            'name': user['name']
            # Include only necessary non-sensitive information
        }
        return jsonify(sanitized_user)
    else:
        return jsonify({'error': 'User not found'}), 404
{% endhighlight %}





## آسیب پذیری Insertion of Sensitive Information Into Sent Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
def send_email(user_email, message):
    subject = "Important Message"
    body = f"Hello {user_email},\n\n{message}\n\nRegards,\nAdmin"
    
    # Code to send email using SMTP
    # ...
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
def send_email(user_email, message):
    subject = "Important Message"
    body = f"Hello,\n\n{message}\n\nRegards,\nAdmin"
    
    # Code to send email using SMTP
    # ...
{% endhighlight %}






## آسیب پذیری  Cross-Site Request Forgery (CSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/transfer', methods=['POST'])
def transfer():
    # Transfer funds
    amount = request.form['amount']
    destination_account = request.form['destination_account']
    # ... logic to transfer funds ...

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run()
{% endhighlight %}



##### ✅ کد اصلاح شده 


{% highlight php %}
from flask import Flask, render_template, request
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
csrf = CSRFProtect(app)

@app.route('/transfer', methods=['POST'])
@csrf.exempt
def transfer():
    # Transfer funds
    amount = request.form['amount']
    destination_account = request.form['destination_account']
    # ... logic to transfer funds ...

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run()
{% endhighlight %}





## آسیب پذیری  Use of Hard-coded Password

##### 🐞 کد آسیب پذیر


{% highlight php %}
def login(username, password):
    if username == 'admin' and password == 'password123':
        # Login successful
        return True
    else:
        # Login failed
        return False
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
import getpass

def login(username, password):
    stored_password = retrieve_password_from_database(username)
    if password_matches(stored_password, password):
        # Login successful
        return True
    else:
        # Login failed
        return False

def retrieve_password_from_database(username):
    # Code to retrieve the hashed password from the database
    # ...

def password_matches(stored_password, entered_password):
    # Code to compare the stored password with the entered password
    # ...

if __name__ == '__main__':
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    login(username, password)
{% endhighlight %}








## آسیب پذیری  Broken or Risky Crypto Algorithm

##### 🐞 کد آسیب پذیر


{% highlight php %}
import base64
from Crypto.Cipher import DES

def encrypt_data(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_data = cipher.encrypt(data)
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_data(encrypted_data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
    return decrypted_data.decode('utf-8')
}

{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_data(data, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')

def decrypt_data(encrypted_data, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(base64.urlsafe_b64decode(encrypted_data)) + decryptor.finalize()
    return decrypted_data.decode('utf-8')
{% endhighlight %}





## آسیب پذیری  Insufficient Entropy

##### 🐞 کد آسیب پذیر


{% highlight php %}
import random

def generate_random_password(length):
    password = ''
    for _ in range(length):
        password += random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
    return password
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import secrets
import string

def generate_random_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password
{% endhighlight %}








## آسیب پذیری  XSS

##### 🐞 کد آسیب پذیر


{% highlight php %}
def generate_html_output(input_data):
    html = "<div>" + input_data + "</div>"
    return html
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
import html

def generate_html_output(input_data):
    escaped_data = html.escape(input_data)
    html = "<div>" + escaped_data + "</div>"
    return html
{% endhighlight %}







## آسیب پذیری  SQL Injection

##### 🐞 کد آسیب پذیر


{% highlight php %}
import sqlite3

def get_user_data(username):
    conn = sqlite3.connect('mydb.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
import sqlite3

def get_user_data(username):
    conn = sqlite3.connect('mydb.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    result = cursor.fetchall()
    conn.close()
    return result
{% endhighlight %}






## آسیب پذیری  External Control of File Name or Path

##### 🐞 کد آسیب پذیر


{% highlight php %}
import os

def delete_file(file_name):
    path = "/path/to/files/" + file_name
    if os.path.exists(path):
        os.remove(path)
        print("File deleted.")
    else:
        print("File not found.")
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
import os
import os.path

def delete_file(file_name):
    base_path = "/path/to/files/"
    path = os.path.join(base_path, file_name)

    if os.path.exists(path) and os.path.isfile(path):
        os.remove(path)
        print("File deleted.")
    else:
        print("File not found.")
{% endhighlight %}







## آسیب پذیری  Generation of Error Message Containing Sensitive Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
def divide_numbers(a, b):
    try:
        result = a / b
        return result
    except Exception as e:
        error_msg = f"An error occurred: {str(e)}"
        print(error_msg)
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
import logging

def divide_numbers(a, b):
    try:
        result = a / b
        return result
    except Exception as e:
        logging.error("An error occurred during division", exc_info=True)
{% endhighlight %}






## آسیب پذیری  unprotected storage of credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
def save_credentials(username, password):
    credentials_file = open("credentials.txt", "w")
    credentials_file.write(f"Username: {username}\n")
    credentials_file.write(f"Password: {password}\n")
    credentials_file.close()
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import hashlib

def save_credentials(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    credentials = f"Username: {username}\nPassword: {hashed_password}\n"
    
    with open("credentials.txt", "w") as credentials_file:
        credentials_file.write(credentials)
{% endhighlight %}






## آسیب پذیری  Trust Boundary Violation

##### 🐞 کد آسیب پذیر


{% highlight php %}
import subprocess

def process_user_input(user_input):
    # Assume user_input comes from an untrusted source
    cmd = f"echo '{user_input}'"
    output = subprocess.check_output(cmd, shell=True)
    print(output)
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import subprocess
import shlex

def process_user_input(user_input):
    # Assume user_input comes from an untrusted source
    cmd_args = shlex.split(f"echo {user_input}")
    output = subprocess.check_output(cmd_args)
    print(output)
{% endhighlight %}









## آسیب پذیری  Insufficiently Protected Credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
import requests

def login(username, password):
    # Assume username and password come from user input
    url = "https://example.com/login"
    data = {"username": username, "password": password}
    response = requests.post(url, data=data)
    
    if response.status_code == 200:
        print("Login successful")
    else:
        print("Login failed")
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import requests
from requests.auth import HTTPDigestAuth

def login(username, password):
    # Assume username and password come from user input
    url = "https://example.com/login"
    auth = HTTPDigestAuth(username, password)
    response = requests.post(url, auth=auth)
    
    if response.status_code == 200:
        print("Login successful")
    else:
        print("Login failed")
{% endhighlight %}













## آسیب پذیری  Restriction of XML External Entity Reference

##### 🐞 کد آسیب پذیر


{% highlight php %}
import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    tree = ET.fromstring(xml_string)
    # Process the XML data
    ...
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    parser = ET.XMLParser()
    parser.entity_declaration = False  # Disable external entity resolution
    tree = ET.fromstring(xml_string, parser=parser)
    # Process the XML data
    ...
{% endhighlight %}









## آسیب پذیری  Vulnerable and Outdated Components


##### 🐞 کد آسیب پذیر


{% highlight php %}
from flask import Flask, render_template
import requests

app = Flask(__name__)

@app.route('/')
def index():
    # Use a vulnerable function to fetch data
    response = requests.get('http://example.com/api/v1/users')
    data = response.json()
    return render_template('index.html', data=data)

if __name__ == '__main__':
    app.run()
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
from flask import Flask, render_template
import requests
from requests.packages.urllib3.util import ssl_

# Disable SSL verification warnings
ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'

app = Flask(__name__)

@app.route('/')
def index():
    # Use a secure function to fetch data
    response = requests.get('https://example.com/api/v1/users', verify=False)
    data = response.json()
    return render_template('index.html', data=data)

if __name__ == '__main__':
    app.run()
{% endhighlight %}








## آسیب پذیری  Improper Validation of Certificate with Host Mismatch

##### 🐞 کد آسیب پذیر


{% highlight php %}
import requests

def get_secure_data(url):
    # Perform a request without proper certificate validation
    response = requests.get(url, verify=False)
    return response.text

# Example usage
data = get_secure_data('https://example.com')
print(data)
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
import requests

def get_secure_data(url):
    # Perform a request with proper certificate validation
    response = requests.get(url)
    response.raise_for_status()  # Raise an exception if the request fails
    return response.text

# Example usage
data = get_secure_data('https://example.com')
print(data)
{% endhighlight %}








## آسیب پذیری  Improper Authentication

##### 🐞 کد آسیب پذیر


{% highlight php %}
import requests

def login(username, password):
    credentials = {'username': username, 'password': password}
    response = requests.post('https://example.com/login', data=credentials)
    if response.status_code == 200:
        return 'Login successful'
    else:
        return 'Login failed'

# Example usage
result = login('admin', 'password')
print(result)
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
import requests
from requests.auth import HTTPBasicAuth

def login(username, password):
    credentials = HTTPBasicAuth(username, password)
    response = requests.post('https://example.com/login', auth=credentials)
    if response.status_code == 200:
        return 'Login successful'
    else:
        return 'Login failed'

# Example usage
result = login('admin', 'password')
print(result)
{% endhighlight %}








## آسیب پذیری  Session Fixation

##### 🐞 کد آسیب پذیر


{% highlight php %}
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = 'insecure_secret_key'

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Authenticate user
    if username == 'admin' and password == 'password':
        session['username'] = username
        return 'Login successful'
    else:
        return 'Login failed'

@app.route('/profile')
def profile():
    if 'username' in session:
        return f"Welcome, {session['username']}!"
    else:
        return 'Please login'

# Example usage
app.run()
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
from flask import Flask, request, session
import os

app = Flask(__name__)
app.secret_key = os.urandom(16)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Authenticate user
    if username == 'admin' and password == 'password':
        session.regenerate()  # Regenerate session ID
        session['username'] = username
        return 'Login successful'
    else:
        return 'Login failed'

@app.route('/profile')
def profile():
    if 'username' in session:
        return f"Welcome, {session['username']}!"
    else:
        return 'Please login'

# Example usage
app.run()
{% endhighlight %}









## آسیب پذیری  Inclusion of Functionality from Untrusted Control

##### 🐞 کد آسیب پذیر


{% highlight php %}
import requests

# Fetch and execute code from an untrusted source
untrusted_code = requests.get('http://example.com/untrusted_code.py').text
exec(untrusted_code)
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
import requests
import ast

# Fetch and evaluate code from an untrusted source
untrusted_code = requests.get('http://example.com/untrusted_code.py').text
ast.parse(untrusted_code)
{% endhighlight %}








## آسیب پذیری  Download of Code Without Integrity Check

##### 🐞 کد آسیب پذیر


{% highlight php %}
import requests

# Download code without integrity check
code_url = 'http://example.com/malicious_code.py'
response = requests.get(code_url)
code = response.text

# Execute the downloaded code
exec(code)
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import requests
import hashlib

# Download code with integrity check
code_url = 'http://example.com/malicious_code.py'
response = requests.get(code_url)
code = response.text

# Verify code integrity
expected_hash = '4a2d8f37ac...'
calculated_hash = hashlib.sha256(code.encode()).hexdigest()
if calculated_hash == expected_hash:
    exec(code)
else:
    print("Integrity check failed. Code execution aborted.")
{% endhighlight %}





## آسیب پذیری  Deserialization of Untrusted Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
import pickle

def deserialize_data(data):
    # WARNING: This code is noncompliant and insecure
    obj = pickle.loads(data)
    return obj
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import pickle

def deserialize_data(data):
    try:
        obj = pickle.loads(data)
        # Validate the deserialized object or perform additional security checks
        # ...
        return obj
    except (pickle.UnpicklingError, AttributeError, ImportError, TypeError) as e:
        # Handle deserialization errors
        # Log or raise an exception, or return a default value
        # ...
        return None
{% endhighlight %}









## آسیب پذیری  Insufficient Logging

##### 🐞 کد آسیب پذیر


{% highlight php %}
import logging

def process_data(data):
    # Process the data
    # ...
    
    # Log the result
    logging.info("Data processed successfully")
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import logging

def process_data(data):
    # Process the data
    # ...
    
    # Log the result with additional information
    logging.info("Data processed successfully: %s", data)
{% endhighlight %}









## آسیب پذیری  Improper Output Neutralization for Logs

##### 🐞 کد آسیب پذیر


{% highlight php %}
import logging

def log_user_input(username):
    # Log user input
    logging.info("Received username: " + username)
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
import logging

def log_user_input(username):
    # Log user input with proper output neutralization
    logging.info("Received username: %s", username)
{% endhighlight %}






          



## آسیب پذیری  Omission of Security-relevant Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
def login(username, password):
    if username == "admin" and password == "password":
        print("Login successful")
    else:
        print("Login failed")
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import logging

def login(username, password):
    if username == "admin" and password == "password":
        logging.info("Successful login for user: %s", username)
    else:
        logging.warning("Failed login attempt for user: %s", username)
{% endhighlight %}











## آسیب پذیری  Sensitive Information into Log File

##### 🐞 کد آسیب پذیر


{% highlight php %}
import logging

def process_payment(payment_data):
    logging.info("Payment processed for user: %s", payment_data['user'])
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
import logging

def process_payment(payment_data):
    logging.info("Payment processed for user: %s", obfuscate_user(payment_data['user']))

def obfuscate_user(user):
    # Code to obfuscate or mask sensitive information
    return "****" + user[-4:]
{% endhighlight %}









## آسیب پذیری  Server-Side Request Forgery (SSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
import requests

def fetch_url(url):
    response = requests.get(url)
    return response.text
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
import requests

def fetch_url(url):
    if is_valid_url(url):
        response = requests.get(url)
        return response.text
    else:
        raise ValueError("Invalid URL")

def is_valid_url(url):
    # Perform URL validation to ensure it's safe to access
    # Implement whitelist-based validation or restrict access to specific domains

    # Example: Allow access to certain domains
    allowed_domains = ['example.com', 'api.example.com']
    parsed_url = urlparse(url)
    return parsed_url.netloc in allowed_domains
{% endhighlight %}



