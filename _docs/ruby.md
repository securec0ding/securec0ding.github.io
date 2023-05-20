---
title: Ruby
tags: 
 - ruby
description: Ruby Vulnerabilities
---

# Ruby



## آسیب پذیری Exposure of sensitive information


##### 🐞 کد آسیب پذیر




{% highlight php %}
def process_payment(user, amount)
  # Log the payment details including sensitive information
  puts "Payment processed for user #{user.name} with amount #{amount}"
  # Process the payment
  # ...
end

{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
require 'logger'

def process_payment(user, amount)
  # Initialize a logger with appropriate settings
  logger = Logger.new('payment.log')
  
  # Log a message without sensitive information
  logger.info("Payment processed for user with ID #{user.id}")
  
  # Process the payment
  # ...
end
{% endhighlight %}





## آسیب پذیری Insertion of Sensitive Information Into Sent Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
def send_data(user, data)
  # Include sensitive information in the sent data
  request_body = { user: user, data: data }
  HTTP.post('https://api.example.com/data', body: request_body.to_json)
end
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
def send_data(user, data)
  # Exclude sensitive information from the sent data
  request_body = { data: data }
  HTTP.post('https://api.example.com/data', body: request_body.to_json)
end
{% endhighlight %}






## آسیب پذیری  Cross-Site Request Forgery (CSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
get '/transfer_funds' do
  amount = params[:amount]
  recipient = params[:recipient]

  # Transfer funds logic here
  # ...
end
{% endhighlight %}



##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
enable :sessions

before do
  csrf_token = session[:csrf_token]
  unless params[:csrf_token] == csrf_token
    halt 403, 'CSRF token verification failed!'
  end
end

get '/transfer_funds' do
  amount = params[:amount]
  recipient = params[:recipient]

  # Transfer funds logic here
  # ...
end
{% endhighlight %}





## آسیب پذیری  Use of Hard-coded Password

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
def login(username, password)
  if username == 'admin' && password == 'password123'
    puts 'Login successful'
  else
    puts 'Invalid credentials'
  end
end
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
def login(username, password)
  stored_password = retrieve_password_from_database(username)

  if stored_password && stored_password == password
    puts 'Login successful'
  else
    puts 'Invalid credentials'
  end
end
{% endhighlight %}








## آسیب پذیری  Broken or Risky Crypto Algorithm

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
require 'openssl'

def encrypt_data(data, key)
  cipher = OpenSSL::Cipher.new('DES')
  cipher.encrypt
  cipher.key = key
  encrypted_data = cipher.update(data) + cipher.final
  encrypted_data
end
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
require 'openssl'

def encrypt_data(data, key)
  cipher = OpenSSL::Cipher.new('AES-256-CBC')
  cipher.encrypt
  cipher.key = key
  iv = cipher.random_iv
  encrypted_data = cipher.update(data) + cipher.final
  encrypted_data
end
{% endhighlight %}





## آسیب پذیری  Insufficient Entropy

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
def generate_password(length)
  charset = Array('A'..'Z') + Array('a'..'z') + Array('0'..'9')
  password = Array.new(length) { charset.sample }.join
  password
end
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
require 'securerandom'

def generate_password(length)
  charset = Array('A'..'Z') + Array('a'..'z') + Array('0'..'9') + ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')']
  password = Array.new(length) { charset.sample }.join
  password
end

def generate_secure_password(length)
  password = SecureRandom.urlsafe_base64(length)
  password
end
{% endhighlight %}








## آسیب پذیری  XSS

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
get '/search' do
  query = params[:query]
  "<h1>Search Results for #{query}</h1>"
end
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
require 'rack/utils'

get '/search' do
  query = params[:query]
  sanitized_query = Rack::Utils.escape_html(query)
  "<h1>Search Results for #{sanitized_query}</h1>"
end
{% endhighlight %}







## آسیب پذیری  SQL Injection

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
get '/search' do
  query = params[:query]
  result = DB.execute("SELECT * FROM products WHERE name = '#{query}'")
  # Process and return search results
end
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
get '/search' do
  query = params[:query]
  result = DB.execute("SELECT * FROM products WHERE name = ?", query)
  # Process and return search results
end
{% endhighlight %}






## آسیب پذیری  External Control of File Name or Path

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
get '/download' do
  filename = params[:filename]
  file_path = "/path/to/files/#{filename}"
  send_file(file_path, disposition: 'attachment')
end
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
get '/download' do
  filename = params[:filename]
  sanitized_filename = File.basename(filename)
  file_path = File.join("/path/to/files/", sanitized_filename)

  if File.exist?(file_path) && File.file?(file_path)
    send_file(file_path, disposition: 'attachment')
  else
    halt 404, 'File not found'
  end
end
{% endhighlight %}







## آسیب پذیری  Generation of Error Message Containing Sensitive Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
get '/user/:id' do
  user_id = params[:id]
  user = User.find(user_id)

  if user.nil?
    error_message = "User with ID #{user_id} not found"
    raise StandardError, error_message
  end

  # Process and return user data
end
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
get '/user/:id' do
  user_id = params[:id]
  user = User.find(user_id)

  if user.nil?
    error_message = "User not found"
    raise StandardError, error_message
  end

  # Process and return user data
end
{% endhighlight %}






## آسیب پذیری  unprotected storage of credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
API_KEY = 'my_api_key'
DB_PASSWORD = 'my_db_password'
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
require 'dotenv'

Dotenv.load('.env')

API_KEY = ENV['API_KEY']
DB_PASSWORD = ENV['DB_PASSWORD']
{% endhighlight %}






## آسیب پذیری  Trust Boundary Violation

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
def process_user_input(user_input)
  if user_input.admin?
    grant_admin_privileges()
  end

  # Process user input
end
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
def process_user_input(user_input, user_role)
  if user_role == 'admin'
    grant_admin_privileges()
  end

  # Process user input
end
{% endhighlight %}









## آسیب پذیری  Insufficiently Protected Credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
API_KEY = 'my_api_key'
DB_PASSWORD = 'my_db_password'

# Code that uses the API key and database password
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
require 'openssl'
require 'base64'

def encrypt_credentials(plaintext)
  cipher = OpenSSL::Cipher.new('AES-256-CBC')
  cipher.encrypt
  cipher.key = ENV['ENCRYPTION_KEY']
  encrypted = cipher.update(plaintext) + cipher.final
  Base64.encode64(encrypted)
end

API_KEY = encrypt_credentials('my_api_key')
DB_PASSWORD = encrypt_credentials('my_db_password')

# Code that uses the encrypted credentials
{% endhighlight %}













## آسیب پذیری  Restriction of XML External Entity Reference

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
require 'nokogiri'

xml_data = "<user><name>John Doe</name><credit_card>&xxe;</credit_card></user>"
doc = Nokogiri::XML(xml_data)

# Process XML document
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
require 'nokogiri'

xml_data = "<user><name>John Doe</name><credit_card>&amp;xxe;</credit_card></user>"
doc = Nokogiri::XML(xml_data) do |config|
  config.nonet # Disable network access
  config.noblanks # Ignore whitespace nodes
  config.noent # Disable entity expansion
end

# Process XML document
{% endhighlight %}









## آسیب پذیری  Vulnerable and Outdated Components


##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
require 'sinatra'

get '/hello' do
  "Hello, World!"
end
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
require 'sinatra'

get '/hello' do
  "Hello, World!"
end
{% endhighlight %}








## آسیب پذیری  Improper Validation of Certificate with Host Mismatch

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
require 'net/http'

def make_secure_request(url)
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  response = http.get(uri.request_uri)
  response.body
end

url = 'https://example.com'
response = make_secure_request(url)
puts response
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
require 'net/http'
require 'openssl'

def make_secure_request(url)
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  http.ca_file = '/path/to/certificate.crt' # Provide the path to the trusted CA certificate
  response = http.get(uri.request_uri)
  response.body
end

url = 'https://example.com'
response = make_secure_request(url)
puts response
{% endhighlight %}








## آسیب پذیری  Improper Authentication

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
def authenticate(username, password)
  if username == 'admin' && password == 'secret'
    puts 'Authentication successful'
  else
    puts 'Authentication failed'
  end
end

# Usage
authenticate('admin', 'guess')  # Noncompliant authentication attempt
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
require 'bcrypt'

def authenticate(username, password)
  hashed_password = get_hashed_password(username)
  if BCrypt::Password.new(hashed_password) == password
    puts 'Authentication successful'
  else
    puts 'Authentication failed'
  end
end

def get_hashed_password(username)
  # Retrieve the hashed password associated with the username from a secure storage (e.g., database)
  # Return the hashed password
end

# Usage
authenticate('admin', 'guess')  # Compliant authentication attempt
{% endhighlight %}








## آسیب پذیری  Session Fixation

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
require 'sinatra'

get '/login' do
  session[:user_id] = params[:user_id]
  redirect '/dashboard'
end

get '/dashboard' do
  # Access user's data based on session[:user_id]
end
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
require 'sinatra'
require 'securerandom'

enable :sessions

get '/login' do
  session.clear # Clear existing session data
  session[:user_id] = params[:user_id]
  session[:session_id] = SecureRandom.uuid # Generate a new session identifier
  redirect '/dashboard'
end

get '/dashboard' do
  # Access user's data based on session[:user_id]
end
{% endhighlight %}









## آسیب پذیری  Inclusion of Functionality from Untrusted Control

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
source_code = params[:source_code]
eval(source_code)
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
require 'sandbox'

source_code = params[:source_code]

sandbox = Sandbox.safe
sandbox.eval(source_code)
{% endhighlight %}








## آسیب پذیری  Download of Code Without Integrity Check

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
require 'open-uri'

file_url = 'http://example.com/malicious_code.rb'
file_content = open(file_url).read

# Process the downloaded file_content
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
require 'open-uri'
require 'digest'

file_url = 'http://example.com/malicious_code.rb'
file_content = open(file_url).read

expected_hash = '5f4dcc3b5aa765d61d8327deb882cf99' # Example expected MD5 hash

if Digest::MD5.hexdigest(file_content) == expected_hash
  # File integrity check passed
  # Process the downloaded file_content
else
  # File integrity check failed
  # Handle the error or reject the downloaded file
end
{% endhighlight %}





## آسیب پذیری  Deserialization of Untrusted Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
data = params[:serialized_data]
object = Marshal.load(data)

# Process the deserialized object
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
# Compliant code
data = params[:serialized_data]
object = nil

begin
  object = YAML.safe_load(data, [Symbol])
rescue Psych::Exception => e
  # Handle deserialization error
  puts "Deserialization error: #{e.message}"
end

# Process the deserialized object if it was successfully loaded
if object
  # Process the deserialized object
else
  # Handle the error or reject the deserialized data
end
{% endhighlight %}









## آسیب پذیری  Insufficient Logging

##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
def transfer_funds(sender, recipient, amount)
  if sender.balance >= amount
    sender.balance -= amount
    recipient.balance += amount
    puts "Funds transferred successfully."
  else
    puts "Insufficient funds."
  end
end
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

