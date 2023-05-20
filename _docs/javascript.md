---
title: Javascript
tags: 
 - javascript
description: Javascript Vulnerabilities
---

# Javascript



## آسیب پذیری Exposure of sensitive information


##### 🐞 کد آسیب پذیر




{% highlight php %}
const fs = require('fs');

function login(username, password) {
  // Validate the username and password
  if (username === 'admin' && password === 'password123') {
    // Log the successful login
    fs.appendFileSync('logs.txt', `Successful login: ${username}`);
    return true;
  } else {
    // Log the failed login
    fs.appendFileSync('logs.txt', `Failed login: ${username}`);
    return false;
  }
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
const fs = require('fs');

function login(username, password) {
  // Validate the username and password
  if (username === 'admin' && password === 'password123') {
    // Log the successful login without sensitive information
    fs.appendFileSync('logs.txt', 'Successful login');
    return true;
  } else {
    // Log the failed login without sensitive information
    fs.appendFileSync('logs.txt', 'Failed login');
    return false;
  }
}
{% endhighlight %}





## آسیب پذیری Insertion of Sensitive Information Into Sent Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();

app.get('/user', (req, res) => {
  const userId = req.query.id;
  const userData = getUserData(userId);

  // Include sensitive information in the response
  res.json({
    id: userId,
    username: userData.username,
    email: userData.email,
    password: userData.password
  });
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();

app.get('/user', (req, res) => {
  const userId = req.query.id;
  const userData = getUserData(userId);

  // Exclude sensitive information from the response
  const { id, username, email } = userData;
  res.json({ id, username, email });
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
{% endhighlight %}






## آسیب پذیری  Cross-Site Request Forgery (CSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();

app.get('/transfer-money', (req, res) => {
  const amount = req.query.amount;
  const toAccount = req.query.to;

  // Transfer money to the specified account
  transferMoney(amount, toAccount);

  res.send('Money transferred successfully!');
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
{% endhighlight %}



##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const csrf = require('csurf');
const app = express();

// Enable CSRF protection middleware
const csrfProtection = csrf({ cookie: true });

// Generate and send CSRF token to the client
app.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Transfer money only for valid CSRF-protected requests
app.post('/transfer-money', csrfProtection, (req, res) => {
  const amount = req.body.amount;
  const toAccount = req.body.to;

  // Transfer money to the specified account
  transferMoney(amount, toAccount);

  res.send('Money transferred successfully!');
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
{% endhighlight %}





## آسیب پذیری  Use of Hard-coded Password

##### 🐞 کد آسیب پذیر


{% highlight php %}
const bcrypt = require('bcrypt');
const saltRounds = 10;
const password = 'myHardcodedPassword';

bcrypt.hash(password, saltRounds, (err, hash) => {
  if (err) {
    console.error('Error hashing password:', err);
    return;
  }

  // Store the hashed password in the database
  storePasswordInDatabase(hash);
});
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
const bcrypt = require('bcrypt');
const saltRounds = 10;

function hashPassword(password, callback) {
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err);
      return callback(err);
    }

    // Store the hashed password in the database
    storePasswordInDatabase(hash, callback);
  });
}

// Usage
const password = 'myPassword';
hashPassword(password, (err) => {
  if (err) {
    console.error('Failed to hash password:', err);
    return;
  }

  console.log('Password hashed and stored successfully');
});
{% endhighlight %}








## آسیب پذیری  Broken or Risky Crypto Algorithm

##### 🐞 کد آسیب پذیر


{% highlight php %}
const crypto = require('crypto');

function hashPassword(password) {
  const hash = crypto.createHash('md5').update(password).digest('hex');
  return hash;
}

// Usage
const password = 'myPassword';
const hashedPassword = hashPassword(password);
console.log('Hashed password:', hashedPassword);
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
const bcrypt = require('bcrypt');
const saltRounds = 10;

function hashPassword(password, callback) {
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err);
      return callback(err);
    }
    return callback(null, hash);
  });
}

// Usage
const password = 'myPassword';
hashPassword(password, (err, hashedPassword) => {
  if (err) {
    console.error('Failed to hash password:', err);
    return;
  }

  console.log('Hashed password:', hashedPassword);
});
{% endhighlight %}





## آسیب پذیری  Insufficient Entropy

##### 🐞 کد آسیب پذیر


{% highlight php %}
function generateApiKey() {
  const length = 32;
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let apiKey = '';

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * chars.length);
    apiKey += chars.charAt(randomIndex);
  }

  return apiKey;
}

// Usage
const apiKey = generateApiKey();
console.log('Generated API key:', apiKey);
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
const crypto = require('crypto');

function generateApiKey() {
  const length = 32;
  const buffer = crypto.randomBytes(length);
  const apiKey = buffer.toString('hex');
  return apiKey;
}

// Usage
const apiKey = generateApiKey();
console.log('Generated API key:', apiKey);
{% endhighlight %}








## آسیب پذیری  XSS

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const query = req.query.q;
  const response = `Search results for: ${query}`;
  res.send(response);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();
const xss = require('xss');

app.get('/search', (req, res) => {
  const query = req.query.q;
  const sanitizedQuery = xss(query);
  const response = `Search results for: ${sanitizedQuery}`;
  res.send(response);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}







## آسیب پذیری  SQL Injection

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();
const mysql = require('mysql');

app.get('/users', (req, res) => {
  const userId = req.query.id;
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  // Execute the SQL query and return the results
  const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'mydb'
  });
  
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();
const mysql = require('mysql');

app.get('/users', (req, res) => {
  const userId = req.query.id;
  const query = 'SELECT * FROM users WHERE id = ?';
  const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'mydb'
  });

  connection.query(query, [userId], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






## آسیب پذیری  External Control of File Name or Path

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();
const fs = require('fs');

app.get('/download', (req, res) => {
  const fileName = req.query.file;
  const filePath = `/path/to/files/${fileName}`;

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.setHeader('Content-Disposition', `attachment; filename=${fileName}`);
      res.send(data);
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();
const fs = require('fs');
const path = require('path');

app.get('/download', (req, res) => {
  const fileName = req.query.file;
  const sanitizedFileName = path.basename(fileName); // Sanitize the file name
  const filePath = path.join('/path/to/files', sanitizedFileName);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.setHeader('Content-Disposition', `attachment; filename=${sanitizedFileName}`);
      res.send(data);
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}







## آسیب پذیری  Generation of Error Message Containing Sensitive Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const user = getUserFromDatabase(userId);

  if (!user) {
    throw new Error(`User ${userId} not found`); // Noncompliant: Error message contains sensitive information
  }

  res.send(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const user = getUserFromDatabase(userId);

  if (!user) {
    res.status(404).send('User not found'); // Compliant: Generic error message without sensitive information
    return;
  }

  res.send(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






## آسیب پذیری  unprotected storage of credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();

let databaseCredentials = {
  username: 'admin',
  password: 'secretpassword'
};

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === databaseCredentials.username && password === databaseCredentials.password) {
    res.send('Login successful');
  } else {
    res.send('Invalid credentials');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();

// These credentials should be stored securely, such as environment variables or a separate configuration file.
const databaseCredentials = {
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD
};

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === databaseCredentials.username && password === databaseCredentials.password) {
    res.send('Login successful');
  } else {
    res.send('Invalid credentials');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






## آسیب پذیری  Trust Boundary Violation

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();

app.post('/submitForm', (req, res) => {
  const isAdmin = req.body.isAdmin;

  if (isAdmin) {
    // Perform privileged operation
    grantAdminAccess();
  } else {
    // Process user request
    processUserRequest();
  }

  res.send('Form submitted successfully');
});

function grantAdminAccess() {
  // Code to grant admin access
  // ...
}

function processUserRequest() {
  // Code to process user request
  // ...
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();

app.post('/submitForm', (req, res) => {
  const isAdmin = Boolean(req.body.isAdmin);

  if (isAdmin) {
    // Verify user authentication and authorization before granting admin access
    authenticateAndAuthorizeUser(req)
      .then(() => {
        grantAdminAccess();
        res.send('Admin access granted');
      })
      .catch(() => {
        res.status(403).send('Access denied');
      });
  } else {
    // Process user request
    processUserRequest();
    res.send('Form submitted successfully');
  }
});

function grantAdminAccess() {
  // Code to grant admin access
  // ...
}

function processUserRequest() {
  // Code to process user request
  // ...
}

function authenticateAndAuthorizeUser(req) {
  // Perform user authentication and authorization
  // ...
  // Return a promise that resolves if the user is authenticated and authorized, or rejects otherwise
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}









## آسیب پذیری  Insufficiently Protected Credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Store the credentials in plain text
  storeCredentials(username, password);

  // Perform authentication
  const isAuthenticated = authenticate(username, password);

  if (isAuthenticated) {
    res.send('Login successful');
  } else {
    res.send('Login failed');
  }
});

function storeCredentials(username, password) {
  // Code to store credentials (noncompliant)
  // ...
}

function authenticate(username, password) {
  // Code to authenticate user
  // ...
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

const saltRounds = 10;

app.post('/login', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Hash the password
  const hashedPassword = await hashPassword(password);

  // Store the hashed password
  storeCredentials(username, hashedPassword);

  // Perform authentication
  const isAuthenticated = await authenticate(username, password);

  if (isAuthenticated) {
    res.send('Login successful');
  } else {
    res.send('Login failed');
  }
});

async function hashPassword(password) {
  // Hash the password using bcrypt
  const salt = await bcrypt.genSalt(saltRounds);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

function storeCredentials(username, hashedPassword) {
  // Code to store hashed credentials
  // ...
}

async function authenticate(username, password) {
  // Retrieve hashed password from storage
  const storedHashedPassword = await getHashedPassword(username);

  // Compare the provided password with the stored hashed password
  const isAuthenticated = await bcrypt.compare(password, storedHashedPassword);
  return isAuthenticated;
}

async function getHashedPassword(username) {
  // Code to retrieve hashed password from storage
  // ...
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}













## آسیب پذیری  Restriction of XML External Entity Reference

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const xml2js = require('xml2js');

app.use(bodyParser.text({ type: 'text/xml' }));

app.post('/parse-xml', (req, res) => {
  const xmlData = req.body;

  // Parse the XML data
  xml2js.parseString(xmlData, (err, result) => {
    if (err) {
      res.status(400).send('Invalid XML data');
    } else {
      // Process the XML data
      // ...
      res.send('XML data processed successfully');
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const xml2js = require('xml2js');

app.use(bodyParser.text({ type: 'text/xml' }));

app.post('/parse-xml', (req, res) => {
  const xmlData = req.body;

  // Configure the XML parser to disable external entity references
  const parser = new xml2js.Parser({
    explicitCharkey: true,
    explicitRoot: false,
    explicitArray: false,
    ignoreAttrs: true,
    mergeAttrs: false,
    xmlns: false,
    allowDtd: false,
    allowXmlExternalEntities: false, // Disable external entity references
  });

  // Parse the XML data
  parser.parseString(xmlData, (err, result) => {
    if (err) {
      res.status(400).send('Invalid XML data');
    } else {
      // Process the XML data
      // ...
      res.send('XML data processed successfully');
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}









## آسیب پذیری  Vulnerable and Outdated Components


##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const mongo = require('mongo');

app.use(bodyParser.json());

app.post('/user', (req, res) => {
  const user = req.body;
  mongo.connect('mongodb://localhost:27017', (err, client) => {
    if (err) {
      res.status(500).send('Internal Server Error');
    } else {
      const db = client.db('myapp');
      db.collection('users').insertOne(user, (err, result) => {
        if (err) {
          res.status(500).send('Internal Server Error');
        } else {
          res.status(200).send('User created successfully');
        }
      });
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const MongoClient = require('mongodb').MongoClient;

app.use(bodyParser.json());

app.post('/user', (req, res) => {
  const user = req.body;
  MongoClient.connect('mongodb://localhost:27017', { useUnifiedTopology: true }, (err, client) => {
    if (err) {
      console.error(err);
      res.status(500).send('Database connection error');
    } else {
      const db = client.db('myapp');
      db.collection('users').insertOne(user, (err, result) => {
        if (err) {
          console.error(err);
          res.status(500).send('User creation error');
        } else {
          res.status(200).send('User created successfully');
        }
        client.close(); // Close the database connection
      });
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}








## آسیب پذیری  Improper Validation of Certificate with Host Mismatch

##### 🐞 کد آسیب پذیر


{% highlight php %}
const https = require('https');

const options = {
  hostname: 'example.com',
  port: 443,
  path: '/',
  method: 'GET',
  rejectUnauthorized: false, // Disabling certificate validation
};

const req = https.request(options, (res) => {
  res.on('data', (data) => {
    console.log(data.toString());
  });
});

req.end();
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
const https = require('https');
const tls = require('tls');

const options = {
  hostname: 'example.com',
  port: 443,
  path: '/',
  method: 'GET',
  checkServerIdentity: (host, cert) => {
    const err = tls.checkServerIdentity(host, cert);
    if (err) {
      throw err; // Terminate the connection on certificate mismatch
    }
  },
};

const req = https.request(options, (res) => {
  res.on('data', (data) => {
    console.log(data.toString());
  });
});

req.end();
{% endhighlight %}








## آسیب پذیری  Improper Authentication

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (username === 'admin' && password === 'admin123') {
    // Successful authentication
    res.send('Login successful!');
  } else {
    // Failed authentication
    res.send('Invalid username or password!');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');

// Mock user data
const users = [
  {
    username: 'admin',
    password: '$2b$10$rZrVJnI1.Y9OyK6ZrLqmguXHBXYTNcIQ00CJQc8XU1gYRGmdxcqzK', // Hashed password: "admin123"
  },
];

app.use(express.json());

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  const user = users.find((user) => user.username === username);
  if (!user) {
    // User not found
    return res.status(401).send('Invalid username or password!');
  }

  bcrypt.compare(password, user.password, (err, result) => {
    if (err) {
      // Error during password comparison
      return res.status(500).send('Internal Server Error');
    }

    if (result) {
      // Successful authentication
      res.send('Login successful!');
    } else {
      // Failed authentication
      res.status(401).send('Invalid username or password!');
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}








## آسیب پذیری  Session Fixation

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const session = require('express-session');
const app = express();

app.use(
  session({
    secret: 'insecuresecret',
    resave: false,
    saveUninitialized: true,
  })
);

app.get('/login', (req, res) => {
  // Generate a new session ID and store it in the session cookie
  req.session.regenerate(() => {
    req.session.userId = 'admin';
    res.send('Logged in!');
  });
});

app.get('/profile', (req, res) => {
  // Accessing the profile without authentication
  const userId = req.session.userId;
  if (userId) {
    res.send(`Welcome, ${userId}!`);
  } else {
    res.send('Please log in!');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const app = express();

app.use(
  session({
    secret: 'securesecret',
    resave: false,
    saveUninitialized: true,
    genid: () => {
      // Generate a unique session ID
      return crypto.randomBytes(16).toString('hex');
    },
  })
);

app.get('/login', (req, res) => {
  // Regenerate session ID to prevent session fixation
  req.session.regenerate(() => {
    req.session.userId = 'admin';
    res.send('Logged in!');
  });
});

app.get('/profile', (req, res) => {
  // Accessing the profile without authentication
  const userId = req.session.userId;
  if (userId) {
    res.send(`Welcome, ${userId}!`);
  } else {
    res.send('Please log in!');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}









## آسیب پذیری  Inclusion of Functionality from Untrusted Control

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();

app.get('/dynamic', (req, res) => {
  const functionName = req.query.function;

  // Execute the specified function from untrusted user input
  eval(functionName);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();

app.get('/dynamic', (req, res) => {
  const functionName = req.query.function;

  // Validate the function name against a whitelist
  if (isFunctionAllowed(functionName)) {
    // Call the allowed function from a predefined set
    const result = callAllowedFunction(functionName);
    res.send(result);
  } else {
    res.status(400).send('Invalid function');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});

function isFunctionAllowed(functionName) {
  // Check if the function name is in the allowed set
  const allowedFunctions = ['function1', 'function2', 'function3'];
  return allowedFunctions.includes(functionName);
}

function callAllowedFunction(functionName) {
  // Implement the logic for each allowed function
  if (functionName === 'function1') {
    return 'Function 1 called';
  } else if (functionName === 'function2') {
    return 'Function 2 called';
  } else if (functionName === 'function3') {
    return 'Function 3 called';
  }
}
{% endhighlight %}








## آسیب پذیری  Download of Code Without Integrity Check

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();

app.get('/download', (req, res) => {
  const fileName = req.query.filename;

  // Download the file without integrity check
  res.download(fileName);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();
const fs = require('fs');
const crypto = require('crypto');

app.get('/download', (req, res) => {
  const fileName = req.query.filename;

  // Read the file contents
  fs.readFile(fileName, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
      return;
    }

    // Calculate the file's hash
    const fileHash = crypto.createHash('sha256').update(data).digest('hex');

    // Perform integrity check
    if (isFileIntegrityValid(fileHash)) {
      // Download the file
      res.download(fileName);
    } else {
      res.status(403).send('Integrity check failed');
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});

function isFileIntegrityValid(fileHash) {
  // Compare the calculated hash with a trusted hash
  const trustedHash = '...'; // Replace with the trusted hash
  return fileHash === trustedHash;
}
{% endhighlight %}





## آسیب پذیری  Deserialization of Untrusted Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const deserialize = require('deserialize');

// Middleware to parse JSON data
app.use(bodyParser.json());

app.post('/user', (req, res) => {
  const userData = req.body;

  // Deserialize user data without validation
  const user = deserialize(userData);

  // Process user data
  // ...

  res.status(200).send('User data processed successfully');
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const validateUser = require('./validateUser');

// Middleware to parse JSON data
app.use(bodyParser.json());

app.post('/user', (req, res) => {
  const userData = req.body;

  // Validate user data
  const validationResult = validateUser(userData);

  if (validationResult.isValid) {
    // Sanitize user data
    const sanitizedData = sanitizeUserData(validationResult.data);

    // Deserialize user data
    const user = deserialize(sanitizedData);

    // Process user data
    // ...

    res.status(200).send('User data processed successfully');
  } else {
    res.status(400).send('Invalid user data');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}









## آسیب پذیری  Insufficient Logging

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Fetch user from the database
  const user = db.getUser(userId);

  // Return user details
  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();
const logger = require('winston');

// Configure logger
logger.configure({
  transports: [
    new logger.transports.Console(),
    new logger.transports.File({ filename: 'app.log' })
  ]
});

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Log the user retrieval event
  logger.info(`User retrieval requested for id: ${userId}`);

  // Fetch user from the database
  const user = db.getUser(userId);

  if (user) {
    // Log successful user retrieval
    logger.info(`User retrieved successfully: ${user.name}`);

    // Return user details
    res.status(200).json(user);
  } else {
    // Log unsuccessful user retrieval
    logger.warn(`User not found for id: ${userId}`);

    // Return appropriate error response
    res.status(404).json({ error: 'User not found' });
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}









## آسیب پذیری  Improper Output Neutralization for Logs

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();
const fs = require('fs');

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Log the user retrieval event
  const logMessage = `User retrieval requested for id: ${userId}`;
  fs.appendFile('app.log', logMessage, (err) => {
    if (err) {
      console.error('Error writing to log file:', err);
    }
  });

  // Fetch user from the database
  const user = db.getUser(userId);

  // Return user details
  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();
const fs = require('fs');
const { sanitizeLogMessage } = require('./utils');

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Log the user retrieval event
  const logMessage = `User retrieval requested for id: ${sanitizeLogMessage(userId)}`;
  fs.appendFile('app.log', logMessage, (err) => {
    if (err) {
      console.error('Error writing to log file:', err);
    }
  });

  // Fetch user from the database
  const user = db.getUser(userId);

  // Return user details
  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






          



## آسیب پذیری  Omission of Security-relevant Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Perform login logic

  if (loggedIn) {
    res.status(200).send('Login successful');
  } else {
    res.status(401).send('Invalid credentials');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Perform login logic

  if (loggedIn) {
    res.status(200).send('Login successful');
  } else {
    console.error(`Login failed for username: ${username}`);
    res.status(401).send('Invalid username or password');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}











## آسیب پذیری  Sensitive Information into Log File

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Fetch user information from the database
  const user = User.findById(userId);

  // Log user information
  console.log(`User information: ${user}`);

  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Fetch user information from the database
  const user = User.findById(userId);

  // Log a generic message instead of sensitive information
  console.log(`User requested: ${userId}`);

  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}









## آسیب پذیری  Server-Side Request Forgery (SSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
const express = require('express');
const axios = require('axios');

const app = express();

app.get('/fetch', (req, res) => {
  const url = req.query.url;

  // Make a request to the provided URL
  axios.get(url)
    .then(response => {
      res.status(200).json(response.data);
    })
    .catch(error => {
      res.status(500).json({ error: 'An error occurred while fetching the URL' });
    });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
const express = require('express');
const axios = require('axios');
const { URL } = require('url');

const app = express();

app.get('/fetch', (req, res) => {
  const url = req.query.url;

  // Validate the URL to ensure it is not an internal resource
  const parsedUrl = new URL(url);
  if (parsedUrl.hostname !== 'example.com') {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  // Make a request to the provided URL
  axios.get(url)
    .then(response => {
      res.status(200).json(response.data);
    })
    .catch(error => {
      res.status(500).json({ error: 'An error occurred while fetching the URL' });
    });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
{% endhighlight %}


