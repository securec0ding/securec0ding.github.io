---
title: Go
tags: 
 - go
description: Go Vulnerabilities
---

# Go




## آسیب پذیری Exposure of sensitive information


##### 🐞 کد آسیب پذیر




{% highlight php %}
package main

import (
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/users", getUsers)
    http.ListenAndServe(":8080", nil)
}

func getUsers(w http.ResponseWriter, r *http.Request) {
    // Access sensitive data from the database
    username := "admin"
    password := "secret"

    // Return the sensitive information in the HTTP response
    fmt.Fprintf(w, "Username: %s, Password: %s", username, password)
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/users", getUsers)
    http.ListenAndServe(":8080", nil)
}

func getUsers(w http.ResponseWriter, r *http.Request) {
    // Access sensitive data from the database
    username := "admin"
    password := "secret"

    // Instead of returning sensitive information, return a generic message
    fmt.Fprint(w, "Access denied")
}
{% endhighlight %}





## آسیب پذیری Insertion of Sensitive Information Into Sent Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "log"
    "net/http"
)

func main() {
    http.HandleFunc("/login", login)
    http.ListenAndServe(":8080", nil)
}

func login(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    // Authenticate the user
    if !authenticate(username, password) {
        errMsg := fmt.Sprintf("Login failed for user: %s", username)
        log.Println(errMsg)
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Proceed with successful login
    // ...
    // Code for handling successful login
}

func authenticate(username, password string) bool {
    // Perform authentication logic
    // ...
    // Code for authenticating the user

    return false
}
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "log"
    "net/http"
)

func main() {
    http.HandleFunc("/login", login)
    http.ListenAndServe(":8080", nil)
}

func login(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    // Authenticate the user
    if !authenticate(username, password) {
        log.Println("Login failed for user:", username)
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Proceed with successful login
    // ...
    // Code for handling successful login
}

func authenticate(username, password string) bool {
    // Perform authentication logic
    // ...
    // Code for authenticating the user

    return false
}
{% endhighlight %}






## آسیب پذیری  Cross-Site Request Forgery (CSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "html/template"
    "log"
    "net/http"
)

var (
    templates = template.Must(template.ParseFiles("index.html"))
)

func main() {
    http.HandleFunc("/", indexHandler)
    http.HandleFunc("/transfer", transferHandler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        templates.ExecuteTemplate(w, "index.html", nil)
    } else if r.Method == http.MethodPost {
        amount := r.FormValue("amount")
        account := r.FormValue("account")

        // Perform the money transfer
        if transferMoney(amount, account) {
            fmt.Fprintln(w, "Transfer successful!")
        } else {
            fmt.Fprintln(w, "Transfer failed!")
        }
    }
}

func transferHandler(w http.ResponseWriter, r *http.Request) {
    // Process transfer request
    // ...
}

func transferMoney(amount, account string) bool {
    // Perform money transfer logic
    // ...
    return false
}
{% endhighlight %}



##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "html/template"
    "log"
    "net/http"

    "github.com/gorilla/csrf"
)

var (
    templates = template.Must(template.ParseFiles("index.html"))
)

func main() {
    http.HandleFunc("/", indexHandler)
    http.HandleFunc("/transfer", transferHandler)
    log.Fatal(http.ListenAndServe(":8080", csrf.Protect([]byte("32-byte-long-auth-key"))(nil)))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        token := csrf.Token(r)
        data := struct {
            Token string
        }{
            Token: token,
        }
        templates.ExecuteTemplate(w, "index.html", data)
    } else if r.Method == http.MethodPost {
        if err := r.ParseForm(); err != nil {
            http.Error(w, "Bad Request", http.StatusBadRequest)
            return
        }

        // Validate CSRF token
        if err := csrf.Protect([]byte("32-byte-long-auth-key")).VerifyToken(csrf.Token(r)); err != nil {
            http.Error(w, "Invalid CSRF token", http.StatusForbidden)
            return
        }

        amount := r.FormValue("amount")
        account := r.FormValue("account")

        // Perform the money transfer
        if transferMoney(amount, account) {
            fmt.Fprintln(w, "Transfer successful!")
        } else {
            fmt.Fprintln(w, "Transfer failed!")
        }
    }
}

func transferHandler(w http.ResponseWriter, r *http.Request) {
    // Process transfer request
    // ...
}

func transferMoney(amount, account string) bool {
    // Perform money transfer logic
    // ...
    return false
}
{% endhighlight %}





## آسیب پذیری  Use of Hard-coded Password

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "log"
)

func main() {
    password := "myHardcodedPassword"
    
    // Rest of the code
    // ...
    
    // Authenticate user with the hardcoded password
    if authenticateUser(password) {
        fmt.Println("Authentication successful!")
    } else {
        fmt.Println("Authentication failed!")
    }
}

func authenticateUser(password string) bool {
    // Perform authentication logic
    // ...
    return password == "myHardcodedPassword"
}
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "log"
    "os"
    "syscall"

    "golang.org/x/crypto/ssh/terminal"
)

func main() {
    // Prompt user to enter the password
    password := promptPassword("Enter your password: ")

    // Rest of the code
    // ...

    // Authenticate user with the entered password
    if authenticateUser(password) {
        fmt.Println("Authentication successful!")
    } else {
        fmt.Println("Authentication failed!")
    }
}

func promptPassword(prompt string) string {
    fmt.Print(prompt)
    password, _ := terminal.ReadPassword(int(syscall.Stdin))
    fmt.Println()
    return string(password)
}

func authenticateUser(password string) bool {
    // Perform authentication logic
    // ...
    return password == "correctPassword"
}
{% endhighlight %}








## آسیب پذیری  Broken or Risky Crypto Algorithm

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "crypto/md5"
    "fmt"
)

func main() {
    data := "Hello, World!"
    hash := md5.Sum([]byte(data))
    fmt.Printf("MD5 Hash: %x\n", hash)
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "crypto/sha256"
    "fmt"
)

func main() {
    data := "Hello, World!"
    hash := sha256.Sum256([]byte(data))
    fmt.Printf("SHA-256 Hash: %x\n", hash)
}
{% endhighlight %}





## آسیب پذیری  Insufficient Entropy

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "math/rand"
)

func generateToken() string {
    charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    length := 8
    token := ""

    for i := 0; i < length; i++ {
        index := rand.Intn(len(charset))
        token += string(charset[index])
    }

    return token
}

func main() {
    token := generateToken()
    fmt.Println("Generated Token:", token)
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
)

func generateToken() string {
    length := 8
    tokenBytes := make([]byte, length)

    _, err := rand.Read(tokenBytes)
    if err != nil {
        panic(err)
    }

    token := base64.URLEncoding.EncodeToString(tokenBytes)[:length]
    return token
}

func main() {
    token := generateToken()
    fmt.Println("Generated Token:", token)
}
{% endhighlight %}








## آسیب پذیری  XSS

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "html/template"
    "log"
    "net/http"
)

func handleHello(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    message := fmt.Sprintf("Hello, %s!", name)

    template := `<h1>Welcome</h1>
                 <p>%s</p>`

    output := fmt.Sprintf(template, message)
    fmt.Fprint(w, output)
}

func main() {
    http.HandleFunc("/hello", handleHello)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "html/template"
    "log"
    "net/http"
)

func handleHello(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    sanitized := template.HTMLEscapeString(name)
    message := fmt.Sprintf("Hello, %s!", sanitized)

    template := `<h1>Welcome</h1>
                 <p>%s</p>`

    output := fmt.Sprintf(template, message)
    fmt.Fprint(w, output)
}

func main() {
    http.HandleFunc("/hello", handleHello)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
{% endhighlight %}







## آسیب پذیری  SQL Injection

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "database/sql"
    "fmt"
    "log"
    "net/http"

    _ "github.com/go-sql-driver/mysql"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    db, err := sql.Open("mysql", "root:password@/mydatabase")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)
    rows, err := db.Query(query)
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()

    // Check if the login was successful
    if rows.Next() {
        fmt.Fprintf(w, "Login successful")
    } else {
        fmt.Fprintf(w, "Login failed")
    }
}

func main() {
    http.HandleFunc("/login", handleLogin)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "database/sql"
    "fmt"
    "log"
    "net/http"

    _ "github.com/go-sql-driver/mysql"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    db, err := sql.Open("mysql", "root:password@/mydatabase")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    query := "SELECT * FROM users WHERE username = ? AND password = ?"
    rows, err := db.Query(query, username, password)
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()

    // Check if the login was successful
    if rows.Next() {
        fmt.Fprintf(w, "Login successful")
    } else {
        fmt.Fprintf(w, "Login failed")
    }
}

func main() {
    http.HandleFunc("/login", handleLogin)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
{% endhighlight %}






## آسیب پذیری  External Control of File Name or Path

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
)

func handleFileDownload(w http.ResponseWriter, r *http.Request) {
    fileName := r.URL.Query().Get("file")

    filePath := "/path/to/files/" + fileName

    file, err := os.Open(filePath)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    fileContent, err := ioutil.ReadAll(file)
    if err != nil {
        log.Fatal(err)
    }

    w.Header().Set("Content-Type", "application/octet-stream")
    w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
    _, err = w.Write(fileContent)
    if err != nil {
        log.Fatal(err)
    }
}

func main() {
    http.HandleFunc("/download", handleFileDownload)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "path/filepath"
)

func handleFileDownload(w http.ResponseWriter, r *http.Request) {
    fileName := r.URL.Query().Get("file")

    // Validate and sanitize the file name
    fileName = filepath.Clean(fileName)
    if fileName == "." || fileName == ".." {
        log.Fatal("Invalid file name")
    }

    filePath := "/path/to/files/" + fileName

    file, err := os.Open(filePath)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    fileContent, err := ioutil.ReadAll(file)
    if err != nil {
        log.Fatal(err)
    }

    w.Header().Set("Content-Type", "application/octet-stream")
    w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
    _, err = w.Write(fileContent)
    if err != nil {
        log.Fatal(err)
    }
}

func main() {
    http.HandleFunc("/download", handleFileDownload)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
{% endhighlight %}







## آسیب پذیری  Generation of Error Message Containing Sensitive Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "log"
    "net/http"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    // Authenticate the user
    if username == "admin" && password == "secretpassword" {
        // Successful login
        fmt.Fprintf(w, "Welcome, admin!")
    } else {
        // Failed login
        errMsg := fmt.Sprintf("Login failed for user: %s", username)
        log.Println(errMsg)
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
    }
}

func main() {
    http.HandleFunc("/login", handleLogin)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "log"
    "net/http"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    // Authenticate the user
    if username == "admin" && password == "secretpassword" {
        // Successful login
        fmt.Fprintf(w, "Welcome, admin!")
    } else {
        // Failed login
        log.Println("Login failed for user:", username)
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
    }
}

func main() {
    http.HandleFunc("/login", handleLogin)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
{% endhighlight %}






## آسیب پذیری  unprotected storage of credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "log"
    "os"
)

var (
    username string
    password string
)

func readCredentials() {
    file, err := os.Open("credentials.txt")
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    fmt.Fscanf(file, "%s\n%s", &username, &password)
}

func main() {
    readCredentials()

    // Use the credentials for authentication
    // ...
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "log"
    "os"
    "path/filepath"

    "golang.org/x/crypto/bcrypt"
)

var (
    username string
    password []byte
)

func readCredentials() {
    file, err := os.Open(filepath.Join("secrets", "credentials.txt"))
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    fmt.Fscanf(file, "%s\n%s", &username, &password)
}

func authenticateUser(inputPassword []byte) bool {
    err := bcrypt.CompareHashAndPassword(password, inputPassword)
    if err != nil {
        return false
    }
    return true
}

func main() {
    readCredentials()

    // Get user input for authentication
    // ...

    // Hash and compare passwords
    inputPassword := []byte("password123")
    if authenticateUser(inputPassword) {
        fmt.Println("Authentication successful!")
    } else {
        fmt.Println("Authentication failed!")
    }
}
{% endhighlight %}






## آسیب پذیری  Trust Boundary Violation

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "net/http"
    "os"
)

func fetchUserData(userID string) ([]byte, error) {
    url := fmt.Sprintf("https://api.example.com/users/%s", userID)
    response, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer response.Body.Close()

    // Read the response body
    data := make([]byte, response.ContentLength)
    _, err = response.Body.Read(data)
    if err != nil {
        return nil, err
    }

    return data, nil
}

func main() {
    userID := os.Args[1]
    userData, err := fetchUserData(userID)
    if err != nil {
        fmt.Printf("Error fetching user data: %s\n", err)
        return
    }

    fmt.Printf("User data: %s\n", userData)
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
$user_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
package main

import (
    "fmt"
    "net/http"
    "os"
    "regexp"
)

func fetchUserData(userID string) ([]byte, error) {
    // Validate the user ID format
    validUserID := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
    if !validUserID.MatchString(userID) {
        return nil, fmt.Errorf("Invalid user ID")
    }

    url := fmt.Sprintf("https://api.example.com/users/%s", userID)
    response, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer response.Body.Close()

    // Read the response body
    data := make([]byte, response.ContentLength)
    _, err = response.Body.Read(data)
    if err != nil {
        return nil, err
    }

    return data, nil
}

func main() {
    userID := os.Args[1]
    userData, err := fetchUserData(userID)
    if err != nil {
        fmt.Printf("Error fetching user data: %s\n", err)
        return
    }

    fmt.Printf("User data: %s\n", userData)
}
{% endhighlight %}









## آسیب پذیری  Insufficiently Protected Credentials

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "net/http"
    "os"
)

const (
    apiUsername = "admin"
    apiPassword = "password"
)

func fetchUserData(userID string) ([]byte, error) {
    url := fmt.Sprintf("https://api.example.com/users/%s", userID)
    request, err := http.NewRequest(http.MethodGet, url, nil)
    if err != nil {
        return nil, err
    }
    request.SetBasicAuth(apiUsername, apiPassword)

    client := &http.Client{}
    response, err := client.Do(request)
    if err != nil {
        return nil, err
    }
    defer response.Body.Close()

    // Read the response body
    data := make([]byte, response.ContentLength)
    _, err = response.Body.Read(data)
    if err != nil {
        return nil, err
    }

    return data, nil
}

func main() {
    userID := os.Args[1]
    userData, err := fetchUserData(userID)
    if err != nil {
        fmt.Printf("Error fetching user data: %s\n", err)
        return
    }

    fmt.Printf("User data: %s\n", userData)
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "net/http"
    "os"
)

func fetchUserData(userID string) ([]byte, error) {
    url := fmt.Sprintf("https://api.example.com/users/%s", userID)
    request, err := http.NewRequest(http.MethodGet, url, nil)
    if err != nil {
        return nil, err
    }
    request.SetBasicAuth(getAPIUsername(), getAPIPassword())

    client := &http.Client{}
    response, err := client.Do(request)
    if err != nil {
        return nil, err
    }
    defer response.Body.Close()

    // Read the response body
    data := make([]byte, response.ContentLength)
    _, err = response.Body.Read(data)
    if err != nil {
        return nil, err
    }

    return data, nil
}

func getAPIUsername() string {
    // Retrieve the API username from a secure configuration or environment variable
    return "admin"
}

func getAPIPassword() string {
    // Retrieve the API password from a secure configuration or environment variable
    return "password"
}

func main() {
    userID := os.Args[1]
    userData, err := fetchUserData(userID)
    if err != nil {
        fmt.Printf("Error fetching user data: %s\n", err)
        return
    }

    fmt.Printf("User data: %s\n", userData)
}
{% endhighlight %}













## آسیب پذیری  Restriction of XML External Entity Reference

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "encoding/xml"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
)

type User struct {
    ID   int    `xml:"id"`
    Name string `xml:"name"`
}

func getUserData(userID string) (*User, error) {
    url := fmt.Sprintf("https://api.example.com/users/%s", userID)
    response, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer response.Body.Close()

    data, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return nil, err
    }

    user := &User{}
    err = xml.Unmarshal(data, user)
    if err != nil {
        return nil, err
    }

    return user, nil
}

func main() {
    userID := os.Args[1]
    user, err := getUserData(userID)
    if err != nil {
        fmt.Printf("Error retrieving user data: %s\n", err)
        return
    }

    fmt.Printf("User ID: %d, Name: %s\n", user.ID, user.Name)
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "encoding/xml"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
)

type User struct {
    ID   int    `xml:"id"`
    Name string `xml:"name"`
}

func getUserData(userID string) (*User, error) {
    url := fmt.Sprintf("https://api.example.com/users/%s", userID)
    response, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer response.Body.Close()

    decoder := xml.NewDecoder(response.Body)
    decoder.Strict = true  // Enable strict XML parsing
    decoder.Entity = xml.HTMLEntity // Disable expansion of external entities

    user := &User{}
    err = decoder.Decode(user)
    if err != nil {
        return nil, err
    }

    return user, nil
}

func main() {
    userID := os.Args[1]
    user, err := getUserData(userID)
    if err != nil {
        fmt.Printf("Error retrieving user data: %s\n", err)
        return
    }

    fmt.Printf("User ID: %d, Name: %s\n", user.ID, user.Name)
}
{% endhighlight %}









## آسیب پذیری  Vulnerable and Outdated Components


##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "github.com/vulnerable/library"
)

func main() {
    data := "Sensitive information"
    encryptedData := library.OldEncryption(data) // Using a vulnerable and outdated encryption function

    fmt.Println("Encrypted Data:", encryptedData)
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "github.com/secure/library"
)

func main() {
    data := "Sensitive information"
    encryptedData := library.NewEncryption(data) // Using a secure and updated encryption function

    fmt.Println("Encrypted Data:", encryptedData)
}
{% endhighlight %}








## آسیب پذیری  Improper Validation of Certificate with Host Mismatch

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "crypto/tls"
    "fmt"
    "net/http"
)

func main() {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, // Disables certificate validation
        },
    }
    client := &http.Client{Transport: tr}

    resp, err := client.Get("https://example.com")
    if err != nil {
        fmt.Println("Error:", err)
        return
    }
    defer resp.Body.Close()

    // Process the response
    // ...
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "crypto/tls"
    "fmt"
    "net/http"
)

func main() {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: false, // Enables certificate validation
        },
    }
    client := &http.Client{Transport: tr}

    resp, err := client.Get("https://example.com")
    if err != nil {
        fmt.Println("Error:", err)
        return
    }
    defer resp.Body.Close()

    // Process the response
    // ...
}
{% endhighlight %}








## آسیب پذیری  Improper Authentication

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/dashboard", dashboardHandler)
    http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    // Perform authentication
    if username == "admin" && password == "password" {
        // Successful authentication
        // ...
        fmt.Fprintf(w, "Login successful!")
    } else {
        // Failed authentication
        // ...
        fmt.Fprintf(w, "Login failed!")
    }
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    // Check if the user is authenticated
    if isAuthenticated(r) {
        // Show dashboard
        // ...
        fmt.Fprintf(w, "Welcome to the dashboard!")
    } else {
        // Redirect to login page
        http.Redirect(w, r, "/login", http.StatusFound)
    }
}

func isAuthenticated(r *http.Request) bool {
    // Check if the user is authenticated
    // ...
    return false
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "golang.org/x/crypto/bcrypt"
    "net/http"
)

func main() {
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/dashboard", dashboardHandler)
    http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    // Retrieve the stored hashed password for the given username
    hashedPassword, _ := getHashedPassword(username)

    // Compare the provided password with the hashed password
    err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
    if err == nil {
        // Successful authentication
        // ...
        fmt.Fprintf(w, "Login successful!")
    } else {
        // Failed authentication
        // ...
        fmt.Fprintf(w, "Login failed!")
    }
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    // Check if the user is authenticated
    if isAuthenticated(r) {
        // Show dashboard
        // ...
        fmt.Fprintf(w, "Welcome to the dashboard!")
    } else {
        // Redirect to login page
        http.Redirect(w, r, "/login", http.StatusFound)
    }
}

func isAuthenticated(r *http.Request) bool {
    // Check if the user is authenticated
    // ...
    return false
}

func getHashedPassword(username string) (string, error) {
    // Retrieve the hashed password from the storage for the given username
    // ...
    return "", nil
}
{% endhighlight %}








## آسیب پذیری  Session Fixation

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "net/http"
)

var sessionID string

func main() {
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/dashboard", dashboardHandler)
    http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")

    // Perform authentication
    if username == "admin" {
        // Successful authentication
        sessionID = "123456" // Fixed session ID
        http.SetCookie(w, &http.Cookie{Name: "sessionID", Value: sessionID})
        fmt.Fprintf(w, "Login successful!")
    } else {
        // Failed authentication
        fmt.Fprintf(w, "Login failed!")
    }
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    // Check if the user has a valid session
    if r.Cookie != nil && r.Cookie["sessionID"] != nil && r.Cookie["sessionID"].Value == sessionID {
        // Show dashboard
        fmt.Fprintf(w, "Welcome to the dashboard!")
    } else {
        // Redirect to login page
        http.Redirect(w, r, "/login", http.StatusFound)
    }
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/dashboard", dashboardHandler)
    http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")

    // Perform authentication
    if username == "admin" {
        // Generate a new session ID
        sessionID := generateSessionID()

        // Set the session ID as a cookie value
        http.SetCookie(w, &http.Cookie{Name: "sessionID", Value: sessionID})

        // Redirect to the dashboard
        http.Redirect(w, r, "/dashboard", http.StatusFound)
    } else {
        // Failed authentication
        fmt.Fprintf(w, "Login failed!")
    }
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    // Check if the user has a valid session
    sessionIDCookie, err := r.Cookie("sessionID")
    if err == nil && isValidSessionID(sessionIDCookie.Value) {
        // Show dashboard
        fmt.Fprintf(w, "Welcome to the dashboard!")
    } else {
        // Redirect to login page
        http.Redirect(w, r, "/login", http.StatusFound)
    }
}

func generateSessionID() string {
    // Generate a new session ID
    // ...
    return "generated-session-id"
}

func isValidSessionID(sessionID string) bool {
    // Check if the session ID is valid
    // ...
    return true
}
{% endhighlight %}









## آسیب پذیری  Inclusion of Functionality from Untrusted Control

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "net/http"
    "os/exec"
)

func main() {
    http.HandleFunc("/execute", executeHandler)
    http.ListenAndServe(":8080", nil)
}

func executeHandler(w http.ResponseWriter, r *http.Request) {
    command := r.FormValue("command")

    // Execute the command received from the user
    output, err := exec.Command(command).CombinedOutput()
    if err != nil {
        fmt.Fprintf(w, "Error executing command: %v", err)
        return
    }

    fmt.Fprintf(w, "Command output:\n%s", output)
}
{% endhighlight %}







##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "net/http"
    "os/exec"
    "strings"
)

func main() {
    http.HandleFunc("/execute", executeHandler)
    http.ListenAndServe(":8080", nil)
}

func executeHandler(w http.ResponseWriter, r *http.Request) {
    command := r.FormValue("command")

    // Validate and sanitize the command input
    if !isValidCommand(command) {
        fmt.Fprintf(w, "Invalid command")
        return
    }

    // Execute the validated command
    output, err := exec.Command(command).CombinedOutput()
    if err != nil {
        fmt.Fprintf(w, "Error executing command: %v", err)
        return
    }

    fmt.Fprintf(w, "Command output:\n%s", output)
}

func isValidCommand(command string) bool {
    // Validate the command input against a whitelist of allowed commands
    allowedCommands := []string{"ls", "echo", "pwd"} // Example whitelist

    for _, allowedCmd := range allowedCommands {
        if command == allowedCmd {
            return true
        }
    }

    return false
}
{% endhighlight %}








## آسیب پذیری  Download of Code Without Integrity Check

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
)

func main() {
    url := "http://example.com/malicious-code.zip"
    filePath := "/path/to/save/malicious-code.zip"

    // Download the file from the specified URL
    response, err := http.Get(url)
    if err != nil {
        fmt.Println("Error downloading file:", err)
        return
    }
    defer response.Body.Close()

    // Read the contents of the response body
    data, err := ioutil.ReadAll(response.Body)
    if err != nil {
        fmt.Println("Error reading response:", err)
        return
    }

    // Save the downloaded file
    err = ioutil.WriteFile(filePath, data, 0644)
    if err != nil {
        fmt.Println("Error saving file:", err)
        return
    }

    fmt.Println("File downloaded successfully!")
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
)

func main() {
    url := "http://example.com/malicious-code.zip"
    filePath := "/path/to/save/malicious-code.zip"

    // Download the file from the specified URL
    response, err := http.Get(url)
    if err != nil {
        fmt.Println("Error downloading file:", err)
        return
    }
    defer response.Body.Close()

    // Read the contents of the response body
    data, err := ioutil.ReadAll(response.Body)
    if err != nil {
        fmt.Println("Error reading response:", err)
        return
    }

    // Perform an integrity check on the downloaded file
    if !isFileIntegrityValid(data) {
        fmt.Println("File integrity check failed!")
        return
    }

    // Save the downloaded file
    err = ioutil.WriteFile(filePath, data, 0644)
    if err != nil {
        fmt.Println("Error saving file:", err)
        return
    }

    fmt.Println("File downloaded and saved successfully!")
}

func isFileIntegrityValid(data []byte) bool {
    // Implement an integrity check algorithm (e.g., cryptographic hash)
    // to validate the integrity of the downloaded file
    // and return true if the integrity check passes, or false otherwise

    // Example using SHA256 hash
    expectedHash := "..."
    actualHash := calculateHash(data)

    return expectedHash == actualHash
}

func calculateHash(data []byte) string {
    // Calculate the hash of the data using a suitable cryptographic hash function
    // and return the hash value as a string

    // Example using SHA256 hash
    // ...

    return "..."
}
{% endhighlight %}





## آسیب پذیری  Deserialization of Untrusted Data

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "encoding/json"
    "fmt"
    "log"
)

type User struct {
    ID       int
    Username string
    Email    string
}

func main() {
    data := `{"ID": 1, "Username": "john", "Email": "john@example.com"}`

    var user User
    err := json.Unmarshal([]byte(data), &user)
    if err != nil {
        log.Fatal("Error deserializing user:", err)
    }

    fmt.Println("User:", user)
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "encoding/json"
    "fmt"
    "log"
)

type User struct {
    ID       int
    Username string
    Email    string
}

func main() {
    data := `{"ID": 1, "Username": "john", "Email": "john@example.com"}`

    // Perform input validation and sanitization
    if !isValidJSON(data) {
        log.Fatal("Invalid JSON data")
    }

    var user User
    err := json.Unmarshal([]byte(data), &user)
    if err != nil {
        log.Fatal("Error deserializing user:", err)
    }

    // Perform additional validation on the deserialized user object
    if !isValidUser(user) {
        log.Fatal("Invalid user data")
    }

    fmt.Println("User:", user)
}

func isValidJSON(data string) bool {
    // Implement validation logic to ensure the input data is valid JSON
    // and return true if valid, or false otherwise

    // Example: use json.Valid function from the encoding/json package
    return json.Valid([]byte(data))
}

func isValidUser(user User) bool {
    // Implement additional validation logic on the deserialized user object
    // to ensure it meets the application's requirements
    // and return true if valid, or false otherwise

    // Example: check if the username and email meet certain criteria
    if len(user.Username) < 3 || len(user.Email) == 0 {
        return false
    }

    return true
}
{% endhighlight %}









## آسیب پذیری  Insufficient Logging

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
)

func main() {
    http.HandleFunc("/", handleRequest)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
    // Process the request
    // ...

    // Log the request details
    log.Println("Request received:", r.Method, r.URL.Path)

    // Perform some sensitive operation
    performSensitiveOperation()

    // Log the completion of the request
    log.Println("Request processed successfully")
}

func performSensitiveOperation() {
    // Perform some sensitive operation
    // ...

    // Log the sensitive operation
    log.Println("Sensitive operation performed")
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "net/http"
    "os"

    log "github.com/sirupsen/logrus"
)

func main() {
    // Initialize the logger
    initLogger()

    http.HandleFunc("/", handleRequest)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func initLogger() {
    // Set the desired log output, format, and level
    log.SetOutput(os.Stdout)
    log.SetFormatter(&log.JSONFormatter{})
    log.SetLevel(log.InfoLevel)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
    // Process the request
    // ...

    // Log the request details
    log.WithFields(log.Fields{
        "method": r.Method,
        "path":   r.URL.Path,
    }).Info("Request received")

    // Perform some sensitive operation
    performSensitiveOperation()

    // Log the completion of the request
    log.Info("Request processed successfully")
}

func performSensitiveOperation() {
    // Perform some sensitive operation
    // ...

    // Log the sensitive operation
    log.Warn("Sensitive operation performed")
}
{% endhighlight %}









## آسیب پذیری  Improper Output Neutralization for Logs

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "log"
    "net/http"
)

func main() {
    http.HandleFunc("/", handleRequest)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")

    // Log the username
    log.Println("User logged in:", username)

    // Process the request
    // ...
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "log"
    "net/http"
    "strings"
)

func main() {
    http.HandleFunc("/", handleRequest)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")

    // Sanitize the username
    sanitizedUsername := sanitizeString(username)

    // Log the sanitized username
    log.Printf("User logged in: %s", sanitizedUsername)

    // Process the request
    // ...
}

func sanitizeString(s string) string {
    // Replace special characters that could affect log output
    s = strings.ReplaceAll(s, "\n", "\\n")
    s = strings.ReplaceAll(s, "\r", "\\r")
    s = strings.ReplaceAll(s, "\t", "\\t")

    return s
}
{% endhighlight %}






          



## آسیب پذیری  Omission of Security-relevant Information

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "log"
    "net/http"
)

func main() {
    http.HandleFunc("/", handleRequest)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    // Log the user login event
    log.Printf("User logged in: %s", username)

    // Process the request
    // ...
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "log"
    "net/http"
)

func main() {
    http.HandleFunc("/", handleRequest)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    // Log the user login event with all relevant information
    log.Printf("User logged in - Username: %s, Password: %s", username, password)

    // Process the request
    // ...
}
{% endhighlight %}











## آسیب پذیری  Sensitive Information into Log File

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
)

func main() {
    http.HandleFunc("/", handleRequest)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    // Log the sensitive information
    logFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        log.Fatal(err)
    }
    defer logFile.Close()

    logger := log.New(logFile, "", log.LstdFlags)
    logger.Printf("Sensitive information - Username: %s, Password: %s", username, password)

    // Process the request
    // ...
}
{% endhighlight %}





##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "log"
    "net/http"
)

func main() {
    http.HandleFunc("/", handleRequest)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    // Process the request

    // Log a message without sensitive information
    log.Printf("Received request - Username: %s", username)

    // Perform authentication
    if !authenticate(username, password) {
        log.Printf("Authentication failed for user: %s", username)
        http.Error(w, "Authentication failed", http.StatusUnauthorized)
        return
    }

    // Continue with the request
    // ...
}

func authenticate(username, password string) bool {
    // Perform authentication logic
    // ...
}
{% endhighlight %}









## آسیب پذیری  Server-Side Request Forgery (SSRF)

##### 🐞 کد آسیب پذیر


{% highlight php %}
package main

import (
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
)

func main() {
    http.HandleFunc("/fetch", handleFetch)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
    url := r.FormValue("url")

    // Make a request to the provided URL
    response, err := http.Get(url)
    if err != nil {
        log.Fatal(err)
    }

    defer response.Body.Close()

    // Read the response body
    body, err := ioutil.ReadAll(response.Body)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Fprintf(w, "Response Body: %s", body)
}
{% endhighlight %}






##### ✅ کد اصلاح شده 


{% highlight php %}
package main

import (
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "net/url"
)

func main() {
    http.HandleFunc("/fetch", handleFetch)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
    rawURL := r.FormValue("url")

    // Parse the URL to ensure it is valid and safe
    parsedURL, err := url.ParseRequestURI(rawURL)
    if err != nil {
        http.Error(w, "Invalid URL", http.StatusBadRequest)
        return
    }

    // Ensure that the URL points to a permitted domain
    allowedDomains := []string{"example.com", "trusteddomain.com"}
    if !isDomainAllowed(parsedURL.Host, allowedDomains) {
        http.Error(w, "Access to the specified domain is not allowed", http.StatusForbidden)
        return
    }

    // Make a request to the provided URL
    response, err := http.Get(parsedURL.String())
    if err != nil {
        log.Fatal(err)
    }

    defer response.Body.Close()

    // Read the response body
    body, err := ioutil.ReadAll(response.Body)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Fprintf(w, "Response Body: %s", body)
}

func isDomainAllowed(domain string, allowedDomains []string) bool {
    for _, allowedDomain := range allowedDomains {
        if domain == allowedDomain {
            return true
        }
    }
    return false
}
{% endhighlight %}

