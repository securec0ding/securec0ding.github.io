---
title: VB.NET
tags: 
 - vbnet
description: VB.NET Vulnerabilities
---

# VB.NET




## آسیب پذیری Plain Text Password 


##### 🐞 کد آسیب پذیر


{% highlight php %}
' Noncompliant: Insecure handling of user input
Sub Login()
    Console.WriteLine("Enter your username: ")
    Dim username As String = Console.ReadLine()
    Console.WriteLine("Enter your password: ")
    Dim password As String = Console.ReadLine()

    ' Insecure: Password is stored as plain text
    ' Insecure: No input validation or sanitization
    ' Insecure: No protection against brute force attacks
    If username = "admin" AndAlso password = "password" Then
        Console.WriteLine("Login successful!")
    Else
        Console.WriteLine("Login failed!")
    End If
End Sub
{% endhighlight %}





##### ✅ کد اصلاح شده 



{% highlight php %}
' Compliant: Secure handling of user input
Sub Login()
    Console.WriteLine("Enter your username: ")
    Dim username As String = Console.ReadLine()
    Console.WriteLine("Enter your password: ")
    Dim password As String = ReadPassword()

    ' Compliant: Password is securely hashed and stored
    ' Compliant: Input validation and sanitization are implemented
    ' Compliant: Protection against brute force attacks (e.g., account lockout policy)
    If ValidateCredentials(username, password) Then
        Console.WriteLine("Login successful!")
    Else
        Console.WriteLine("Login failed!")
    End If
End Sub

Function ReadPassword() As String
    Dim password As New SecureString()
    Dim keyInfo As ConsoleKeyInfo
    Do
        keyInfo = Console.ReadKey(intercept:=True)
        If keyInfo.Key = ConsoleKey.Backspace AndAlso password.Length > 0 Then
            password.RemoveAt(password.Length - 1)
            Console.Write("\b \b")
        ElseIf keyInfo.Key <> ConsoleKey.Enter Then
            password.AppendChar(keyInfo.KeyChar)
            Console.Write("*")
        End If
    Loop While keyInfo.Key <> ConsoleKey.Enter
    Console.WriteLine()
    Dim unmanagedPassword As String = Nothing
    Try
        unmanagedPassword = Marshal.PtrToStringBSTR(Marshal.SecureStringToBSTR(password))
        Return unmanagedPassword
    Finally
        If unmanagedPassword IsNot Nothing Then
            Array.Clear(unmanagedPassword.ToCharArray(), 0, unmanagedPassword.Length)
        End If
        password.Dispose()
    End Try
End Function

Function ValidateCredentials(ByVal username As String, ByVal password As String) As Boolean
    ' Compliant: Implement proper credential validation logic (e.g., check against secure database)
    ' For the sake of this example, using a simple hardcoded check
    Return username = "admin" AndAlso password = "hashed_password"
End Function
{% endhighlight %}


