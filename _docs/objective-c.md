---
title: Objective-C
tags: 
 - objective-c
description: Objective-C Vulnerabilities
---

# Objective-C




## آسیب پذیری XML External Entity (XXE)



##### 🐞 کد آسیب پذیر


{% highlight php %}
// Noncompliant code
NSString *input = [request parameterForKey:@"input"];
NSLog(@"Processing input: %@", input);
// Process the input without any validation or sanitization
{% endhighlight %}




##### ✅ کد اصلاح شده 


{% highlight php %}
// Compliant code
NSString *input = [request parameterForKey:@"input"];
NSCharacterSet *allowedCharacterSet = [NSCharacterSet alphanumericCharacterSet];
NSString *sanitizedInput = [[input componentsSeparatedByCharactersInSet:[allowedCharacterSet invertedSet]] componentsJoinedByString:@""];
NSLog(@"Processing input: %@", sanitizedInput);
// Process the sanitized input
{% endhighlight %}


