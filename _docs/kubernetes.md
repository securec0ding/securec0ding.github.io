---
title: Kubernetes
tags: 
 - kubernetes
description: Kubernetes Vulnerabilities
---

# Kubernetes



## آسیب پذیری Hardcoded Credential

##### 🐞 کد آسیب پذیر

{% highlight php %}
# Noncompliant code
apiVersion: v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 3
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: my-app-container
        image: my-app:v1
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          value: "mysql://root:password@localhost:3306/my_database"
{% endhighlight %}



##### ✅ کد اصلاح شده 




{% highlight php %}
# Compliant code
apiVersion: v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 3
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: my-app-container
        image: my-app:v1
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: my-app-secrets
              key: database-url
{% endhighlight %}
