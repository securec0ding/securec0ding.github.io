---
title: Terraform
tags: 
 - terraform
description: Terraform Vulnerabilities
---

# Terraform


  

## آسیب پذیریHardcoded Credential


##### 🐞 کد آسیب پذیر


{% highlight php %}
# Noncompliant code
resource "aws_instance" "my_instance" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t2.micro"
  key_name      = "my_key_pair"
  security_groups = ["${var.security_group_id}"]
}
{% endhighlight %}

##### ✅ کد اصلاح شده 





{% highlight php %}
# Compliant code
variable "ami_id" {
  type    = string
  default = "ami-0123456789abcdef0"
}

variable "instance_type" {
  type    = string
  default = "t2.micro"
}

variable "key_name" {
  type    = string
  default = "my_key_pair"
}

variable "security_group_id" {
  type    = string
  default = ""
}

resource "aws_instance" "my_instance" {
  ami           = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name
  security_groups = [var.security_group_id]
}
{% endhighlight %}


