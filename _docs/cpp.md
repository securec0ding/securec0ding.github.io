---
title: C++
tags: 
 - cpp
description: C++ Vulnerabilities
---

# C++


### آسیب پذیری Null Pointer Dereference


<button class="btn btn-danger">آسیب پذیری</button>




##### 🐞 کد آسیب پذیر

{% highlight php %}
void foo(int* ptr) {
    if (ptr != nullptr) {
        *ptr = 42;
    } else {
        // handle error
    }
}

int main() {
    int* ptr = nullptr;
    foo(ptr);
    return 0;
}
{% endhighlight %}



##### ✅ کد اصلاح شده

{% highlight php %}
void foo(int* ptr) {
    if (ptr != nullptr) {
        *ptr = 42;
    } else {
        // handle error
    }
}

int main() {
    int i = 0;
    int* ptr = &i;
    foo(ptr);
    return 0;
}
{% endhighlight %}




مطالعه بیشتر:
<a href="#"></a>

