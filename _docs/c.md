---
title: C
tags: 
 - c
description: C Vulnerabilities
---

# C

### آسیب پذیری XSS

<button class="btn btn-danger">آسیب پذیری</button>


آسیب پذیری XSS (Cross-Site Scripting) یکی از مهم ترین آسیب های امنیتی است که می تواند در برنامه های وب وجود داشته باشد. این آسیب پذیری به کاربران اجازه می دهد تا از وب سایت یک سفارشی سازی با استفاده از اسکریپت های جاوااسکریپت اجرا کنند. این اسکریپت ها می توانند بر روی وب سایت های دیگر هم نشان داده شوند و باعث آسیب های امنیتی بزرگ می شوند.

برای جلوگیری از آسیب پذیری XSS، لازم است که تمام ورودی های کاربر در برنامه های وب به طور دقیق تأیید و سانتی سازی شوند. همچنین می توان از کتابخانه های مخصوص امنیتی برای اعمال عملیات سانتی سازی استفاده کرد.


##### 🐞 کد آسیب پذیر

{% highlight php %}
#include <stdio.h>
#include <string.h>

void print_page(char *name, char *message) {
  printf("<html><head><title>XSS Example</title></head><body>\n");
  printf("<h1>Welcome, %s!</h1>\n", name);
  printf("<p>%s</p>\n", message);
  printf("</body></html>\n");
}

int main(int argc, char **argv) {
  char name[64];
  char message[1024];

  printf("Content-Type: text/html\n\n");

  strcpy(name, getenv("QUERY_STRING"));
  strcpy(message, getenv("QUERY_STRING"));

  print_page(name, message);

  return 0;
}
{% endhighlight %}



##### ✅ کد اصلاح شده توسط `htmlspecialchars`

{% highlight php %}
void print_page(char *name, char *message) {
  char page[1024];

  sprintf(page, "<html><head><title>XSS Example</title></head><body>\n");
  sprintf(page + strlen(page), "<h1>Welcome, %s!</h1>\n", htmlspecialchars(name, 64));
  sprintf(page + strlen(page), "<p>%s</p>\n", htmlspecialchars(message, 1024));
  sprintf(page + strlen(page), "</body></html>\n");

  printf("Content-Type: text/html\n\n");
  printf("%s", page);
}
{% endhighlight %}




مطالعه بیشتر:
<a href="https://securecoding.ir/index.php/%D8%AA%D8%B2%D8%B1%DB%8C%D9%82_%D8%A7%D8%B3%DA%A9%D8%B1%DB%8C%D9%BE%D8%AA(Cross_Site_Scripting)">آسیب پذیری XSS چیست</a>



