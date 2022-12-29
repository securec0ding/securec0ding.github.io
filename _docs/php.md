---
title: PHP
tags: 
 - php
description: PHP Vulnerabilities
---

# PHP

### آسیب پذیری XSS

<button class="btn btn-danger">آسیب پذیری</button>


آسیب پذیری XSS (Cross-Site Scripting) یکی از مهم ترین آسیب های امنیتی است که می تواند در برنامه های وب وجود داشته باشد. این آسیب پذیری به کاربران اجازه می دهد تا از وب سایت یک سفارشی سازی با استفاده از اسکریپت های جاوااسکریپت اجرا کنند. این اسکریپت ها می توانند بر روی وب سایت های دیگر هم نشان داده شوند و باعث آسیب های امنیتی بزرگ می شوند.

برای جلوگیری از آسیب پذیری XSS، لازم است که تمام ورودی های کاربر در برنامه های وب به طور دقیق تأیید و سانتی سازی شوند. همچنین می توان از کتابخانه های مخصوص امنیتی برای اعمال عملیات سانتی سازی استفاده کرد.


##### 🐞 کد آسیب پذیر

{% highlight php %}
<?php

// اتصال به پایگاه داده
$db = new PDO('mysql:host=localhost;dbname=guestbook', 'username', 'password');

// بررسی میزان ثبت فرم
if (isset($_POST['name']) && isset($_POST['message'])) {
    // سانتی سازی ورودی های کاربر
    $name = htmlspecialchars($_POST['name']);
    $message = htmlspecialchars($_POST['message']);

    // وارد کردن پیام جدید در پایگاه داده
    $stmt = $db->prepare("INSERT INTO messages (name, message) VALUES (?, ?)");
    $stmt->execute([$name, $message]);
}

// دریافت همه پیام ها از پایگاه داده
$stmt = $db->prepare("SELECT * FROM messages");
$stmt->execute();
$messages = $stmt->fetchAll();

?>
<!doctype html>
<html>
<head>
    <title>Guestbook</title>
</head>
<body>
    <h1>Guestbook</h1>

    <form action="" method="post">
        <label for="name">Name:</label>
        <input type="text" id="name" name="name" required>
        <br>
        <label for="message">Message:</label>
        <textarea id="message" name="message" required></textarea>
        <br>
        <input type="submit" value="Submit">
    </form>

    <h2>Messages</h2>

    <?php foreach ($messages as $message): ?>
        <p><strong><?= $message['name'] ?></strong>: <?= $message['message'] ?></p>
    <?php endforeach; ?>
</body>
</html>
{% endhighlight %}



##### ✅ کد اصلاح شده توسط ‍`htmlentities`

{% highlight php %}
// sanitize the user input
$name = htmlentities($_POST['name']);
$message = htmlentities($_POST['message']);
{% endhighlight %}

##### ✅ کد اصلاح شده توسط ‍`strip_tags`

{% highlight php %}
// sanitize the user input
$name = strip_tags($_POST['name']);
$message = strip_tags($_POST['message']);
{% endhighlight %}

##### ✅ کد اصلاح شده توسط ‍`strip_tags+htmlentities`

{% highlight php %}
// sanitize the user input
$name = strip_tags(htmlentities($_POST['name']));
$message = strip_tags(htmlentities($_POST['message']));
{% endhighlight %}



مطالعه بیشتر:
<a href="https://securecoding.ir/index.php/%D8%AA%D8%B2%D8%B1%DB%8C%D9%82_%D8%A7%D8%B3%DA%A9%D8%B1%DB%8C%D9%BE%D8%AA(Cross_Site_Scripting)">آسیب پذیری XSS چیست</a>

