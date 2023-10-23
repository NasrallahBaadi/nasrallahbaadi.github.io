---
title: "HackTheBox - Preignition"
author: Nasrallah
description: ""
date: 2022-06-17 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy]
img_path: /assets/img/hackthebox/machines/preignition/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello l33ts, I hope you are doing well. Today we are going to look at [Preignition](https://app.hackthebox.com/starting-point?tier=0) from [HackTheBox](https://www.hackthebox.com). It's an easy machine running a webserver, we find a login page through a directory scan, and use some default credentials to get in.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.200.99 (10.129.200.99)
Host is up (0.20s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
```

We have a linux machine running nginx 1.14.2 on port 80.

## Web

let's navigate to the webpage.

![](1.png)

It's the default page of nginx.

## Gobuster

Let's run directory scan:`gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.129.200.99/`

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.200.99/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
12:49:14 Starting gobuster in directory enumeration mode
===============================================================
/admin.php            (Status: 200) [Size: 999]
                                               
===============================================================

```

Found /admin.php page. Let's navigate to it.

![](2.png)

It's a login page.

# **Foothold**

The first things to do when presented with a login page is to try some default credentials like : admin:admin - admin:password - root:root.

Let's try them.

![](2.png)

We managed to login using admin:admin.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

# References
