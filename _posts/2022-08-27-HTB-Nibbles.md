---
title: "HackTheBox - Nibbles"
author: Nasrallah
description: ""
date: 2022-08-27 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sudo, cve, metasploit]
img_path: /assets/img/hackthebox/machines/nibbles
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Nibbles](https://app.hackthebox.com/machines/Nibbles) from [HackTheBox](https://www.hackthebox.com). The target is running a vulnerable service allowing us to get foothold. Exploit sudo permission gives root.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.75
Host is up (0.49s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There a webserver on port 80.

## Web

Navigate the the website.

![](1.png)

Let's view the source code with `ctrl + u`.

![](2.png)

Found **/nibbleblog/ directory** directory.

![](3.png)

This is **Nibbleblog**, let's see if there is any exploit available for this service.

```terminal
$ searchsploit nibbleblog                                      
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                                                                                     | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                                                                      | php/remote/38489.rb
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

Great! There is arbitrary file upload vulnerability on metasploit.

# **Foothold**

Fire up metasploit and use the exploit.

![](4.png)

After setting up the required options, let's start the exploit.

![](5.png)

# **Privilege Escalation**

Let's check our privileges.

![](6.png)

We can run the script `monitor.sh` as root without any password.

I first created the `personal/stuff` directories with the command `mkdir -p dir1/dir2`.

then put the command `cp /bin/bash /tmp/bash && chmod +s /tmp/bash` in monitor.sh script. give is execute permission and the run it.

![](7.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).