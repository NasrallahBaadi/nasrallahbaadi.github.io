---
title: "TryHackMe - Avengers Blog"
author: Nasrallah
description: ""
date: 2022-10-01 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy]
img_path: /assets/img/tryhackme/avengersblog
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Avengers Blog](https://tryhackme.com/room/avengers) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.2.129
Host is up (0.10s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 11:72:9e:e8:be:b3:ff:a7:20:83:c1:56:bd:73:99:d2 (RSA)
|   256 ee:03:dd:4c:89:ec:68:ac:65:e0:29:93:f4:d2:ef:af (ECDSA)
|_  256 0f:d9:55:cb:8b:46:52:82:bc:10:7d:23:00:2c:a3:bd (ED25519)
80/tcp open  http    Node.js Express framework
|_http-title: Avengers! Assemble!
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

There are 3 open ports, 21(ftp), 22(ssh) and 80(http).

### Web

Let's navigate to the web page.

![](1.png)

Here we can see some of the avengers' posts and comments.

Check the cookie with `F12` -> `storage`

![](8.png)

Got the first flag.

Let's check the headers by pressing F12 and going to the network tab.

![](2.png)

We found the second flag.

At the bottom, we see an interesting post.

![](3.png)

We got the passoword of groot, let's login via ftp.

![](4.png)

Got the third flag. Let's move on.

### Gobuster

Let's run a directory scan.

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.2.129/ | tee scans/gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.2.129/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/09/15 06:59:59 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 179] [--> /assets/]
/css                  (Status: 301) [Size: 173] [--> /css/]   
/home                 (Status: 302) [Size: 23] [--> /]        
/Home                 (Status: 302) [Size: 23] [--> /]        
/img                  (Status: 301) [Size: 173] [--> /img/]   
/js                   (Status: 301) [Size: 171] [--> /js/]    
/logout               (Status: 302) [Size: 29] [--> /portal]  
/portal               (Status: 200) [Size: 1409]              
                                                              
===============================================================
```

Found **/portal** directory, let's check it out.

![](5.png)

We found a login page, i tried some default credentials but no luck, then i tried sql injection and managed to login with this payload `' or 1=1 -- -`.

![](6.png)

Seems we can execute some command here, let's try `ls`.

![](7.png)

We can execute commands but not everything. Checking one directory up we find the fifth flag.

![](9.png)


We can't run the command `cat` to print out the flag, instead we can use the following command that would base64 encode the flag and then decode it.

```bash
base64 ../flag5.txt | base64 -d
```

![](10.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
