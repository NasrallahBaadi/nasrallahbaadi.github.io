---
title: "TryHackMe - Easy Peasy"
author: Nasrallah
description: ""
date: 2022-06-05 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, steganography, john, cracking, cronjob, easy]
img_path: /assets/img/tryhackme/easypeasy/
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Easy Peasy](https://tryhackme.com/room/easypeasyctf) from [TryHackMe](https://tryhackme.com). The machines has 3 open ports, 2 webservers and ssh on a non-default port. One of the webservers contains an image that has a hidden file inside of it, and the latter contains ssh credentials. For root access, there is a cronjob running every minute as root, modify the file to escalate privileges.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.196.34 (10.10.196.34)
Host is up (0.070s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.16.1
|_http-server-header: nginx/1.16.1
|_http-title: Welcome to nginx!
| http-robots.txt: 1 disallowed entry 
|_/
```

We found a web server on port 80 running nginx 1.16.1.

Let's run another scan for all ports: `sudo nmap --min-rate 5000 -p- 10.10.10.10`

```terminal
Nmap scan report for 10.10.196.34
Host is up (0.068s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE
80/tcp    open  http
6498/tcp  open  unknown
65524/tcp open  unknown
```

We found another two ports, let's scan the services on them:`sudo nmap -sC -sV -T4 10.10.196.34 -p6498,65524`

```terminal
Nmap scan report for 10.10.196.34 (10.10.196.34)
Host is up (0.068s latency).

PORT      STATE SERVICE VERSION
6498/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 30:4a:2b:22:ac:d9:56:09:f2:da:12:20:57:f4:6c:d4 (RSA)
|   256 bf:86:c9:c7:b7:ef:8c:8b:b9:94:ae:01:88:c0:85:4d (ECDSA)
|_  256 a1:72:ef:6c:81:29:13:ef:5a:6c:24:03:4c:fe:3d:0b (ED25519)
65524/tcp open  http    Apache httpd 2.4.43 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.43 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The first port is running ssh and the second port is another web server running apache.

## Web

Let's run some directory scans on the webserver we found.

### Gobuster

Starting with the webserver on port 80: `gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.10/`

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.196.34/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
09:15:58 Starting gobuster in directory enumeration mode
===============================================================
/hidden               (Status: 301) [Size: 169] [--> http://10.10.196.34/hidden/]
/index.html           (Status: 200) [Size: 612]                                  
/robots.txt           (Status: 200) [Size: 43]                                   
                                                                                 
===============================================================
```

We found the page **/hidden** and it has the following.

![](1.png)

Run another scan on this page.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.196.34/hidden/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/whatever             (Status: 301) [Size: 169] [--> http://10.10.196.34/hidden/whatever/]
===============================================================
```

Found another directory saying it's a dead end.

![](3.png)

View the source code by pressing `ctrl + u`.

![](4.png)

Found a base64 encoded string. Decode it to get first flag.

The robots.txt file doesn't have anything useful so let's move to the other webserver.

Start another directory scan, this time on port 65524 : `gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.10:65524/`.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.196.34:65524/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
 09:21:04 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 280]
/.htaccess            (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/index.html           (Status: 200) [Size: 10818]
/robots.txt           (Status: 200) [Size: 153]  
/server-status        (Status: 403) [Size: 280]  
                                                 
===============================================================
```

The robots.txt file contains the following.

![](2.png)

That looks like a hash, crack it for the second flag.

![](10.png)


index.html is just apache default page.

![](5.png)

Press `ctrl + u` to view the source code of the page.

![](6.png)

Found a hidden encoded string, use [CyberChef](https://gchq.github.io/CyberChef/)

![](7.png)

We got a page, let's navigate to it: http://10.10.10.10:65524/n0th1ng3ls3m4tt3r

![](8.png)

Let's view the source code.

![](9.png)

We found an image and a hash, let's download the image, and try to crack the hash using the provided task file.

Use john to crack the hash : `john --wordlist=easypeasy.txt --format=gost hash`

![](11.png)

We got a password.

# **Foothold**

Let's download the image to our machine.

![](12.png)

Using the `steghide` and the password we cracked, let's extract hidden files from the image.

![](13.png)

Great! We got a username and some binary code, let's decode it on [CyberChef](https://gchq.github.io/CyberChef/).

![](14.png)

Using the credentials we found, login as *boring* via ssh.

![](15.png)

We are in.

# **Privilege Escalation**

Doing some basic enumeration on the target, we found a cronjob.

![](16.png)

This script run every minute as root. Let's see what the script does.

![](17.png)

We are the owner of the file, we can put a command that gives us root.

I run the following command `echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' >> .mysecretcronjob.sh`, what it does is add a script to the file that makes a copy of /bin/bash in /tmp and gives /bash suid bit so it can be run as it's owner (root).

![](18.png)

Wait a little and the file will get copied to /tmp with suid bit.

To get a root shell, run `/tmp/bash -p`.

![](19.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
