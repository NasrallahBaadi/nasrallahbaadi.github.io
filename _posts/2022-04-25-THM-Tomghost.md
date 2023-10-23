---
title: "TryHackMe - Tomghost"
author: Nasrallah
description: ""
date: 2022-04-25 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, gpg, scp]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello l33ts, I hope you are doing well. We are doing [Thomghost](https://tryhackme.com/room/tomghost) from [TryHackMe](https://tryhackme.com)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```Terminal
Nmap scan report for 10.10.192.136
Host is up (0.11s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are 4 open ports, we have ssh on port 22 and two web services, ajp13 on port 8009 and http on 8080.

## Web

Let's navigate to the webpage on port 8080.

![](/assets/img/tryhackme/tomghost/1.png)

It's the default page for Apache Tomcat. Let's see if we can access the manager panel. `http://{Target_IP}:8080/manager`

![](/assets/img/tryhackme/tomghost/2.png)

We cant' access the manager panel. 

Let's check if any of the services we found are vulnerable. I wasn't able to find any vulnerability on Tomcat, but i found the following on **ajp**:

![](/assets/img/tryhackme/tomghost/3.png)

We have a file read/inclusion vulnerability.

# **Foothold**

Let's the download the [exploit](https://www.exploit-db.com/exploits/48143) and use it.

![](/assets/img/tryhackme/tomghost/4.png)

Great! We managed to retrieve some ssh credentials. Let's login using those credentials.

![](/assets/img/tryhackme/tomghost/5.png)

Great! We're in. To privilege escalation.


# **Privilege Escalation**

## Horizontal

Let's see what's on our user's home directory.

![](/assets/img/tryhackme/tomghost/6.png)

We found two files, **credentials.pgp** and **tryhackme.asc**, the first file is encrypted with `pgp` and the second file is a key we can use to decrypt the file. For that, we can use the command `gpg` to import the key, and then decrypt the file. But when we try to decrypt it, it asks us for a password, but we don't have one.

Let's download the key file to our machine using `scp` and try to get a password. `scp skyfuck@10.10.192.136:tryhackme.asc .`

![](/assets/img/tryhackme/tomghost/7.png)

Great, now we can use `gpg2john` to get a hash, and use `john` to crack the password.

![](/assets/img/tryhackme/tomghost/8.png)

We have successfully cracked the hash and got the password. Let's go decrypt the **credentials.pgp** file now.

![](/assets/img/tryhackme/tomghost/9.png)

We got the password for the user *merlin*, let's switch to that user now. `su merlin`

![](/assets/img/tryhackme/tomghost/10.png)

## Vertical

Let's check our current privileges with `sudo -l`.

![](/assets/img/tryhackme/tomghost/11.png)

We can run the command /usr/bin/zip as root. If we chech on [GTFPBins](https://gtfobins.github.io/), we found an [exploit](https://gtfobins.github.io/gtfobins/zip/#sudo) that gives us root access.

![](/assets/img/tryhackme/tomghost/12.png)

Let's copy and paste those commands into the terminal and run them.

![](/assets/img/tryhackme/tomghost/13.png)

And just like that we got root.

---

Thank you for taking the time to read my writeup, I hope you have learned something with this, if you have any questions or comments, please feel free to reach out to me. See you in the next hack :) .

# References

https://www.exploit-db.com/exploits/48143

https://gtfobins.github.io/gtfobins/zip/#sudo