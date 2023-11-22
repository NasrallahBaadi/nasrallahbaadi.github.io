---
title: "TryHackMe - GamingServer"
author: Nasrallah
description: ""
date: 2022-08-25 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, ssh2john, crack, john, lxd]
img_path: /assets/img/tryhackme/gamingserver
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Gaming Server](https://tryhackme.com/room/gamingserver) from [TryHackMe](https://tryhackme.com). The machines is running a webserver that has some hidden directories and files in which we find a private ssh key. Being part of a specific group enables us to escalate to root.


## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.213.197
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:0e:fe:06:12:67:3e:a4:eb:ab:7a:c4:81:6d:fe:a9 (RSA)
|   256 49:61:1e:f4:52:6e:7b:29:98:db:30:2d:16:ed:f4:8b (ECDSA)
|_  256 b8:60:c4:5b:b7:b2:d0:23:a0:c7:56:59:5c:63:1e:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: House of danak
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have ssh on port 22 and Apache webserver on port 80.

### Web

Navigate to the webpage.

![](1.png)

It's a website about House of Danak (whatever that is), looking through the website we find an uploads page.

![](2.png)

The most interesting file there is the dict.lst which contains a list of possible passwords, so let's download it with the following command. `wget http://{target_IP}/uploads/dict.lst`.

### Gobuster

Let's run a directory scan.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.227.232
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/10/02 05:18:03 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 2762]
/robots.txt           (Status: 200) [Size: 33]  
/secret               (Status: 301) [Size: 315] [--> http://10.10.227.232/secret/]
/server-status        (Status: 403) [Size: 278]                                   
/uploads              (Status: 301) [Size: 316] [--> http://10.10.227.232/uploads/]
===============================================================
```

Found **/secret** directory.

![](3.png)

It contains some secret key, let's download it and see what is it.

![](4.png)

Looks like a private ssh key.


## **Foothold**

With the ssh private key, let's connect to the target, but wait, we need a username.

![](5.png)

Looking through the source code of the website, i find user john. Now let's use the key to connect `ssh -i secretkey john@10.10.10.10`.

![](6.png)

After giving the secretkey the right permission and trying to connect with it, it turns out it requires a passphrase. Lucky for us, there is a tool called `ssh2john` that gives us the hash of the passphrase and we crack it using either `john` or `hashcat`.

![](7.png)

With the dict.lst file we got earlier, we managed to crack the hash and get the passphrase for the secret key.

![](8.png)

Great! We got in.

## **Privilege Escalation**

Running the command `id` shows that john us part of a group called `lxd`.

```terminal
john@exploitable:~$ id
uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

As we did in this [writeup](https://nasrallahbaadi.github.io/posts/HTB-Included/#privilege-escalation), we're going to follow the steps provided in this [Article](https://www.hackingarticles.in/lxd-privilege-escalation/).

On the attacker machine, we execute the following commands:

![](9.png)

>`up` is an alias for `sudo python3 -m http.server 80`.

On the target machine, execute the following commands:

![](10.png)

And just like that we got root, for the root flag, go to `/mnt/root/root.txt`.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---
