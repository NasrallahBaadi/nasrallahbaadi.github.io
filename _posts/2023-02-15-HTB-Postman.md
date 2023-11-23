---
title: "HackTheBox - Postman"
author: Nasrallah
description: ""
date: 2023-02-15 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, redis, metasploit]
img_path: /assets/img/hackthebox/machines/postman
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Postman](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
Nmap scan report for postman.htb (10.10.10.160)
Host is up (0.16s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46834ff13861c01c74cbb5d14a684d77 (RSA)
|   256 2d8d27d2df151a315305fbfff0622689 (ECDSA)
|_  256 ca7c82aa5ad372ca8b8a383a8041a045 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: The Cyber Geek's Personal Website
|_http-server-header: Apache/2.4.29 (Ubuntu)
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-server-header: MiniServ/1.910
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are four open ports on this Ubuntu machine.

 - 22/tcp OpenSSH

 - 80/tcp Apache http

 - 6379/tcp redis

 - 10000/tcp webmin http 1.910


### Web

Let's navigate to the first web page.

![](1.png)

We got the welcome page of TCG, nothing interesting.

Let's go to the web page on port 10000.

![](2.png)

The server is in SSL mode, the page also reveals a hostname.

Let's add postman to /etc/hosts and got the ssl page.

![](3.png)

It's the login page for Webmin

The webmin version running is vulnerable to remote code execution but we need credentials for that.

We got nothing from the web servers, let's move on.

### Redis

For redis, i managed to connect to it using `redis-cli`.

```bash
$ redis-cli -h 10.10.10.160
10.10.10.160:6379> keys *
(empty array)
10.10.10.160:6379>
```

Unfortunately there was no keys.

I also tried some rce on metasploit but didn't get a thing.

## **Foothold**

Searching for more ways to enumerate `redis` on [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis), i came across this [section](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#ssh) showing how to get a shell by uploading ssh public key.

![](4.png)

Let's do the same.

![](5.png)

Great! We got in.

## **Privilege Escalation**

### Matt

Now i run linpeas and managed to find the following.

![](6.png)

We found an encrypted ssh private key that belongs to user `matt`. Let's copy it to our machine and crack it's passphrase.

![](7.png)

We got the passphrase of the key, now let's connect.

![](8.png)

Every time we try to connect the connection gets closed.

After that i tried to switch to user Matt on our privious ssh session with the password we cracked and it worked.

![](9.png)

Checking the sshd_config file we see why we couldn't connect.

### root

Using matt's credentials, i attempted to connect to webmin and it worked.

Now let's run metasploit and use `exploit/linux/http/webmin_packageup_rce`.

![](10.png)

And just like that we got root.


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
