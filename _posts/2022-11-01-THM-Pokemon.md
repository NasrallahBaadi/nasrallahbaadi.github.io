---
title: "TryHackMe - Gotta Catch'em All!"
author: Nasrallah
description: ""
date: 2022-11-01 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy]
img_path: /assets/img/tryhackme/pokemon
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Gotta Catch'em All!](https://tryhackme.com/room/pokemon) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.166.250
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:14:75:69:1e:a9:59:5f:b2:3a:69:1c:6c:78:5c:27 (RSA)
|   256 23:f5:fb:e7:57:c2:a5:3e:c2:26:29:0e:74:db:37:c2 (ECDSA)
|_  256 f1:9b:b5:8a:b9:29:aa:b6:aa:a2:52:4a:6e:65:95:c5 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Can You Find Them All?
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found 2 open ports, port 22 running OpenSSH and port 80 running an Apache web server.

### Web

Let's go to the web page.

![](1.png)

It's the default page for Apache2. Let's check the source code.

![](2.png)

We found a comment and some weird tags separated by a colon, maybe it's username:password.


## **Foothold**

Let's login to the machine via ssh.

![](3.png)


## **Privilege Escalation**

Checking the directories and files inside the home directory we find a zip file inside Desktop directory.

![](4.png)

Got the grass pokemon, but we got some hex encoded string, we can decode it using [CyberChef](https://gchq.github.io/CyberChef/).

![](5.png)

Checking other directories, we find some interesting things inside `Videos`.

![](6.png)

Found credentials for use `ash`. Let's switch to it.

![](7.png)

As we can see, running `sudo -l`, we see that this user can run any command as root, so let's change user to root with `sudo su`.

```terminal
ash@root:/home/pokemon/Videos/Gotta/Catch/Them$ sudo su
root@root:/home/pokemon/Videos/Gotta/Catch/Them# id
uid=0(root) gid=0(root) groups=0(root)
root@root:/home/pokemon/Videos/Gotta/Catch/Them#
```

Let's search for the other Pokemons.

Let's check the web server's directory `/var/www/html`.

![](8.png)

We got another encoded flag, this one looks like `rot13`, let's go to [CyberChef](https://gchq.github.io/CyberChef/)

![](9.png)

Couldn't decode it with rot13, so i changed it to 14 and managed to decode it.

We can see that the flag has a naming scheme, `{pokemontype}-type.txt`, we can use that to search for fire type pokemon.

```terminal
root@root:/var/www/html# locate fire-type.txt
/etc/why_am_i_here?/fire-type.txt
```

![](10.png)

We found the flag encoded with base64 and managed to decode it using `base64 -d`

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
