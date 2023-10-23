---
title: "TryHackMe - Bounty Hacker"
author: Nasrallah
description: ""
date: 2022-04-03 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, ftp, hydra, bruteforce, tar, sudo]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello l33ts, I hope you are doing well. We are doing [Bounty Hacker](https://tryhackme.com/room/cowboyhacker) from [TryHackMe](https://tryhackme.com)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```Terminal
Nmap scan report for 10.10.120.252
Host is up (0.11s latency).
Not shown: 970 filtered tcp ports (no-response), 27 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.11.31.131
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
|_  256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

We got 3 open ports

 - 21 ftp vsftpd 3.0.3
 - 22 ssh OpenSSH 7.2p2
 - 80 http Apache httpd 2.4.18

## FTP

From the nmap scan we see that Anonymous login is allowed is this ftp server, let's login and see what we can find.

![](/assets/img/tryhackme/bountyhunter/b1.png)

We found two interesting files, locks.txt and task.txt, we can download them to our machine using the command `get {filename}`. Let's see what's on the files.

![](/assets/img/tryhackme/bountyhunter/b2.png)

The first file, locks.txt, contains a list of words that i assume are passwords, the other file, task.txt, contains a notes from someone called **lin**, which is a possible username. Now we the information we have, let's try to brute force ssh and see if we can find something.


# **Foothold**

To brute force ssh, we can use `hydra`.

![](/assets/img/tryhackme/bountyhunter/b3.png)

We managed to get the correct password for **lin**, let's login with ssh now.

![](/assets/img/tryhackme/bountyhunter/b4.png)

# **Privilege Escalation**

Now that we have access to the machine, let's what we can do.

![](/assets/img/tryhackme/bountyhunter/b5.png)

By running `sudo -l`, we see that we can run `/usr/tar` as **root**,  we can use [GTFOBins](https://gtfobins.github.io/) to see how we can leverage that and get root.

![](/assets/img/tryhackme/bountyhunter/b8.png)

We can use that command to get a root shell.

![](/assets/img/tryhackme/bountyhunter/b6.png)

And just like that we became root.

---

Thank you for taking the time to read my writeup, I hope you have learned something with this, if you have any questions or comments, please feel free to reach out to me. See you in the next hack :) .
