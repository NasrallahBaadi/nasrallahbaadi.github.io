---
title: "TryHackMe - Poster"
author: Nasrallah
description: ""
date: 2022-11-15 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, sudo, metasploit]
img_path: /assets/img/tryhackme/poster
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Poster](https://tryhackme.com/room/poster) from [TryHackMe](https://tryhackme.com). The target is running a database that uses weak credentials for authentication, we brute force that and get valid credentials which allowed us to execute commands on the target after that. Enumerating the files in the system we find that multiple passwords have been stored in plain text which allowed us to escalate privileges easily.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.20.82
Host is up (0.10s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 71ed48af299e30c1b61dffb024cc6dcb (RSA)
|   256 eb3aa34e6f1000abeffcc52b0edb4057 (ECDSA)
|_  256 3e4142353805d392eb4939c6e3ee78de (ED25519)
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Poster CMS
5432/tcp open  postgresql PostgreSQL DB 9.5.8 - 9.5.10 or 9.5.17 - 9.5.23
| ssl-cert: Subject: commonName=ubuntu
| Not valid before: 2020-07-29T00:54:25
|_Not valid after:  2030-07-27T00:54:25
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are 3 open ports, port 22 running OpenSSH, port 80 running an Apache web server and port 5432 running postgresql.

Let's brute force the login using the following metasploit module: `auxiliary/scanner/postgres/postgres_login`

![](1.png)

We found the username and password.

We can use the following module to execute commands in the database `auxiliary/admin/postgres/postgres_sql`.

![](2.png)

To dump hashes, we use this module `auxiliary/scanner/postgres/postgres_hashdump`

![](3.png)

# **Foothold**

To execute commands on the target, we use this module `exploit/multi/postgres/postgres_copy_from_program_cmd_exec`

![](4.png)

Great! We got command execution, and if we check dark's home directory we find his credentials.

![](5.png)

Let's login now via ssh.

![](6.png)

# **Privilege Escalation**

Checking the web server's file, we find a config file that holds some credentials of the other user.

![](7.png)

Let's login as alison.

![](8.png)

We checked the privileges of alison with `sudo -l` and found that the user can run any command as root, so we easily get a root shell.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
