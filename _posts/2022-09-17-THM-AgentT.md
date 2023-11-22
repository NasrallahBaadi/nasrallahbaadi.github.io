---
title: "TryHackMe - Agent T"
author: Nasrallah
description: ""
date: 2022-09-17 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, php, rce, cve]
img_path: /assets/img/tryhackme/agentt
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Agent T](https://tryhackme.com/room/agentt) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.162.187
Host is up (0.079s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    PHP cli server 5.5 or later (PHP 8.1.0-dev)
|_http-title:  Admin Dashboard
```

There is only port 80 open running http web server with `php 8.1.0-dev`.

From a machine i've done in the past from HACKTHEBOX, i remember this version of php being vulnerable to remote code execution, here is the [exploit](https://www.exploit-db.com/exploits/49933).

![](1.png)

We can find it using `searchsploit` and copy the exploit to our working directory with the following command:

```terminal
searchsploit -m php/webapps/49933.py
```

![](2.png)


## **Foothold**

Let's run the exploit with `python3 49933.py`.

![](3.png)

We see that we are root, we can grab the flag with `cat /flag.txt`.


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
