---
title: "TryHackMe - Break Out The Cage.1"
author: Nasrallah
description: ""
date: 2022-05-03 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, cipher, spectrogram]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Break Out The Cage.1](https://tryhackme.com/room/breakoutthecage1) from [TryHackMe](https://tryhackme.com). We scan the machine for open port and find 3 open ports, the first port 21 is an ftp server with anonymous login enabled, there we find an file that has an encrypted password. We move to port 80 which is a webserver, we run a directory scan against it and find an audio file that has a text as spectrogram, we use it to decrypt the password we found on ftp and login as *Weston*. On the machine, a text gets printed on the screen every now and then, we found the script responsible for that and exploit the way it works and upgrade to the user *Cage*. After that we find some emails on Cage's home directory, one of the emails contains an encrypted password, and another email has a hint for the keyword we can use to decrypt the password. We do that and change user to root. Let's get started.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.245.11
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             396 May 25  2020 dad_tasks
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
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dd:fd:88:94:f8:c8:d1:1b:51:e3:7d:f8:1d:dd:82:3e (RSA)
|   256 3e:ba:38:63:2b:8d:1c:68:13:d5:05:ba:7a:ae:d9:3b (ECDSA)
|_  256 c0:a6:a3:64:44:1e:cf:47:5f:85:f6:1f:78:4c:59:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Nicholas Cage Stories
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

There are 3 open ports, 21(FTP), 22(SSH) and 80(HTTP).

### FTP

Since the ftp server allows anonymous login, let's login and see what's there.

![](/assets/img/tryhackme/breakout/1.png)

We found a file named **dad_tasks**, and downloaded it with the command `get dad_tasks`.

Now let's see what the file has.

![](/assets/img/tryhackme/breakout/2.png)

The file contains a base64 encoded text, we decode it using `base64 -d dad_tasks`, but it gives us another encoded text, it look like a Vigenere cipher and we need a key to decrypt that, so let's move to other things.

### Web

Navigating to the webserver we get this page.

![](/assets/img/tryhackme/breakout/3.png)

Nothing really useful in this page.

### Gobuster

Let's run a directory scan.

![](/assets/img/tryhackme/breakout/4.png)

We found a couple of directories, but the **/auditions** directory has an interesting audio file.

![](/assets/img/tryhackme/breakout/5.png)

When we play the file we hear nicholas Cage talking and weird noise. Let's load the audio file to `sonic-visualizer`, add a spectrogram layer by going to `Layer -> Add Spectrogram`

![](/assets/img/tryhackme/breakout/6.png)

We can see some text there, let's save it.


## **Foothold**

Now that we have a possible key for the vigenere cipher, let's try to decode the text we got from the ftp server.

![](/assets/img/tryhackme/breakout/7.png)

Great! We managed to decrypt the text and get the password of *Weston*. Let's login with ssh now.

![](/assets/img/tryhackme/breakout/8.png)

Great! Let's move to privilege escalation. 

## **Privilege Escalation**

### Cage

Let's start by checking our current privileges by running `sudo -l`

![](/assets/img/tryhackme/breakout/9.png)

We can run a `bees` as root, this runs the command `wall` with some text, so there isn't a way to escalate with that.

While logged in, we a get the following message from time to time.

![](/assets/img/tryhackme/breakout/10.png)

Looking around the file system, we found a python script named spread_the_quotes.py inside /opt/.dad_scripts, which is is the script responsible for the message we get periodically.

```python
#!/usr/bin/env python

#Copyright Weston 2k20 (Dad couldn't write this with all the time in the world!)
import os
import random

lines = open("/opt/.dads_scripts/.files/.quotes").read().splitlines()
quote = random.choice(lines)
os.system("wall " + quote)
```

The script reads the quotes file, randomly chooses a line and outputs it via the command `wall`.

We can't edit the python script but we can edit the .quotes file.

We can make a script that make a copy of `/bin/bash` and give it suid bit so that we can run it as it's owner, in our case it's *Cage*. 

```Bash
#!/bin/bash

cp /bin/bash /tmp/bash && chmod +s /tmp/bash
```

After that, we can replace the quotes in the quote file with a payload that would call our script, in this case, we can use this payload `tryhackme ; script_location`. Let's break it down, *tryhackme* is the text passed to the command `wall`, The semicolon "*;*" permits us to run multiple commands in the same line and and the script_location is the place where we wrote the script.

![](/assets/img/tryhackme/breakout/11.png)

Now if we wait for the script to run, we should found a copy of bash in /tmp with the suid bit set, run `/bin/bash -p` to get a shell as Cage.

![](/assets/img/tryhackme/breakout/12.png)

We can now grab Cage's ssh private key and connect with it.

### Root

In Cage's home directory, there is an email folder with tree emails, one of them contains a possible password for Sean who has *root* as his username. If we tried to change user to root with that password, we fail. The password must be encrypted.

We know that Sean is obsessed with Cage's face, and since we used vigenere cipher before, let's use it now with **face** as a key.

After decrypting the password we can change the user to root with it.

![](/assets/img/tryhackme/breakout/13.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---