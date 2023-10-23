---
title: "TryHackMe - Tokyo Ghoul"
author: Nasrallah
description: ""
date: 2022-07-27 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, steganography, lfi, python, john, crack]
img_path: /assets/img/tryhackme/tokyoghoul
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Tokyo Ghoul](https://tryhackme.com/room/tokyoghoul666) from [TryHackMe](https://tryhackme.com). This machine is based on Tokyo Ghoul anime. Lot of stuff are put in this box, like steganography, exploiting LFI, cracking hahses, and escaping python jails. Let's have some fun.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.12.47
Host is up (0.14s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    3 ftp      ftp          4096 Jan 23  2021 need_Help?
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
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fa:9e:38:d3:95:df:55:ea:14:c9:49:d8:0a:61:db:5e (RSA)
|   256 ad:b7:a7:5e:36:cb:32:a0:90:90:8e:0b:98:30:8a:97 (ECDSA)
|_  256 a2:a2:c8:14:96:c5:20:68:85:e5:41:d0:aa:53:8b:bd (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Welcome To Tokyo goul
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

There are 3 open ports on a linux system, port 21 running FTP with anonymous login enabled, port 22 runs ssh and port 80 running an Apache web server.

## Web

Let's navigate to the website.

![](1.png)

We got a brief story about a teenager called Kaneki who's been kidnaped and tortured by someone named Jason.

Let's help him escape.

![](2.png)

Nothing interesting in this page, let's view the source code `ctrl + u`.

![](3.png)

We need to go to the FTP server.

## FTP

Since FTP allows anonymous login, let's go see what there.

![](4.png)

Found a total of three files, one text file, one executable and on image file. We download them to our machine with this command : `get {file_name}`.

Let's investigate the files.

### Aogiri_tree.txt

```
Why are you so late?? i've been waiting for too long .
So i heard you need help to defeat Jason , so i'll help you to do it and i know you are wondering how i will. 
I knew Rize San more than anyone and she is a part of you, right?
That mean you got her kagune , so you should activate her Kagune and to do that you should get all control to your body , i'll help you to know Rise san more and get her kagune , and don't forget you are now a part of the Aogiri tree .
Bye Kaneki.
```

Nothing really useful in this text file, let's move on to the executable.

### need_to_talk

![](5.png)

We needed to give the file execute permissions first, when we run it, Rize starts talking to us, then we are prompt to give her the passphrase, but we don't know it yet.

Running the command `strings` with the executable, we get every human readable words on the file.

![](6.png)

We see multiple words that might be the passphrase we need. Let's try them.

![](7.png)

Nice, we found the passphrase, and got a response of a compound word. Let's note it and move to the image file.

### rize_and_kaneki.jpg

Let's try to extract any hidden files inside the image using the command : `steghide extract -sf rize_and_kaneki.jpg`.

![](8.png)

I got prompt for a password so i used the one Rize gave us from the executable, and got a text file.

![](9.png)

We got some dots and dashes, which look like morse code. Let's take it to [CyberChef](https://gchq.github.io/CyberChef/) and decode it.

![](10.png)

We managed to decode that, and it had multiple levels. We got a possible web directory, let's check it out.

## Web

![](11.png)

The page says scan me, let's use `gobuster` to do that.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.12.47/d1r3c70ry_center
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/08/08 11:50:55 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/claim                (Status: 301) [Size: 327] [--> http://10.10.12.47/d1r3c70ry_center/claim/]
/index.html           (Status: 200) [Size: 312]                                                 
                                                                                                
===============================================================
```

Found **/claim** directory. Let's navigate to it.

![](12.png)

There is a `YES` and `NO` button, both of them does the same job which is displaying `flower.gif` through the view parameter.
`http://10.10.12.47/d1r3c70ry_center/claim/index.php?view=flower.gif`. This might be vulnerable to LFI.

I tried different payloads manually but no luck so i used `wfuzz` to try multiple payloads.

```bash
wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt --hl 13,11 http://10.10.12.47/d1r3c70ry_center/claim/index.php?view=FUZZ
```

![](14.png)

Let's try it in the browser.

![](13.png)

Great! We can see there is a user named `kamishiro` and we can see his hash!


# **Foothold**

Let's crack the hash using `john`.

![](15.png)

Got the password, let's login to the machine using ssh.

![](16.png)


# **Privilege Escalation**

Let's check our privileges on the machine with `sudo -l`.

![](17.png)

There is a python script named `jail.py` in our home directory. Let's check the file.

![](18.png)

We can't edit the file and can't do anything really in our home directory, everything belongs to root. Let's execute the file.

![](19.png)

We get prompt for an input, but the commands that could possibly give us a shell are blocked in the script as we saw.

Googling about this python jail code, i find this [Article](https://anee.me/escaping-python-jails-849c65cf306e), which is where the author of this room probably took this python script, the article explains in detail how to escape this jail.

We can get a root shell by providing the following code:

```python
__builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('/bin/bash')
```

![](20.png)

Great! We saved Kaneki.
---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
