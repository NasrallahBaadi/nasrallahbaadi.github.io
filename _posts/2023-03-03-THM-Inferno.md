---
title: "TryHackMe - Inferno"
author: Nasrallah
description: ""
date: 2023-03-03 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, sudo, rce, hydra]
img_path: /assets/img/tryhackme/inferno
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Inferno](https://tryhackme.com/room/) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
Nmap scan report for 10.10.155.218                                                                                                                    [25/266]
Host is up (0.11s latency).                                                                                                                                   
Not shown: 958 closed tcp ports (reset)                                                                                                                       
PORT      STATE SERVICE           VERSION                                                                                                                     
21/tcp    open  ftp?                                                                                                                                          
22/tcp    open  ssh               OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)                                                                
| ssh-hostkey:                                                                                                                                                
|   2048 d7ec1a7f6274da2964b3ce1ee26804f7 (RSA)                                                                                                               
|   256 de4feefa862efbbd4cdcf96773028434 (ECDSA)                                                                                                              
|_  256 e26d8de1a8d0bd97cb9abc03c3f8d885 (ED25519)                                                                                                            
23/tcp    open  telnet?                                                                                                                                       
25/tcp    open  smtp?                                                                                                                                         
|_smtp-commands: Couldn't establish connection on port 25                                                                                                     
80/tcp    open  http              Apache httpd 2.4.29 ((Ubuntu))                                                                                              
|_http-title: Dante's Inferno                                                                                                                                 
|_http-server-header: Apache/2.4.29 (Ubuntu)                                                                                                                  
88/tcp    open  kerberos-sec?                                                                                                                                 
106/tcp   open  pop3pw?                                                                                                                                       
110/tcp   open  pop3?                                                                                                                                         
389/tcp   open  ldap?                                                                                                                                         
443/tcp   open  https?                                                                                                                                        
464/tcp   open  kpasswd5?                                                                                                                                     
636/tcp   open  ldapssl?                                                                                                                                      
777/tcp   open  multiling-http?                                                                                                                               
783/tcp   open  spamassassin?                                                                                                                                 
808/tcp   open  ccproxy-http?                                                                                                                                 
873/tcp   open  rsync?
1001/tcp  open  webpush?
1236/tcp  open  bvcontrol?
1300/tcp  open  h323hostcallsc?
2000/tcp  open  cisco-sccp?
2003/tcp  open  finger?

```

We found a whole bunch of open ports, but the one's returning a banner are 22 and 80.

## Web

Let's check the web page on port 80.

![](1.png)

Let's run a directory scan.

```terminal
00      GET       36l       82w      638c http://10.10.155.218/
401      GET       14l       54w      460c http://10.10.155.218/inferno
403      GET        9l       28w      278c http://10.10.155.218/server-status
```

We found a directory called inferno that requires http authentication.

## Hydra

Let's brute force the password with the username `admin` using `hydra`.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.155.218 http-get /inferno
```

![](4.png)

We got the password, let's login.

![](2.png)

We got a login page for `Codiad`, trying the same credential as before we manage to login.

![](5.png)

# **Foothold**

Searching for `Codiad` exploit, we find a remote code execution vulnerability on [exploit-db](https://www.exploit-db.com/exploits/50474).

![](6.png)

If we go to `themes/default/filemanager/images/codiad/manifest/files/codiad/example/INF/` directory we can upload a reverse shell.

![](7.png)

Now we setup a listener and request the reverse shell file at `http://10.10.155.218/inferno/themes/default/filemanager/images/codiad/manifest/files/codiad/example/INF/htbshell.php`

![](8.png)

# **Privilege Escalation**

## dante

Checking dante's home directories, we find a hidden file in the Downloads directory.

![](9.png)

The file has some hex data, let's decode.

![](10.png)

We got dante's password.

## root

After switching to user `dante`, let's check his privileges

![](11.png)

Dante can run `tee` as root.

![](3.png)

With that we can write to any file on the system.

One way to exploit that which i used is to copy my public ssh key to root's authorized ssh keys.

![](12.png)

And just like that we got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
