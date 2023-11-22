---
title: "HackTheBox - Netmon"
author: Nasrallah
description: ""
date: 2022-08-01 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, rce, metasploit, ftp]
img_path: /assets/img/hackthebox/machines/netmon
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Netmon](https://app.hackthebox.com/machines/Netmon) from [HackTheBox](https://www.hackthebox.com), an easy box where there is PRTG on a webserver and ftp running with anonymous access allowed giving us the ability to read PRTG netmon config files storing passwords. The PRTG version is vulnerable to RCE which can be exploited to gain a shell with privileged access.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.152 (10.10.10.152)
Host is up (0.15s latency).
Not shown: 995 closed tcp ports (reset)       
PORT    STATE SERVICE      VERSION
21/tcp  open  ftp          Microsoft ftpd                                                                                                                     
| ftp-anon: Anonymous FTP login allowed (FTP code 230)      
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs          
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_02-25-19  11:49PM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp  open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-server-header: PRTG/18.1.37.13946
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds 
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-08-09T10:30:57
|_  start_date: 2022-08-09T10:27:28
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
```

We have a windows machine running FTP with anonymous login enabled on port 21, an HTTP web server on port 80, and SMB on it's default ports.

### FTP

Let's login to FTP as `anonymous`.

![](1.png)

Wow, We're in the file system of this windows machine. We can grab the user flag from `Users\Public\user.txt`.

![](2.png)

There is a lot to search in windows system so let's go see what's on the web server to help us narrow our enumeration.

### Web

![](3.png)

We have a login page for PRTG Network Monitor (NETMON) version 18.1.37. I tried some default credentials but no luck.

Next i searched for any exploit in this version and found that there is a authenticated remote code execution exploit on metasploit. Since we don't have any credentials yet, let's see if we can find anything useful with our access to the ftp server.

A quick search on google on where PRTG netmon stores password we found [this](https://kb.paessler.com/en/topic/463-how-and-where-does-prtg-store-its-data) info saying PRTG stores data in `C:\All Users\Paessler\PRTG Network Monitor`.

![](4.png)

Let's download that .bak file into our machine with the command `get "PRTG Configuration.old.bak"`

Let's inspect the file.

![](5.png)

Found some credentials. Let's test them in the login page.

## **Foothold**

![](6.png)

Couldn't login. Let's try changing the year at the end of the password.

![](7.png)

Great! We got the password, let's now use the exploit on metasploit to get a shell on the target.

![](8.png)

We set the required options and run the exploit.

![](9.png)

Nice, we got a shell and with the highest privilege.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
