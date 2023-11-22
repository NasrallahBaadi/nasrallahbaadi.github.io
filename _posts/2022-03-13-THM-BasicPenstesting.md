---
title: "TryHackMe - Basic Pentesting"
author: Nasrallah
description: ""
date: 2022-03-13 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, smb, john, crack, hydra]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello l33ts, I hope you are doing well. We will be doing [Basic Pentesting](https://tryhackme.com/room/basicpentestingjt) from [TryHackMe](https://tryhackme.com). It's an easy machine where we enumerate SMB to get a username, we brute force ssh after that to get a password that will give us access to the machine. Some basic enumeration on the machine after that will give us a way to get root. Let's get into it.

## **Enumeration**

### Nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressice scan to provide faster results.

```terminal
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-14 12:12 EDT                                                                                              
Nmap scan report for 10.10.226.39                                                                                                                            
Host is up (0.097s latency).                                                  
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION                                            
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)                                                                      
| ssh-hostkey:       
|   2048 db:45:cb:be:4a:8b:71:f8:e9:31:42:ae:ff:f8:45:e4 (RSA)            
|   256 09:b9:b9:1c:e0:bf:0e:1c:6f:7f:fe:8e:5f:20:1b:ce (ECDSA)           
|_  256 a5:68:2b:22:5f:98:4a:62:21:3d:a2:e2:c5:a9:f7:c2 (ED25519)         
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))                 
|_http-server-header: Apache/2.4.18 (Ubuntu)                                                                                                                 
|_http-title: Site doesn't have a title (text/html).                      
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)    
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
8009/tcp open  ajp13?                                                         
| ajp-methods:                                                                
|_  Supported methods: GET HEAD POST OPTIONS                              
8080/tcp open  http-proxy                                                     
| fingerprint-strings:                                                                                                                                       
|   LDAPBindReq:                                                              
|     HTTP/1.1 400                                                            
|     Content-Type: text/html;charset=utf-8                               
|     Content-Language: en                                                    
|     Content-Length: 2243
|     Date: Mon, 14 Mar 2022 15:54:14 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tah
oma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-
size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-colo
r:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;bac
kground-color:#525D76;border:none;}</style></head><bod
|   SIPOptions:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 2154
|     Date: Mon, 14 Mar 2022 15:54:15 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|_    Request</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tah
oma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-
size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-colo
r:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;bac
kground-color:#525D76;border:none;}</style></head><bod
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.7
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cg

Host script results:
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: basic2
|   NetBIOS computer name: BASIC2\x00
|   Domain name: \x00
|   FQDN: basic2
|_  System time: 2022-03-14T11:54:19-04:00
|_clock-skew: mean: 59m33s, deviation: 2h18m34s, median: -20m27s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: BASIC2, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time:
|   date: 2022-03-14T15:54:18
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

We found about 6 open port.

 - 22 SSH
 - 80 HTTP
 - 139/445 Samba
 - 8009 ajp13
 - 8080 HTTP

### WebPage

Let's navigate to the webpage on port 80.

![webpage](/assets/img/tryhackme/basicpen/webpage.png)

Checking the source code we see a comment.

![webpage](/assets/img/tryhackme/basicpen/sourcecode.png)


### Gobuster

Let's run a directory scan using the following command: `gobuster dir -w /usr/share/wordlists/dirb/common.txt  -u http://{target_IP}`

```terminal
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.226.39
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
12:22:10 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 291]
/.htpasswd            (Status: 403) [Size: 296]
/.htaccess            (Status: 403) [Size: 296]
/development          (Status: 301) [Size: 318] [--> http://10.10.226.39/development/]
/index.html           (Status: 200) [Size: 158]                                       
/server-status        (Status: 403) [Size: 300]                                       

===============================================================
```

We found `/development` directory, let's see what there.

![webpage](/assets/img/tryhackme/basicpen/dev.png)

The **decelopment** directory has two text files in it.

Let's read the **dev.txt** text file.

![webpage](/assets/img/tryhackme/basicpen/devnote.png)

It seems that this is the dev note we say earlier, we also notice **J** and **K** at the end of every note.


Let's check the **j.txt** file.

![webpage](/assets/img/tryhackme/basicpen/jnote.png)

It looks like it's a message for **J** noting that the password the latter uses is weak, and it's from **K**.

### SMB

Let's now enumerate samba using `Enum4linux` with `-A` option for all simple enumeration, and it will enumerate for : users, groups, shares...etc.

```terminal
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon May 24 07:04:30 2021

 ==========================
|    Target Information    |
 ==========================
Target ........... 10.10.40.158
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ====================================================
|    Enumerating Workgroup/Domain on 10.10.40.158    |
 ====================================================
[+] Got domain/workgroup name: WORKGROUP

 ============================================
|    Nbtstat Information for 10.10.40.158    |
 ============================================
Looking up status of 10.10.40.158
	BASIC2          <00> -         B <ACTIVE>  Workstation Service
	BASIC2          <03> -         B <ACTIVE>  Messenger Service
	BASIC2          <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 =====================================
|    Session Check on 10.10.40.158    |
 =====================================
[+] Server 10.10.40.158 allows sessions using username '', password ''

 ===========================================
|    Getting domain SID for 10.10.40.158    |
 ===========================================
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ======================================
|    OS information on 10.10.40.158    |
 ======================================
[+] Got OS info for 10.10.40.158 from smbclient:
[+] Got OS info for 10.10.40.158 from srvinfo:
	BASIC2         Wk Sv PrQ Unx NT SNT Samba Server 4.3.11-Ubuntu
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03

 =============================
|    Users on 10.10.40.158    |
 =============================


 =========================================
|    Share Enumeration on 10.10.40.158    |
 =========================================
lpcfg_do_global_parameter: WARNING: The "client use spnego" option is deprecated
lpcfg_do_global_parameter: WARNING: The "client ntlmv2 auth" option is deprecated

	Sharename       Type      Comment
	---------       ----      -------
	Anonymous       Disk      
	IPC$            IPC       IPC Service (Samba Server 4.3.11-Ubuntu)
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------
	BASIC2               Samba Server 4.3.11-Ubuntu

	Workgroup            Master
	---------            -------
	WORKGROUP            BASIC2

[+] Attempting to map shares on 10.10.40.158
//10.10.40.158/Anonymous	Mapping: OK, Listing: OK
//10.10.40.158/IPC$	[E] Can't understand response:
lpcfg_do_global_parameter: WARNING: The "client use spnego" option is deprecated
lpcfg_do_global_parameter: WARNING: The "client ntlmv2 auth" option is deprecated
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

 ====================================================
|    Password Policy Information for 10.10.40.158    |
 ====================================================


[+] Attaching to 10.10.40.158 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

	[+] BASIC2
	[+] Builtin

[+] Password Info for Domain: BASIC2

	[+] Minimum password length: 5
	[+] Password history length: None
	[+] Maximum password age: 37 days 6 hours 21 minutes
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: None
	[+] Reset Account Lockout Counter: 30 minutes
	[+] Locked Account Duration: 30 minutes
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: 37 days 6 hours 21 minutes


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 5


 ==============================
|    Groups on 10.10.40.158    |
 ==============================

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 =======================================================================
|    Users on 10.10.40.158 via RID cycling (RIDS: 500-550,1000-1050)    |
 =======================================================================
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-2853212168-2008227510-3551253869
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
.
.
.
S-1-5-32-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-5-21-2853212168-2008227510-3551253869 and logon username '', password ''
S-1-5-21-2853212168-2008227510-3551253869-500 *unknown*\*unknown* (8)
.
.
.
.
.
S-1-5-21-2853212168-2008227510-3551253869-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\kay (Local User)
S-1-22-1-1001 Unix User\jan (Local User)

 =============================================
|    Getting printer info for 10.10.40.158    |
 =============================================
No printers returned.


enum4linux complete on Mon May 24 07:13:07 2021


```

At the end of the enumeration, we were able to find 2 usernames, **Kay** and **Jan**.

## **Foothold**

With the information we have now, we can see that the note in **j.txt** file we read earlier was from **kay** to **jan**. We know that **Jan**'s password is weak, so let's use hydra to brute force the password on ssh.

![hydra](/assets/img/tryhackme/basicpen/hydra.png)

Great! We got jan's password, let's ssh to the machine as jan.

## **Privilege Escalation**

Let's do some basic enumeration on the machine.

![sshkay](/assets/img/tryhackme/basicpen/kayssh.png)

We found kay's home directory, it contains a file called **pass.bak** but we can't read it, but it also has **.ssh** directory, and inside it there a readable private key, let's copy the private key and put it in our machine and connect with it.

![idrsa](/assets/img/tryhackme/basicpen/idrsa.png)

The private key is protected with a password, we can use `ssh2john` and try to crack that password.

![rsapass](/assets/img/tryhackme/basicpen/rsapass.png)

Now that we got the pass let's ssh to the machine as kay using the private key.

![kay](/assets/img/tryhackme/basicpen/kay.png)

Let's see if we can get root.

![root](/assets/img/tryhackme/basicpen/root.png)

Great! Kay have the permission to run anything on the machine as root so it was easy to get root.

---

Thank you for taking the time to read my writeup, I hope you have learned something with this, if you have any questions or comments, please feel free to reach out to me. See you in the next hack :) .
