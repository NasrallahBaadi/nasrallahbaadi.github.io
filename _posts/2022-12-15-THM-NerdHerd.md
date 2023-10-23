---
title: "TryHackMe - NerdHerd"
author: Nasrallah
description: ""
date: 2022-12-15 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, cipher, smb, ftp, kernel, cve]
img_path: /assets/img/tryhackme/nerdherd
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [NerdHerd](https://tryhackme.com/room/nerdherd) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.128.42                                                                                                                             
Host is up (0.11s latency).                                                                                                                                   
Not shown: 996 closed tcp ports (reset)                                                                                                                       
PORT    STATE SERVICE     VERSION                                                                                                                             
21/tcp  open  ftp         vsftpd 3.0.3                                                                                                                        
| ftp-syst:                                                                                                                                                   
|   STAT:                                                                                                                                                     
| FTP server status:                                                                                                                                          
|      Connected to ::ffff:10.18.0.188                                                                                                                        
|      Logged in as ftp                                                                                                                                       
|      TYPE: ASCII                                                                                                                                            
|      No session bandwidth limit                                                                                                                             
|      Session timeout in seconds is 300                                                                                                                      
|      Control connection is plain text                                                                                                                       
|      Data connections will be plain text                                                                                                                    
|      At session startup, client count was 4                                                                                                                 
|      vsFTPd 3.0.3 - secure, fast, stable                                                                                                                    
|_End of status                                                                                                                                               
| ftp-anon: Anonymous FTP login allowed (FTP code 230)                                                                                                        
|_drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 pub                                                                                                 
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)                                                                       
| ssh-hostkey: 
|   2048 0c:84:1b:36:b2:a2:e1:11:dd:6a:ef:42:7b:0d:bb:43 (RSA)
|   256 e2:5d:9e:e7:28:ea:d3:dd:d4:cc:20:86:a3:df:23:b8 (ECDSA)
|_  256 ec:be:23:7b:a9:4c:21:85:bc:a8:db:0e:7c:39:de:49 (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: NERDHERD; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -40m00s, deviation: 1h09m16s, median: -1s
|_nbstat: NetBIOS name: NERDHERD, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2022-11-11T07:10:44
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: nerdherd
|   NetBIOS computer name: NERDHERD\x00
|   Domain name: \x00
|   FQDN: nerdherd
|_  System time: 2022-11-11T09:10:44+02:00

```

We have 4 ports open, 21 running vsftpd with anonymous login allowed, 22 running OpenSSH and 139/445 belongs to SMB.

## FTP

Let's login to the ftp server as anonymous and see what can we find.

![](1.png)

We found two files and downloaded them to our machine using the command `get {filename}`.

the text file contains the following message.

```
all you need is in the leet
```

Not sure what that means, also the png file doesn't have anything useful except for the owner name we found in the exif data.

```terminal
└──╼ $ exiftool youfoundme.png                                                                                                                          130 ⨯ 
ExifTool Version Number         : 12.16                                                                                                                       
File Name                       : youfoundme.png                                                                                                              
Directory                       : .                                                                                                                           
File Size                       : 88 KiB
.
.
Owner Name                      : fijbxslz
Image Size                      : 894x894
Megapixels                      : 0.799
```

## SMB

Let's list the available share on this smb server using the command `sudo smbclient -L 10.10.128.42 -N`.

![](2.png)

We found three shares, let's try to connect to `nerdherd_classified` share.

```terminal
──╼ $ sudo smbclient //10.10.128.42/nerdherd_classified -N            
tree connect failed: NT_STATUS_ACCESS_DENIED
```

We couldn't connect.

Let's enumerate users using `enum4linux`.

```terminal
 =============================                                                                                                                                
|    Users on 10.10.128.42    |                                                                                                                               
 =============================                                                                                                                                
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: chuck    Name: ChuckBartowski    Desc:                                                                         
                                                                                                                                                              
user:[chuck] rid:[0x3e8]                                      
```

We managed to find user `chuck`

Let's run another nmap scan but for all ports this time using this command `sudo nmap --min-rate 5000 -p- 10.10.128.42`.

```terminal
Nmap scan report for 10.10.128.42
Host is up (0.16s latency).
Not shown: 43747 closed tcp ports (reset), 21783 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
1337/tcp open  waste
```

We found port 1337 open, scan that port for it's services we find that's it's running Apache web server.

```terminal
PORT     STATE SERVICE VERSION
1337/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
```

## Web

Let's navigate to the web page.

![](3.png)

It's the default page for Apache2, let's check the source code.

![](4.png)

We found a link to a youtube video about a song called `bird is the word`.

We discover that the name we found earlier in the png file (fijbxslz) is a Vigenere Cipher, and its key is the name of the song.

![](5.png)

This decoded to a password, let's go back to the smb and login as `chuck` with the password we just found.

![](6.png)

Great! We managed to login and found a secret file that gave us a web directory. Let's check it.

![](7.png)

Great! We found ssh credentials.

# **Foothold**

Let's login using the credentials we found.

![](8.png)


# **Privilege Escalation**

Let's check the kernel version of this machine.

```terminal
chuck@nerdherd:~$ uname -a
Linux nerdherd 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
```

This version is vulnerable to local privilege escalation and we can find the exploit [here](https://www.exploit-db.com/exploits/45010).

Let's upload the exploit to the target, compile it and run it.

![](9.png)

And just like that we got root. The root flag can be found in **/opt** directory and the bonus flag in the **bash_history** file of root.



---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
