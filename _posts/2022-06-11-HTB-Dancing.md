---
title: "HackTheBox - Dancing"
author: Nasrallah
description: ""
date: 2022-06-11 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, smb, easy]
img_path: /assets/img/hackthebox/machines/dancing/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello l33ts, I hope you are doing well. Today we are going to look at [Dancing](https://app.hackthebox.com/starting-point?tier=0) from [HackTheBox](https://www.hackthebox.com). It's a windows machine running smb with a misconfigured share that permits to log in to it without valid credentials.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 -Pn {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.196.235 (10.129.196.235)
Host is up (0.20s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-07-21T14:31:05
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: 3h59m59s
```

We see that the target is a windows machine running SMB - Server Message Block Protocol - and it is a client-server communication protocol used for sharing access to files, printers, serial ports and other resources on a network.

SMB share drives on a server that can be connected to and used to view or transfer files. SMB can often be a great starting point for an attacker looking to discover sensitive information.

In order to enumerate SMB, we can use a tool called `enum4linux` or `smbclient`.

First, we need to list available share in the server, we do that with the following command : `sudo smbclient -L 10.192.196.235`. We will be prompt to submit a password, we just press enter without giving one.

![](1.png)

 - ADMIN$ - Administrative shares are hidden network shares created by the Windows NT family of operating systems that allow system administrators to have remote access to every disk volume on a network-connected system. These shares may not be permanently deleted but may be disabled.
 - C$ - Administrative share for the C:\ disk volume. This is where the operating system is hosted.
 - IPC$ - The inter-process communication share. Used for inter-process communication via named pipes and is not part of the file system.
 - WorkShares - Custom share.

# **Foothold**

Let's connect to the custom share '**WorkShares**'. `sudo smbclient \\\\10.129.196.235\\WorkShares`.

![](2.png)

Great! The WorkShares share was misconfigured and allowed to log in without a password. Most of the commands of SMB are the same as the ones in linux, so we can list the content of the directory with `ls`.

![](3.png)

We found two directories, one for `Amy.J` and one for `James.P`.

Let's go into Amy's directory and list it's content.

![](4.png)

Found file named *worknotes.txt*. To View the file's content, we first need to download it to our machine. To do that, we can use `get worknotes.txt`.

![](5.png)

We downloaded the file successfully, now let's go to james directory and do the same steps as before.

![](6.png)

Found flag.txt file and downloaded it to our machine.

To exit smb, enter `quit`, after that we can see the file we downloaded in our current directory.

![](7.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

# References
