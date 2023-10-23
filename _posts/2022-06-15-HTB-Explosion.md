---
title: "HackTheBox - Explosion"
author: Nasrallah
description: ""
date: 2022-06-15 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, rdp]
img_path: /assets/img/hackthebox/machines/explosion
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello l33ts, I hope you are doing well. Today we are going to look at [Explosion](https://app.hackthebox.com/starting-point?tier=0) from [HackTheBox](https://www.hackthebox.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.190.225 (10.129.190.225)        
Host is up (0.29s latency).
Not shown: 996 closed tcp ports (reset)                 
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: EXPLOSION
|   NetBIOS_Domain_Name: EXPLOSION
|   NetBIOS_Computer_Name: EXPLOSION
|   DNS_Domain_Name: Explosion
|   DNS_Computer_Name: Explosion
|   Product_Version: 10.0.17763
|_  System_Time: 2022-07-22T10:55:03+00:00
| ssl-cert: Subject: commonName=Explosion
| Not valid before: 2022-07-21T10:33:19 
|_Not valid after:  2023-01-20T10:33:19 
|_ssl-date: 2022-07-22T10:55:11+00:00; -1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-07-22T10:55:06
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
```

We see that we are dealing with a windows machine running smb and RDP on port 3389.

# **Foothold**

Let's try to connect to RDP using `xfreerdp`.

The script need some switches for it to try to connect to the target.

 - /u:{username} : Specifies the login username.
 - /v:{target_IP} : Specifies the target IP of the host we would like to connect to.

We will be login as user **Administrator** and submit a blank.

`xfreerdp /v:10.129.190.225 /u:Administrator`

![](1.png)

Wait a little bit and we get a GUI access to the target as Administrator.

![](2.png)

For better access, use the following command `xfreerdp /v:10.129.190.225 /u:Administrator /dynamic-resolution +clipboard`. This will allow us to us clipboard and resize the pane.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).