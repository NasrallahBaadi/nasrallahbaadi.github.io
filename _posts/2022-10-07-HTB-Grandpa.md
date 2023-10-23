---
title: "HackTheBox - Grandpa"
author: Nasrallah
description: ""
date: 2022-10-07 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, metasploit]
img_path: /assets/img/hackthebox/machines/grandpa
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Grandpa](https://app.hackthebox.com/machines/Grandpa) from [HackTheBox](https://www.hackthebox.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.14
Host is up (0.16s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-title: Under Construction
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Server Date: Fri, 16 Sep 2022 10:30:30 GMT
|   Server Type: Microsoft-IIS/6.0
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|_http-server-header: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

We only got 1 port open which is 80 and it's running Microsoft IIS httpd 6.0.

Searching on google for `Microsoft IIS httpd 6.0 exploit` we find that this version is vulnerable to a buffer overflow allowing the attacker to execute arbitrary code. Check [this](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl/) for more info.

![](1.png)

# **Foothold**

There is a module in metasploit that helps us exploit this vulnerability called `exploit/windows/iis/iis_webdav_scstoragepathfromurl`.

![](2.png)

Let's use the module and set the required options.

![](3.png)


# **Privilege Escalation**

For this part, i migrated to another stable process and run local_exploit_suggester module.

![](4.png)

That gave us a couple of modules but we'll be using `exploit/windows/local/ms14_070_tcpip_ioctl` module.

![](5.png)

And just like that we got system privileges.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).