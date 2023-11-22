---
title: "TryHackMe - Blaster"
author: Nasrallah
description: ""
date: 2022-08-23 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, windows, cve, rdp]
img_path: /assets/img/tryhackme/blaster
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Blaster](https://tryhackme.com/room/blaster) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.183.181
Host is up (0.083s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2022-08-22T07:50:07+00:00; -29m54s from scanner time.
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2022-08-21T07:02:43
|_Not valid after:  2023-02-20T07:02:43
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2022-08-22T07:50:05+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

We found 2 open port, port 80 running IIS windows server and port 3389 is RDP.

### WEB

Let's navigate to the webserver.

![](1.png)

It's the default page for IIS windows server, nothing interesting.

#### Gobuster

Let's run a directory scan.

```bash
$ gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://10.10.183.181/ 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.183.181/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/08/22 04:31:05 Starting gobuster in directory enumeration mode
===============================================================
/retro                (Status: 301) [Size: 150] [--> http://10.10.183.181/retro/]
                                                                                 
===============================================================
```

Found a directory named **/retro**, let's see what's there.

![](2.png)

It's a blog named **Retro Fanatics** and the posts there are written by user `Wade`.

Scrolling down we see an interesting post.

![](3.png)

If we click on the post we find the following comment.

![](4.png)

## **Foothold**

Let's login to the machine via RDP with username `wade` and the password we found.

```bash
xfreerdp /u:wade /p:{password} /v:10.10.183.181 /dynamic-resolution +clipboard
```

![](5.png)

![](6.png)


## **Privilege Escalation**

On Wade's desktop, there is user.txt which is the flag and a file named `hhupd`. If we googled that we find that it's related to a privilege escalation vulnerability.

![](7.png)

The room author suggests this [Video](https://www.youtube.com/watch?v=3BQKpPNlTSo) to follow in case we get stuck.

To start the exploitation, we run the binary as administrator and cause the `UAC` prompt to be displayed, we click `show more details`.

![](8.png)

Then click `show more information about the publisher`, this displays another tab, click the link shown there.

![](9.png)

Now press ok and close the `UAC` tab.

The last action launches a browser process running as `SYSTEM`.

![](10.png)

Now go to Tools -> file -> save as..

![](11.png)

An error would appear but dismiss it and continue

Now go the the search tab, type `cmd` and click Enter.

![](12.png)

We got a shell as NT authority\system


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---
