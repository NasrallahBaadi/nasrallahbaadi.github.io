---
title: "HackTheBox - Arctic"
author: Nasrallah
description: ""
date: 2023-04-01 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, rce]
img_path: /assets/img/hackthebox/machines/arctic
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Arctic](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.11                                                                                                                              
Host is up (0.11s latency).                                                                                                                                   
Not shown: 997 filtered tcp ports (no-response)                                
PORT      STATE SERVICE VERSION                                                                                                                               
135/tcp   open  msrpc   Microsoft Windows RPC                                                                                                                 
8500/tcp  open  fmtp?                                                                                                                                         
49154/tcp open  msrpc   Microsoft Windows RPC                                                                                                                 
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows      
```

We found 3 open ports, MSRPC (135, 49154) and port 8500.

## Web

Let's check port 8500 and see if it's accessible via http.

![](1.png)

We find a directory listing with two directories (CFIDE and cfdocs)

On te CFIDE directory we find the following.

![](2.png)

There is an Administrator directory, let's see what's there.

![](3.png)

It's a login page for Adobe Coldfusion 8.

Searching for this version on exploit-db we find it's vulnerable to [remote code execution](https://www.exploit-db.com/exploits/50057)

![](4.png)


# **Foothold**

Let's download the exploit, change the lhost variable and run it.

![](5.png)

We got a shell.

# **Privilege Escalation**

Let's run windows exploit suggester

```terminal
$ python2 windows-exploit-suggester.py --database 2023-03-27-mssb.xls --systeminfo sysinfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```

We got multiple exploits, but after some trial and error, we manage to elevate out privileges using `MS10-059.exe`, we can find the exploit [here](https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-059/MS10-059.exe).

![](6.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).