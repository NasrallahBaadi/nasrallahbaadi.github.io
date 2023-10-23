---
title: "PwnTillDawn - Mr. Blue"
author: Nasrallah
description: ""
date: 2022-08-17 00:00:00 +0000
categories : [PwnTillDawn]
tags: [pwntilldawn, windows, easy]
img_path: /assets/img/pwntilldawn/mrblue
---

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Mr. Blue](https://online.pwntilldawn.com/Target/Show/4) from [PwnTillDawn](https://online.pwntilldawn.com/).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.150.150.242                                           
Host is up (0.11s latency).
Not shown: 985 closed tcp ports (reset)                                                                                                                      
PORT      STATE SERVICE      VERSION                                          
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB1446A) (Windows Server 2008 R2 SP1)                                                                  
| dns-nsid:                                                                   
|_  bind.version: Microsoft DNS 6.1.7601 (1DB1446A)
80/tcp    open  http         Microsoft IIS httpd 7.5
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Microsoft-IIS/7.5 
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2008 R2 Enterprise 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2012 11.00.2100.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: MRBLUE
|   NetBIOS_Domain_Name: MRBLUE
|   NetBIOS_Computer_Name: MRBLUE
|   DNS_Domain_Name: MrBlue
|   DNS_Computer_Name: MrBlue
|_  Product_Version: 6.1.7601
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2020-03-25T14:11:19 
|_Not valid after:  2050-03-25T14:11:19 
|_ssl-date: 2022-08-19T18:01:08+00:00; +13m15s from scanner time.
3389/tcp  open  tcpwrapped
|_ssl-date: 2022-08-19T18:01:08+00:00; +13m15s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: MRBLUE
|   NetBIOS_Domain_Name: MRBLUE
|   NetBIOS_Computer_Name: MRBLUE
|   DNS_Domain_Name: MrBlue
|   DNS_Computer_Name: MrBlue
|   Product_Version: 6.1.7601
|_  System_Time: 2022-08-19T18:00:54+00:00
| ssl-cert: Subject: commonName=MrBlue
| Not valid before: 2022-08-18T16:02:13 
|_Not valid after:  2023-02-17T16:02:13 
8089/tcp  open  ssl/http     Splunkd httpd
|_http-title: splunkd
|_http-server-header: Splunkd
| http-robots.txt: 1 disallowed entry 
|_/
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2019-10-25T09:53:52 
|_Not valid after:  2022-10-24T09:53:52 
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: MRBLUE; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-08-19T18:00:53
|_  start_date: 2020-03-25T14:11:23
|_nbstat: NetBIOS name: MRBLUE, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:ab:46:29 (VMware)
|_clock-skew: mean: 13m15s, deviation: 0s, median: 13m14s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| ms-sql-info: 
|   10.150.150.242:1433: 
|     Version: 
|       name: Microsoft SQL Server 2012 RTM
|       number: 11.00.2100.00
|       Product: Microsoft SQL Server 2012
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Enterprise 7601 Service Pack 1 (Windows Server 2008 R2 Enterprise 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: MrBlue
|   NetBIOS computer name: MRBLUE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-08-19T18:00:53+00:00
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required

```

Nmap tells us the it's a windows server machine with a bunch of open ports. We can see that it has SMB open with a domain name of `MRBLUE`, that made me think directly of the `ms17_010_eternalblue`.

# **Foothold**

Let's fire up `metasploit` and use the `ms17_010_eternalblue` module.

![](2.png)

Let's run the exploit by entering `run`.

![](1.png)

Nice! We got a shell and we have SYSTEM privileges so no need for privilege escalation.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).