---
title: "HackTheBox - Delivery"
author: Nasrallah
description: ""
date: 2024-12-23 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy]
img_path: /assets/img/hackthebox/machines/delivery
image:
    path: delivery.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Delivery](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/delivery) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ).

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
PORT     STATE SERVICE VERSION                                                                                                                                                                
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)                                                                                                                         
| ssh-hostkey:                                                                                                                                                                                
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)            
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)           
|_  256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)         
80/tcp   open  http    nginx 1.14.2                                                            
|_http-server-header: nginx/1.14.2                                                             
|_http-title: delivery                                                                         
8065/tcp open  unknown                                                                         
| fingerprint-strings:                                                                         
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request                                                                 
|     Content-Type: text/plain; charset=utf-8
```

we found three open ports, 22 running ssh, 80 running nginx webserver, and port 8065 also looks like a webserver.

### web

Let's navigate to the website on port 80.

![website](1.png)

The website contains a link to `helpdesk.delivery.htb`, let's add both domains to our `/etc/hosts` file.

![helpdesk](2.png)

This is a support ticket system where we can send support requests and track each ticket with a number.

Let's check what's on port 8065.

![otherport](3.png)

This is running `mattermost`. When trying to create an account we get asked to verify our email address.

![verify](4.png)

Let's get back to the ticket system and create a ticket.

![ticket](5.png)

After sending the ticket we get the following.

![res](6.png)

We got ticket id that allows us to track the ticket and we also got an email address that allows us to add data to our ticket just by sending an email to that address.

## **Foothold**

We can use the email address provided to us to create an account in `mattermost`, and when the verification email is sent to us, it will appear in the ticket.

![v](7.png)

After clicking on `Check Ticket status` and entering the email and id we see the email from matter most.

Now we navigate to the link provided to us.

![asdf](8.png)

The email got verified, now we login.

![pass](9.png)

We found messages by root reveling credentials to the box `maildeliverer:Youve_G0t_Mail!`.

With that we can ssh to the box

```terminal
[★]$ ssh maildeliverer@delivery.htb
maildeliverer@delivery.htb's password: 
Linux Delivery 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Dec 18 15:08:22 2024 from 10.10.16.7
maildeliverer@Delivery:~$ id
uid=1000(maildeliverer) gid=1000(maildeliverer) groups=1000(maildeliverer)
maildeliverer@Delivery:~$
```

## **Privilege Escalation**

On the `/opt` directory resides the `mattermost` directory with a config file.

```terminal
maildeliverer@Delivery:/opt/mattermost/config$ cat config.json
[...]
"SqlSettings": {                                                                           
        "DriverName": "mysql",  
        "DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8\u0026readTimeout=30s\u0026writeTimeout=30s",
        "DataSourceReplicas": [],             
        "DataSourceSearchReplicas": [],                                                        
        "MaxIdleConns": 20,            
        "ConnMaxLifetimeMilliseconds": 3600000, 
        "MaxOpenConns": 300,             
        "Trace": false,                    
        "AtRestEncryptKey": "n5uax3d4f919obtsp1pw1k5xetq1enez",                                
        "QueryTimeout": 30,                                                                    
        "DisableDatabaseSearch": false    
```

We find credentials to the mysql service, Let's login and see what we can find. `mmuser:Crack_The_MM_Admin_PW`

```terminal
maildeliverer@Delivery:/opt/mattermost/config$ mysql -u mmuser -p                                                                                                                             
Enter password:                                                                                                                                                                               
Welcome to the MariaDB monitor.  Commands end with ; or \g.                                                                                                                                   
Your MariaDB connection id is 287                                                                                                                                                             
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10                                                                                                                                           
                                               
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.
                                               
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.


MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mattermost         |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use mattermost;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [mattermost]> select Username, Password from Users;
+----------------------------------+--------------------------------------------------------------+
| Username                         | Password                                                     |
+----------------------------------+--------------------------------------------------------------+
| surveybot                        |                                                              |
| root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO |
+----------------------------------+--------------------------------------------------------------+

```

We got the hash of root user.

If we look back at mattermost messages, we see that user root mentions that they are using variants of `PleaseSubscribe!` as passwords.

He also hints that we can use hashcat rules to crack the hashes if we got them.

### hashcat

Let's try cracking the hash using the best64 rule.

```terminal
λ .\hashcat.exe hashes.txt file.txt -m 3200 -r rules\best64.rule
hashcat (v6.2.6) starting


$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO:PleaseSubscribe!21

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v...JwgjjO
Time.Started.....: Thu Dec 19 10:42:35 2024 (40 secs)
Time.Estimated...: Thu Dec 19 10:43:15 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (file.txt)
Guess.Mod........: Rules (rules\best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:        1 H/s (1.55ms) @ Accel:1 Loops:1 Thr:16 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 21/77 (27.27%)
Rejected.........: 0/21 (0.00%)
Restore.Point....: 0/1 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:20-21 Iteration:1023-1024
Candidate.Engine.: Device Generator
Candidates.#1....: PleaseSubscribe!21 -> PleaseSubscribe!21
```

We got the password `PleaseSubscribe!21`.

No we can either ssh or just `su` from the current ssh session.

```terminal
maildeliverer@Delivery:/opt/mattermost/config$ su root
Password: 
root@Delivery:/opt/mattermost/config#
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
