---
title: "HackTheBox - Sequel"
author: Nasrallah
description: ""
date: 2022-06-21 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sql, mysql]
img_path: /assets/img/hackthebox/machines/sequel/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello l33ts, I hope you are doing well. Today we are going to look at [Sequel](https://app.hackthebox.com/starting-point?tier=1) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.95.232 (10.129.95.232)
Host is up (0.14s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
3306/tcp open  mysql?
|_sslv2: ERROR: Script execution failed (use -d to debug)
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.27-MariaDB-0+deb10u1
|   Thread ID: 65
|   Capabilities flags: 63486
|   Some Capabilities: FoundRows, SupportsLoadDataLocal, SupportsTransactions, Support41Auth, Speaks41ProtocolOld, ConnectWithDatabase, IgnoreSigpipes, LongColumnFlag, ODBCClient, DontAllowDatabaseTableColumn, InteractiveClient, Speaks41ProtocolNew, SupportsCompression, IgnoreSpaceBeforeParenthesis, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: zJAEvF9)^$4x";E'4mLq
|_  Auth Plugin Name: mysql_native_password
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
```

Port 3306 is open and running mysql. MySQL is a service designed for database management: creating, modifying, and updating databases, changing and adding data, and more.

## **Foothold**

In order to communicate with the mysql database, we need a username and password, but sometimes there might be a misconfiguration allowing a passwordless authentication.

To connect we use the command `mysql` with the following switches.

 - -h : Connect to host.
 - -u : User for log-in if not current user.

As an initial attempt, we will try to log-in as the root user, naturally having the highest level of privileges on the system.

![](1.png)

Great! We managed to login without a password. We are placed in a MySQL service shell from where we can explore the tables and data therein that are available to us.

The commands we will be using are the following:

 - SHOW databases; : Prints out the databases we can access.
 - USE {database_name}; : Set to use the database named {database_name}.
 - SHOW tables; : Prints out the available tables inside the current database.
 - SELECT * FROM {table_name}; : Prints out all the data from the table {table_name}.

Let's list the available databases with `SHOW databases;`.

![](2.png)

To be able to see what's inside a database, we need to select it. We can use the command `USE {database}` to do that. In our case, the `htb` database seems relevant for our exercise so let's select it.

![](3.png)

The next move is to prints our the available tables inside the `htb` database. We use the command `SHOW tables;`.

![](4.png)

There are two tables. Let's check their content with the `SELECT * FROM {table_name};` command.

![](5.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
