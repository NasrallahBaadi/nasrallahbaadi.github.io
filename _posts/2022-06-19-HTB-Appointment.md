---
title: "HackTheBox - Appointment"
author: Nasrallah
description: ""
date: 2022-06-19 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sqli]
img_path: /assets/img/hackthebox/machines/appointment/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello l33ts, I hope you are doing well. Today we are going to look at [Appointment](https://app.hackthebox.com/starting-point?tier=1) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.197.23 (10.129.197.23)
Host is up (0.18s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Login
|_http-server-header: Apache/2.4.38 (Debian)
```

Port 80 is open running Apache.

### Web

Let's navigate to the webpage.

![login page](1.png)

It's a login form.

## **Foothold**

One of the first things to try is default credentials like admin:admin, admin:password, root:root.

Unfortunately the default credentials don't work.

Next things is to test the login form for SQL injection vulnerability.

> SQL Injection is a common way of exploiting web pages that use `SQL Statements` that
retrieve and store user input data. If configured incorrectly, one can use this attack
to exploit the well-known `SQL Injection` vulnerability, which is very dangerous. There
are many different techniques of protecting from SQL injections, some of them being
input validation, parameterized queries, stored procedures, and implementing a WAF (Web
Application Firewall) on the perimeter of the server's network. However, instances can
be found where none of these fixes are in place, hence why this type of attack is
prevalent, according to the [OWASP Top 10](https://owasp.org/www-project-top-ten/) list
of web vulnerabilities.

One of the most common payload used for authentication bypass using SQL injection is `' or 1=1 --`.

Before we send the payload, let's first understand how things work in the backend.

The following PHP code demonstrates a dynamic SQL query in a login from. The user and password variables from the POST request is concatenated directly into the SQL statement.

`$query = "SELECT * FROM users WHERE username='" + $_POST["user"] + "' AND password= '" + $_POST["password"]$ + '";"`

When we submit our payload as username and password, the sql query would look like the following.

`SELECT * FROM users WHERE username = '' OR 1=1--' AND password = ''`

If the database executes the SQL statement above, all the users in the users table are returned. Consequently, the attacker bypasses the application's authentication mechanism and is logged in as the first user returned by the query.

Let's break down the payload:

 - The character ' will close the brackets in the SQL query.
 - 'OR' in a SQL statement will return true if either side of it is true. As 1=1 is always true, the whole statement is true. Thus it will tell the server that the email is valid, and log us into user id 0, which happens to be the administrator account.
 - The -- character is used in SQL to comment out data, any restrictions on the login will no longer work as they are interpreted as a comment. This is like the # and // comment in python and javascript respectively.

Great! Now let's submit our payload and see what happens.

![](2.png)

We logged in successfully.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
