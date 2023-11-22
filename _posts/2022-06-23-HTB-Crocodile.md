---
title: "HackTheBox - Crocodile"
author: Nasrallah
description: ""
date: 2022-06-23 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, hydra, bruteforce]
img_path: /assets/img/hackthebox/machines/crocodile/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello l33ts, I hope you are doing well. Today we are going to look at [Crocodile](https://app.hackthebox.com/starting-point?tier=1) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.1.15 (10.129.1.15)
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
|_-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.16.29
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Smash - Bootstrap Business Template
Service Info: OS: Unix
```

We found 2 open ports, 21 running a ftp server that allows anonymous login, and port 80 running apache web server.

### FTP

Let's login to the ftp server and download the files there.

![](1.png)

Let's see what's on those file.

![](2.png)

We have a list of username and a list of password.

### Web

Navigate to the webpage. http://10.129.1.15/

![](3.png)

It's a Bootstrap Business Template, nothing useful for us.

### Gobuster

Let's run a directory scan using gobuster:`gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.129.1.15/`

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.1.15/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/assets               (Status: 301) [Size: 311] [--> http://10.129.1.15/assets/]
/css                  (Status: 301) [Size: 308] [--> http://10.129.1.15/css/]   
/dashboard            (Status: 301) [Size: 314] [--> http://10.129.1.15/dashboard/]
/fonts                (Status: 301) [Size: 310] [--> http://10.129.1.15/fonts/]    
/index.html           (Status: 200) [Size: 58565]                                  
/js                   (Status: 301) [Size: 307] [--> http://10.129.1.15/js/]       
/server-status        (Status: 403) [Size: 276]                                    
                                                                                   
===============================================================
```

There is /dashboard page. Let's navigate to it.

![](4.png)

We get redirected to a login page.

## **Foothold**

Let's use the username and password lists we found earlier and attempt to login.

Since we have a small list, no need for an automated tool. But we will do it anyway for demonstration purposes. 

First thing we need is the name of the parameters used for the login, for that, we either use burp suite and intercept the login request or just use the developer tool of the browser, we will use the latter.

Press `F12` and got to network tab. 

Now submit a test username and password (admin:admin for example) and try to login.

![](7.png)

Here we can see that there is three parameters; Username, Password and Submit.

The username and password parameters' values are the ones we're going to brute force, the Submit value will stay 'Login'.

Next thing we need is an error message of a failed login so the script knows when we get a successful login.

![](5.png)

Now it's time to craft the command. `hydra -L allowed.userlist -P allowed.userlist.passwd 10.129.1.15 http-post-form "/login.php:Username=^USER^&Password=^PASS^&Submit='Login':Incorrect"`.

![](8.png)

Great! We got the valid credentials. Let's login.

![](6.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
