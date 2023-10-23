---
title: "HackTheBox - Ignition"
author: Nasrallah
description: ""
date: 2022-06-27 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy]
img_path: /assets/img/hackthebox/machines/ignition/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello l33ts, I hope you are doing well. Today we are going to look at [Ignition](https://app.hackthebox.com/starting-point?tier=1) from [HackTheBox](https://www.hackthebox.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.1.27 (10.129.1.27)
Host is up (0.63s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2
|_http-title: Did not follow redirect to http://ignition.htb/
|_http-server-header: nginx/1.14.2
```

Port 80 is open running nginx web server.

##  Web

Let's navigate to the web page.

![](1.png)

We get redirected to `ignition.htb`, so let's add that to our `/etc/hosts`.

![](2.png)

Let's try again.

![](3.png)

Nothings really useful.

## Gobuster

Let's run a directory scan.`gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://ignition.htb/ `

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://ignition.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
 Starting gobuster in directory enumeration mode
===============================================================
/0                    (Status: 200) [Size: 25803]      
/admin                (Status: 200) [Size: 7095]                                                                                                              
/catalog              (Status: 302) [Size: 0] [--> http://ignition.htb/]
/checkout             (Status: 302) [Size: 0] [--> http://ignition.htb/checkout/cart/]
/cms                  (Status: 200) [Size: 25817]                                                                                                            
/contact              (Status: 200) [Size: 28673]                                      
/enable-cookies       (Status: 200) [Size: 27176]                                      
/errors               (Status: 301) [Size: 185] [--> http://ignition.htb/errors/]     
/Home                 (Status: 301) [Size: 0] [--> http://ignition.htb/home]           
/home                 (Status: 200) [Size: 25802]                                      
/index.php            (Status: 200) [Size: 25815]                                      
/media                (Status: 301) [Size: 185] [--> http://ignition.htb/media/]      
/opt                  (Status: 301) [Size: 185] [--> http://ignition.htb/opt/] 
/rest                 (Status: 400) [Size: 52]                                         
/robots               (Status: 200) [Size: 1]                                          
/robots.txt           (Status: 200) [Size: 1]                                          
/setup                (Status: 301) [Size: 185] [--> http://ignition.htb/setup/]      
/soap                 (Status: 200) [Size: 391]                                        
/static               (Status: 301) [Size: 185] [--> http://ignition.htb/static/]     
/wishlist             (Status: 302) [Size: 0] [--> http://ignition.htb/customer/account/login/referer/aHR0cDovL2lnbml0aW9uLmh0Yi93aXNobGlzdA%2C%2C/]
                                                                                                                                                     
===============================================================
```

Let's see what's on **/admin** page.

![](4.png)

Found a Magento login page. 

# **Foothold**

Let's try some of the common used passwords with the username admin.

 - admin admin123
 - admin root123
 - admin password1
 - admin administrator1
 - admin changeme1
 - admin password123
 - admin qwerty123
 - admin administrator123
 - admin changeme123

![](5.png)

Nice! We got in.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).