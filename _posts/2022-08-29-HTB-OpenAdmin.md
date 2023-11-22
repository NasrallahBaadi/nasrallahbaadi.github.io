---
title: "HackTheBox - OpenAdmin"
author: Nasrallah
description: ""
date: 2022-08-29 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, john, crack, rce, sudo]
img_path: /assets/img/hackthebox/machines/openadmin
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [OpenAdmin](https://app.hackthebox.com/machines/OpenAdmin) from [HackTheBox](https://www.hackthebox.com). It's an easy machine running a web server with a service vulnerable to rce allowing us to get easy foothold. Enumerating the server's file we find a password of a user that have access to another an internal web server that reveals an ssh key that we use to move to another user. A sudo misconfiguration in then exploited to gain root shell.

## **Enumeration**
 
### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.171
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

We have 2 ports open, 22(SSH) and 80 running Apache http webserver.

### Web

Let's check the website.

![](1.png)

We got the Apache ubuntu  default page.

#### Gobuster

Let's run a directory scan.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.171/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/08/27 06:33:27 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/artwork              (Status: 301) [Size: 314] [--> http://10.10.10.171/artwork/]
/index.html           (Status: 200) [Size: 10918]                                 
/music                (Status: 301) [Size: 312] [--> http://10.10.10.171/music/]  
/server-status        (Status: 403) [Size: 277]                                   
===============================================================
```

We found two interesting directories, **/artwork** and **music**, let's check the first one.

#### artwork

![](2.png)

It's a website template, nothing really useful. Let's check the other directory.


#### music

![](3.png)

In this page we can see that we can login or create an account along with some other pages. Let's try logging in.

![](4.png)

We get redirected to **/ona** where we are logged in as Guest, and it seems the service on this page is running on an old version and we are asked to download the latest version. The download link is going to **opennetadmin** page aka **ONA**.

## **Foothold**

Let's check if there is any exploit in this version.

```terminal
$ searchsploit opennetadmin
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution                                                                              | php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)                                                               | php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                                                                                | php/webapps/47691.sh
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

This version is vulnerable to remote code execution, let's copy the exploit to our current directory with the command `searchsploit -m php/webapps/47691.sh` and use it.

![](5.png)

We got code execution. Let's upload a [php reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) to the webserver.

![](6.png)

Now set up a listener and request the file the receive a reverse shell.

![](7.png)

We got a shell, and i stabilized it with python3 as you can see in the screenshot above. 

## **Privilege Escalation**

After some very long enumeration in the target, we find a php file that contains mysql credentials.

![](8.png)

The credentials belong to the user `jimmy`, run the command `su jimmy` to switch to that user.

running the command `id`, we see that jimmy is part of a group named `internal`, if we search for files that belongs to that group we find the following.

![](9.png)

There is a web server running on a high port, and it's located in /var/www/internal.

The file main.php prints `joanna`'s ssh private key.

![](10.png)

Let's request the file and see what happens.

![](11.png)

Nice, we got the key. Let's put in a file, give it the right permission and connect with it.

![](12.png)

The key was protected with a password but we managed to crack it using `john`.

Let's check our privileges.

![](13.png)

We can run nano as root, let's check [GTFOBins](https://gtfobins.github.io/gtfobins/nano/#sudo).

![](14.png)

There is a way to get root shell, we just need to execute the following commands.

```terminal
sudo /bin/nano /opt/priv

"ctrl + R"
"ctrl + X"

reset; sh 1>&0 2>&0
```

>Press Enter multiple time to get a clear shell.

![](15.png)

Great! We got root.


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).