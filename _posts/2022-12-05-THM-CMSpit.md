---
title: "TryHackMe - CMSpit"
author: Nasrallah
description: ""
date: 2022-12-05 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, sudo, cve, reverse-shell, mongodb]
img_path: /assets/img/tryhackme/cmspit
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [CMSpit](https://tryhackme.com/room/cmspit) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.68.97
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7f25f9402325cd298b28a9d982f549e4 (RSA)
|   256 0af429ed554319e773a7097930a8491b (ECDSA)
|_  256 2f43ada3d15b648633075d94f9dca401 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Authenticate Please!
|_Requested resource was /auth/login?to=/
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open ports on a Ubuntu machine, port 22 running OpenSSH and port 80 running Apache web server.

### Web

Let's check the web page.

![](1.png)

When we visit the page we get redirected to a login page of cockpit, i tried some default credentials as well as sql injection but couldn't log in.

Let's search for any vulnerabilities in this CMS.

```terminal
$ searchsploit cockpit
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Cockpit CMS 0.11.1 - 'Username Enumeration & Password Reset' NoSQL Injection                                               | multiple/webapps/50185.py
Cockpit CMS 0.4.4 < 0.5.5 - Server-Side Request Forgery                                                                    | php/webapps/44567.txt
Cockpit CMS 0.6.1 - Remote Code Execution                                                                                  | php/webapps/49390.txt
Cockpit Version 234 - Server-Side Request Forgery (Unauthenticated)                                                        | multiple/webapps/49397.txt
openITCOCKPIT 3.6.1-2 - Cross-Site Request Forgery                                                                         | php/webapps/47305.py
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

The latest vulnerability is in version 0.11.1 allowing us to enumerate users and reset passwords.

Let's copy the exploit to our machine with the command `searchsploit -m multiple/webapps/50185.py` and see what we can do with it.

![](2.png)

We managed to find 4 users, we can also reset passwords, so let's reset the admin's password.

![](3.png)

Great we got the password, let's log in.

![](4.png)

## **Foothold**

Navigating through the different pages, i find a page called **/finder** where i can browse file of the web server and create files.

![](5.png)

I created a file and named it shell.php, then copied [Pentest Monkey's reverse shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php) to the file and saved it.

![](6.png)

Then i setup a listener to catch the shell and requested the file.

![](7.png)


## **Privilege Escalation**

Searching through the files of the web server, we find `mongo` file, we try to connect to the mondo database and we succeed.

![](8.png)

We list the databases with `show dbs`, we select a specific database with `use DATABASENAME` then we `show collections.`

To dump the collections we run `db.Name.find()`.

![](9.png)

We found `stux`'s password, let's switch to him with `su stux`.

Now let's check our current privileges.

```terminal
stux@ubuntu:~$ sudo -l
Matching Defaults entries for stux on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User stux may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/local/bin/exiftool

```

We can run exiftool as root, let's go to [GTFOBins](https://gtfobins.github.io/gtfobins/exiftool/#sudo)

![](11.png)

We can read any file we want so let's get the root flag with the following command:

```bash
sudo /usr/local/bin/exiftool -filename=./root.txt /root/root.txt
```

![](10.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
