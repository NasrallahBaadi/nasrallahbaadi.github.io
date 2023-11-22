---
title: "TryHackMe - Lazy Admin"
author: Nasrallah
description: ""
date: 2022-04-07 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, crack, easy]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello l33ts, I hope you are doing well. We are doing [LazyAdmin](https://tryhackme.com/room/lazyadmin) from [TryHackMe](https://tryhackme.com). We find a webserver running a vulnerable 

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```Terminal
Nmap scan report for 10.10.151.18
Host is up (0.099s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We got ssh on port 22 and a http webserver on port 80, let's check the webserver.


### Webserver

Let's navigate to the web page.

![](/assets/img/tryhackme/lazyadmin/l1.png)

It's the default page of Apache, nothing useful, let's run directory scan.

### Gobuster

```Terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.149.81/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/13 07:44:21 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/content              (Status: 301) [Size: 314] [--> http://10.10.149.81/content/]
/index.html           (Status: 200) [Size: 11321]                                 
/server-status        (Status: 403) [Size: 277]                                   
===============================================================
```

We found a directory called **/content**, let's navigate to it.

![](/assets/img/tryhackme/lazyadmin/l2.png)

We found a welcome page of **SweetRice** website management system, I searched for SweetRice on [Exploitdb](https://www.exploit-db.com/) and found that it has a backup disclosure vulnerability, this [exploit](https://www.exploit-db.com/exploits/40718) explains how to get a mysql backup.

![](/assets/img/tryhackme/lazyadmin/l3.png)

We can navigate to `http://{target_IP}/inc/mysql_backup` and find a mysql backup file.

![](/assets/img/tryhackme/lazyadmin/l4.png)

Let's download the file to our machine and see what it has for us.

![](/assets/img/tryhackme/lazyadmin/l5.png)

The file has the username **manager** and a password hash that looks like an md5 hash, so we can use [crackstation](https://crackstation.net/) to crack the password.

![](/assets/img/tryhackme/lazyadmin/l6.png)

We managed to crack the password, but where to use it.

Let's run another directory scan but this time on **/content**.

```Terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.151.18/content
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/04/08 12:15:07 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/_themes              (Status: 301) [Size: 322] [--> http://10.10.151.18/content/_themes/]
/as                   (Status: 301) [Size: 317] [--> http://10.10.151.18/content/as/]     
/attachment           (Status: 301) [Size: 325] [--> http://10.10.151.18/content/attachment/]
/images               (Status: 301) [Size: 321] [--> http://10.10.151.18/content/images/]    
/inc                  (Status: 301) [Size: 318] [--> http://10.10.151.18/content/inc/]       
/index.php            (Status: 200) [Size: 2198]                                             
/js                   (Status: 301) [Size: 317] [--> http://10.10.151.18/content/js/]        

===============================================================
```

Let's see what on **/as** directory, navigate to `http://{target_IP}/content/as`.

![](/assets/img/tryhackme/lazyadmin/l8.png)

Great! We found a login page, let's use the credentials we found to login.

![](/assets/img/tryhackme/lazyadmin/l9.png)


## **Foothold**

We have access, now what? Earlier when we searched for possible exploits, there was an *arbitrary file upload* exploit in [Exploitdb](https://www.exploit-db.com/).

![](/assets/img/tryhackme/lazyadmin/l10.png)

Download the exploit [here](https://www.exploit-db.com/exploits/40716) and run it with `sudo python3 {exploitfile}`.

![](/assets/img/tryhackme/lazyadmin/l11.png)

We need to provide the target url `{target_IP}/content`, the username `manager`, the password we managed to crack, and a php reverse shell, in my case i used this one from [pentestmonkeys](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php), the extension of the file has to be `php5` for a successful upload.

Now let's set up a listener on our machine with `nc -lvnp {port_number}` and visit the link the exploit gave us `http://target_IP/content/attachment/reverse.php5`

![](/assets/img/tryhackme/lazyadmin/l12.png)

Great! We managed to get a shell, and i used the python3 pty trick to get a functional shell, now the privesc part.


## **Privilege Escalation**

Let's check our privileges by running `sudo -l`

![](/assets/img/tryhackme/lazyadmin/l13.png)

We can run a perl script as root. We don't have write permissions on the script so let's check script does.

![](/assets/img/tryhackme/lazyadmin/l14.png)

backup.pl just runs another script called copy.sh, and we have write permissions on that file.

I added the following command: `chmod +s /bin/bash`, this gives suid permission to /bin/bash so that i can run it as it's owner root, i run the perl script after that and we can see the suid bit got added to /bin/bash.

running `/bin/bash -p` will give us a root shell

![](/assets/img/tryhackme/lazyadmin/l15.png)

And just like that we have rooted **LazyAdmin**.

---

Thank you for taking the time to read my writeup, I hope you have learned something with this, if you have any questions or comments, please feel free to reach out to me. See you in the next hack :) .
