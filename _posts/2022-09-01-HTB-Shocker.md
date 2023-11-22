---
title: "HackTheBox - Shoker"
author: Nasrallah
description: ""
date: 2022-09-01 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, cve, rce, shellshock, sudo]
img_path: /assets/img/hackthebox/machines/shocker
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Shoker](https://app.hackthebox.com/machines/Shoker) from [HackTheBox](https://www.hackthebox.com). In this machine, we us the shellshock exploit to gain foothold, and a sudo misconfiguration gives us root access.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-30 13:22 EDT
Nmap scan report for 10.10.10.56
Host is up (0.24s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports, port 80 running Apache web server and 2222 running SSH on a non-standard port.

### Web

Navigate to the web page.

![](1.png)

Nothing useful in this page, even it's source code. Let's run a directory scan.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/08/30 13:28:33 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 290]
/.htaccess            (Status: 403) [Size: 295]
/.htpasswd            (Status: 403) [Size: 295]
/cgi-bin/             (Status: 403) [Size: 294]
/index.html           (Status: 200) [Size: 137]
/server-status        (Status: 403) [Size: 299]
===============================================================

```

The scan found **/cgi-bin**. Let's run another scan in this directory but this time we add the **sh** extension.

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.56/cgi-bin/ -x sh | tee scans/gobuster2                                    130 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              sh
[+] Timeout:                 10s
===============================================================
2022/08/30 14:48:23 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 298]
/.hta.sh              (Status: 403) [Size: 301]
/.htaccess.sh         (Status: 403) [Size: 306]
/.htpasswd            (Status: 403) [Size: 303]
/.htaccess            (Status: 403) [Size: 303]
/.htpasswd.sh         (Status: 403) [Size: 306]
/user.sh              (Status: 200) [Size: 118]
                                               
===============================================================
```

We found **user.sh** file.

## **Foothold**

From the machine's name, we can guess the the exploit we're going to use is `shellshock`(Apache mod_cgi). Let's fire up metasploit and use `exploit/multi/http/apache_mod_cgi_bash_env_exec` module.

![](2.png)

After setting up the required options, we run the exploit to get a shell.

![](3.png)

## **Privilege Escalation**

Let's check our privileges with `sudo -l`.

![](4.png)

We can run perl as root. let's go to [GTFOBins](https://gtfobins.github.io/gtfobins/perl/#sudo).

![](5.png)

Running the following command gives us a root shell.

```bash
sudo perl -e 'exec "/bin/sh";'
```

![](6.png)

Got root! Congrats

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).