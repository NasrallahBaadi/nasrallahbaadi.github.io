---
title: "HackTheBox - Poison"
author: Nasrallah
description: ""
date: 2023-04-07 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, freebsd, easy, lfi, encoding, vnc, tunneling]
img_path: /assets/img/hackthebox/machines/poison
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Poison](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.84
Host is up (0.28s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e33b7d3c8f4b8cf9cd7fd23ace2dffbb (RSA)
|   256 4ce8c602bdfc83ffc98001547d228172 (ECDSA)
|_  256 0b8fd57185901385618beb34135f943b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```

We found two open ports, OpenSSH on port 22 and Apache http web server on port 80.

### Web

Let's navigate to the web page.

![](1.png)

Seems we can test local php scripts, and we're given some examples.

The `listfiles.php` sounds interesting so let's run it.

![](2.png)

It did list files and we see the file `pwdbackup.txt`.

### LFI

Let's see if the site is vulnerable to local file inclusion.

![](3.png)

We managed to read `/etc/passwd` and found username `charix`.

Now let's read the `pwdbackup.txt` file.

![](4.png)

The file is located in the web root directory so we didn't have to jump backwards.

We got a base64 encoded string but it's encoded 13 times.

![](5.png)

Using CyberChef we manage to decode the string and get the password.

## **Foothold**

With the password we can ssh to the box as user `charix`

```terminal
$ ssh charix@10.10.10.84                             
Password for charix@Poison:
Last login: Mon Mar 19 16:38:00 2018 from 10.10.14.4
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

[...]

This will also automatically install the packages that are dependencies
for the package you install (ie, the packages it needs in order to work.)
csh: The terminal database could not be opened.
csh: using dumb terminal settings.
charix@Poison:~ % id
uid=1001(charix) gid=1001(charix) groups=1001(charix)
charix@Poison:~ %
```


## **Privilege Escalation**

On charix home directory we a zip file, let's download it and unzip it.

![](6.png)

We got a file called `secret` doesn't seem useful.

Checking for listening ports we find two additional open ports.

```terminal
charix@Poison:~ % netstat -an -p tcp
Active Internet connections (including servers)
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4       0     44 10.10.10.84.22         10.10.17.90.57450      ESTABLISHED
tcp4       0      0 127.0.0.1.25           *.*                    LISTEN
tcp4       0      0 *.80                   *.*                    LISTEN
tcp6       0      0 *.80                   *.*                    LISTEN
tcp4       0      0 *.22                   *.*                    LISTEN
tcp6       0      0 *.22                   *.*                    LISTEN
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN

```

The ports 5801 and 5901 are VNC ports.

We run linpeas and see there is a VNC process running.

![](7.png)

The process is running as root connecting to port 5901 and specifying a password file located at `/root/.vnc/passwd`.

Maybe the secret file we got earlier is a password file for VNC.

Let's forward port 5901 using ssh.

```bash
ssh charix@10.10.10.84 -L 5901:127.0.0.1:5901
```

Now let's try to connect to port 5901 using `vncviewer` and specifying the `secret` file.

```bash
vncviewer 127.0.0.1:5901 -passwd secret
```

![](8.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).