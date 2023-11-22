---
title: "TryHackMe - Thompson"
author: Nasrallah
description: ""
date: 2022-03-25 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, web, metasploit, rce, cronjob, suid]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello l33ts, I hope you are doing well. Today we are going to look at [Thompson](https://tryhackme.com/room/bsidesgtthompson) from [TryHackMe](https://tryhackme.com). It's an easy machine where we find a mis-configured Apache Tomcat server that leads to an information disclosure where where get a username and password for Tomcat manager. We use an exploit that gives us a remote shell on the machine, with some enumeration we find a cronjob that runs a world writable script as root, we exploit that and get root access.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.109.215
Host is up (0.092s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 fc:05:24:81:98:7e:b8:db:05:92:a6:e7:8e:b0:21:11 (RSA)
|   256 60:c8:40:ab:b0:09:84:3d:46:64:61:13:fa:bc:1f:be (ECDSA)
|_  256 b5:52:7e:9c:01:9b:98:0c:73:59:20:35:ee:23:f1:a5 (ED25519)
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http    Apache Tomcat 8.5.5
|_http-title: Apache Tomcat/8.5.5
|_http-favicon: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are 3 open ports, port 8080 is running apache tomcat, let's navigate to the webpage at `{target_IP}:8080`

### WebPage

![the web page](/assets/img/tryhackme/thompson/webpage.png)

We see the default page of Apache Tomcat.Let's run a directory scan to see if there is anything useful.

### Gobuster

```terminal
===============================================================
[+] Url:                     http://10.10.70.81:8080/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
 05:18:22 Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/favicon.ico          (Status: 200) [Size: 21630]             
/manager              (Status: 302) [Size: 0] [--> /manager/]
===============================================================
```

There is a **/manager** page, let's go there on `http://{target_IP}:8080/manager`.

![login_form](/assets/img/tryhackme/thompson/credsprompt.png)

We are being to enter a username and password, i tried some known credentials like admin:admin and admin:password but got nothing, if we hit `Cancel`, we see the following.

![information_disclosure](/assets/img/tryhackme/thompson/disclosure.png)

We get redirected to this unauthorized access error page, where we can find the username and password for the manager page. Now we can go and login.

![tomcat_manager](/assets/img/tryhackme/thompson/manager.png)

## **Foothold**

Now that we have access to Tomcat manager, i searched on google for ways to get code execution on tomcat, and i found a module on metasploit that can give us a shell on the machine, the module is called `exploit/multi/http/tomcat_mgr_upload`.

![metasploit_tomcat_rce](/assets/img/tryhackme/thompson/metasploit.png)

We need to set the username and password of the Tomcat manager along with the other necessary options, and run the exploit.

![meterpreter](/assets/img/tryhackme/thompson/meterpreter.png)

We have successfully gained a shell on our target.


## **Privilege Escalation**

Let's do some manual enumeration on the machine.

![jack_home](/assets/img/tryhackme/thompson/jackhome.png)

We found a user named **jack**, on his home directory, there are two interesting files, **id.sh** and **test.txt**.

The **id.sh** file has a command that runs the command `id` and put the output of that command into the file **test.txt**, and in the latter file, we see the output of the `id` command that was run by root. We can also notice that from all the other files, **test.txt** got modified very lately in comparison with other files, this means that there is a cronjob running on the machine, let's check **/etc/crontab** for cron jobs.

![cronjob](/assets/img/tryhackme/thompson/crontab.png)

We found a cronjob that is run by root, and what it does is it moves to /home/jack directory and runs the id.sh script. We saw on jack's home directory that the **id.sh** file is writable. With that, we can change the content of that file and put a command on it that would permit us to become root.

![suidbash](/assets/img/tryhackme/thompson/suidbash.png)

First, i dropped a shell, used python pty trick to get a nice shell, then i put the command in **id.sh**. The command i used takes a copy of /bin/bash and put it in /tmp directory, then it gives it suid permission so that we can run it as it's owner which is root. We can run the command `/tmp/bash -p` for root

![root_access](/assets/img/tryhackme/thompson/root.png)

And just like that, we have rooted the machine.

---

Thank you for taking the time to read my writeup, I hope you have learned something with this, if you have any questions or comments, please feel free to reach out to me. See you in the next hack :) .
