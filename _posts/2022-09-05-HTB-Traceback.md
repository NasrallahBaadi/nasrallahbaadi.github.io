---
title: "HackTheBox - Traceback"
author: Nasrallah
description: ""
date: 2022-09-05 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sudo]
img_path: /assets/img/hackthebox/machines/traceback
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Traceback](https://app.hackthebox.com/machines/Traceback) from [HackTheBox](https://www.hackthebox.com). The machine is running an Apache web server which has been hacked and the hacker put a backdoor allowing us to get a reverse shell as `webadmin` user. This user is able to run a tool called `luvit` which executes `Lua` as `sysadmin`. The user `sysadmin` has write permissions to update-motd.d scripts that get executed every time someone logs to the system, so we exploit that to escalate our privileges to root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.181
Host is up (7.5s latency).
Not shown: 795 closed tcp ports (reset), 203 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Help us
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open ports, port 22 running OpenSSH and port 80 running Apache web server.

### Web

Let's go to the webpage.

![](1.png)

The web server has been hacked and defaced. There is a note from the hacker saying that he left a backdoor. The hacker's name is `Xh4H`.

Viewing the source code we find the following comment. `Some of the best web shells that you might need ;)`. No idea what that means.

Let's run a directory scan.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.181
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/08/31 06:13:23 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 291]
/.htpasswd            (Status: 403) [Size: 296]
/.htaccess            (Status: 403) [Size: 296]
/index.html           (Status: 200) [Size: 1113]
/server-status        (Status: 403) [Size: 300] 
===============================================================
```

Nothing really interesting.

If we search for the hacker's name, we find that he has a [github account](https://github.com/Xh4H/), looking at his repositories we find the following [repository](https://github.com/Xh4H/Web-Shells).

![](2.png)

It's bunch of web-shells, scrolling down we find this.

![](3.png)

Aha! It's the same note we find in the webpage's source code.

The backdoor he left should be one of those php files in the repository. Let's see if any of those file are in the web-server.

![](4.png)

We found the backdoor. Looking at the source code of the backdoor we can find the username and password, so let's login.

![](5.png)

Here we see that we can execute commands, upload files and much much more. 


## **Foothold**

I decided to upload this [reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).

After that i setup a listener and requested the file.

![](6.png)

After getting a shell, i stabilized it using python pty; 


## **Privilege Escalation**

Let's check our privileges with `sudo -l`.

![](7.png)

There is a file called `luvit` that we can run as user `sysadmin`. There is a note.txt file in webadmin's home directory.

![](8.png)

So `luvit` must be the tool sysadmin left to practice lua. Let's check [GTFOBins](https://gtfobins.github.io/gtfobins/lua/#shell).

![](9.png)

We can run the command `os.execute("/bin/bash")` to get a shell.

Let's run the luvit command as sysadmin with `sudo -u sysadmin /home/sysadmin/luvit`, and then run `os.execute("/bin/bash")` after that.

![](10.png)

We got sysadmin.

I uploaded linpeas.sh and run it, and it found the following.

![](11.png)

The directory **/etc/update-motd.d** is writeable by the sysadmin group.

The scripts inside this directory are executed by root each time a user logs into the machine.

First, let's put our public key in the authorized_keys file inside .ssh directory so that we can log in with ssh.

![](12.png)

Next i added the following command to `10-help-text` script.

```bash
cp /home/sysadmin/.ssh/authorized_keys /root/.ssh/
```

>This command copies our public key and put it in root's ssh directory.

```terminal
sysadmin@traceback:/etc/update-motd.d$ echo "cp /home/sysadmin/.ssh/authorized_keys /root/.ssh/" >> 10-help-text
```

Now let's login to sysadmin via ssh and then root.

![](13.png)

Great! We got a root shell.


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).