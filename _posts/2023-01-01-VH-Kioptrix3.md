---
title: "VulnHub - Kioptrix #3"
author: Nasrallah
description: ""
date: 2023-01-01 00:00:00 +0000
categories: [VulnHub]
tags: [vulnhub, linux, easy, sudo, cracking, phpmyadmin, rce]
img_path: /assets/img/vulnhub/kioptrix3
---


---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Kioptrix level 3](https://www.vulnhub.com/entry/kioptrix-level-12-3,24/) from [VulnHub](https://www.vulnhub.com/).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 192.168.56.11
Host is up (0.00011s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:e3:f6:dc:2e:22:5d:17:ac:46:02:39:ad:71:cb:49 (DSA)
|_  2048 9a:82:e6:96:e4:7e:d6:a6:d7:45:44:cb:19:aa:ec:dd (RSA)
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Ligoat Security - Got Goat? Security ...
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
MAC Address: 08:00:27:37:31:E6 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

We found two open port:

 - Port 22 running OpenSSH 4.7p1

 - Port 80 running Apache 2.2.8


## Web

Let's navigate to the web page.

![](1.png)

Nothing interesting in this page.

## Gobuster

Let's run a directory scan

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.11/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/12/17 20:39:30 Starting gobuster in directory enumeration mode
===============================================================
/modules              (Status: 301) [Size: 355] [--> http://192.168.56.11/modules/]
/gallery              (Status: 301) [Size: 355] [--> http://192.168.56.11/gallery/]
/data                 (Status: 403) [Size: 324]                                    
/core                 (Status: 301) [Size: 352] [--> http://192.168.56.11/core/]   
/style                (Status: 301) [Size: 353] [--> http://192.168.56.11/style/]  
/cache                (Status: 301) [Size: 353] [--> http://192.168.56.11/cache/]  
/phpmyadmin           (Status: 301) [Size: 358] [--> http://192.168.56.11/phpmyadmin/]
/server-status        (Status: 403) [Size: 333]                                       
===============================================================
```
 
We found different directories as well as `phpmyadmin`, but before checking each on of them, let's first check the login page.

![](2.png)

We see a login form powered by `LotusCMS`.

I tried to enter some default credentials as well as do a sql injection but no luck.


# **Foothold**

On google i searched for `lotuscms exploit` and managed to find a remote code execution exploit [here](https://github.com/Hood3dRob1n/LotusCMS-Exploit/blob/master/lotusRCE.sh).

Let's download the exploit and run it with the following command.

```bash
./lotusRCE.sh {Target_IP} /
```

![](3.png)

Great! We got a shell. After that we stabilize the shell using python pty.

![](4.png)

# **Privilege Escalation**

After the foothold, I checked the config file inside `gallery` directory and managed to find the password of the database.

![](8.png)

Now let's navigate to `/phpmyadmin` page.

![](5.png)

We enter the credentials we found and press `Go`.

![](6.png)

Great! Now let's go to `gallery` database.

![](10.png)

Now press the icon next to `dev_accounts`.

![](7.png)

We managed to find what looks like md5 hashes.

We can easily crack them using on [Crackstation.net](https://crackstation.net/).

![](9.png)

Great! We got the passwords, now let's switch to `loneferret` and check his current privileges.

![](11.png)

We can run `/usr/local/bin/ht` as root which is a text editor.

To escalate our privilege using ht, we need to run it as root, navigate to `/etc/sudoers` file and add `/bin/bash` to the commands we can run as root.

So let's open it with `sudo /usr/local/bin/ht`

![](12.png)

Press `F3` to open a file and write `/etc/sudoers`.

![](13.png)

After opening the file, we go down and add `/bin/bash`.

![](14.png)

We save the changes by pressing `F2`.

Now if we check out privileges again with `sudo -l`, we should see /bin/bash.

![](15.png)

Great! Now we run `sudo /bin/bash` to get a root shell.

![](16.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
