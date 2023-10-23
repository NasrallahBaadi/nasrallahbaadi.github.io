---
title: "VulnHub - FritiLeaks"
author: Nasrallah
description: ""
date: 2022-12-29 00:00:00 +0000
categories: [VulnHub]
tags: [vulnhub, linux, easy, python, reverse-shell, cronjob]
img_path: /assets/img/vulnhub/fristileaks
---


---


# **Description**

Hello hackers, I hope you are doing well. We are doing [FristiLeaks](https://www.vulnhub.com/entry/fristileaks-13,133/) from [VulnHub](https://www.vulnhub.com/).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 192.168.56.10
Host is up (0.00035s latency).
Not shown: 65394 filtered tcp ports (no-response), 140 filtered tcp ports (host-prohibited)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.15 ((CentOS) DAV/2 PHP/5.3.3)
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 3 disallowed entries 
|_/cola /sisi /beer
|_http-server-header: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
MAC Address: 08:00:27:A5:A6:76 (Oracle VirtualBox virtual NIC)
```

There is only one open port which is port 80 running Apache 2.2.15.

## Web

Let's navigate to the web page.

![](1.png)

We can see an image that says "Keep calm and drink Fristi". Not sure what that means.


### Gobuster

Let's run a directory scan.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.10/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/12/14 19:02:17 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 236] [--> http://192.168.56.10/images/]
/beer                 (Status: 301) [Size: 234] [--> http://192.168.56.10/beer/]  
/cola                 (Status: 301) [Size: 234] [--> http://192.168.56.10/cola/]  
===============================================================
```

We found two interesting directories **/beer** and **/cola**, let's check them out.

![](2.png)

Both display an image that says "This is not the url you were looking for".

Thinking a little bit about it, we can drink beer and cola, and the motto from the first page says `Drink Fristi`, so maybe there is a page called `/fristi`.

![](3.png)

Great! We were right, the **/fristi** page has a login form.

If we check the source code of the page we find some interesting stuff.

![](4.png)

We found a possible user name as well as html comment with a base64 encoded data.

![](5.png)

Let's copy the base64 string and decode it using [CyberChef](https://gchq.github.io/CyberChef/).

![](6.png)

After decoding the base64 string we can see that it's a PNG file, so let's save it and see what's on the image.

![](7.png)

We found what looks like a password.

# **Foothold**

With the username and the password we now have, let's login into fristi page.

![](8.png)

Nice, we found an upload feature, let's try uploading a reverse shell, I'll be using [Pentest Monkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)'s php reverse shell.

![](9.png)

It seems that we're only allowed to upload png,jpg and gif file only. No problem, we'll change the name of our shell from shell.php to shell.php.png

![](10.png)

Let's now upload it.

![](11.png)

Great! The file now is located at **/uploads**, so let's setup a listener with `nc -lvnp 1234` and request the file.

![](12.png)

Great! We a shell, and stabilized with python pty.

# **Privilege Escalation**

The current user we have now is `apache` so we obviously we need to escalate our privileges. Checking files on the web directory, we find the following note.

![](13.png)

There is something important in `eezeepz`'s home directory, lucky for us we can see it's contents os let's check it out.

![](14.png)

We found another note from `admin` stating that we can run commands from `/home/admin` and `/usr/bin` with his account privileges, we just need to put the commands in a file called `runthis` in `/tmp`.

One of the command admin has in his home directory is `chmod`, so i'm gonna use that to make his home directory readable.

![](15.png)

Great, it worked! Let's see what we can find there.

![](16.png)

We found two file containing an encrypted passwords, and the python script used to encrypt them.

```python
#Enhanced with thanks to Dinesh Singh Sikawar @LinkedIn
import base64,codecs,sys

def encodeString(str):
    base64string= base64.b64encode(str)
    return codecs.encode(base64string[::-1], 'rot13')

cryptoResult=encodeString(sys.argv[1])
print cryptoResult
```

This python script takes a string, encode it with base64, reverse it's characters then encode with `rot13`.

We can reverse this process using [CyberChef](https://gchq.github.io/CyberChef/) as follows.

![](17.png)

We can also use python to reverse this process just as follows.

```python
import base64,codecs,sys

def decodeString(str):
    password = codecs.decode(str[::-1],'rot13')
    return base64.b64decode(password)

cryptoResult=decodeString(sys.argv[1])
print cryptoResult

```

![](18.png)

Great! Now that we have clear text password, let's switch to user `fristigod` and check what privileges we have.

![](19.png)

We can run `/var/fristigod/.secret_admin_stuff/doCom` as `fristi`, let's see what the program does.

```bash
bash-4.1$ sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom       
Usage: ./program_name terminal_command ...
```

We need to specify a terminal command as an argument, let's try `whoami`.

```bash
bash-4.1$ sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom whoami
root
```

Wow, this program allows us to run commands as root.

Let's make a copy of `/bin/bash` in `/tmp` directory and give it suid permission so that we can easily get a root shell.

![](20.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
