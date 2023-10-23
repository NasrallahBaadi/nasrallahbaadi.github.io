---
title: "TryHackMe - Brooklyn Nine Nine"
author: Nasrallah
description: ""
date: 2022-04-27 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, hydra, bruteforce, steganography]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello l33ts, I hope you are doing well. We are doing [Brooklyn Nine Nine](https://tryhackme.com/room/brooklynninenine) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```Terminal
Nmap scan report for 10.10.168.172
Host is up (0.098s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.11.31.131
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
|   256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
|_  256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

There are 3 open ports, FTP on port 21, SSH on port 22, and HTTP on port 80. Let's start with FTP.

## FTP

Let's login to the ftp server as anonymous. `ftp {target_IP}`.

![](/assets/img/tryhackme/brooklyn/1.png)

We found a text file, let's download it to our machine with the command `get {filename}`.

Now let's see what's on that file.

![](/assets/img/tryhackme/brooklyn/2.png)

It's a note from Amy to Jake saying that Jake's password is too weak.

## Web

Let's navigate to the webpage.

![](/assets/img/tryhackme/brooklyn/8.png)

We have a picture of Brooklyn nine-nine and some text, let's view the source code `ctrl+u`.

![](/assets/img/tryhackme/brooklyn/9.png)

We found an HTML comment talking about steganography

# **Foothold**

## Method 1

Let's use `hydra` to brute force Jake's password. `hydra -l jake -P /usr/share/wordlists/rockyou.txt 10.10.168.172 ssh -t 30`

![](/assets/img/tryhackme/brooklyn/3.png)

Great! We got Jake's password, let's login.

![](/assets/img/tryhackme/brooklyn/4.png)

And we're in.

## Method 2

First, let's download the picture to our machine using this command. `wget http://{target_ip}/brooklyn99.jpg}`.
Now let's use `steghide` to extract any hidden files on the picture.`steghide --extract -sf brooklyn99.jpg`.

![](/assets/img/tryhackme/brooklyn/10.png)

The file is protected with a password.

Let's use [stegseek](https://github.com/RickdeJager/stegseek) to get that password.

![](/assets/img/tryhackme/brooklyn/11.png)

Great! We got the password and extracted the data successfully. Let's see what we got.

![](/assets/img/tryhackme/brooklyn/12.png)

We got Holt's password. Let's use it to login.

![](/assets/img/tryhackme/brooklyn/13.png)

We're in. To privesc.

# **Privilege Escalation**

## Jake

Let's check our current privileges by running `sudo -l`.

![](/assets/img/tryhackme/brooklyn/5.png)

We can execute the command `less` as root, let's take a look at [GTFOBins](https://gtfobins.github.io/) for exploits.

![](/assets/img/tryhackme/brooklyn/6.png)


We found a way to get root access by executing some commands, so let's run them.

![](/assets/img/tryhackme/brooklyn/7.png)

Good! We are root now.

## Holt

Let's check our privileges with `sudo -l`.

![](/assets/img/tryhackme/brooklyn/14.png)

We can run nano as root, let's go to [GTFOBins](https://gtfobins.github.io/) and see if there is a way to exploit that.

![](/assets/img/tryhackme/brooklyn/15.png)

Good, we found a way.

 First, run the command `sudo nano`, now that you are in the nano editor, press `ctrl+R` + `ctrl+X`, after that, enter the command `reset; sh 1>&0 2>&0`, it should look like this.

![](/assets/img/tryhackme/brooklyn/16.png)

Now press Enter to execute the command.

>Note: you might need to press enter multiple time to get a clear shell.

![](/assets/img/tryhackme/brooklyn/17.png)

And just like that, we got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References

https://github.com/RickdeJager/stegseek

https://gtfobins.github.io/gtfobins/less/#sudo

https://gtfobins.github.io/gtfobins/nano/#sudo