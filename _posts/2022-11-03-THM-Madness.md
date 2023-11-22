---
title: "TryHackMe - Madness"
author: Nasrallah
description: ""
date: 2022-11-03 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy]
img_path: /assets/img/tryhackme/madness
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Madness](https://tryhackme.com/room/madness) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.147.83
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ac:f9:85:10:52:65:6e:17:f5:1c:34:e7:d8:64:67:b1 (RSA)
|   256 dd:8e:5a:ec:b1:95:cd:dc:4d:01:b3:fe:5f:4e:12:c1 (ECDSA)
|_  256 e9:ed:e3:eb:58:77:3b:00:5e:3a:f5:24:d8:58:34:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We got 2 open ports, 22 running OpenSSH and 80 running Apache web server.

### Web

Let's navigate to the web page.

![](1.png)

It's the default page for Apache, but we notice an image there. Let's check the source code.

![](2.png)

We found the image, let's download it and inspect it.

![](3.png)

We see the image has .jpg extension but the exif data says it's a png. Let's try opening the image.

![](4.png)

It's says `image magick`. Let's check the magic number of the image with `xxd thm.jpg | head`.

![](5.png)

We found the magic number of `png`, we need change it to jpg magic number. [Magic number list](https://en.wikipedia.org/wiki/List_of_file_signatures)

![](6.png)

We need to change the first bytes to `FF D8 FF E0 00 10 4A 46 49 46 00 01`, to do that we can use `hexeditor`.

![](7.png)

After saving the change, let's check the file again.

![](8.png)

Great! Now let's open the image.

![](9.png)

We found a hidden directory. Let's go there.

![](10.png)

It seems we need to enter a secret.

Let's check the source code.

![](11.png)

The secret is a number between 0-11.

The secret can be entered by adding the parameter `?secret=` at the end of the url

![](12.png)

Let's start burp suite, intercept the request and send it to intruder.

![](13.png)

Now we set up the payload for numbers and the range of 1 to 99.

![](14.png)

Let's start the attack.

![](15.png)

After a while, we see a request with a different length.

Let's check it on the browser.

![](16.png)

We got a password.

## **Foothold**

Let's try to extract any hidden files in the image with the command `steghide --extract -sf thm.jpg` and use the password we just got.

![](17.png)

We got a username. It's encoded with rot13, decode it to get the right username.

Now we have a username but no password, the answer is in the rooms image.

![](18.png)

Download it and extract hidden file in it.

![](19.png)

We got the password, let's ssh into the machine.

![](20.png)

## **Privilege Escalation**

I uploaded a copy of linpeas, run it and found the following.

![](21.png)

There is a unusual binary with suid bit, i googled it and found the following [exploit](https://www.exploit-db.com/exploits/41154).

![](22.png)

Let's upload the exploit to the target an run it.

![](23.png)

Great! We got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

https://en.wikipedia.org/wiki/List_of_file_signatures