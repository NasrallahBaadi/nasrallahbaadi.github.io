---
title: "TryHackMe - Agent Sudo"
author: Nasrallah
description: ""
date: 2022-04-19 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, burpsuite, hydra, bruteforce, steganography, cracking, john]
#img_path: /assets/img/tryhackme
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello l33ts, I hope you are doing well. We are doing [Agent Sudo](https://tryhackme.com/room/agentsudoctf) from [TryHackMe](https://tryhackme.com). We start off by a nmap scan where we find 3 open port, ftp-ssh-http. We brute force the user-agent of the webserver to access a hidden page which gives us a hints for ftp. The ftp server contains some pictures that holds hidden files inside them, extracting those files gives us ssh credentials. To escalate our privileges, we find a vulnerable version of sudo on the machine that we leverage to become root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```Terminal
Nmap scan report for 10.10.129.47
Host is up (0.10s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

There are 3 open ports:

 - 21 open  ftp  vsftpd 3.0.3
 - 22 open  ssh  OpenSSH 7.6p1
 - 80 open  http Apache httpd 2.4.29

There is no anonymous login for ftp, we have no credentials for ssh so let's start off by enumerating the http webserver.

### Web

Let's navigate to the webpage. http://{target_IP}/

![wepage](/assets/img/tryhackme/agentsudo/1.png)

We have a note from someone called **Agent R**, telling us we need to use our codename as a user-agent to be able to access the site.

The User-Agent request header is a characteristic string that lets servers and network peers identify the application, operating system, vendor, and/or version of the requesting user agent.

So we need to change the user-agent header to a codename, but what is this codename. We see that the note is written by **Agent R**, and the letter **R** can be the first letter of his name, and there can be other agents like **Agent A** **Agent T** for example. So the first letter must be the codename.

### Burp

Let's fire up burp suite and try to brute force the user-agent header with different Letters. First let's intercept the request and send it to intruder.

![](/assets/img/tryhackme/agentsudo/2.png)

Select the user-agent value and press the Add button on the left.

Next go to payloads tab, select brute forcer as a payload type, set an A to Z list of characters as charachter set, and set 1 as a min and max lenght.

![](/assets/img/tryhackme/agentsudo/3.png)

Now start the attack.

![](/assets/img/tryhackme/agentsudo/4.png)

Now if we filter by length, we can see the correct user-agent.

Now intercept a request and replace the user-agent header with the one we found.

![](/assets/img/tryhackme/agentsudo/5.png)

We got redirected to a page. Therem we got a username, and another message from Agent R telling us that our password is weak!

Let's try brute forcing ftp and see if we can get a password.

### Hydra

Let's hydra to brute force ftp. `hydra -l {username} -P /usr/share/wordlists/rockyou.txt {target_IP} ftp`

![](/assets/img/tryhackme/agentsudo/6.png)

Great! We got a valid password.

### FTP

Let's now login to ftp using the credentials we have.

![](/assets/img/tryhackme/agentsudo/7.png)

We found 3 file, we can download them to our machine with `get {filename}`

Let's see what on the text file.

![](/assets/img/tryhackme/agentsudo/8.png)

It's a message from Agent C saying that there is a login password inside a picture. This indicates the use of steganography.

### Steganography

Let's start with **cutie.png** picture. For .png files, we can use `binwalk` to extract hidden files. `binwalk -e cutie.png`

![](/assets/img/tryhackme/agentsudo/9.png)

We managed to extract a zip file that contains another message **To_AgentR.txt**, but it has nothing in it. The zip file must be protected with a password, let's use `zip2john` to get a hash and try to crack it.

![](/assets/img/tryhackme/agentsudo/10.png)

We got a password, let's extract the zip file and provide the password this time.

![](/assets/img/tryhackme/agentsudo/11.png)

We are able to read the file now, and it's a message by Agent R giving us an base64 encoded password we can use with the other alien picture.

For the other picture, we can use `steghide` to extract files from the picture. `steghide --extract -sf cute-alien.jpg`

![](/assets/img/tryhackme/agentsudo/12.png)

We extracted a text file that contains a message from Agent C, giving us a password and username for ssh.


## **Foothold**

Let's use the credentials we have to login via ssh.

![](/assets/img/tryhackme/agentsudo/13.png)

Great! We are in the machine now.

Let's download the Alien picture and look for the incident. To do that, we can use `scp` to download the picture.

![](/assets/img/tryhackme/agentsudo/14.png)

And we can upload the picture to google images and get results.

![](/assets/img/tryhackme/agentsudo/15.png)


## **Privilege Escalation**

Let's check our current privileges on the machine by running `sudo -l`

![](/assets/img/tryhackme/agentsudo/16.png)

We can run execute **/bin/bash** as any user but not root.

Running the command `sudo -V` we get the Sudo version 1.8.21p2. We google that and get this [exploit](https://www.exploit-db.com/exploits/47502)

We can run `sudo -u#-1 /bin/bash` and become root.

![](/assets/img/tryhackme/agentsudo/17.png)

Great! We are root!

---

Thank you for taking the time to read my writeup, I hope you have learned something with this, if you have any questions or comments, please feel free to reach out to me. See you in the next hack :) .

---

## References

https://www.exploit-db.com/exploits/47502
