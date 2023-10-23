---
title: "TryHackMe - Jack-of-All-Trades"
author: Nasrallah
description: ""
date: 2022-11-07 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, steganography, encoding]
img_path: /assets/img/tryhackme/jack
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Jack-of-All-Trades](https://tryhackme.com/room/jackofalltrades) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.145.236                                                                                                                           
Host is up (0.096s latency).                                                                                                                                 
Not shown: 997 closed tcp ports (reset)                              
PORT     STATE    SERVICE VERSION                                                                                                                            
22/tcp   open     http    Apache httpd 2.4.10 ((Debian))                   
|_http-server-header: Apache/2.4.10 (Debian)                                                                                                                 
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)             
80/tcp   open     ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)                                                                                              
| ssh-hostkey:                                                                
|   1024 13:b7:f0:a1:14:e2:d3:25:40:ff:4b:94:60:c5:00:3d (DSA)                                                                                               
|   256 a3:fb:09:fb:50:80:71:8f:93:1f:8d:43:97:1e:dc:ab (ECDSA)        
|_  256 65:21:e7:4e:7c:5a:e7:bc:c6:ff:68:ca:f1:cb:75:e3 (ED25519)                                                                                            
6129/tcp filtered unknown                                                     
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel          
```

We have two open ports, 22 running Apache web server and 80 running OpenSSH, weird.

## Web

Let's navigate to the web page at port 22.

![](1.png)

>If you got `This address is restricted`, go to **about:config**, put **network.security.ports.banned.override** in the search bar, select **String** and press the **+** button, enter 22 and press enter.

After checking the page, we know there is a guy named jack who lefts random notes lying around.

Let's view the source code.

![](2.png)

We found two html comments, one reveals a page named `recovery.php` and the other is base64 encoded.

![](3.png)

After decoding the string, we get ourselves a password.

Let's go the **/recovery.php**.

![](4.png)

It's a login page, i tried usename `jack` with the password we just got but couldn't login.

Let's view the source code.

![](5.png)

Found another encoded string, lets' decode it.

![](6.png)

The creds are on the home page, and we got a link to a wikipedia about **Stegosauria**.

Stegosauria, maybe Steganography. Let's download the images from the home page and try extracting hidden files from them.

![](7.png)

We managed to extract a file from header.jpg using the password we got earlier and we got the credentials for the cms.

Now let's login.

![](8.png)


# **Foothold**

The page says we `GET` it a `cmd` and it will run it.

the `GET` hints for http get request, so let's add cmd parameter to the end of the url and give it a command.

![](9.png)

We managed to run the command.

Next I checked the home directory and found this.

![](10.png)

There is a password list there, let's print it out.

![](11.png)

We got a list of possible password of jack, let's copy that to a file and brute force ssh.

![](12.png)

We got the password. let's login.

![](13.png)

In jack home directory, we find an image named user.jpg, we download it using the command `scp -P 80 jack@10.10.145.236:/home/jack/user.jpg .`

![](14.png)

We got the flag.

# **Privilege Escalation**

If we run the command `id`, we see that jack is part of a group called **dev**. Let's search for files that belongs to this group with `find / -type f -group dev 2>/dev/null`.

```terminal
jack@jack-of-all-trades:~$ find / -type f -group dev 2>/dev/null 
/usr/bin/strings
/usr/bin/find
```

We found `strings` and `find`. I tried to use strings and print out /root/root.txt and it worked.

![](15.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
