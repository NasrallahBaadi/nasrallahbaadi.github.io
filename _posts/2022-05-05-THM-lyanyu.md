---
title: "TryHackMe - Lyan_yu"
author: Nasrallah
description: ""
date: 2022-05-05 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, steganography]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Lyan_yu](https://tryhackme.com/room/lianyu) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.247.111
Host is up (0.10s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
21/tcp  open  ftp     vsftpd 3.0.2
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey: 
|   1024 56:50:bd:11:ef:d4:ac:56:32:c3:ee:73:3e:de:87:f4 (DSA)
|   2048 39:6f:3a:9c:b6:2d:ad:0c:d8:6d:be:77:13:07:25:d6 (RSA)
|   256 a6:69:96:d7:6d:61:27:96:7e:bb:9f:83:60:1b:52:12 (ECDSA)
|_  256 3f:43:76:75:a8:5a:a6:cd:33:b0:66:42:04:91:fe:a0 (ED25519)
80/tcp  open  http    Apache httpd
|_http-title: Purgatory
|_http-server-header: Apache
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          33339/udp   status
|   100024  1          36579/udp6  status
|   100024  1          39031/tcp6  status
|_  100024  1          54934/tcp   status
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

We found 4 open ports, let's enumerate the webserver on port 80.

### Web

Navigating to the webpage we see the following.

![](/assets/img/tryhackme/lyanyu/1.png)

It's a story about ARROWVERSE, nothing really useful in this page, let's run a directory scan.

```terminal
# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://10.10.118.55/
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian
===============================================================
[+] Url:                     http://10.10.118.55/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
11:21:49 Starting gobuster in directory enumeration mode
===============================================================
/island               (Status: 301) [Size: 235] [--> http://10.10.118.55/island/]
===============================================================
```

We found **/island** directory, let's navigate to it.

![](/assets/img/tryhackme/lyanyu/2.png)

There is a code word but we can't see it, let's view the source code.

![](/assets/img/tryhackme/lyanyu/3.png)

Great! We got the code, let's save it and continue our enumeration.

Since we got nothing really useful, let's run another directory scan on **/island** page


```Terminal
# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://10.10.118.55/island/
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian
===============================================================
[+] Url:                     http://10.10.118.55/island/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
11:38:25 Starting gobuster in directory enumeration mode
===============================================================
/2100                 (Status: 301) [Size: 240] [--> http://10.10.118.55/island/2100/]
===============================================================
```

We found a directory, let's see what's there.

![](/assets/img/tryhackme/lyanyu/4.png)

We have a youtube video and a question. Let's again view the source code.

![](/assets/img/tryhackme/lyanyu/5.png)

We got a hint that there is a ticket we can get, and it ends with *.ticket*. We can run a gobuster scan and instruct it to add the extension .ticket at the end of every search.


```Terminal
# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://10.10.118.55/island/2100/ -x ticket
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian
===============================================================
[+] Url:                     http://10.10.118.55/island/2100/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              ticket
[+] Timeout:                 10s
===============================================================
2022/05/10 11:45:02 Starting gobuster in directory enumeration mode
===============================================================
/green_arrow.ticket   (Status: 200) [Size: 71]
===============================================================
```

We found our ticket, let's take a look at it.

![](/assets/img/tryhackme/lyanyu/6.png)

We got what looks like an encoded text, let's go to [CyberChef](https://gchq.github.io/CyberChef/) and decode it.

![](/assets/img/tryhackme/lyanyu/7.png)

We managed to decode it using base58, and it looks like a password.

### FTP

Using the code we found as a username and the password we decoded, let's login to the ftp server and see what's there.

![](/assets/img/tryhackme/lyanyu/8.png)

It looks like we are is vigilante's home directory, unfortunately, there is no *.ssh* directory, but there are some files in forme of images, let's download them to our machine using the command `get filename`

![](/assets/img/tryhackme/lyanyu/9.png)

Now using the command `steghide`, let's try to extract hidden file in the image **aa.jpg**

![](/assets/img/tryhackme/lyanyu/10.png)

Using *password* as a password, we managed to extract two files, one of the files has a password, but we need a username.

Going back to the ftp server, we see that we can navigate freely on the machine, and if we go to **/home** folder, we can see the users there.

![](/assets/img/tryhackme/lyanyu/11.png)

Great! We got our username.


## **Foothold**

Now, let's use the credentials we managed to collect to login with ssh.

![](/assets/img/tryhackme/lyanyu/12.png)

Great! Let's move to privilege escalation.


## **Privilege Escalation**

First, let's check our current privileges on the machine by running `sudo -l`

![](/assets/img/tryhackme/lyanyu/13.png)

We can run the command `pkexec` as root. Let's go to [GTFOBins](https://gtfobins.github.io/gtfobins/pkexec/) to see what we can do.

![](/assets/img/tryhackme/lyanyu/15.png)

We see that we ca run `sudo pkexec /bin/sh` to escalate to root. Let's do it.

![](/assets/img/tryhackme/lyanyu/14.png)

Great! We have successfully rooted this machine.

---


Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

https://gchq.github.io/CyberChef/

https://gtfobins.github.io/gtfobins/pkexec/