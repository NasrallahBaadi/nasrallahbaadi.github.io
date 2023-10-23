---
title: "TryHackMe - Startup"
author: Nasrallah
description: ""
date: 2022-04-23 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, ftp, wireshark, reverse-shell]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello l33ts, I hope you are doing well. We are doing [Startup](https://tryhackme.com/room/startup) from [TryHackMe](https://tryhackme.com). We start off with nmap scan that reveals 3 open port, we get an FTP server with anonymous login allowed and is linked to the http webserver. We upload a php reverse shell to the ftp server, run it via the webserver and get access to the machine. We find a strange directory in the file system that contains a pcap file, we inspect the file and find a password of a user. Inside that user's home directory is a scripts that runs regularly, we leverage that to get root.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```Terminal
Nmap scan report for 10.10.61.7
Host is up (0.090s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.11.31.131
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Maintenance
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

There are 3 open ports. We have FTP that runs on port 21 and allows anonymous login, SSH on port 22 and HTTP on port 80.

## FTP

Since FTP allows anonymous login, let's start off with that.

To connect to ftp, simply run the command `ftp {target_IP}`, and provide `anonymous` as a username, and we can leave the password blank.

![](/assets/img/tryhackme/startup/1.png)

We logged in successfully, and we find a couple of files there, let's download them to our machine with the command `get {filename}`.

![](/assets/img/tryhackme/startup/2.png)

Let's inspect these files.

![](/assets/img/tryhackme/startup/3.png)

The file **.test.log** has nothing interesting, in the other hand, the file **important.txt** gives us a possible username. The picture is just an AmongUs meme as mentioned in the text file.

## WEB

Moving to the webserver, let's navigate to the webpage.

![](/assets/img/tryhackme/startup/4.png)

It's a message from the dev team, nothing really useful. Let's now do some directory busting.

## Feroxbuster

For directory busting, I'll be using `feroxbuster` with the **common.txt** list.

![](/assets/img/tryhackme/startup/5.png)

We found **files** directory, let's navigate to it.

![](/assets/img/tryhackme/startup/6.png)

Wow, These are the same files we found on the ftp server.


# **Foothold**

Now, we our ability to login to ftp with no password, and access the ftp server via the web, let's upload a php reverse shell to ftp, navigate to it on the webpage and get a shell on the machine. 

I'll be using [penteste monkey reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php), download it and change the ip address to your machine's ip.

Now, put the reverse shell code in your current directory, login to ftp, and use the command `put {filename}` to upload the file.

![](/assets/img/tryhackme/startup/7.png)

We managed to upload the file to ftp, now let's navigate to it in the webpage.

![](/assets/img/tryhackme/startup/8.png)

We see that the file is there, now before clicking the file, setup a listener on your attacking machine, and then go click the file

![](/assets/img/tryhackme/startup/9.png)

We have successfully recieved a reverse shell on the machine and I used the python pty trick to stabalize my shell. To privesc now.


# **Privilege Escalation**

## Horizontal

Let's inspect this machine and see what we can find.

![](/assets/img/tryhackme/startup/10.png)

Here we can see an unusual directory, let's see what's there.

![](/assets/img/tryhackme/startup/11.png)

It's a pcap file, let's download it and inspect it. To do so, i setup a python http server with the command `python3 -m http.server 8000`.

![](/assets/img/tryhackme/startup/12.png)

Now navigate to it on your browser `http:{target_IP}:8000/` and you should be able to see the file.

![](/assets/img/tryhackme/startup/13.png)

Now download the file and open it with `wireshark`.

![](/assets/img/tryhackme/startup/14.png)

Looking through the packets, we see a GET request to /files/ftp/shell.php, right after that packet, a new connection opened up(packet 35), and that was similar to what we've done to get a reverse shell, let's inspect the packet number 35 with rightclick -> Follow -> TCP Stream

![](/assets/img/tryhackme/startup/15.png)

We are right, it is a reverse shell, looking throught the data, we see a password for lennie, let's see if it works.

![](/assets/img/tryhackme/startup/16.png)

Great! We switch to lennie now.

## Vertical

Let's see what's on lennie's home directory.

![](/assets/img/tryhackme/startup/17.png)

We found 2 directories, Documents and scripts. We inspected Documents and found nothing interesting, now let's see what' on scripts.

![](/assets/img/tryhackme/startup/18.png)

Theres is a bash script named **planner.sh** and a text file named **startup_list.txt**, we notice that the text file got edited very recently, and it's the planner.sh writing it. With that, there must be a cronjob running the **planner.sh** regularly. Let's see what the file does.

![](/assets/img/tryhackme/startup/19.png)

The script writes the content of the variable **LIST** to **startup_list.txt** and then runs another script **/etc/print.sh** which by itself prints **Done!** to the screen.

The **print.sh** script is owned by our current user *lennie*, so we can easly modify it.

To escalate to root, i added a command to print.sh that gives /bin/bash suid bit so that it can be run as it's owner which is root.

![](/assets/img/tryhackme/startup/20.png)

So i added the command, waited a bit and we can see it worked.

Now run `/bin/bash -p` for root.

![](/assets/img/tryhackme/startup/21.png)

Great! We are root now.

---

Thank you for taking the time to read my writeup, I hope you have learned something with this, if you have any questions or comments, please feel free to reach out to me. See you in the next hack :) .

---

# References

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php