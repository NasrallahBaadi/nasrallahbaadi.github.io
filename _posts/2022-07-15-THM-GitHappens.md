---
title: "TryHackMe - Git Happens"
author: Nasrallah
description: ""
date: 2022-07-15 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, web, git]
img_path: /assets/img/tryhackme/githappens/

---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Git Happens](https://tryhackme.com/room/githappens) from [TryHackMe](https://tryhackme.com). The machine is running a webserver on port 80 with a exposed git directory. We pull that directory using GitTools, check the history of commits and find a password on one of the commits.

## Enumeration

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.207.110
Host is up (0.091s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0 (Ubuntu)
| http-git: 
|   10.10.207.110:80/.git/
|     Git repository found!
|_    Repository description: Unnamed repository; edit this file 'description' to name the...
|_http-title: Super Awesome Site!
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only port 80 is open.

### Web

Let's navigate to the webpage.

![](1.png)

It's a login page but can't login.

From the nmap scan, we found out that there is a `.git` directory, and we can also see it if we run a directory scan.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.240.237/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/08/03 08:51:34 Starting gobuster in directory enumeration mode
===============================================================
/.git/HEAD            (Status: 200) [Size: 23]
/css                  (Status: 301) [Size: 194] [--> http://10.10.240.237/css/]
/index.html           (Status: 200) [Size: 6890]                               
                                                                               
===============================================================
```

![](2.png)

### Git

We can use a tool called [GitTools](https://github.com/internetwache/GitTools) to pull that directory to our machine.

Clone the repo with the following command.

```terminal
git clone https://github.com/internetwache/GitTools
```

Now we can pull the `.git` directory with dumper from the GitTools.

```terminal
./gitdumper.sh http://10.10.240.237/.git/ {destination-directory}
```

![](3.png)

Now go to where the `.git` directory is located and list the history of the commits with this command `git log --oneline`.

![](4.png)

There is a commit with the description `"Made the login page, boss!"` and it's ID is `395e087`.

To view the commit, we run the command `git show 395e087`. If we scroll down we found the following.

![](5.png)

Great! Found the password.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
