---
title: "HackTheBox - Oopsie"
author: Nasrallah
description: ""
date: 2022-07-09 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, idor, suid]
img_path: /assets/img/hackthebox/machines/oopsie/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Oopsie](https://app.hackthebox.com/starting-point?tier=2) from [HackTheBox](https://www.hackthebox.com). The target is running a webserver on port 80, we find a login page that permits us to login as a guest. Once we're in we exploit an IDOR vulnerability to get information disclosure, we modify our cookies with the information we got and upload a reverse shell after that and get access into the target. Once inside we enumerate the web server's files to find credentials for a user in the system, that user is part of a group that can run a binary with suid bit, the script is not well written and permits us to elevate to root easily.

## Enumeration

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.187.186 (10.129.187.186)
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
|   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
|_  256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Welcome
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have 2 open ports, port 22 running ssh and 80 running Apache web server.

### Web

Let's navigate to the web page.

![](1.png)

Nothing interesting.

### Gobuster

Let's run a directory scan using gobuster: `gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.10/`.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.187.186/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/css                  (Status: 301) [Size: 314] [--> http://10.129.187.186/css/]
/fonts                (Status: 301) [Size: 316] [--> http://10.129.187.186/fonts/]
/images               (Status: 301) [Size: 317] [--> http://10.129.187.186/images/]
/index.php            (Status: 200) [Size: 10932]                                  
/js                   (Status: 301) [Size: 313] [--> http://10.129.187.186/js/]    
/server-status        (Status: 403) [Size: 279]                                    
/themes               (Status: 301) [Size: 317] [--> http://10.129.187.186/themes/]
/uploads              (Status: 301) [Size: 318] [--> http://10.129.187.186/uploads/]
                                                                                    
===============================================================
```

Also nothing useful for us besides the **/uploads** page.

Let's look at the source code of the page.

![](2.png)

There is a login page at **/cdn-cgi/login**, let's navigate to it.

![](3.png)

Tried some default credentials as well as sql injection but not luck, let's login as a guest.

![](4.png)

Nice. There is an upload section, but unfortunately we're not allowed to upload.

![](5.png)

The Account section on the other hand has some interesting things.

![](6.png)

In this page, we can see our name, email and access ID, and we also notice in the url a parameter named **id** with the value of **2**, if we change the value to **1** we get the following.

![](7.png)

WOW! We got an information disclosure vulnerability. We can see the admin's access ID and email. This vulnerability is known as `IDOR` or **I**nsecure **D**irect **O**bject **R**eferences, and it occurs when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability attackers can bypass authorization and access resources in the system directly, for example database records or files.

If we check our cookies using a firefox extension named `Cookie-Editor` or just the developer tool in firefox(F12 -> Storage) we see the following data.

![](8.png)

Our current role is **guest**, and user is **2233**, which is the Guest's access ID, let's change the role to **admin** and the user to **34322** which is admin's access ID.

![](9.png)

Save the changes and reload the page.

Now we are able to upload anything.

![](10.png)


## Foothold

Let's upload a [Pentest Monkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)'s reverse shell.
> Change the ip in the code to your tun0 ip.

![](11.png)

Press upload.

![](12.png)

Got a confirmation message that our file has been uploaded.

The file now must be in the **/uploads** directory we found earlier with our gobuster scan. Let's setup a listener `nc -lvnp 1234`, and let's navigate to our file in **/uploads/shell.php**.

We should get a shell after that.

![](13.png)

Great! We got in.

## Privilege Escalation

As a good practice, I stabilized my shell using the python pty trick:

```terminal
python3 -c 'import pty;pty.spawn("/bin/bash")'

export TERM=xterm

"ctrl + z"

stty raw -echo;fg
```

![](14.png)


Now, doing some basic enumeration, we find a file containing credentials in the web server files.

![](15.png)

Let's use those credentials to login via ssh.

![](16.png)

By running the command `id`, we notice that the user **robert** in a group named `bugtracker`.

Let's search for files that belongs to that groups using the following command:`find / -group bugtracker 2>/dev/null`.

![](17.png)

We find a binary with the same group name. Let's execute it and see what it does.

![](18.png)

The binary asks us for a Bug id, and then prints it out. Let's give it some random characters.

![](19.png)

We got an error saying the file not found. This tells us a lot:

 - The script use `cat` to print out the file we provide.
 - It search for the file in /root/reports/ directory.

What we can do is instead of providing a file, we give it another command to execute after the `cat` command.

To get a shell for example, we supply the following command : `;/bin/bash`, and the script would run the following: `cat ;/bin/bash`

>The ";" permits us to run another command in the same line.

![](20.png)

And boom, we got a root shell.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
