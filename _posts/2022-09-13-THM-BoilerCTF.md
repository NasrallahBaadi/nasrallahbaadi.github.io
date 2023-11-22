---
title: "TryHackMe - Boiler CTF"
author: Nasrallah
description: ""
date: 2022-09-13 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, cipher, crack, suid, gobuster]
img_path: /assets/img/tryhackme/boilerctf
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Boiler CTF](https://tryhackme.com/room/boilerctf2) from [TryHackMe](https://tryhackme.com). The machine is running a webserver on a non-standard port, we keep running directory scans until we find ssh credentials for a user. After we login to the machine we find a shell script that has another user's credentials. A binary with SUID bit is used after that to get root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.157.140
Host is up (0.088s latency).
Not shown: 995 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
21/tcp    open     ftp     vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.11.31.131
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp    open     http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
993/tcp   filtered imaps
2106/tcp  filtered ekshell
10000/tcp open     http    MiniServ 1.930 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: MiniServ/1.930
Service Info: OS: Unix
```

We have 3 open ports, 21(FTP), 80(Apache) and 10000(Webmin).

### FTP

We see that FTP has anonymous login enabled, so let's log in.

![](1.png)

We find a hidden text file, downloaded it with `get .info.txt` and found it has some encoded text.

Let's go to [CyberChef](https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,13)&input=V2hmZyBqbmFncnEgZ2IgZnJyIHZzIGxiaCBzdmFxIHZnLiBZYnkuIEVyenJ6b3JlOiBSYWh6cmVuZ3ZiYSB2ZiBndXIgeHJsIQ) and decode the text.

![](2.png)

The text was encoded with `rot13` and it has nothing useful for us.

## Web

Let's navigate to the webpage.

![](3.png)

Found the default page for Apache.

### Gobuster

Let's run a directory scan.

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.157.140/                                                                      130 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.157.140/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/09/04 04:48:26 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 292]
/.htpasswd            (Status: 403) [Size: 297]
/.htaccess            (Status: 403) [Size: 297]
/index.html           (Status: 200) [Size: 11321]
/joomla               (Status: 301) [Size: 315] [--> http://10.10.157.140/joomla/]
/manual               (Status: 301) [Size: 315] [--> http://10.10.157.140/manual/]
/robots.txt           (Status: 200) [Size: 257]                                   
/server-status        (Status: 403) [Size: 301]                                   
                                                                                  
===============================================================
```

We found **Joomla** CMS, a manual directory and **robots.txt**.

#### robots.txt

Let's check the robots file.

![](4.png)

Found some directories that doesn't exist and strings of numbers that looks like ASCII to me, let's decode it.

![](5.png)

It gave us another encoded text that looks like base64.

![](6.png)

That decoded to what looks like a md5 hash, let's crack it using [crackstation](https://crackstation.net/).

![](7.png)

Another rabbit hole.

#### Joomla

Let's go to **/joomla** directory.

![](8.png)

Nothing interesting to see, let's run a directory scan.

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.157.140/joomla                                                                      
===============================================================                                                                                              
Gobuster v3.1.0                                                                                                                                              
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                                                                                                
===============================================================
[+] Url:                     http://10.10.157.140/joomla
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/09/04 05:12:43 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 299]
/.htaccess            (Status: 403) [Size: 304]
/.htpasswd            (Status: 403) [Size: 304]
/_archive             (Status: 301) [Size: 324] [--> http://10.10.157.140/joomla/_archive/]
/_database            (Status: 301) [Size: 325] [--> http://10.10.157.140/joomla/_database/]
/_files               (Status: 301) [Size: 322] [--> http://10.10.157.140/joomla/_files/]   
/_test                (Status: 301) [Size: 321] [--> http://10.10.157.140/joomla/_test/]    
/~www                 (Status: 301) [Size: 320] [--> http://10.10.157.140/joomla/~www/]     
/administrator        (Status: 301) [Size: 329] [--> http://10.10.157.140/joomla/administrator/]
/bin                  (Status: 301) [Size: 319] [--> http://10.10.157.140/joomla/bin/]          
/build                (Status: 301) [Size: 321] [--> http://10.10.157.140/joomla/build/]        
/cache                (Status: 301) [Size: 321] [--> http://10.10.157.140/joomla/cache/]        
/components           (Status: 301) [Size: 326] [--> http://10.10.157.140/joomla/components/]   
/images               (Status: 301) [Size: 322] [--> http://10.10.157.140/joomla/images/]       
/includes             (Status: 301) [Size: 324] [--> http://10.10.157.140/joomla/includes/]     
/index.php            (Status: 200) [Size: 12484]                                                
/installation         (Status: 301) [Size: 328] [--> http://10.10.157.140/joomla/installation/] 
/language             (Status: 301) [Size: 324] [--> http://10.10.157.140/joomla/language/]     
/layouts              (Status: 301) [Size: 323] [--> http://10.10.157.140/joomla/layouts/]      
/libraries            (Status: 301) [Size: 325] [--> http://10.10.157.140/joomla/libraries/]    
/media                (Status: 301) [Size: 321] [--> http://10.10.157.140/joomla/media/]        
/modules              (Status: 301) [Size: 323] [--> http://10.10.157.140/joomla/modules/]      
/plugins              (Status: 301) [Size: 323] [--> http://10.10.157.140/joomla/plugins/]      
/templates            (Status: 301) [Size: 325] [--> http://10.10.157.140/joomla/templates/]    
/tests                (Status: 301) [Size: 321] [--> http://10.10.157.140/joomla/tests/]        
/tmp                  (Status: 301) [Size: 319] [--> http://10.10.157.140/joomla/tmp/]          
                                                                                                 
===============================================================
```

We found a bunch of directories, in one of then we find this:

![](9.png)

Searching for this service we find that it's vulnerable to rce, but the one we have here is not, let's run another directory scan and add txt extension.

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.157.140/joomla/_test -x txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.157.140/joomla/_test
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt
[+] Timeout:                 10s
===============================================================
2022/09/04 05:23:20 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 305]
/.hta.txt             (Status: 403) [Size: 309]
/.htaccess            (Status: 403) [Size: 310]
/.htpasswd            (Status: 403) [Size: 310]
/.htaccess.txt        (Status: 403) [Size: 314]
/.htpasswd.txt        (Status: 403) [Size: 314]
/index.php            (Status: 200) [Size: 4802]
/log.txt              (Status: 200) [Size: 716] 
                                                
===============================================================
```

Found **log.txt** file.

![](10.png)

Inside the log file, we find ssh credentials.

## **Foothold**

We found ssh username and password, but we didn't find an ssh service running from the previous nmap scan. Let's run another scan for all ports. `sudo nmap --min-rate 5000 -p- {Target_ip}`.

```terminal
Nmap scan report for 10.10.157.140
Host is up (0.077s latency).
Not shown: 65359 closed tcp ports (reset), 172 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
10000/tcp open  snet-sensor-mgmt
55007/tcp open  unknown

```

Let's run a service scan on port 55007.

```terminal
Nmap scan report for 10.10.157.140
Host is up (0.10s latency).
PORT      STATE SERVICE VERSION
55007/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found ssh port number.

Using the credentials we got from the log file, let's connect via ssh.

![](11.png)

## **Privilege Escalation**

In the home directory of `basterd` user we find the following shell script.

![](12.png)

After printing the file we can see another user's credentials. Let's connect to that user's account.

![](13.png)

Now i uploaded a copy on linpeas, run it and got the following results.

![](14.png)

The binary `find` has suid bit, let's check [GTFOBins](https://gtfobins.github.io/gtfobins/find/#suid).

![](15.png)

We can run the following command to get root.

```bash
find . -exec /bin/bash -p \; -quit
```

![](16.png)

Congratulations, we have successfully rooted the machine.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
