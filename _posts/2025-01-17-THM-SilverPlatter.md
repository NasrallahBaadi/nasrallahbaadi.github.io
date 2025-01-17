---
title: "TryHackMe - Silver Platter"
author: Nasrallah
description: ""
date: 2025-01-17 07:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, cve, adm]
img_path: /assets/img/tryhackme/silverplatter
image:
    path: silverplatter.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[Silver Platter](https://tryhackme.com/r/room/silverplatter) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) is running a known web application vulnerable to authentication bypass allowing us to logging without a password and find ssh credentials. The user we got foothold with is part of the `adm` group allowing to read log and find a password of database but works for the second user on the machine, this user can ran any command with sudo giving us an easy way for a root shell.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.73.62                                                               
Host is up (0.10s latency).                                                                    
Not shown: 997 closed tcp ports (reset)                                                        
PORT     STATE SERVICE    VERSION                                                              
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                                                 
|   256 1b:1c:87:8a:fe:34:16:c9:f7:82:37:2b:10:8f:8b:f1 (ECDSA)           
|_  256 26:6d:17:ed:83:9e:4f:2d:f6:cd:53:17:c8:80:3d:09 (ED25519)         
80/tcp   open  http       nginx 1.18.0 (Ubuntu)                           
|_http-title: Hack Smarter Security                                                            
|_http-server-header: nginx/1.18.0 (Ubuntu)                                                    
8080/tcp open  http-proxy                                                                      
| fingerprint-strings:                                                                         
|   FourOhFourRequest:                                                                         
|     HTTP/1.1 404 Not Found                                                                   
|     Connection: close                                                                        
|     Content-Length: 74                                                                       
|     Content-Type: text/html                                                                  
|     Date: Fri, 17 Jan 2025 17:25:26 GMT                                                      
|     <html><head><title>Error</title></head><body>404 - Not Found</body></html>
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SMBProgNeg, SSLSessionReq, Socks5, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request                                                                 
|     Content-Length: 0                                                                        
|     Connection: close                                                                        
|   GetRequest, HTTPOptions:                                                                   
|     HTTP/1.1 404 Not Found                          
```

We found three open ports running on an ubuntu system.

The first port is 22 running OpenSSH, second is port 80 running nginx web server and port 8080 seems to be an http proxy.

### Web

Let's check the web page on port 80.

![root](1.png)

The page seems to be static, the links goes to anchor points on the page.

The contact section has some interesting information.

![contact](2.png)

We found a possible username `scr1ptkiddy` and also something called `silverpeas`.

Searching on google for `Silverpeas` reveals it's a web application that facilitates collaboration in and organization.

I searched for exploits and found the [CVE-2024-36042](https://gist.github.com/ChrisPritchard/4b6d5c70d9329ef116266a6c238dcb2d) which bypass authentication on the application.

### Authentication bypass

The POC shows a post request made to `/silverpeas`, this page doesn't exist on port 80 but it does on port 8080.

![peas](3.png)

The bypass happens when we logging without submitting the password parameter in the post request.

The username provided in the POC is `SilverAdmin`, let's try replicate the exploit.

I'll enter both username and password, intercept the login request with `Burp` and remove the password parameter.

![burp](4.png)

We forward the request and go back to the browser.

![logged](5.png)

We logged in successfully as administrator.

Nothing here seems useful, I'll try with the user we found earlier `scr1ptkiddy`

![script](6.png)

After logging we found a notification, the name `tyler` is mentioned both nothing else is interesting.

Looking through the website I clicked on `Directory` and got the following.

![man](7.png)

This show us the current users on the application, Looking back at the notification we can see that it came from user `Manager`.

## **Foothold**

Let's login as `Manager` and see if we can find anything useful.

![pass](8.png)

We found some notifications and one has credentials for ssh access to the machine.

```terminal
[★]$ ssh tim@10.10.73.62
tim@10.10.73.62's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)
[...]
tim@silver-platter:/$ id
uid=1001(tim) gid=1001(tim) groups=1001(tim),4(adm)
```

## **Privilege Escalation**

After getting access and running the `id` command we find that user tim is part of the `adm` group.

> The adm group is used for system monitoring tasks. Members of this group can read many log files in /var/log.
{: .prompt-info }

The first good file to check is the `auth.log` which usually include records of login attempts, authentication successes or failures, and other related security events.

```terminal
tim@silver-platter:/var/log$ cat auth.log.2 | grep password -i
Dec 12 19:34:46 silver-platter passwd[1576]: pam_unix(passwd:chauthtok): password changed for tim
Dec 12 19:39:15 silver-platter sudo:    tyler : 3 incorrect password attempts ; TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/apt install nginx
Dec 13 15:39:07 silver-platter usermod[1597]: change user 'dnsmasq' password
Dec 13 15:39:07 silver-platter chage[1604]: changed password expiry for dnsmasq
Dec 13 15:40:33 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name postgresql -d -e POSTGRES_PASSWORD=[REDACTED] -v postgresql-data:/var/lib/postgresql/data postgres:12.3
Dec 13 15:44:30 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database sivlerpeas:silverpeas-6.3.1
Dec 13 15:45:21 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:silverpeas-6.3.1
Dec 13 15:45:57 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:6.3.1
```

We manged to find a postgres password.

There is no postgres port open on the box, and the command shows that it's a docker container.

We can try using the password for user `tyler.

```terminal
tim@silver-platter:/var/log$ su tyler
Password: 
tyler@silver-platter:/var/log$ id
uid=1000(tyler) gid=1000(tyler) groups=1000(tyler),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)
```

It worked! Let's check our privileges.

```terminal
tyler@silver-platter:/var/log$ sudo -l
[sudo] password for tyler: 
Matching Defaults entries for tyler on silver-platter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tyler may run the following commands on silver-platter:
    (ALL : ALL) ALL
```

We have ALL, a simple `sudo su` will give us root shell.

```terminal
tyler@silver-platter:/var/log$ sudo su
root@silver-platter:/var/log# id
uid=0(root) gid=0(root) groups=0(root)
```

## **Prevention and Mitigation**

### CVE-2024-36042

The version of silverpeas running on the webserver is vulnerable to authentication bypass giving access to not only admin portal but other users where we were able to read messages between users.

#### Fix

Update silverpeas to the latest version and maintain an active patch schedule for any updates that may be released in the future.

### adm

Being part of the `adm` group gave us read access to different types of logs

#### Fix

Remove user tim from the adm group and apply the principle of least privilege.

### Password Reuse

We found a postgres password on the logs in clear text and it was reused by user `tyler` allowing us to escalate our privileges to that user and later to root.

#### Fix

Avoid passing clear text credentials in commands, and if that's necessary, ensure that the commands are not being logged.

Also never use a password for more than one account, and use a secure password manager with good reputation to store your passwords.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

<https://gist.github.com/ChrisPritchard/4b6d5c70d9329ef116266a6c238dcb2d>

<https://askubuntu.com/questions/612751/what-is-the-difference-between-the-groups-adm-and-admin>
