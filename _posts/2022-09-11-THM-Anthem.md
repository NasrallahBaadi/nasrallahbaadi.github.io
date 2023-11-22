---
title: "TryHackMe - Anthem"
author: Nasrallah
description: ""
date: 2022-09-11 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, windows, web, rdp]
img_path: /assets/img/tryhackme/anthem
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Anthem](https://tryhackme.com/room/anthem) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 -Pn {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

- -Pn: Skip host discovery. Usually used on windows targets.

```terminal
Nmap scan report for 10.10.253.248
Host is up (0.085s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2022-09-03T08:27:57+00:00; -30m34s from scanner time.
| ssl-cert: Subject: commonName=WIN-LU09299160F
| Not valid before: 2022-09-02T08:11:51
|_Not valid after:  2023-03-04T08:11:51
| rdp-ntlm-info: 
|   Target_Name: WIN-LU09299160F
|   NetBIOS_Domain_Name: WIN-LU09299160F
|   NetBIOS_Computer_Name: WIN-LU09299160F
|   DNS_Domain_Name: WIN-LU09299160F
|   DNS_Computer_Name: WIN-LU09299160F
|   Product_Version: 10.0.17763
|_  System_Time: 2022-09-03T08:26:55+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

The target is a windows machine running a web server on port 80, and RDP on port 3389.

### Web

Let's navigate to the webpage.

![](1.png)

The website is a blog called `Anthem`. Before we dive into the blog, let's run a directory scan.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.253.248/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/09/03 05:05:52 Starting gobuster in directory enumeration mode
===============================================================
/Archive              (Status: 301) [Size: 118] [--> /]
/archive              (Status: 301) [Size: 118] [--> /]
/authors              (Status: 200) [Size: 4075]       
/Blog                 (Status: 200) [Size: 5399]       
/blog                 (Status: 200) [Size: 5399]       
/categories           (Status: 200) [Size: 3546]       
/install              (Status: 302) [Size: 126] [--> /umbraco/]
/robots.txt           (Status: 200) [Size: 192]                
/rss                  (Status: 200) [Size: 1867]               
/RSS                  (Status: 200) [Size: 1867]               
/search               (Status: 200) [Size: 3422]               
/Search               (Status: 200) [Size: 3422]               
/sitemap              (Status: 200) [Size: 1042]               
/SiteMap              (Status: 200) [Size: 1042]               
/tags                 (Status: 200) [Size: 3549]               
===============================================================
```

Found a bunch on directories, but let's start with the **robots.txt** file.

![](2.png)

We found a string of text at the top saying `UmbracoIsTheBest!` and a bunch of other directories. Searching for **Umbraco** we find that it is a CMS.

Back to the blog, if we go the the `we are hiring` post we find this.

![](3.png)

Found an email address and a username, and we see that the pattern for the email uses the first letters of the first name and last name. In our case here, we have user **J**ane **D**oe with the email **JD**@anthem.com.

Let's check the other post.

![](4.png)

Some one wrote a poem to IT department. If we googled the poem, we find who wrote it.

![](5.png)

Solomon Grundy wrote the poem, so his email might be `SG@anthem.com`.

## **Foothold**

Using the string we found in robots.txt as a password, and SG as a username, let's login to the machine via rdp using `xfreerdp`.

```bash
xfreerdp /u:sg /p:UmbracoIsTheBest! /v:10.10.253.248 /cert:ignore /dynamic-resolution +clipboard
```

![](6.png)

## **Privilege Escalation**

After going down a deep rabbit hole, i checked the hint and it says `it's hidden`. I checked the hidden item box and started searching.

![](7.png)

We find a hidden directory under the C drive with a file in it.

![](8.png)

Unfortunately, we can't read the file. Surprisingly, it's turns out we can edit the file's permission.

Right click the file and go to properties, head the the security tab and press the edit button.

We need now to add our current user "**SG**" to the people who can read the file, so click `add` and type `SG`.

![](9.png)

Now press ok, then `apply`.

![](10.png)

Now if we can read the file.

![](11.png)

With that password, login to administrator's account with the following command.

```bash
xfreerdp /u:administrator /p:ChangeMeBaby1MoreTime /v:10.10.253.248 /cert:ignore /dynamic-resolution +clipboard
```

![](12.png)

Great! We became domain admin.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
