---
title: "CyberSecLabs - Shares"
author: Nasrallah
description: ""
date: 2022-03-19 00:00:00 +0000
categories : [CyberSecLabs]
tags: [cyberselabs, linux, nfs, john, crack]
---

---

# **Description**

Hello l33ts, I hope you are doing well. Today we are going to look at **Shares** from [Shares](https://www.cyberseclabs.co.uk/labs/info/Shares/) from [CyberSecLabs](https://www.cyberseclabs.co.uk).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -SSST4: Aggressice scan to provide faster results.

![](/assets/img/cyberseclabs/shares/Untitled.png)

There are 4 open port.

- 21/tcp     ftp     vsftpd 3.0.3
- 80/tcp     http    Apache httpd 2.4.29
- 111/tcp    rpcbind 2-4
- 2049/tcp   nfs_acl 3

Since the machine is called shares, i decided to look for any nfs shares.

## NFS

We can list nfs shares using the following command: `showmount -e {target_IP}`

![](/assets/img/cyberseclabs/shares/Untitled1.png)

We found a share, let's mount it on our attacking machine.

First, use `mkdir /tmp/share` to create a directory on your machine to mount the share to. Now let's use the following command to mount the nfs share to our machine. `sudo mount -t nfs IP:/home/amir /tmp/share -nolock`

- sudo:Run as root
- mount:Execute the mount command
- -t nfs:Type of device to mount, then specifying that it's NFS
- IP:share:The IP Address of the NFS server, and the name of the share we wish to mount
- -nolock:Specifies not to use NLM locking

![](/assets/img/cyberseclabs/shares/Untitled2.png)

Great! We have successfully mounted the share.
It appears to be the home directory of **amir**, and it a **.ssh** directory that contains a private key, but when we run a port scan, there was no ssh service listening on the machine, let's run another scan for all ports. `sudo nmap -p- {target_IP}`

![](/assets/img/cyberseclabs/shares/Untitled3.png)

Great! We found the port of ssh.

## **Foothold**

Let's now use the private key we got from the nfs share so connect to the machine.

![](/assets/img/cyberseclabs/shares/Untitled4.png)

the private key has a password protecting it, using `ssh2john` we were able to extract a hash that we managed to crack using `john`. Let's try connecting again.

![](/assets/img/cyberseclabs/shares/Untitled5.png)

## **Privilege Escalation**

We now have access to the machine as **amir**, let's do some basic enumeration.

```terminal
amir@shares:~$ sudo -l
Matching Defaults entries for amir on shares:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User amir may run the following commands on shares:
    (ALL : ALL) ALL
    (amy) NOPASSWD: /usr/bin/pkexec
    (amy) NOPASSWD: /usr/bin/python3
```

We see that as amir, we can execute any command as root but we need a password for that, on the other hand, we can execute `/usr/bin/pkexec` and `/usr/bin/python3` as **amy**. We go to [GTFOBins](https://gtfobins.github.io/) and get a pkexec/python3 command that would give us a shell as amy.

- python3 : `sudo -u amy python -c 'import os; os.system("/bin/bash")'`
- pkexec : `sudo -u amy pkexec /bin/sh`

We can't escalate to amy with `pkexec` so let's use `python3`

![](/assets/img/cyberseclabs/shares/Untitled6.png)

We have amy's shell now, let's run another `sudo -l` to see what we can run.

```terminal
amy@shares:~$ sudo -l
Matching Defaults entries for amy on shares:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User amy may run the following commands on shares:
    (ALL) NOPASSWD: /usr/bin/ssh
```

We can run `ssh` as root.
Going back to [GTFOBins](https://gtfobins.github.io/) and searching for ssh, we find that we can run the following command to get root `sudo ssh -o ProxyCommand=';bash 0<&2 1>&2' x`

![](/assets/img/cyberseclabs/shares/Untitled7.png)

---

Thank you for taking the time to read my writeup, I hope you have learned something with this, if you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
