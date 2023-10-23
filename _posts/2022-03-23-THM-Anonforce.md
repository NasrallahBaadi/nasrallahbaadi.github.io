---
title: "TryHackMe - Anonforce"
author: Nasrallah
description: ""
date: 2022-03-23 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, ftp, cryptography, gpg, john, hashcat, crack]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello l33ts, I hope you are doing well. Today we are going to look at [Anonforce](https://tryhackme.com/room/bsidesgtanonforce) from [TryHackMe](https://tryhackme.com), an easy machine where we are able to login to ftp as anonymous and see all of the system files of the machine, we find an unusual directory that contains an encrypted file, we decrypt it and get some hashes that we will be able to crack one of them and get root access.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.175.75                                             
Host is up (0.10s latency).                                                   
Not shown: 998 closed tcp ports (reset)                       
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3                                                                                                                            
| ftp-anon: Anonymous FTP login allowed (FTP code 230)      
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 bin
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 boot
| drwxr-xr-x   17 0        0            3700 Mar 22 11:12 dev
| drwxr-xr-x   85 0        0            4096 Aug 13  2019 etc
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 home
| lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img -> boot/initrd.img-4.4.0-157-generic
| lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img.old -> boot/initrd.img-4.4.0-142-generic
| drwxr-xr-x   19 0        0            4096 Aug 11  2019 lib
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 lib64
| drwx------    2 0        0           16384 Aug 11  2019 lost+found
| drwxr-xr-x    4 0        0            4096 Aug 11  2019 media
| drwxr-xr-x    2 0        0            4096 Feb 26  2019 mnt
| drwxrwxrwx    2 1000     1000         4096 Aug 11  2019 notread [NSE: writeable]
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 opt
| dr-xr-xr-x   94 0        0               0 Mar 22 11:12 proc
| drwx------    3 0        0            4096 Aug 11  2019 root
| drwxr-xr-x   18 0        0             540 Mar 22 11:13 run
| drwxr-xr-x    2 0        0           12288 Aug 11  2019 sbin
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 srv
| dr-xr-xr-x   13 0        0               0 Mar 22 11:12 sys
|_Only 20 shown. Use --script-args ftp-anon.maxlist=-1 to see all.
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.11.31.131
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8a:f9:48:3e:11:a1:aa:fc:b7:86:71:d0:2a:f6:24:e7 (RSA)
|   256 73:5d:de:9a:88:6e:64:7a:e1:87:ec:65:ae:11:93:e3 (ECDSA)
|_  256 56:f9:9f:24:f1:52:fc:16:b7:7b:a3:e2:4f:17:b4:ea (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open port, 21(FTP) and 22(SSH).

## FTP

From the nmap scan, anonymous login seems to be enabled on the ftp server. Let's login by typing the following command `ftp {target_IP}`, for the username enter **anonymous** and password can be submitted blank.

![ftp](/assets/img/tryhackme/anonforce/ftp.png)


# **Foothold**

We see that we are in the root of the file system of a linux machine. Looking at these directories/files, we see an unusual directory called **notread**, let's see what's there.

![files](/assets/img/tryhackme/anonforce/files.png)

There is a pgp encrypted file named **backup.pgp** and file named **private.asc** which seems to be private key for the encrypted file, let's get those file into our attacking machine. We can do that by running `get filename` on the ftp prompt.

We can also navigate to the home page and file a user that have the user flag, use `get user.txt` to download the file to your machine.

![user](/assets/img/tryhackme/anonforce/user.png)

After getting those 2 file, we can use the command `gpg` to decrypt the file. First we need to import the private key, we can do that with the following command `gpg --import private.asc`, and to decrypt it we can run `gpg --output backup --decrypt backup.pgp`

![decr1](/assets/img/tryhackme/anonforce/decr1.png)

We were asked for a password when we tried to decrypt the file, that's because the private key is protected with a password. We can use `gpg2john` to get a hash and use `john` to crack that hash.

![hash](/assets/img/tryhackme/anonforce/keyhash.png)

Great! We managed to crack the hash and get the private key's password, let's decrypt the file now.

![passwd](/assets/img/tryhackme/anonforce/passwd.png)

After decrypting the file, we get a copy of shadow file that contains password hashes for **melodias** and **root**.

# **Privilege Escalation**

Let's try to crack the root hash with `hashcat`, first copy the hash to a file and run the command `hashcat -m 1800 roothash /usr/share/wordlists/rockyou.txt`

![hash](/assets/img/tryhackme/anonforce/rootpass.png)

Great! We managed to crack the root hash, let's now ssh to the machine and grab the flag.

![root](/assets/img/tryhackme/anonforce/root.png)

---

Thank you for taking the time to read my writeup, I hope you have learned something with this, if you have any questions or comments, please feel free to reach out to me. See you in the next hack :) .
