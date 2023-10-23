---
title: "HackTheBox - Legacy"
author: Nasrallah
description: ""
date: 2022-08-05 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, smb]
img_path: /assets/img/hackthebox/machines/legacy
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Legacy](https://app.hackthebox.com/machines/Legacy) from [HackTheBox](https://www.hackthebox.com). The machine is running an old version of windows with SMB, we use a module from metasploit to get access.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.4                                                                                                                              
Host is up (0.29s latency).                                                                                                                                  
Not shown: 997 closed tcp ports (reset)                                                                                                                      
PORT    STATE SERVICE      VERSION                                            
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn                                                                                                     
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp
                                                                              
Host script results:                                                          
|_clock-skew: mean: 4d23h58m06s, deviation: 2h07m16s, median: 4d22h28m06s                                                                                    
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:38:02 (VMware)
| smb-security-mode:          
|   account_used: guest          
|   authentication_level: user                                                
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:                                                           
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00                                         
|   Workgroup: HTB\x00
|_  System time: 2022-08-21T14:04:36+03:00
```

We have a windows XP machine running SMB.

# **Foothold**

Searching for windows XP SMB exploit we find that there is a metasploit module named `(MS08–067)` allowing us to get remote code execution.

Let's fire up `metasploit` and use the following module `exploit/windows/smb/ms08_067_netapi`

![](1.png)

After setting the lhost and rhost options, we run the exploit and get a reverse shell with system privileges.


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).