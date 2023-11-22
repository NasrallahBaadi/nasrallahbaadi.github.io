---
title: "HackTheBox - Optimum"
author: Nasrallah
description: ""
date: 2022-08-07 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, metasploit, rce]
img_path: /assets/img/hackthebox/machines/optimum
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Optimum](https://app.hackthebox.com/machines/Optimum) from [HackTheBox](https://www.hackthebox.com). This Box is running a version of HFS vulnerable to remote code execution allowing us to easily get access to the machine, then we use a metasploit module to escalate our privileges to SYSTEM. 

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.8
Host is up (0.088s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

We found port 80 open running `httpfileserver` version `2.3`.

Let's use `searchsploit` to see if there is any exploits in this version.

```bash
$ searchsploit hfs 2.3
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)                                                                | windows/remote/49584.py
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                                | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                             | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                        | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                        | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                   | windows/webapps/34852.txt
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

This version of HFS is vulnerable to remote command execution.

## **Foothold**

There is a module in metasploit named `windows/http/rejetto_hfs_exec` that would give us a reverse shell on the target, so let's use it.

![](1.png)

After setting the required options, let's run the exploit by entering `exploit`.

![](2.png)

Waiting a little bit for the exploit to fully run, we go back to metasploit command line and run `sessions` to see that we have a received a meterpreter session.

![](3.png)

## **Privilege Escalation**

Running the command `sysinfo` reveals that we're in a x64 architecture but our reverse shell is running on a x32 architecture.

![](4.png)

Let's list the precesses with the command `ps` and then move to a process like `explorer.exe` since it's x64 with the command `migrate <pid>.

```shell
meterpreter > ps                                                                                                                                             
                                                                                                                                                             
Process List                                                                                                                                                 
============                                                                                                                                                 
                                                                                                                                                             
 PID   PPID  Name                     Arch  Session  User            Path                                                                                    
 ---   ----  ----                     ----  -------  ----            ----                                                                                    
 0     0     [System Process]                                                                                                                                
 4     0     System                                                                                                                                          
 136   612   conhost.exe              x64   1        OPTIMUM\kostas  C:\Windows\System32\conhost.exe                                                         
 228   4     smss.exe                                                                                                                                        
 284   476   spoolsv.exe                                                                                                                                     
 332   320   csrss.exe                                                                                                                                       
 384   320   wininit.exe                                                                                                                                     
 392   376   csrss.exe                                                                                                                                       
 436   376   winlogon.exe  
 476   384   services.exe                                                                                                                                    
 484   384   lsass.exe                                                                                                                                       
 544   476   svchost.exe                                                                                                                                     
 572   476   svchost.exe                                                                                                                                     
 588   2504  powershell.exe           x86   1        OPTIMUM\kostas  C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
 612   3008  cmd.exe                  x86   1        OPTIMUM\kostas  C:\Windows\SysWOW64\cmd.exe
 620   476   vmtoolsd.exe
<**SNIP**>
 1944  2940  ezZKJbudGn.exe           x86   1        OPTIMUM\kostas  C:\Users\kostas\AppData\Local\Temp\radFACD7.tmp\ezZKJbudGn.exe
 1956  1180  explorer.exe             x64   1        OPTIMUM\kostas  C:\Windows\explorer.exe
 2000  696   taskhostex.exe           x64   1        OPTIMUM\kostas  C:\Windows\System32\taskhostex.exe
 2220  2504  wscript.exe              x86   1        OPTIMUM\kostas  C:\Windows\SysWOW64\wscript.exe

meterpreter > migrate 1956
[*] Migrating from 2272 to 1956...
[*] Migration completed successfully.

```

After some research, we find that we can use a module named `windows/local/ms16_032_secondary_logon_handle_privesc` that would give us a SYSTEM shell.

![](5.png)

We need to set the following options:

 - set session <session id>
 - set lhost tun0
 - set lport <port number>

After we run the exploit, we should get a meterpreter shell with privileged access/

![](6.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
