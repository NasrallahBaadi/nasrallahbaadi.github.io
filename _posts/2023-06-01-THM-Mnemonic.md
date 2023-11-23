---
title: "TryHackMe - Mnemonic"
author: Nasrallah
description: ""
date: 2023-06-01 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, john, python, sudo, crack, hydra]
img_path: /assets/img/tryhackme/mnemonic
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Mnemonic](https://tryhackme.com/room/mnemonic) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.226.130
Host is up (0.12s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-robots.txt: 1 disallowed entry 
|_/webmasters/*
1337/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e042c0a57d426f0022f8c754aa35b9dc (RSA)
|   256 23eba99b45269ca213abc1ce072b98e0 (ECDSA)
|_  256 358fcbe20d112c0b63f2bca034f3dc49 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Found three open ports, 21 running a FTP server, port 80 is an Apache web server and port 1337 is SSH.

### Web

We don't have any credentials for ftp and ssh so let's check the web page on port 80.

![](1.png)

Nothing special in this page so let's run a directory scan.

```terminal
$ feroxbuster -w /usr/share/wordlists/dirb/common.txt -u http://10.10.226.130/ -x php,txt                                                          130 ⨯
                                                                                                                                                              
 ___  ___  __   __     __      __         __   ___                                                                                                            
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                                                             
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                            
by Ben "epi" Risher 🤓                 ver: 2.7.2                                                                                                             
───────────────────────────┬──────────────────────                                                                                                            
 🎯  Target Url            │ http://10.10.226.130/                                                                                                            
 🚀  Threads               │ 50                                                                                                                               
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt                                                                                             
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]                                                                               
 💥  Timeout (secs)        │ 7                                                                                                                                
 🦡  User-Agent            │ feroxbuster/2.7.2                                                                                                                
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                                                               
 💲  Extensions            │ [php, txt]                                                                                                                       
 🏁  HTTP methods          │ [GET]                                                                                                                            
 🔃  Recursion Depth       │ 4                                                                                                                                
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest              
───────────────────────────┴──────────────────────                                                                                                            
 🏁  Press [ENTER] to use the Scan Management Menu™                                                                                                           
──────────────────────────────────────────────────                                                                                                            
200      GET        2l        1w       15c http://10.10.226.130/                                                                                              
403      GET        9l       28w      278c http://10.10.226.130/.hta                                                                                          
403      GET        9l       28w      278c http://10.10.226.130/.htaccess                                                                                     
403      GET        9l       28w      278c http://10.10.226.130/.htpasswd                                                                                     
403      GET        9l       28w      278c http://10.10.226.130/.htpasswd.php
403      GET        9l       28w      278c http://10.10.226.130/.htpasswd.txt                                                                                 
403      GET        9l       28w      278c http://10.10.226.130/.htaccess.php                                                                                 
403      GET        9l       28w      278c http://10.10.226.130/.hta.php                                                                                      
403      GET        9l       28w      278c http://10.10.226.130/.hta.txt
403      GET        9l       28w      278c http://10.10.226.130/.htaccess.txt
200      GET        2l        1w       15c http://10.10.226.130/index.html
200      GET        3l        6w       48c http://10.10.226.130/robots.txt
301      GET        9l       28w      319c http://10.10.226.130/webmasters => http://10.10.226.130/webmasters/
301      GET        9l       28w      325c http://10.10.226.130/webmasters/admin => http://10.10.226.130/webmasters/admin/
301      GET        9l       28w      327c http://10.10.226.130/webmasters/backups => http://10.10.226.130/webmasters/backups/
200      GET        0l        0w        0c http://10.10.226.130/webmasters/index.html
200      GET        0l        0w        0c http://10.10.226.130/webmasters/admin/index.html
200      GET        0l        0w        0c http://10.10.226.130/webmasters/backups/index.html
[####################] - 4m     55368/55368   0s      found:37      errors:945     
[####################] - 1m     13842/13842   177/s   http://10.10.226.130/ 
[####################] - 3m     13842/13842   75/s    http://10.10.226.130/webmasters/ 
[####################] - 3m     13842/13842   74/s    http://10.10.226.130/webmasters/admin/ 
[####################] - 3m     13842/13842   75/s    http://10.10.226.130/webmasters/backups/ 
```

We found a directory called `webmasters`, and inside of it we find two other directories `admin` and `backups`.

There is nothing interesting in the directories, but since we found a `backups` directory, let's scan for zip files.

```terminal
$ feroxbuster -w /usr/share/wordlists/dirb/common.txt -u http://10.10.226.130/webmasters/backups -x zip

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.226.130/webmasters/backups
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [zip]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      278c http://10.10.226.130/webmasters/backups/.hta
301      GET        9l       28w      327c http://10.10.226.130/webmasters/backups => http://10.10.226.130/webmasters/backups/
403      GET        9l       28w      278c http://10.10.226.130/webmasters/backups/.htpasswd
403      GET        9l       28w      278c http://10.10.226.130/webmasters/backups/.hta.zip
403      GET        9l       28w      278c http://10.10.226.130/webmasters/backups/.htpasswd.zip
403      GET        9l       28w      278c http://10.10.226.130/webmasters/backups/.htaccess
403      GET        9l       28w      278c http://10.10.226.130/webmasters/backups/.htaccess.zip
200      GET        9l       17w      409c http://10.10.226.130/webmasters/backups/backups.zip
200      GET        0l        0w        0c http://10.10.226.130/webmasters/backups/index.html
[####################] - 33s     9228/9228    0s      found:9       errors:0      
[####################] - 33s     9228/9228    275/s   http://10.10.226.130/webmasters/backups/ 

```

We found the file `backups.zip`.

### Zip file

Let's download the file and unzip it.

![](2.png)

The zip file is protected with a password, so we use `zip2john` to get a hash of that password and then use `john` to crack the hash.

We got the password and unzipped the file and found the file `note.txt`

```text
@vill

James new ftp username: ftpuser
we have to work hard
```

The note revealed a username for FTP but no password.

### Hydra

Let's use `hydra` and brute force the password.

![](4.png)

We got the password, now let's login to ftp server.

```terminal
 ftp 10.10.226.130    
Connected to 10.10.226.130.                                                    
220 (vsFTPd 3.0.3)                                                             
Name (10.10.226.130:sirius): ftpuser
331 Please specify the password.                                               
Password:       
230 Login successful.         
Remote system type is UNIX.                                                    
Using binary mode to transfer files.                                           
ftp> ls               
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-1
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-10
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-2
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-3
drwxr-xr-x    4 0        0            4096 Jul 14  2020 data-4
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-5
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-6
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-7
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-8
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-9
226 Directory send OK.
ftp> cd data-4
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 14  2020 3
drwxr-xr-x    2 0        0            4096 Jul 14  2020 4
-rwxr-xr-x    1 1001     1001         1766 Jul 13  2020 id_rsa
-rwxr-xr-x    1 1000     1000           31 Jul 13  2020 not.txt
226 Directory send OK.
```

After listing the the directories available, we notice on the second column that `data-4` has a different number than the others, and inside of it we find a ssh private key and a note.

Let's download them and see what the note says.

```text
james change ftp user password
```

The private key seems to be encrypted:

```bash
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,01762A15A5B935E96A1CF34704C79AC3
```

Let's use `ssh2john` and crack the hash.

![](3.png)

## **Foothold**

Let's use the private key and ssh to the target as `james`

![](5.png)

The key didn't do it's job but the passphrase of it works as password for james. 

## **Privilege Escalation**

After logging in we got the following message from root

```text
Broadcast message from root@mnemonic (somewhere) (Thu Jun 15 13:14:42 2023):   
                                                                               
     IPS/IDS SYSTEM ON !!!!                                                    
 **     *     ****  **                                                         
         * **      *  * *                                                      
*   ****                 **                                                    
 *                                                                             
    * *            *                                                           
       *                  *                                                    
         *               *                                                     
        *   *       **                                                         
* *        *            *                                                      
              ****    *                                                        
     *        ****                                                             
                                                                               
 Unauthorized access was detected.           
```

The shell we're using is `rbash` aka `restricted bash`, let's run /bin/bash to get a normal shell.

On james directory we find another note

```text
noteforjames.txt

@vill

james i found a new encryption İmage based name is Mnemonic  

I created the condor password. don't forget the beers on saturday
```

`vill` used an encryption method that uses images called `Mnemonic` to create the password for user `condor`.

If we list `condor`'s home directory we find two directories with a base64 encoded string as a name

```bash
james@mnemonic:/home$ ls -l condor
ls: cannot access 'condor/'\''VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ=='\''': Permission denied
ls: cannot access 'condor/aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==': Permission denied
total 0
d????????? ? ? ? ?            ? ''\''VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ=='\'''
d????????? ? ? ? ?            ? 'aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw=='
```

If we decrypt the first one it gives us the flag, and the other one gives a link to an image.

On this [github repo](https://github.com/MustafaTanguner/Mnemonic) a script that's going to help us get condor password.

Let's run the script.

![](6.png)

We got the password, now let's ssh as `condor`

![](7.png)

Let's check our privileges.

```terminal
condor@mnemonic:~$ sudo -l
[sudo] password for condor: 
Matching Defaults entries for condor on mnemonic:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User condor may run the following commands on mnemonic:
    (ALL : ALL) /usr/bin/python3 /bin/examplecode.py
```

There is a python script we can run as root.

```python
#!/usr/bin/python3
import os
import time
import sys
def text(): #text print 


	print("""

	------------information systems script beta--------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	----------------@author villwocki------------------""")
	time.sleep(2)
	print("\nRunning...")
	time.sleep(2)
	os.system(command="clear")
	main()


def main():
	info()
	while True:
		select = int(input("\nSelect:"))

		if select == 1:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="ip a")
			print("Main Menü press '0' ")
			print(x)

		if select == 2:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="ifconfig")
			print(x)

		if select == 3:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="ip route show")
			print(x)

		if select == 4:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="cat /etc/os-release")
			print(x)

		if select == 0: 
			time.sleep(1)
			ex = str(input("are you sure you want to quit ? yes : "))
		
			if ex == ".":
				print(os.system(input("\nRunning....")))
			if ex == "yes " or "y":
				sys.exit()
                      

		if select == 5:                     #root
			time.sleep(1)
			print("\nRunning")
			time.sleep(2)
			print(".......")
			time.sleep(2)
			print("System rebooting....")
			time.sleep(2)
			x = os.system(command="shutdown now")
			print(x)

		if select == 6:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="date")
			print(x)




		if select == 7:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="rm -r /tmp/*")
			print(x)

                      
              


       


            

def info():                         #info print function
	print("""

	#Network Connections   [1]

	#Show İfconfig         [2]

	#Show ip route         [3]

	#Show Os-release       [4]

    #Root Shell Spawn      [5]           

    #Print date            [6]

	#Exit                  [0]

	""")

def run(): # run function 
	text()

run()
```

The script can retrieve multiple system information by running commands like `ifconfig` or `date` and the user can control what he want to get.

From line 50 to 66 we see some interesting stuff.

```python
if select == 0: 
	time.sleep(1)
	ex = str(input("are you sure you want to quit ? yes : "))
		
	if ex == ".":
		print(os.system(input("\nRunning....")))
	if ex == "yes " or "y":
		sys.exit()
```

If the user chose to quit and entered 0, the script prompt for input to confirm the action, if the input is `yes` or `y` the program exits, but if we enter a dot `.` the script prompts us for another input and whatever we type got to `os.system()` which means the system runs it.

So let's run the python script with sudo, press 0 to exit the program, press `.` and then type bash to get a root shell.

![](8.png)

We got root!

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---
