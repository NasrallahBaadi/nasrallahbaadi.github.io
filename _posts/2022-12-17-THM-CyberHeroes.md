---
title: "TryHackMe - CyberHeroes"
author: Nasrallah
description: ""
date: 2022-12-17 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, web]
img_path: /assets/img/tryhackme/cyberheroes
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [CyberHeroes](https://tryhackme.com/room/cyberheroes) from [TryHackMe](https://tryhackme.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.117.173                                                                                                                            
Host is up (0.10s latency).                                                                                                                                   
Not shown: 998 closed tcp ports (reset)                                                                                                                       
PORT   STATE SERVICE VERSION                                                                                                                                  
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)                                                                             
| ssh-hostkey:                                                                                                                                                
|   3072 4b:e4:b2:e1:4d:7a:54:da:c0:09:17:08:e8:2a:67:c0 (RSA)                                                                                                
|   256 cf:af:e2:04:d6:de:9f:7c:3c:7d:e5:fb:7a:87:94:dc (ECDSA)                                                                                               
|_  256 31:54:95:e0:9c:a5:37:60:43:0e:3b:f8:aa:d6:46:0c (ED25519)                                                                                             
80/tcp open  http    Apache httpd 2.4.48 ((Ubuntu))                                                                                                           
|_http-title: CyberHeros : Index                                                                                                                              
|_http-server-header: Apache/2.4.48 (Ubuntu)                                                                                                                  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web

Let's navigate to the web page.

![](1.png)

This is CyberHeroes home page. We can also find a login page.

![](2.png)

Checking the source code of this page, we find the following javascript code.

```js
function authenticate() {
      a = document.getElementById('uname')
      b = document.getElementById('pass')
      const RevereString = str => [...str].reverse().join('');
      if (a.value=="h3ck3rBoi" & b.value==RevereString("54321@terceSrepuS")) { 
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
            document.getElementById("flag").innerHTML = this.responseText ;
            document.getElementById("todel").innerHTML = "";
            document.getElementById("rm").remove() ;
          }
        };
        xhttp.open("GET", "RandomLo0o0o0o0o0o0o0o0o0o0gpath12345_Flag_"+a.value+"_"+b.value+".txt", true);
        xhttp.send();
      }
      else {
        alert("Incorrect Password, try again.. you got this hacker !")
      }
    }
```

This is the login functionality, we can see the username `h3ck3rBoi` and the password reversed `54321@terceSrepuS`.

Let's login and get the flag.

![](3.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
