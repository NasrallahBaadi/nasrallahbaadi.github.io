---
title: "TryHackMe - JacobTheBoss"
author: Nasrallah
description: ""
date: 2023-03-13 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, jboss, rce, suid]
img_path: /assets/img/tryhackme/jacobtheboss
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [JacobTheBoss](https://tryhackme.com/room/jacobtheboss) from [TryHackMe](https://tryhackme.com). We find a vulnerable instance of jboss that exploit to get foothold. On the target system we find a SUID binary that we exploit to get a root shell.

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
Nmap scan report for 10.10.112.107                                                                                                                    [43/141]
Host is up (0.10s latency).                                                                                                                                   
Not shown: 987 closed tcp ports (reset)                                                                                                                       
PORT     STATE SERVICE     VERSION                                                                                                                            
22/tcp   open  ssh         OpenSSH 7.4 (protocol 2.0)                                                                                                         
| ssh-hostkey:                                                                                                                                                
|   2048 82ca136ed963c05f4a23a5a5a5103c7f (RSA)                                                                                                               
|   256 a46ed25d0d362e732f1d529ce58a7b04 (ECDSA)                                                                                                              
|_  256 6f54a65eba5badcc87eed3a8d5e0aa2a (ED25519)                                                                                                            
80/tcp   open  http        Apache httpd 2.4.6 ((CentOS) PHP/7.3.20)                                                                                           
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.3.20                                                                                                        
|_http-title: My first blog                                                                                                                                   
111/tcp  open  rpcbind     2-4 (RPC #100000)                                                                                                                  
| rpcinfo:                                                                                                                                                    
|   program version    port/proto  service                                                                                                                    
|   100000  2,3,4        111/tcp   rpcbind                                                                                                                    
|   100000  2,3,4        111/udp   rpcbind                                                                                                                    
|   100000  3,4          111/tcp6  rpcbind                                                                                                                    
|_  100000  3,4          111/udp6  rpcbind                                                                                                                    
1090/tcp open  java-rmi    Java RMI                                                                                                                           
|_rmi-dumpregistry: ERROR: Script execution failed (use -d to debug)                                                                                          
1098/tcp open  java-rmi    Java RMI
1099/tcp open  java-object Java Object Serialization                                                                                                          
| fingerprint-strings:                                                                                                                                        
|   NULL:                                                                                                                                                     
|     java.rmi.MarshalledObject|                                                                                                                              
|     hash[                                                                                                                                                   
|     locBytest                                                                                                                                               
|     objBytesq                                                                                                                                               
|     http://jacobtheboss.box:8083/q                                                                                                                          
|     org.jnp.server.NamingServer_Stub                                                                                                                        
|     java.rmi.server.RemoteStub                                                                                                                              
|     java.rmi.server.RemoteObject                                                                                                                            
|     xpw;                                                                                                                                                    
|     UnicastRef2                                                                                                                                             
|_    jacobtheboss.box                                                                                                                                        
3306/tcp open  mysql       MariaDB (unauthorized)
4444/tcp open  java-rmi    Java RMI
4445/tcp open  java-object Java Object Serialization
4446/tcp open  java-object Java Object Serialization
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE TRACE OPTIONS
|   Potentially risky methods: PUT DELETE TRACE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Welcome to JBoss&trade;
| http-methods: 
|_  Potentially risky methods: PUT DELETE TRACE
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache-Coyote/1.1 
8083/tcp open  http        JBoss service httpd
|_http-title: Site doesn't have a title (text/html).
```

There are a lot of open ports here, but the one we're probably interested in is port 8080 that's running jboss.

## Web

![](1.png)

# **Foothold**

Using the tool [JexBoss](https://github.com/joaomatosf/jexboss), let's see if this jboss instance has any vulnerabilities.

![](2.png)

The tool found 3 vulnerable entries.

Let's submit our tun0 ip and listening port to the tool to get a reverse shell.

![](3.png)

# **Privilege Escalation**

By running `linpeas` on the target we manage to find an suid binary

![](5.png)

This is an unusual binary, searching this binary i came across this [post](https://security.stackexchange.com/questions/196577/privilege-escalation-c-functions-setuid0-with-system-not-working-in-linux) on stackexchange.

To exploit the binary, we run the following command:

```bash
ping '127.0.0.1 -c 1;/bin/bash'
```

![](4.png)

And just like that we got root.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---
