---
title: "HackTheBox - Wrong Spooky Season"
author: Nasrallah
description: ""
date: 2023-01-27 00:00:00 +0000
categories : [HackTheBox, Challenges]
tags: [hackthebox, easy, wireshark, forensics]
img_path: /assets/img/hackthebox/challenges/spooky
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing **Wrong Spooky Season** from [HackTheBox](https://www.hackthebox.com).

## **Challenge**

In this challenge, we got a pcap file that we need to analyze, so let's open the file on `wireshark`.

Scrolling through the packets, we see that the conversation is between a web server and a client.

When we arrive at packet No 416, we see what looks like a web shell.

![](1.png)

Here we see the attacker run the command `whoami` and `id` then proceeded to download socat using the command `apt -y install socat`.

On the next packets, the attacker used socat send himself a reverse shell.

![](2.png)

The attacker's ip is 192.168.1.180 and he used port 1337 to receive the shell which he succeeded at getting as we can see on packet No 466.

Now right click the that packet and follow tcp stream.

![](4.png)

Here we can see every command he ran. At the bottom we can see a long string that looks like an inverted base64.

Let's got to [CyberChef](https://gchq.github.io/CyberChef/) and decode the string.

![](3.png)

Great! We got the flag.

But wait, how did the attacker got the webshell in the first place?

Going back to before the attacker got the webshell, we can see some weird data getting passed to the server from stream 6 to 9.

![](5.png)

![](6.png)

![](7.png)

![](8.png)

Searching on google for the first post data that got passed to the server, we find that this was a Sping4Shell exploit.

![](9.png)

For information about Spring4Shell, check this [article](https://www.dynatrace.com/news/blog/anatomy-of-spring4shell-vulnerability/).

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
