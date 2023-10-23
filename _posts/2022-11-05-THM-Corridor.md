---
title: "TryHackMe - Corridor"
author: Nasrallah
description: ""
date: 2022-11-05 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, web, easy, idor]
img_path: /assets/img/tryhackme/corridor
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Corridor](https://tryhackme.com/room/corridor) from [TryHackMe](https://tryhackme.com). In this challenge, you will explore potential IDOR vulnerabilities. Examine the URL endpoints you access as you navigate the website and note the hexadecimal values you find (they look an awful lot like a hash, don't they?). This could help you uncover website locations you were not expected to access.

## Web

Let's go to the web page.

![](1.png)

There are a bunch of door and each one goes to a page. Let's check the source code.

![](2.png)

As we can see every page has a name hashed with what looks like md5.

Let's click on one of the doors.

![](3.png)

It took us to an empty room, let's crack the hash on [crackstation](https://crackstation.net/).

![](4.png)

We got 8, this means the other doors are also hashed numbers.

Let's try the hash of number `0`.

![](5.png)

If go the that page, we get the flag.

![](6.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
