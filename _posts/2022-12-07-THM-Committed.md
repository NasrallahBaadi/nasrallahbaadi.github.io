---
title: "TryHackMe - Committed"
author: Nasrallah
description: ""
date: 2022-12-07 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, git]
img_path: /assets/img/tryhackme/committed
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Committed](https://tryhackme.com/room/committed) from [TryHackMe](https://tryhackme.com).


## **Solution**

After starting the machine, let's unzip the file and enter the committed directory.

![](1.png)

We see there is a hidden directory called **.git**. Git is a version control system where you can track changes on any set of files. This allow us to see any changes the developers has made to the code.

### Git

Let's check the logs with the command `git log --oneline`.

![](2.png)

We can see 5 defferent commits, but none seems to have anything interesting, maybe there are some deleted commits we can't see. To view them we run this command `git reflog show`.

![](3.png)

We managed to view more commits, we see a specific commit with the comment `Oops`, maybe this is the commit that contains sensitive information, let's view with the command : `git show c56c470`.

![](4.png)

Great! We got the flag.s

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
