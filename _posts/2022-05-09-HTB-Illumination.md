---
title: "HackTheBox - Illumination"
author: Nasrallah
description: ""
date: 2022-05-09 00:00:00 +0000
categories : [HackTheBox, Challenges, Forensics]
tags: [hackthebox, forensics, easy, challenges, git]
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


# **Description**

Hello Hackers, I hope you are doing well. Today we are going to look at [Illumination](https://app.hackthebox.com/challenges/illumination#) from [HackTheBox](https://www.hackthebox.com). A Junior Developer just switched to a new source control platform. Can you find the secret token?

# **Solution**

After download the zip file and unzipping it, let's look at the files we've extracted.

![](/assets/img/hackthebox/challenges/forensics/illumination/1.png)

There is a **.git** directory. Git is a version control system where you can track changes on any set of files.

This means that we can see the changes this junior developer has made. To do that, we can run the following command to see the logs: `git log`

![](/assets/img/hackthebox/challenges/forensics/illumination/2.png)

We can see the commit where he made the change to the token. We need to compare this commit with the one made before it.

First, let's take a note of the commits we want the compare, running `git log --oneline` will display a short version of the commit's id.

![](/assets/img/hackthebox/challenges/forensics/illumination/3.png)

Now, let's see the differences between those two commits by running the following command: `git diff COMMIT COMMIT`.

>Note: Replace *COMMIT* with the id of the commit.

![](/assets/img/hackthebox/challenges/forensics/illumination/4.png)

And there is the token, it's encoded with base64, decode it to get the flag.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

# References
