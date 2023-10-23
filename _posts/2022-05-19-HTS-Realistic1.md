---
title: "HackThisSite - Uncle Arnold's Local Band Review"
author: Nasrallah
description: ""
date: 2022-05-19 00:00:00 +0000
categories : [HackThisSite, Realistic]
tags: [hackthissite, hts, easy, web, realistic]
---

![](/assets/img/hackthissite/realistic/rm1/banner.png)

---


# **Description**

Hello l33ts, I hope you are doing well. We will be doing [Uncle Arnold's Local Band Review](https://www.hackthissite.org/missions/realistic/1/) from [HackThisSite](https://www.hackthissite.org/) which is part of the **realistic missions**.


# **Solution**

The challenge has the following message.

![](/assets/img/hackthissite/realistic/rm1/1.png)

Let's navigate to that [page](https://www.hackthissite.org/missions/realistic/1/).

![](/assets/img/hackthissite/realistic/rm1/2.png)

It's a local brand review page, if we scroll down, we can see Raging Inferno is at the bottom and has the lowest rank.

![](/assets/img/hackthissite/realistic/rm1/3.png)

Let's fire up `burp suite` and turn intercept on.

Now let's vote for our Raging Inferno brand and intercept the request.

![](/assets/img/hackthissite/realistic/rm1/4.png)

We can see the parameter responsible for voting is named `vote`, so let's change it's value to something higher.

![](/assets/img/hackthissite/realistic/rm1/5.png)

Let's forward the request.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

# References
