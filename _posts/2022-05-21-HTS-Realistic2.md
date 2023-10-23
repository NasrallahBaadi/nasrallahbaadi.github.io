---
title: "HackThisSite - Chicago American Nazi Party"
author: Nasrallah
description: ""
date: 2022-05-21 00:00:00 +0000
categories : [HackThisSite, Realistic]
tags: [hackthissite, hts, easy, web, realistic]
---

![](/assets/img/hackthissite/realistic/rm2/banner.png)

---

# **Description**

Hello l33ts, I hope you are doing well. We will be doing [Chicago American Nazi Party](https://www.hackthissite.org/playlevel/2/) from [HackThisSite](https://www.hackthissite.org/), part of the realistic challenges.

# **Solution**

The challenge has the following message.

![](/assets/img/hackthissite/realistic/rm2/1.png)

Let's go to that [Website](https://www.hackthissite.org/missions/realistic/2/).

![](/assets/img/hackthissite/realistic/rm2/2.png)

As we can see, this website belongs to a nazi party. Let's check the source code.

![](/assets/img/hackthissite/realistic/rm2/3.png)

There is a link at the bottom of the page that goes to **update.php** page, let's see what there.

![](/assets/img/hackthissite/realistic/rm2/4.png)

It's a login page, let's try some submitting some known credentials(admin:admin).

![](/assets/img/hackthissite/realistic/rm2/5.png)

Well, that was not necessary. Let's try a sql injection by entering the this `' or 1=1 -- -` for both username and password.

![](/assets/img/hackthissite/realistic/rm2/6.png)

Great! We solved the challenge.


---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

# References
