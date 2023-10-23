---
title: "HackThisSite - Peace Poetry: HACKED"
author: Nasrallah
description: ""
date: 2022-05-23 00:00:00 +0000
categories : [HackThisSite, Realistic]
tags: [hackthissite, hts, easy, web, realistic]
---

![](/assets/img/hackthissite/realistic/rm3/banner.png)

---


# **Description**

Hello l33ts, I hope you are doing well. We will be doing [Peace Poetry: HACKED](https://www.hackthissite.org/missions/realistic/1/) from [HackThisSite](https://www.hackthissite.org/), the 3rd challenge of the **realistic missions**.


# **Solution**

The challenge has the following message.

![](/assets/img/hackthissite/realistic/rm3/0.png)

Let's navigate to that [page](https://www.hackthissite.org/missions/realistic/3/).

![](/assets/img/hackthissite/realistic/rm3/1.png)

We can see what the hacker has posted on the page, Let's check the source code.

![](/assets/img/hackthissite/realistic/rm3/2.png)

At the bottom of the source code, we can see a comment from the hacker stating that the old website is still up, and he copied the old index.html file to oldindex.html. Let's add that file to the url 'https://www.hackthissite.org/missions/realistic/3/oldindex.html'

![](/assets/img/hackthissite/realistic/rm3/3.png)

Great! This is the original page.

We can also see two sections, the first one is **Read The Poetry** where we can read different poems, and the other one is **Submit Poetry**, and it's the one the hacker used to change the page.

![](/assets/img/hackthissite/realistic/rm3/4.png)

The way this form works is we specify a name for the poem and the poem itself. When we click `add poem` button, the program creates a file and name it with the poem name we choose earlier and writes the poem to the file, it's looks something like this:

```bash
echo "The poem" > NameOfPoem
```

So if we choose a poem name and there is a file with the same name, we could delete the content of that file and replace it with what we put in the Poem.

What the attacker did is choose the name of the poem as **../index.html** and put the content he wanted to display as a poem. With that the program has replaced the content of index.html which is one directory up (../):

```bash
echo "hacker" > ../index.html
```

To solve the challenge, we need to specify the name of the poem as **../index.html** and put the source code of **oldindex.html** file as a poem so that we can restore the old page.

![](/assets/img/hackthissite/realistic/rm3/5.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

# References
