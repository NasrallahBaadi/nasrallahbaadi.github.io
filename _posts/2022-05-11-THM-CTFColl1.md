---
title: "TryHackMe - CTF Collection vol 1"
author: Nasrallah
description: ""
date: 2022-05-11 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, steganography, cipher, xxd, wireshark]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [CTF Collection vol 1](https://tryhackme.com/room/ctfcollectionvol1) from [TryHackMe](https://tryhackme.com).

# What does the base said?

In this task, we're given the following encoded string: VEhNe2p1NTdfZDNjMGQzXzdoM19iNDUzfQ==

By the looks of it, it seems like a base64. We can go to [CyberChef](https://gchq.github.io/CyberChef/) and decode it.

![](/assets/img/tryhackme/ctfcoll/1.png)

We can also put the string in a file and decode it using the command `base64`.

![](/assets/img/tryhackme/ctfcoll/2.png)

# Meta meta.

When we download the task file, we see that it's an image. To view the meta data of an image, we can use `exiftool`.

![](/assets/img/tryhackme/ctfcoll/3.png)

# Mon, are we going to be okay?

Something is hiding. That's all you need to know.

The file task is a jpg image, and there is some hidden content in it. The term we use for this technique is `Steganography`, and it is basically the practice of hiding one file within another.

To extract the hidden content in an image, we can use a tool called `steghide`.

![](/assets/img/tryhackme/ctfcoll/4.png)


# Erm......Magick

In this task, there is no file to download, so the flag must be in the task, but we don't see anything.

![](/assets/img/tryhackme/ctfcoll/5.png)

If we select the text in this task, we can actually see the flag.

![](/assets/img/tryhackme/ctfcoll/6.png)

# QRrrr

Downloading the task file we see that it's an image of a QR code. We can upload the image to an online qr code reader or use a smart phone to read it. I used this [Website](https://zxing.org/)

![](/assets/img/tryhackme/ctfcoll/7.png)


# Reverse it or read it?

The task file is a program that prints some text when we it's run.

![](/assets/img/tryhackme/ctfcoll/8.png)

The title of this task says we can reverse it or read it. We can use the command `strings` that looks for human-readable characters in a file, and see if we can find the flag this way.

![](/assets/img/tryhackme/ctfcoll/9.png)

# Another decoding stuff

In this task, we got another encoded string : 3agrSy1CewF9v8ukcSkPSYm3oKUoByUpKG4L

We can use [CyberChef](https://gchq.github.io/CyberChef/) to identify the encoding scheme using the magic operation.

![](/assets/img/tryhackme/ctfcoll/10.png)

The magic operation identifies string as a base58. We can now use `from base58` operation to decode it.

![](/assets/img/tryhackme/ctfcoll/11.png)

# Left or right

Left, right, left, right... Rot 13 is too mainstream. Solve this

We are given the following : MAF{atbe_max_vtxltk}

At the first glance, this look like a rot13, but it's not, if we check the hint, it says it's a caesar cipher. We can search on google for a caesar cipher decoder and get plenty of websites. In my case, i use this [website](https://www.dcode.fr/caesar-cipher).

Since we don't have a key, this website can brute force the key and decode the flag.

![](/assets/img/tryhackme/ctfcoll/12.png)

# Make a comment

No downloadable file, no ciphered or encoded text. Huh .......

Let's check the source code of the page for any comments.

![](/assets/img/tryhackme/ctfcoll/13.png)


# Can you fix it?

I accidentally messed up with this PNG file. Can you help me fix it? Thanks.

If we try to open the image we get this.

![](/assets/img/tryhackme/ctfcoll/14.png)

Let's check the file type using the command `file`.

![](/assets/img/tryhackme/ctfcoll/15.png)

It's says data while it should be PNG image. Let's now check the magic numbers of the file.

>Magic numbers are the first frw bytes of a file that are uniq to a particular file type.

![](/assets/img/tryhackme/ctfcoll/16.png)

Now let's search for png's magic numbers if the ones is the file are correct.

![](/assets/img/tryhackme/ctfcoll/17.png)

We found the correct numbers, now let's fix the file. To do that, we can use hexedit.

![](/assets/img/tryhackme/ctfcoll/18.png)


TO change a byte using hexedit, you simply have to move the cursor over a byte and type what you would like to. In our case, we need to replace `2333 445f 0d0a 1a0a` with `89 50 4E 47 0D 0A 1A 0A`. 

![](/assets/img/tryhackme/ctfcoll/19.png)

To save the changes, press `ctrl` + `X` and then `y`.

Now let's check the changes.

![](/assets/img/tryhackme/ctfcoll/20.png)

![](/assets/img/tryhackme/ctfcoll/20-2.png)

Great! We fixed the file, now let's open it and get the flag.

![](/assets/img/tryhackme/ctfcoll/21.png)


# Read it

Some hidden flag inside Tryhackme social account.

If we check tryhackme's subreddit, we can find the flag in one of the posts.

![](/assets/img/tryhackme/ctfcoll/22.png)

# Spin my head

What is this?

`++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>++++++++++++++.------------.+++++.>+++++++++++++++++++++++.<<++++++++++++++++++.>>-------------------.---------.++++++++++++++.++++++++++++.<++++++++++++++++++.+++++++++.<+++.+.>----.>++++.`

This is a `brainfuck` code, `brainfuck` is a programming language. I used this [website](https://www.dcode.fr/brainfuck-language) in order to execute this code.

![](/assets/img/tryhackme/ctfcoll/23.png)

# An Exclusive!

Exclusive strings for everyone!

S1: 44585d6b2368737c65252166234f20626d
S2: 1010101010101010101010101010101010

In the hint we have `XOR`, searching for this xor thing, i found this [website](https://xor.pw/) that we can use to get the flag.

![](/assets/img/tryhackme/ctfcoll/24.png)

# Binary walk

We can use a tool called `binwalk` that searches binary images for embedded files and executable code.

![](/assets/img/tryhackme/ctfcoll/25.png)

# Darkness

The task file is an image, when we open it, we see that it's all dark.

We can use a tool called `stegoveritas`.

![](/assets/img/tryhackme/ctfcoll/26.png)

# A Sounding QR

We got another qr code, let's upload it to this[website](https://zxing.org/).

![](/assets/img/tryhackme/ctfcoll/27.png)

We got a link to a soundcloud clip, and it spells it to us.


# Dig up the past

Sometimes we need a 'machine' to dig the past

Targeted website: https://www.embeddedhacker.com/
Targeted time: 2 January 2020

In order to see a website at a specific time in the past, we can use the [WayBackMachine](https://archive.org/)

![](/assets/img/tryhackme/ctfcoll/28.png)

Now enter the targeted website and press enter.

![](/assets/img/tryhackme/ctfcoll/29.png)

Now let's select 2020 and go to 2nd january.

![](/assets/img/tryhackme/ctfcoll/30.png)

Now hover the mouse over the number 2 and click the clock time.

![](/assets/img/tryhackme/ctfcoll/31.png)

# Uncrackable!

Can you solve the following? By the way, I lost the key. Sorry >.<

MYKAHODTQ{RVG_YVGGK_FAL_WXF}

Flag format: TRYHACKME{FLAG IN ALL CAP}

This looks like a vigenere cipher, we don't have a key, but we know that it starts with TRYHACKME. Let's got to [dcode website](https://www.dcode.fr/vigenere-cipher).

![](/assets/img/tryhackme/ctfcoll/32.png)

Since we don't have a key, we selected `knowing a plain text word` and entered `TRYHACKME`, with that, we were able to retrieve the flag.

# Small bases

decode the following text.

581695969015253365094191591547859387620042736036246486373595515576333693

The hints says `dec -> hex -> ascii`. We have to convert this decimal text to hex, and then to ascii. We can use this [Website](https://www.binaryhexconverter.com/).

![](/assets/img/tryhackme/ctfcoll/33-1.png)

Now select decimal to hex converter, and convert the text.

![](/assets/img/tryhackme/ctfcoll/33.png)

Copy the result and go back to select hex to ascii converter, and convert to get the flag.

![](/assets/img/tryhackme/ctfcoll/34.png)

# Read the packet

Now with the final challenge, we need to read a packet. Let's load the file to `wireshark` and investigate the packets.

Let's search for the word `flag`, we ca do that by pressing `ctrl + F`, select string and type the word flag, then press `Find`.

![](/assets/img/tryhackme/ctfcoll/35.png)

Great! We found the packet, now right click the packet -> follow > http stream

![](/assets/img/tryhackme/ctfcoll/36.png)

With that, we have successfully completed this wonderful room.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
