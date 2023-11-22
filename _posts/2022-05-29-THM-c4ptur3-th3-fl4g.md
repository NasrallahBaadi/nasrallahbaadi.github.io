---
title: "TryHackMe - c4ptur3th3fl4g"
author: Nasrallah
description: ""
date: 2022-05-29 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, easy, spectrogram, steganography, encoding]
img_path: /assets/img/tryhackme/capture/
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


##**Description**

Hello hackers, I hope you are doing well. We are doing [c4ptur3th3fl4g](https://tryhackme.com/room/c4ptur3th3fl4g) from [TryHackMe](https://tryhackme.com).

## **Translation & Shifting**

Translate, shift and decode the following.


### #1 : c4n y0u c4p7u23 7h3 f149?


This one looks like leetspeak, we need to replace the numbers with their corresponding letters.

0 = O | 1 = I | 2 = Z | 3 = E | 4 = A | 5 = S | 6 = G | 7 = T | 8 = B | 9 = g


`ans : can you capture the flag?`

### #2

This one is binary, we can go to [CyberChef](https://gchq.github.io/CyberChef/) and convert it.

![](1.png)

### #3 : MJQXGZJTGIQGS4ZAON2XAZLSEBRW63LNN5XCA2LOEBBVIRRHOM======

This one looks a base. Let's use [CyberChef](https://gchq.github.io/CyberChef/).

![](2.png)

It's a bse32.

### #4 : RWFjaCBCYXNlNjQgZGlnaXQgcmVwcmVzZW50cyBleGFjdGx5IDYgYml0cyBvZiBkYXRhLg==

This is base64.

![](3.png)

### #5 : 68 65 78 61 64 65 63 69 6d 61 6c 20 6f 72 20 62 61 73 65 31 36 3f

This one is hex.

![](4.png)

### #6 : Ebgngr zr 13 cynprf!

I see the number 13, so i'm guessing it's rot13.

![](5.png)

### #7 : *@F DA:? >6 C:89E C@F?5 323J C:89E C@F?5 Wcf E:>6DX

This is rot47.

![](6.png)

### #8 : - . .-.. . -.-. --- -- -- ..- -. .. -.-. .- - .

This looks like morse code.

![](7.png)

### #9 : 85 110 112 97 99 107 32 116 104 105 115 32 66 67 68

This is decimal.

![](8.png)

### #10 : LS0tLS0gLi0tLS0gLi0tLS0gLS0tLS0gLS0tL

We got a very long string here, let's inspect it.

![](9.png)

We see that the string ends with an equal sign, which can be a base64.

![](10.png)

After we decoded it, it gave us a morse code.

![](11.png)

Morse code gave a hex code.

![](12.png)

The hex gives a rot47.

![](13.png)

We decode that and get decimal.

![](14.png)

And this was the final one.

## **Spectrograms**

A spectrogram is a visual representation of the spectrum of frequencies of a signal as it varies with time. When applied to an audio signal, spectrograms are sometimes called sonographs, voiceprints, or voicegrams. When the data is represented in a 3D plot they may be called waterfalls.

Let's download the task file and open it with `sonic-visualizer`.

```terminal
sonic-visualiser secretaudio.wav
```

![](15.png)

Now we need to add a spectrogram layer by going to `Layer -> Add Spectrogram` or pressing `shift + G`.

![](16.png)


## **Steganography**

Steganography is the practice of concealing a file, message, image, or video within another file, message, image, or video.

Let's download the task file.

In order to extract files from images, we can use a tool called `steghide`.

```terminal
Steghide extract -sh stegosteg.jpg`
```

After that we submit an empty password.

![](17.png)


## **Security through obscurity**

Security through obscurity is the reliance in security engineering on the secrecy of the design or implementation as the main method of providing security for a system or component of a system.

After downloading the task file, we run the command `strings` on the file.

```terminal
Strings meme.jpg
```

![](18.png)

At the very end we can see the answer to the last questions.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References
