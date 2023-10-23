---
title: "TryHackMe - Crack the hash"
author: Nasrallah
description: ""
date: 2022-05-13 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, cracking, hashcat]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


# **Description**

Hello hackers, I hope you are doing well. We are doing [Crack the hash](https://tryhackme.com/room/crackthehash) from [TryHackMe](https://tryhackme.com).

# **Level 1**

## Hash 1

### Hashcat

To crack a hash using `hashcat` we first need to know the type of the hash since hashcat does not auto identify the hash. For that, we can use `hash-identifier`.

![](/assets/img/tryhackme/crackthehash/2.png)

This one is `MD5`, We can use thi [Table](https://hashcat.net/wiki/doku.php?id=example_hashes) provided by `hashcat` in order to know what hash-mode to use. In our case, the hash-mode for md5 is **0**.

`hashcat -m 0 hash_file /usr/share/wordlists/rockyou.txt`

![](/assets/img/tryhackme/crackthehash/3.png)

### CrackStation

We can use [CrackStation](https://crackstation.net/) that uses tables to crack unsalted passwords. Let's give it our first password.

![](/assets/img/tryhackme/crackthehash/1.png)

## Hash 2

### Hashcat

Let's use `hash-identifier`.

![](/assets/img/tryhackme/crackthehash/4.png)

It's a `SHA-1` hash, and the hash-mode for it is 100.

`hashcat -m 100 hash_file /usr/share/wordlists/rockyou.txt`

![](/assets/img/tryhackme/crackthehash/5.png)


### CrackStation

Let's give the hash to crackstation.

![](/assets/img/tryhackme/crackthehash/6.png)

## Hash 3

### Hashcat

Let's identify the hash.

![](/assets/img/tryhackme/crackthehash/7.png)

It's `SHA-256`, the hash-mode is **1400**

`hashcat -m 1400 hash_file /usr/share/wordlists/rockyou.txt`

![](/assets/img/tryhackme/crackthehash/8.png)

### CrackStation

On crackstation:

![](/assets/img/tryhackme/crackthehash/9.png)

## Hash 4

We ca see that this hash is salted, so we can't use crackstation.

### Hashcat 

To identify the hash, i googled the first 4 characters `$2y$`.

![](/assets/img/tryhackme/crackthehash/10.png)

The hash type is `bcrypt`, and the hash-mode is **3200**.

Before start cracking, we see that the hint suggests to filter rockyou for 4 character words because this type of hashes take a long time. We can do that with the following command.

![](/assets/img/tryhackme/crackthehash/11.png)

Now, let's start cracking.

`hashcat -m 3600 hash_file ./list`

![](/assets/img/tryhackme/crackthehash/12.png)


## Hash 5

### Hashcat 

Let's identify the hash.

![](/assets/img/tryhackme/crackthehash/13.png)

It's `MD4`, the hash-mode is **900**

`hashcat -m 900 hash_file /usr/share/wordlists/rockyou.txt`

I couldn't crack it because the password is not in rockyou.txt. Let's try crackstation. 

### CrackStation

If we give the hash to crack station, it manages to crack it.

![](/assets/img/tryhackme/crackthehash/14.png)


# **Level 2**

We will only be using `hashcat` in this level. Let's start.

## Hash 1

Hash-identifier:

![](/assets/img/tryhackme/crackthehash/15.png)

It's `SHA-256`, the hash-mode is **1400**

`hashcat -m 1400 hash_file /usr/share/wordlists/rockyou.txt`

![](/assets/img/tryhackme/crackthehash/16.png)

## Hash 2 

This one is a `NTLM` hash, the hash-mode for it is **1000**.

`hashcat -m 1000 hash_file /usr/share/wordlists/rockyou.txt`

![](/assets/img/tryhackme/crackthehash/17.png)


## Hash 4

This one is a `sha512crypt` hash, the hash-mode is **1800**

`hashcat -m 1800 hash_file /usr/share/wordlists/rockyou.txt`

This can a long time, so the password is **waka99**

## Hash 5

The hash is `sha1`, the hash-mode is **110**.

`hashcat -m 110 hash_file /usr/share/wordlists/rockyou.txt`

The password is : **481616481616**

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

# References
