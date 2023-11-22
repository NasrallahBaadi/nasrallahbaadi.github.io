---
title: "TryHackMe - Ninja Skills"
author: Nasrallah
description: ""
date: 2022-10-19 00:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, regex, find, grep]
img_path: /assets/img/tryhackme/ninjaskills
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---


## **Description**

Hello hackers, I hope you are doing well. We are doing [Ninja Skills](https://tryhackme.com/room/ninjaskills) from [TryHackMe](https://tryhackme.com).


## Q1

Which of the above files are owned by the **best-group** group.

We're gonna use `find` with the following options:

```bash
find / -type f -group best-group 2>/dev/null
```

```terminal
[new-user@ip-10-10-164-110 ~]$ find / -type f -group best-group 2>/dev/null
/mnt/D8B3
/home/v2Vb
```

## Q2

Which of these files contain an IP address?

We can use this regex `[0-9][0-9]*[.][0-9][0-9]*[.][0-9][0-9]*[.][0-9][0-9]*` for IP addresses along with `grep` with -Eo option. Then we add that to a new find command like the following.

```bash
find / -type f -exec grep -E -o '[0-9][0-9]*[.][0-9][0-9]*[.][0-9][0-9]*[.][0-9][0-9]*' {} \; 2>/dev/null
```

But this would return every file in the system that has an ip address, so we're gonna tune our find command to search in the files provided by the room.

```bash
find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiMO -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) 2>/dev/null
```

Our final command would look like this:

```bash
find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiMO -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) -exec grep -E -o '[0-9][0-9]*[.][0-9][0-9]*[.][0-9][0-9]*[.][0-9][0-9]*' * {} \; 2>/dev/null
```

## Q3

Which file has the SHA1 hash of 9d54da7584015647ba052173b84d45e8007eba94 ?

We'll the find command with `sha1sum`.

```bash
find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiMO -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) -exec sha1sum {} \; 2>/dev/null
```

```terminal
[new-user@ip-10-10-174-113 ~]$ find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiMO -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) -exec sha1sum {} \; 2>/dev/null

2c8de970ff0701c8fd6c55db8a5315e5615a9575  /mnt/D8B3
9d54da7584015647ba052173b84d45e8007eba94  /mnt/c4ZX
d5a35473a856ea30bfec5bf67b8b6e1fe96475b3  /var/FHl1
57226b5f4f1d5ca128f606581d7ca9bd6c45ca13  /var/log/uqyw
256933c34f1b42522298282ce5df3642be9a2dc9  /opt/PFbD
5b34294b3caa59c1006854fa0901352bf6476a8c  /opt/oiMO
4ef4c2df08bc60139c29e222f537b6bea7e4d6fa  /media/rmfX
0323e62f06b29ddbbe18f30a89cc123ae479a346  /etc/8V2L
acbbbce6c56feb7e351f866b806427403b7b103d  /etc/ssh/SRSq
7324353e3cd047b8150e0c95edf12e28be7c55d3  /home/v2Vb
59840c46fb64a4faeabb37da0744a46967d87e57  /X1Uy

```

## Q4

Which file contains 230 lines?

Again, the find command with `wc -l`.

```bash
find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiMO -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) -exec wc -l {} \; 2>/dev/null
```

```terminal
209 /mnt/D8B3
209 /mnt/c4ZX
209 /var/FHl1
209 /var/log/uqyw
209 /opt/PFbD
209 /opt/oiMO
209 /media/rmfX
209 /etc/8V2L
209 /etc/ssh/SRSq
209 /home/v2Vb
209 /X1Uy
```

One file here is missing. It's the one we're looking for.

## Q5

Which file's owner has an ID of 502?

Find command with `ls -ln`

```bash
find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiMO -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) -exec ls -ln {} \; 2>/dev/null
```

```terminal
-rw-rw-r-- 1 501 502 13545 Oct 23  2019 /mnt/D8B3
-rw-rw-r-- 1 501 501 13545 Oct 23  2019 /mnt/c4ZX
-rw-rw-r-- 1 501 501 13545 Oct 23  2019 /var/FHl1
-rw-rw-r-- 1 501 501 13545 Oct 23  2019 /var/log/uqyw
-rw-rw-r-- 1 501 501 13545 Oct 23  2019 /opt/PFbD
-rw-rw-r-- 1 501 501 13545 Oct 23  2019 /opt/oiMO
-rw-rw-r-- 1 501 501 13545 Oct 23  2019 /media/rmfX
-rwxrwxr-x 1 501 501 13545 Oct 23  2019 /etc/8V2L
-rw-rw-r-- 1 501 501 13545 Oct 23  2019 /etc/ssh/SRSq
-rw-rw-r-- 1 501 502 13545 Oct 23  2019 /home/v2Vb
-rw-rw-r-- 1 502 501 13545 Oct 23  2019 /X1Uy
```

## Q6

Which file is executable by everyone?

```bash
find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiMO -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) -exec ls -l {} \; 2>/dev/null
```

```teminal
-rw-rw-r-- 1 new-user best-group 13545 Oct 23  2019 /mnt/D8B3
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /mnt/c4ZX
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /var/FHl1
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /var/log/uqyw
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /opt/PFbD
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /opt/oiMO
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /media/rmfX
-rwxrwxr-x 1 new-user new-user 13545 Oct 23  2019 /etc/8V2L
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /etc/ssh/SRSq
-rw-rw-r-- 1 new-user best-group 13545 Oct 23  2019 /home/v2Vb
-rw-rw-r-- 1 newer-user new-user 13545 Oct 23  2019 /X1Uy

```

We can see only one file with x permission.

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).
