---
title: "HCMUS-CTF 2023"
description: "Write up for rev problem in hcmusctf-2023"
summary: "Write up for rev problem in hcmusctf-2023"
categories: ["Writeup"]
tags: ["Reverse", "CTF","Honors"]
#externalUrl: ""
date: 2023-05-08
draft: false
authors:
  - Jinn
---
# HCMUS-CTF 2023

Hi, I'm Jinn
As a reverser of the team, I try my best on 2 challenge: `Is that crypto?` and `Go Mal!`. These 2 challenges are fantastic and so cool. Btw, I also solve some other easy problems like `Japanese`, `python is safe?`, `grind`.Therefore, I will provide detailed explanations for 2 reverse challenges and briefly mention the remaining ones.

## Rev + Crypto: Is this crypto?

Challenge file: [main](https://anonfiles.com/53deY2pfz2/main)

IDA .i64 file (renamed function, variable): [main.i64](https://anonfiles.com/gfe5Y1p3z1/main_i64)

This challenge give me binary written in C++, but it seem clearly and without any strip, here is inside of main function:

![](https://hackmd.io/_uploads/Syr6yW8V3.png)

As we can see, it take 2 input as name and favorite_word, check them before encrypt flag.txt.

If name and favorite_word are true, they will calculate key and IV from them like this:

```
key = SHA256(name)
IV = MD5(favorite_word)
```

They used these agrument for `enc` function, we easily confirm that function just a normal AES mode CBC. 

![](https://hackmd.io/_uploads/Hy5jlbU4h.png)

So, in order to find `name` and `favorite_word`, we need to look deep into function `check()`:

![](https://hackmd.io/_uploads/B1eBZWL43.png)

>Btw, to identify some function like: base64, hash function, or something. We can use yara-findcrypt (an IDA plugin) to easily detect them.

We can see there are 2 array `v8` and `v9`. Each array contain total 28 bytes and it compare with return value of function `sus(name) or sus(word)`.

![](https://hackmd.io/_uploads/Sy2Df-8E2.png)

Look into that funtion, Im sure that is SHA224 (some sha224 constant is here) so, I have an idea:

``Take v8 and v9 convert they to hex and using crack station to break these hash``

```python
import hashlib
v8 = [0]*7
v8[0] = "ACB7842B"
v8[1] = "5DFEBCAF"
v8[2] = "33801F1C"
v8[3] = "4F3FB333"
v8[4] = "A8F98777"
v8[5] = "CE40F926"
v8[6] = "EC339422"
v8 = [bytes.fromhex(i)[::-1] for i in v8] #little endian
print(b''.join(v8).hex())
#output: 2b84b7acafbcfe5d1c1f803333b33f4f7787f9a826f940ce229433ec
```
But there is no result:

![](https://hackmd.io/_uploads/SyTd7-8E3.png)

I confuse in a time, I debug this file and type 'a' as name and check output of this hash, here is what I got:

```python
print('sha224 name:', hashlib.sha224(b'a').hexdigest())
#output: "sha224 name: abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5"
```

and I saw a hash while debugging:

![](https://hackmd.io/_uploads/SJUhNZLEh.png)


![](https://hackmd.io/_uploads/BkwoEZLV3.png)

Look different, but when I compare this sha224 funtion and sha256 (sha224 differs from sha256 only in blocksize and constant) funtion given I see this:

![](https://hackmd.io/_uploads/S1_KBb8Vh.png)

Right side is sha256 function, and it has switch endian before return and sus function don't. So we just need to change the endian of v8 and v9:

```python
import hashlib
v8 = [0]*7
v8[0] = "ACB7842B"
v8[1] = "5DFEBCAF"
v8[2] = "33801F1C"
v8[3] = "4F3FB333"
v8[4] = "A8F98777"
v8[5] = "CE40F926"
v8[6] = "EC339422"
v8 = [bytes.fromhex(i) for i in v8] #big endian
print(b''.join(v8).hex())
#output: acb7842b5dfebcaf33801f1c4f3fb333a8f98777ce40f926ec339422
```

And we got name:

![](https://hackmd.io/_uploads/B1fhIbLE2.png)

similar to favorite_word:

![](https://hackmd.io/_uploads/r1-C8W84h.png)

Then we have `name` and `favorite_word`, we easily decrypt the flag:

```python
key = hashlib.sha256(b'recis').digest()
iv = hashlib.md5(b'cannibalization').digest()

aes = AES.new(key,AES.MODE_CBC,iv)
with open('flag.txt.enc','rb') as f:
    d = f.read()
    print(aes.decrypt(d))
#output: b'HCMUS-CTF{r_u_ready_for_fREddy?}\x10\x10\...'
```
Full script here: [solve.py]()

Flag: `b'HCMUS-CTF{r_u_ready_for_fREddy?}`

## Rev: Go Mal!

Challenge file: [server]([server](https://anonfiles.com/Sbn9Yep7z5/server))

IDA .i64 file (added breakpoint): [server.i64](https://anonfiles.com/t0o7Y4p9z4/server_i64)

This program written in Golang, so it little hard, as a first time I see it, I'm clueless about this main funtion:V

![](https://hackmd.io/_uploads/S1FTO-8Nh.png)

After trying to run thi file, I see something:

![](https://hackmd.io/_uploads/S1RmKbUV2.png)

Server have 2 while loop to listen something from client. We can see that server receive a hash and print out ~60 hash.

So, we start from string and find "flag", I see it:

![](https://hackmd.io/_uploads/ByJRtb8Vn.png)

Reference to this string, I found the compare code:

![](https://hackmd.io/_uploads/B10zc-LNn.png)

and the main key:

![](https://hackmd.io/_uploads/SyZZcZ8Nh.png)

Here is the code we focused:

![](https://hackmd.io/_uploads/rkZDcW8E2.png)

>To debug this file, we need to attach in stead of direct debug because golang has built-in anti-debug (perhaps). So we need to run `./server`, using IDA attach option, add breakpoint and debug them.

I debugged many time and I got something, let me explain:

This function receive a hash and get the current time:

![](https://hackmd.io/_uploads/Hk059Z8E2.png)

After that, in a while loop, rely on the timestamp, it calculate something and save in `int64buf.array`

![](https://hackmd.io/_uploads/rJp_jWI42.png)

They using 8 bytes of `int64buf.array` to calculate the hmac hash (with the main key given)

![](https://hackmd.io/_uploads/S15ps-84n.png)

Then, this hash converted to hex and compare with our input. If they are same, it will print flag.

![](https://hackmd.io/_uploads/HJ9_2WUV3.png)

So, the problem is how it `int64.array` was caculated? In the time I debug this file, I see this array in this format:

```python
byte1 + byte2 + b"Vd" + b"\x00"*4
```
> b"Vd" may different in this time, you need to debug and get another one

So, we just need to find 2 bytes, and it must be same with one of 60 hash given.

I used this script to testing something:

```python
sus = """70f181860de673250e2548df1fe51014473af59022866ea9c9db8bbdbd963798"""
main_key = b'Bj7tSK6L4E8tmVebTzH0O0ylb1dTcdpahryyGi2of3q3TLXJxeNYdeUFveFehbOWqrjFQAxV4EF9Rb4c'
for i in range(255):
    for j in range(255):
        array = bytes([100,75]) +b'Vd' + b'\x00'*4
        signature = hmac.new(main_key,msg=array,digestmod=hashlib.sha256).digest()
        if signature.hex() in sus:
            print(i,j,bytes([i,j]))
            break
#output: 45 75 b'-K'
```

with sus is one of hash I got from 60 hash server print out.

As we can see, it's just 2 number and after I try with 60 hash in a time I see `j` permanent and `i` is 60 consecutive numbers.

So, to get flag, we need to choose new_j near and greater than `j` (example: 76 maybe)
and `i` is random in range [0,255]

```python
array = bytes([100,76]) +b'Vd' + b'\x00'*4
signature = hmac.new(main_key,msg=array,digestmod=hashlib.sha256).digest()
while True:
    r = remote("go-mal.chall.ctf.blackpinker.com", 443, ssl=True)
    r.send(signature.hex().encode())
    rec = r.recv(1024)
    if b"{" in rec:
        print(rec)
        break
    # r.interactive()
    r.close()
```
Just wait several minute, and I get flag:

![](https://hackmd.io/_uploads/H1OSefUN3.png)

Flag: `HCMUS-CTF{1_us3_t1mest4Mp_W1tH_k3y_T0_4UTHENT1c4t3d_dATA}`

## PWN: Python is safe?

Code:
```python=
#!/usr/bin/env python3

from ctypes import CDLL, c_buffer
libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
buf1 = c_buffer(512)
buf2 = c_buffer(512)
libc.gets(buf1)
if b'HCMUS-CTF' in bytes(buf2):
    print(open('./flag.txt', 'r').read())
```

It's just bufferover flow (buf1) by using `gets()`. 

Calc Payload:
```bash
python3 -c 'print("a"*612 + "HCMUS-CTF")'
```
## Grind

This one little guessing, in the first time, as descsription given, I try using this query:

```sql
select DISTINCT uid,name from ranking where (uid like "23______" or uid Like "24______" )and points > 900000000 and points < 1000000000
INTERSECT
select DISTINCT uid,name from 'data-64-final'.ranking where (uid like "23______" or uid Like "24______" ) and rank  > 5000 
and name REGEXP '^[a-zA-Z0-9]+$'
ORDER BY name ASC
```
>23 or 24 mean uid right before 2019

Nothing interested
![](https://hackmd.io/_uploads/BymnGNIE3.png)

So, at the last time, I see my query has wrong point condition, so I changed this query like this:

```sql
select * from "data-64-final".ranking as df where df.uid in
(select day2.uid from 'data-64-day2'.ranking as day2, ranking as day3 where (day3.uid like "23______" or day3.uid Like "24______" )and (day3.points - day2.points between 900000000 and 1000000000) and day2.uid = day3.uid
INTERSECT
select fn.uid from 'data-64-final'.ranking as fn where (fn.uid like "23______" or fn.uid Like "24______" ) and rank  > 5000)
```

And here is result:

![](https://hackmd.io/_uploads/ryUAO4LN3.png)

As we can see that user name ζ(2) is sussy and this is: Zeta function

![](https://hackmd.io/_uploads/S1R0wE84h.png)

![](https://hackmd.io/_uploads/HyYzu48Nn.png)


Flag:`HCMUS-CTF{23983477-1.6449340668-2391789368-9614}`
