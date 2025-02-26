---
title: "UIUCTF 2024"
description: "Writeup for UIUCTF 2024"
summary: "Writeup for UIUCTF 2024"
categories: ["Writeup"]
tags: ["Reverse"]
#externalUrl: ""
date: 2024-07-06
draft: false
authors:
  - Jinn
cover: /images/post_covers/uiuctf2024.jpeg
---

# UIUCTF 2024

At the weekend, our team **CoSGang** from the **Vietnamese Gang** joined UIUCTF 2024 and got into the top 5 (1 point above the top 6), big shoutout to my team for fair plays, they got into The Liems and has good prize. Also, this is the third time we have played UIUCTF, special thanks to the organizer for a good CTF.

![image](https://hackmd.io/_uploads/BJvfkvlDA.png)

## Goose Chase/ Wild Goose Chase

>    **Goose Chase**
>    Author: ronanboyarski
> 
>    Description: The threat group GREGARIOUS GOOSE has hacked into SIGPwny servers and stolen one of our flags! Can you use the evidence to recover the flag?
>
> WARNING: This challenge contains malware that may read images on your hard disk. Ensure that you do not have anything sensitive present.
> 
>Attachments:
    - Goose.DMP
    - evidence.pcapng

Firstly, I think Goose Chase and Wild Goose Chase are the same. Because of Goose Chase has an unintended solution. So **Wild Goose Chase** like a revenge challenge.

Therefore, the greatest part is I spent 3 hours on the first one, and then one of my teammates said that he submitted the flag after looking for a couple of minutes. I've been surprised and realize that we just need to use `strings` and `grep` on `Goose. dmp` 🤣🤣🤣.

![image](https://hackmd.io/_uploads/H1i30DlPR.png)

Okay just for fun, at least I know that I'm not wasting 3 hours on the challenge, thanks for the revenge. So the next part is only an analysis of the Goose Chase, which is only different from others based on the traffic captured and the .dmp file. 

### Approach

I've looked into the Pcap capture file, there is some suspicious traffic in here. I see that they have sent each other a Windows executable, and the remaining like encrypted traffic.

An executable:

![image](https://hackmd.io/_uploads/rJgSHdlP0.png)

Others:

![image](https://hackmd.io/_uploads/HJBkLulPC.png)

After I used the export object and obtained the binary. I use IDA to analyze it:

![image](https://hackmd.io/_uploads/r1vDduxv0.png)

Rely on the main function, I found the `main_process` that does all the stuff here:

![image](https://hackmd.io/_uploads/rkIoOulPA.png)


I've taken the time to rename and comment on the code for clarity and easy reference. Before we dive deeper into the analysis, I used the flare-capa IDA plugin to get an overall view of the code's structure and functionality. 

Here's the result:

![image](https://hackmd.io/_uploads/SJhJ9ueD0.png)

It's not correct at all but the preliminary step should help us identify key areas to focus on and streamline our investigation.

First, I see the function decode a string as the path of ntdll.dll: "C:\Windows\System32\ntdll.ll", probably used for resolving this library later.

![image](https://hackmd.io/_uploads/ryfK5Oxw0.png)

I'm sure that I can't reverse all of the functions correctly, but at least I can understand their behavior while performing static analysis and debugging. This process helps me grasp the overall functionality and identify critical parts of the code, even if some details remain unclear.

Check for MZ and PE header:

![image](https://hackmd.io/_uploads/r1QUhOlvA.png)

![image](https://hackmd.io/_uploads/rkaOndgP0.png)

Resolve the function name of `ntdll.dll` and other dll:

![image](https://hackmd.io/_uploads/r1xm2OxvA.png)

Okay, here is the part we need to focus on, they're resolve functions from the library and call them:

![image](https://hackmd.io/_uploads/BJ1VTOgvC.png)

When I look around, I see the Unzip_data function (I renamed):

```c
void __noreturn Unzip_data()
{
  Unzip_process();
  Exit_process(0xBEEFu);
}
```

I've reversed and found the Zipped data, then I extracted it as a file and unzip:

![image](https://hackmd.io/_uploads/HJlgBfQvC.png)

![image](https://hackmd.io/_uploads/HJ5fHGQDA.png)

After unzipped:

![image](https://hackmd.io/_uploads/rkg34SfXvA.png)

It's just a gooose game, it grabs your mouse and runs away, very fun haha but our flag is not here:

![image](https://hackmd.io/_uploads/r185HfXw0.png)

![image](https://hackmd.io/_uploads/B1heIfQwR.png)

I also found an AES process, and it's the main one we need to focus on:

![image](https://hackmd.io/_uploads/rypKUGQDA.png)

We easily see the key in the AES_keyschedule function:

![image](https://hackmd.io/_uploads/BJSnYMmwA.png)

I see it using AES CBC mode, here is the IV:

![image](https://hackmd.io/_uploads/S1SlKzXwA.png)


It copied the buffer with length 0x106e0e0, as well as the encrypted buffer.


```python
from Crypto.Cipher import AES


with open('suspicious_buffer','rb') as f:
    data = f.read()

aes = AES.new(b"uiuctf{NO_THIS_FLAG_AIN'T_IT321}",AES.MODE_CBC,b'YOU\\?_+GITGOOSED')
dec = aes.decrypt(data)
print(dec[:100])
with open('dropped.exe','wb') as wf:
    wf.write(dec[0xe55:])
```

After decrypting it, I loaded the decrypted buffer into IDA and found the MZ header, then I dumped it as `dropped.exe`.

### The dropped binary

After loading into IDA, I also use the old method. I used plugins flare-capa and findcrypt, and I found some helpful results:

![image](https://hackmd.io/_uploads/H1IoazmPR.png)

And here is main function:

![image](https://hackmd.io/_uploads/Sks6af7wA.png)

The first time I tried it debug with Assembly code, there was a simple anti-debugger using IsDebuggerPresent (found in the obfuscated string) and syscall.

```c
__int64 __fastcall check_IsDebuggerPresent(__int64 a1, __int64 a2)
{
  __int64 v2; // r14
  __int64 i; // rax
  unsigned __int64 v5; // rax
  _BYTE v6[11]; // [rsp+0h] [rbp-3Eh] BYREF
  _BYTE v7[11]; // [rsp+Bh] [rbp-33h]
  void *retaddr; // [rsp+3Eh] [rbp+0h] BYREF

  if ( (unsigned __int64)&retaddr <= *(_QWORD *)(v2 + 16) )
    sub_4597A0();
  if ( !qword_149AD60 )
  {
    *(_DWORD *)v7 = 18369660;
    *(_QWORD *)&v7[3] = 0x61EE9F493C915F01LL;
    *(_DWORD *)v6 = 790160570;
    *(_QWORD *)&v6[3] = 0xCF4291E7F49FD12FLL;
    for ( i = 0LL; i < 11; ++i )
    {
      a2 = (unsigned __int8)v6[i];
      v6[i] = a2 + v7[i];
    }
    runtime_slicebytetostring();
    v5 = sub_4CBD80(64LL, a2);
    if ( v6 )
      qword_149AD60 = 60000000000LL;
    else
      qword_149AD60 = v5;
  }
  return qword_149AD60;
}
```

We also see the Golang binary is keeping the symbol "github_com_bishopfox_sliver_implant_sliver_transports_StartBeaconLoop_func1".

Here is the original of this one, it's Sliver proxy-aware C2 over HTTP.

>https://github.com/BishopFox/sliver
>https://sliver.sh/docs?name=HTTPS+C2

![image](https://hackmd.io/_uploads/B1ZSy7XDR.png)

There are also many analyses about them:

>https://www.immersivelabs.com/blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide/
> https://github.com/Immersive-Labs-Sec/SliverC2-Forensics


I took a lot of time on the binary before knowing them as an open source C2, so I see there is not much modification from the original, so I'll not mention here too much, and I decided to use the tool to decrypt the traffic.

```shell
$ python3 sliver_pcap_parser.py --pcap ../evidence.pcapng --filter http --domain_name 10.0.0.101
```

We also have given .dmp file, so I can use FORCE option to find the key automatically:

```bash
python3 sliver_decrypt.py --file_path http-sessions.json --transport http --force ../Goose.dmp
```

Luckily, the flag is here:

```bash
[+] Finding all possible keys in ../Goose.dmp
  [-] Found 5391 possible keys
  [*] Keys will be tested during first decryption attempt
[+] Running HTTP Decoder
[+] Processing: http://10.0.0.101:80/oauth2callback/oauth/api.html?bv=5849e5085&r=8r0345412
  [-] Decoding: b64
  [!] Session Key: Unable to find a valid key for this session
[+] Processing: http://10.0.0.101:80/oauth2callback/oauth/api.html?bv=5849e5085&r=8r0345412
  [-] Decoding: b64
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
[+] Processing: http://10.0.0.101:80/api.php?n=369d59499
  [-] Decoding: gzip-b64
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 1
[=] Message Data
b'\n\ngoosechase\x12\x0fDESKTOP-DEQMME0\x1a$e1a84d56-400f-3cd4-a1f3-233922586739"\x15DESKTOP-DEQMME0\\Ronan*-S-1-5-21-1165601571-417196110-1223264716-10012,S-1-5-21-1165601571-417196110-1223264716-513:\x07windowsB\x05amd64H\x94)R\x18C:\\Users\\Ronan\\Goose.exeZ\x15https://10.0.0.101:80b\x1510 build 22631 x86_64h\x80\xb0\x9d\xc2\xdf\x01\x82\x01$aa00c4d8-3b17-4ff4-85cd-809c35cfd666\x88\x01\xe2\x9d\xb9\x91\xfd\xa0\x89\xb1\xfb\x01\x92\x01\x05en-US'

[+] Processing: http://10.0.0.101:80/assets/array.js?o=68257360
  [-] Decoding: gzip-words
  [!] Session Key: Unable to find a valid key for this session
[+] Processing: http://10.0.0.101:80/oauth2callback/oauth/auth/samples.php?h=m31953704
  [-] Decoding: words
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 0
[=] Message Data
b'\n\x17C:\\Users\\Ronan\\flag.txt\x12\x04gzip\x18\x012O\x1f\x8b\x08\x00\x00\x00\x00\x00\x04\xff\x003\x00\xcc\xffuiuctf{GOOS3_CH4S3_ST0P_RUNN1NG_STR1NGS_0N_MY_CHAL}\x01\x00\x00\xff\xff\xe1\xd1\xe1\xcc3\x00\x00\x00@\x01J\x00'
[+] Processing: http://10.0.0.101:80/bootstrap.min.js?i=70189559
  [-] Decoding: b64
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 7
[=] Message Data
b'\n\x08flag.txtJ\x07\x10\x80\xb0\x9d\xc2\xdf\x01'

...stripped...

[+] Processing: http://10.0.0.101:80/auth/database/oauth2callback/api.php?n=59z33056
  [-] Decoding: b64
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 0
[=] Message Data
b'\n\x17C:\\Users\\Ronan\\flag.txt\x12\x04gzip\x18\x012O\x1f\x8b\x08\x00\x00\x00\x00\x00\x04\xff\x003\x00\xcc\xff
uiuctf{GOOS3_CH4S3_ST0P_RUNN1NG_STR1NGS_0N_MY_CHAL}\x01\x00\x00\xff\xff\xe1\xd1\xe1\xcc3\x00\x00\x00@\x01J\x00'
```

![image](https://hackmd.io/_uploads/rybB2TUDR.png)


Special thanks to the Author who created a good challenge, I already have enjoyed it.


Also, here is write-up from UIUCTF2022:

https://lephuduc.github.io/posts/uiuctf2022/


**Thanks for reading!**