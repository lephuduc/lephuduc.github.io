---
title: "A Simple way to Emulate TP-Links Devices"
subtitle: "Working around a TP-Links BE230 from decrypt firmware to setup emulate easily for debugging"
date: 2026-09-03 13:30:40
category: blogs
tags: ["research"]
draft: true
---

## Hi guys, I'm back

Hi guys, base on my research recently, I am currently working on some IoT devices, especially in router category but with my minimal experience. Actually, I don't know where to start.

So, I buy for my own a new router, which will start of my research and to see how much we learn from them, especially the some of hardest step of exploiting an IoT Devices: hacking and emulating.

For now, I just focus on this devices. My device is TP-Link Ancher BE230, which a budget friendly Dual-band Wi-Fi 7 router with wireless speed up to 3.6Ghz.

[Insert router image here]

The reason I choose this becuase they are wide global used and have many feature that we want as a normal home router. The hardware version is US/1.0, which the only one I can buy at this time.


< the reason why we choose this router and what we will do with the router>
- the firmware obtainable not really hard or impossible
- multiple or many attack surface
- its a modern device, I want to see how they secure it

## Setup this as normal router

Before we going deeper, I would say this blog will not about exploiting the router directly, I just only help you setup and run the binary inside if possible.

If we want to emulate the device for debugging, we need to make it run normally first, for do that, we need it specific firmware currently running it:

[Image of Firmware download page, special device hardware version]

< Explain the hardware version and why it matter>

< recon part of downloaded firmware, what should we know, what things we care about, what's normal firmware updates look like, bla bla >

## Decrypt the firmware

Recently, TP-Link firmware is not plaintext anymore. It is an encrypted blob, so we need to decrypt it before we can do anything further.

For IoT devices, we have two ways to play around with this:

1. If the firmware is downloadable, download it first and then try to decrypt it.
2. If there is no public firmware to download, the only way is to dump the firmware directly from the flash chip, and read the other chips to find the hardware key that decrypts it.

Luckily this device has a downloadable firmware, you can find it [here](https://www.tp-link.com/us/support/download/archer-be230/).

### The header

Only the body is encrypted. The first 0x230 bytes are still readable, so we can just look at them:

```bash
$ xxd -l 48 be230_1.2.6.bin
00000000: 02e5 4747 e98f b5d7 0c37 53c5 8742 d3ab  ..GG.....7S..B..
00000010: 376e 74b6 6677 2d74 7970 653a 436c 6f75  7nt.fw-type:Clou
00000020: 640a 0000 0000 0000 0000 0000 0000 0000  d...............
```
{{< note >}}`xxd` prints a file as hex. `-s` is where to start and `-l` is how many bytes to show.{{< /note >}}

The `fw-type:Cloud` string is already a good sign. Here is the whole header:

| Offset | Size | What it is |
|---|---|---|
| 0x000 | 20 | digest of the image |
| 0x014 | 14 | the string `fw-type:Cloud\n` |
| 0x110 | 4 | `00 00 02 00`, big endian 0x200, means RSA-2048 |
| 0x114 | 20 | `AA55` + 16 bytes + `55AA` |
| 0x130 | 256 | RSA-2048 PSS signature |
| 0x230 | rest | AES-128-CBC ciphertext |

We can read the two fields that matter in three lines:

```python
data = open("be230_1.2.6.bin", "rb").read()
data[0x14:0x22]                              # b'fw-type:Cloud\n'
int.from_bytes(data[0x110:0x114], "big")     # 512, so RSA-2048
```

A value of 0x100 at 0x110 would mean RSA-1024, and that older format is not encrypted. The size also tells us how long the signature is, 256 bytes for RSA-2048, so the ciphertext can only start at 0x230:

```bash
$ xxd -s 0x110 -l 48 be230_1.2.6.bin
00000110: 0000 0200 aa55 4c5e 831f 534b a1f8 f7c9  .....UL^..SK....
00000120: 18df 8fbf 7da1 55aa 0000 0000 0000 0000  ....}.U.........
00000130: 94dd f733 2ccc 67ca d6e5 0ad3 e2b7 cb9c  ...3,.g.........
```

The `AA55 ... 55AA` pair at 0x114 wraps 16 bytes. It is a marker TP-Link uses in their own images, and the signature starts right after the zeros, at 0x130.

### Where is the AES key

This part surprised me. There is no fixed AES key hidden in some binary. Every image carries its own key, and the key is stored inside the RSA signature.

TP-Link signs the image with RSA-2048 PSS. In PSS the signature does not only hold the message hash, it also holds a random value called the salt. TP-Link puts the AES key and IV in the first 32 bytes of that salt. So when we verify the signature with the public key, the key comes out at the same time.

Two good things come from this:

- We only need the public key, and TP-Link ships it inside its own firmware and GPL code.
- We still cannot sign our own firmware, because that needs the private key.
{{< note >}}RSA-PSS is a signature scheme. It mixes the message hash with a random salt before signing, so the same file signed twice gives two different signatures. When we verify, we get the salt back.{{< /note >}}
{{< side >}}Reference: [Probabilistic signature scheme on Wikipedia](https://en.wikipedia.org/wiki/Probabilistic_signature_scheme){{< /side >}}

The public key sits in a binary called `nvrammanager`, inside an older TP-Link router firmware that is still plaintext. It is a base64 blob that starts with `BgIAAAwk`, in the Microsoft PUBLICKEYBLOB format. So unpack any older image with binwalk and search the files for that string:
{{< side >}}The idea of taking the keys from files the vendor publishes comes from this prior work: [tp-link-decrypt by Watchful_IP](https://github.com/watchfulip/tp-link-decrypt), his [C210 v2 writeup](https://watchfulip.github.io/28-12-24/tp-link_c210_v2.html), the [maintained fork by robbins](https://github.com/robbins/tp-link-decrypt), and [tangrs on finding the keys in the GPL dumps](https://blog.tangrs.id.au/2025/09/22/decrypting-tplink-smart-switch-firmware/).{{< /side >}}

```bash
$ python3 extract_key.py ./old_rootfs -o rsa_pub.txt

[1] searching 207 file(s) under ./old_rootfs

[2] key in ./old_rootfs/usr/bin/nvrammanager at offset 0x19240
    RSA-2048, e=65537
    modulus starts b6c7a388c3ce2ae87f390f7f30a88945...
    BgIAAAwkAABSU0ExAAgAAAEAAQCdocMdSvAkLmNelNXLolhx4/OqVrxm6g1XCIlMdTgW...

[3] 1 blob(s), 1 different
    written to rsa_pub.txt
```

After base64, the blob is simple: the magic `RSA1`, then the key size, then the exponent, then the modulus.
{{< note >}}A public key is only two numbers: the modulus n and the exponent e. Here e is 65537, the usual one, and n is 256 bytes long.{{< /note >}}
{{< side >}}Reference: [Base provider key BLOBs on Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs){{< /side >}}

The same key works for their whole router line, so this is a one time job.

### The decryption logic

After a while of researching, and thanks to some prior research, I rewrote my own version for this router. I put it in my github, which you can see at [this](https://github.com/lephuduc/tplink-be230) link.

Here is a short explanation about the decryption logic. I think you can also apply it to other TP-Link devices as well, at least the ones with `fw-type:` in the header.

```
1. sig = reversed(data[0x130:0x230])
2. em = pow(int(sig), e, n)                 # 256 bytes, e=65537
3. EMSA-PSS-decode(em) with MGF1-SHA256
   assert em[-1] == 0xBC
   db = maskedDB XOR MGF1(H, 223)
   db[0] &= 0x7F
   assert db[:pad] == 0x00... and db[pad] == 0x01
   salt = db[-222:]
4. key = salt[0:16]                          # AES-128
   iv = salt[16:32]
5. verify: msg = data[0x14:] with data[0x130:0x230] zeroed
   H' = SHA256(b"\x00"*8 || SHA256(msg) || salt)
   assert H' == H                            # proves the key is correct
6. buf = data with data[0x130:0x230] set to zeros
   plaintext = AES-128-CBC-decrypt(key, iv, buf[0x130:])
   the real payload starts at 0x230
```
{{< note >}}MGF1 is a mask generation function. It takes a short seed and gives back as many bytes as you ask for, by hashing the seed with a counter. PSS uses it to hide the salt.{{< /note >}}

Three points there are worth remembering.

Step 1, the signature is stored little endian, so we must reverse it before we treat it as a number:

```python
sig = data[0x130:0x230][::-1]                        # reverse the 256 bytes
em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(256, "big")
```
{{< note >}}Little endian means the lowest byte is written first. RSA works on one big number, so the bytes have to be put back in normal order before the math.{{< /note >}}

Step 3, the salt here is 222 bytes, not the usual 32. Only the first 32 bytes are used:

```python
salt = db[db.find(b"\x01") + 1:]     # everything after the 0x01 separator
key, iv = salt[0:16], salt[16:32]    # the rest of the salt is not used
```

Step 6, the AES stream starts at 0x130, not at 0x230. The signature field sits inside the stream and is zeroed first, the same buffer we hashed in step 5:

```python
buf = bytearray(data)
buf[0x130:0x230] = bytes(256)        # zero the signature field
plain = AES.new(key, AES.MODE_CBC, iv).decrypt(bytes(buf[0x130:]))
```

If you start at 0x230 instead, everything still comes out right except the first 16 bytes, because CBC only needs the block before it. That is why this one is easy to miss.
{{< note >}}In CBC every block is XORed with the block before it, and the IV plays that role for the first block. So a wrong start point only damages the first 16 bytes, the rest still decrypts fine.{{< /note >}}
{{< side >}}Reference: [Block cipher mode of operation on Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)){{< /side >}}

Running it on our image, the output follows the same six steps:

```bash
$ python3 decrypt.py be230_1.2.6.bin -k rsa_pub.txt

[1] public key rsa_pub.txt
    RSA-2048, e=65537
[2] header of 48580423 bytes
    0x014  fw-type:Cloud
    0x110  0x200, RSA-2048
    0x130  signature, 256 bytes
[3] signature reversed and raised to e mod n
    last byte 0xbc, PSS
    H    = 1953e99cb049f0350fec339ace53a74b9913f26747299f653a535859d0c7ab95
    salt = 222 bytes
[4] the first 32 bytes of the salt are the key and the IV
    KEY = e9b527c7ee114d795608552aa951f269
    IV  = 06634586c19612d14c70f2b895b56512
[5] H' = SHA256(8 zeros || SHA256(message) || salt)
    H' = 1953e99cb049f0350fec339ace53a74b9913f26747299f653a535859d0c7ab95
    H' is H, the key is correct and the image is the vendor one
[6] AES-128-CBC from 0x130, 48580112 bytes
    written to be230_1.2.6.bin.dec

squashfs at 0xa1f747, carve it out with dd or binwalk
```

The key and IV only work for this exact build. Another firmware version gives another key.

### Read the plaintext

Two things in the plaintext look wrong at first, but they are normal:

```bash
$ xxd -s 0x230 -l 64 be230_1.2.6.bin.dec
00000230: 0663 4586 c196 12d1 4c70 f2b8 95b5 6512  .cE.....Lp....e.
00000240: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000250: 0000 0100 aa55 9dd1 a8c8 8331 c969 fbbf  .....U.....1.i..
00000260: bcf0 d432 70c7 55aa 0000 0000 0000 0000  ...2p.U.........
```

The range 0x130 to 0x230 is garbage, not data. We set the signature to zero before we verify it, and the decrypt pass runs over those zeros too.

At 0x230 the plaintext starts with `0663 4586 ...`, which is the IV again, the same 16 bytes we just used. Then at 0x250 there is a second TP-Link header with the same shape as the outer one, this time saying RSA-1024. That inner image is not encrypted again.

The filesystem is the first `hsqs` magic in the plaintext:

```bash
$ xxd -s 0xa1f747 -l 16 be230_1.2.6.bin.dec
00a1f747: 6873 7173 2813 0000 9511 336a 0000 0200  hsqs(.....3j....
```
{{< note >}}squashfs is a small read only filesystem, used by almost every router. `hsqs` is its magic, the 4 bytes that mark where it begins.{{< /note >}}
{{< side >}}Reference: [SquashFS on Wikipedia](https://en.wikipedia.org/wiki/SquashFS){{< /side >}}

Cut from there to the end of the file, then unpack it:

```bash
$ dd if=be230_1.2.6.bin.dec of=rootfs.squashfs bs=1M iflag=skip_bytes skip=10614599
$ unsquashfs -d squashfs-root rootfs.squashfs
```
{{< note >}}Use `iflag=skip_bytes` with a big block size. `dd bs=1 skip=...` gives the same result but takes minutes on a 38MB file.{{< /note >}}

This gives a normal squashfs 4.0 with xz compression, 4904 inodes and 3978 files. Stock `unsquashfs` is enough here, we do not need `sasquatch`.

### The same way for other firmware

The steps above are for this router, but the order of work is the same for most vendors:

1. Try binwalk first. If it finds a filesystem, the image is only compressed and there is nothing to decrypt.
{{< side >}}Reference: [binwalk](https://github.com/ReFirmLabs/binwalk){{< /side >}}
2. Read the plaintext header. Vendors almost always leave a tag, a length, or a version number in the clear. Here it was `fw-type:`.
3. Look for a block that has the size of a signature, 256 bytes for RSA-2048 or 128 bytes for RSA-1024. If the vendor uses PSS, the key can be inside it like here.
4. If the key is not in the image, it is in a binary. Look for an older firmware of the same vendor that is still plaintext, or for their GPL source drop. Vendors add encryption late, so old builds are often open.
5. Only if nothing is public, go to hardware and dump the flash chip.

The point to remember is that the key does not have to be a secret constant. Here it travels with the file, and the signature that is supposed to protect the image is also what gives the key away.

## Examinate the firmware

After extracted the device, we see thse folder:
```
....
```

but the only interesting thing we should look into is squashfs, which mean 

A short explain about these router:

When you press the boot button, there things will perform:
1. a
2. 3
3. 4

And for the third step, it will find the init file and run it fist. The init executable is the things that it will run firstly after the firmware booted and from that, we can see the default services will be initialized.

< The examinate about the decrypted firmware, what we should looking at, how can we handle each firmware and this specific one >
### Setup emulator for this specific hardware

Firstly, we need to know what's the current input is:
- Linux version
- kernel image

After check these information, things we known about this device:

- kernel version
- build
- requirement
- architecture


And after gathering and summary these information. for this and tplink-related devices, I would use this https://people.debian.org/~gio/dqib/


But to build this successfully, we need to buy out 


After extracting the system, we have these files:

initrd
kernel
image.qcow2

which

initrd is initial ram disk ...
kernel ..
... 

You can try to put it into the vm and run it with qemu normaly to see if it work or not, the given qemu command is show in readme.txt

```
qemu-system-...
```

Try to run it alone to make sure the machine boot successfully first


After it booted, you can see the debian login prompt and you know it success, now leave it alone.

[image of debian login prompt:]

For now, you can also try to SSH to the system with the given keys or you can using ssh with default credentials: `root/root`


Because this only the armhf system, not contain our firmware yet, we need to find a way to put our firmware into that system and make it run normally

For this, you can do it simply like make our squashfs-root as a device that plug into the server. Before going to do that, we need to build our squashfs-root as an image. device, the way I build is using this written script:

```bash
Insert the create-images.sh script here
```

> Importance note: for me I would choose to build the squashfs-root as raw image then we can access it directly inside the vm without any problem.

and then adjust the qemu boot command by adding an additional device:

```bash
Insert edited qemu command
```

After boot it successfully 

> If you got this error message:  .... , which mean your build image is wrong somewhere, try to use the correct command and rebuild the image again

And successfully, try to SSH again then you will list the devices inside 

```
lsblk
```

Then you need to mount the device into /mnt or whatever you see

and then

```
chroot into the mounted location
```

## Going more further

In general of IoT and router specially, some binary can't run normally, which require the real interact with kernel, specific hardware, and for this, we only able to make it run on userland, for kernel it is very complicated and specific, which I will don't mention here:

### debugging these binaries with IDA

So, for some normal binary inside /bin, /usr/bin or /usr/local/bin, if it run normally we can also put our armhf_linux debug server of IDA into the qemu-system and let it run in the background, and after that, we can attach our IDA instance, connect to that server, and that why in our qemu command including the expose port.

Try to run the armhf server, then on the IDA instance, change the host into the device that we run qemu and save the debugger option.

[Set IDA debugger options]

Choose the IDA debug -> remote arm linux server then use the Debugger -> Attach to process option.

By the process list windows, you can see many process with the same name, probably but you can only choosing the first one (least pid number without chroot mount).

[The image of list debugger]

Attach to that process and now you can debug this program normally.

From there, you can start audit things and use the debugger whenever you need to confirm finding. Good luck hacking!
### Before you go

I would like to say I'd love being researcher, which can do examinate thing that I love understand how they work. So for now, I think i will contributes to this site as much as possible (probably once a month or twice a month). I'm also have many things that I need to share but not written yet. And if you also love it, I very appreciated.

I also love being practice and research, if you also want to research an interesting topic and want to collab, you can contact me with the email, I'm sure be response you as soon as possible. Finally thanks you for your time to reading this.

### Acknowledgments


- This research is support for education purpose only
- This is userland emu only, fit for single binary debug (some binary can run directly without hard interact with kernel) and examinate manually by your self.
- I put document and source of this project into: [github repo containing these].


Thanks for your time, see you again!


