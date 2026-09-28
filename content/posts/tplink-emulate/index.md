---
title: "Emulate TP-Link devices"
subtitle: "The way I use to emulate TP-Link BE230 and you can also use it for other ARM IoT devices"
date: 2026-09-03
category: research
# tags:
---
## Guys, I'm back

Hi guys, base on my research recently, I am currently working on some IoT devices, especially in router category but with my success attempt to do something, so this blog may help you if your work related.

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

### Make sure it is really encrypted

Before we look for a key, we should make sure the file is encrypted and not only compressed. This is easy to mix up, because both look like noise.

```python
# entropy per 64KB block, plus a scan for common filesystem magic
import collections, math

data = open("be230_1.2.6.bin", "rb").read()
BS = 64 * 1024
low = 0
for off in range(0, len(data), BS):
    count = collections.Counter(data[off:off + BS])
    total = sum(count.values())
    e = -sum((v / total) * math.log2(v / total) for v in count.values())
    if e < 7.5:
        low += 1
print("blocks:", len(data) // BS, "low entropy blocks:", low)

for magic in (b"hsqs", b"UBI#", b"\xfd7zXZ", b"\x27\x05\x19\x56"):
    print(magic, data.find(magic))
```

For our image every block is 8.0 and no magic is found:

```
blocks: 741 low entropy blocks: 0
b'hsqs' -1
b'UBI#' -1
b'\xfd7zXZ' -1
b"'\x05\x19V" -1
```

A compressed image still shows its superblock magic, and still has low entropy at the partition borders. Here we have neither, so the body is ciphertext.
{{< note >}}Entropy tells how random the bytes are. 8.0 is the highest value for one byte. Compressed data is close to 8.0 too, but it still keeps some structure. Encrypted data is 8.0 everywhere and keeps nothing.{{< /note >}}

### The header

The header is still plaintext. This is the part we need to read:

| Offset | Size | What it is |
|---|---|---|
| 0x000 | 20 | digest of the image |
| 0x014 | 14 | the string `fw-type:Cloud\n` |
| 0x110 | 4 | `00 00 02 00`, big endian 0x200, means RSA-2048 |
| 0x114 | 20 | `AA55` + 16 bytes + `55AA` |
| 0x130 | 256 | RSA-2048 PSS signature |
| 0x230 | rest | AES-128-CBC ciphertext |

The `fw-type:` string at 0x14 is what tells us this is the router image format. A value of 0x100 at 0x110 would mean RSA-1024, and that older format is not encrypted.

### Where is the AES key

This part surprised me. There is no fixed AES key hidden in some binary. Every image carries its own key, and the key is stored inside the RSA signature.

TP-Link signs the image with RSA-2048 PSS. In PSS the signature does not only hold the message hash, it also holds a random value called the salt. TP-Link puts the AES key and IV in the first 32 bytes of that salt. So when we verify the signature with the public key, the key comes out at the same time.

Two good things come from this:

- We only need the public key, and TP-Link ships it inside its own firmware and GPL code.
- We still cannot sign our own firmware, because that needs the private key.
{{< note >}}RSA-PSS is a signature scheme. It mixes the message hash with a random salt before signing, so the same file signed twice gives two different signatures. When we verify, we get the salt back.{{< /note >}}
{{< side >}}Reference: [Probabilistic signature scheme on Wikipedia](https://en.wikipedia.org/wiki/Probabilistic_signature_scheme){{< /side >}}

The public key sits in a binary called `nvrammanager`, inside an older TP-Link router firmware that is still plaintext. It is a base64 blob that starts with `BgIAAAwk`, in the Microsoft PUBLICKEYBLOB format.
{{< side >}}The idea of taking the keys from files the vendor publishes comes from this prior work: [tp-link-decrypt by Watchful_IP](https://github.com/watchfulip/tp-link-decrypt), his [C210 v2 writeup](https://watchfulip.github.io/28-12-24/tp-link_c210_v2.html), the [maintained fork by robbins](https://github.com/robbins/tp-link-decrypt), and [tangrs on finding the keys in the GPL dumps](https://blog.tangrs.id.au/2025/09/22/decrypting-tplink-smart-switch-firmware/).{{< /side >}}

### The decryption logic

After a while of researching, and thanks to some prior research, I rewrote my own version for this router. I put it in my github, which you can see at [this](<insert github link>) link.

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

Some small points that cost me time:

Step 1, the signature is stored little endian, so we must reverse it before we treat it as a number.

Step 3, the salt here is 222 bytes, not the usual 32. That means there is no padding before the `0x01` separator, so `db[0]` is already `0x01`. Only the first 32 bytes of the salt are the key and IV, the rest is not used.

Step 5 is the step that is easy to skip, but it is the one that tells us we did everything right. If `H' == H` then the key we took from the salt is the real key, and the image is the one the vendor signed. Without this check you only know the AES output looks fine, you do not know it is correct.

Step 6, the AES stream starts at 0x130, not at 0x230. The signature field sits inside the stream, and it is zeroed first, the same buffer we built in step 5. If you start at 0x230 instead, everything still comes out right except the first 16 bytes, because CBC only needs the block before it. That is why this one is easy to miss.

For our image the result is:

```
KEY = e9b527c7ee114d795608552aa951f269
IV  = 06634586c19612d14c70f2b895b56512
```

These two values only work for this exact build. Another firmware version gives another key.

### Read the plaintext

Two things in the plaintext look wrong at first, but they are normal:

The range 0x130 to 0x230 is garbage, not data. We set the signature to zero before we verify it, and then the decrypt pass runs over those zeros too.

At 0x230 the plaintext starts with the IV again, the same 16 bytes we just used. After some zeros, at 0x250, there is a second TP-Link header with the same `AA55 ... 55AA` shape. That inner image is not encrypted again.

Now we can find the filesystem and carve it out:

```python
data = open("be230_1.2.6.bin.dec", "rb").read()
print(hex(data.find(b"hsqs")))   # 0xa1f747
```

```bash
dd if=be230_1.2.6.bin.dec of=rootfs.squashfs bs=1M iflag=skip_bytes skip=10614599
unsquashfs -d squashfs-root rootfs.squashfs
```
{{< note >}}Use `iflag=skip_bytes` with a big block size. `dd bs=1 skip=...` gives the same result but takes minutes on a 38MB file.{{< /note >}}

This gives a normal squashfs 4.0 with xz compression, 4904 inodes and 3978 files. Stock `unsquashfs` is enough here, we do not need `sasquatch`.

### What we have now

- the image is encrypted, not compressed, and we proved it
- the header is read, and we know where the signature is
- the AES key and IV come out of the RSA-PSS salt
- the `H' == H` check proves the key is correct
- the image is decrypted and the root filesystem is extracted

### The same way for other firmware

The steps above are for this router, but the order of work is the same for most vendors:

1. Check entropy first. If some blocks are low, the file is only compressed and you can go straight to binwalk.
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
- Actually, if you need only able to run your binary, qemu-user is enough, this is my idea of setting up these thing also for IDA debugging, if you have any better ideas, please share, I very appriciated.
- I put document and source of this project into: [github repo containing these].


Thanks for your time, see you again!