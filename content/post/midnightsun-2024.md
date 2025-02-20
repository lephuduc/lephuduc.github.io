---
title: "MidnightSun CTF 2024"
description: "Write up all reverse challenges in MidnightSun CTF 2024"
summary: "Write up all reverse challenges in MidnightSun CTF 2024"
categories: ["Writeup"]
tags: ["Reverse"]
#externalUrl: ""
date: 2024-04-20
draft: false
authors:
  - Jinn
cover: /images/post_covers/midnightsun2024-ori.jpeg
---
# MidnightSun 2024 Qualifications

Last weekend I have play Midnight CTF with `purf3ct`. It was a good time  that I try so hard. There are three reverse challenges I've done and one crypto with hardware/reverse tag that I try as must as I can and it's a happy ending that we've got into top ten, big shoudout for `purf3ct`!
Let's go Sweden! 🇸🇪 🇸🇪

![image](https://hackmd.io/_uploads/Syl8HHW4bC.png)

> There are 3 reverse challenges and all of them are very doable, so I enjoy so much, thanks for the authors.
## minus10


Attachment: [minus10.sr](https://github.com/lephuduc/CTFs-Honors/blob/main/2024-Writeups/MidnightSun2024/minus_10_fold/minus10.sr)

This is the first one I tried, not regular reverse, and it involves hardware analysis.

After a while search for what is `.sr` file and I found the tools:

First of all, extrac the file as zip:

![image](https://hackmd.io/_uploads/S18kdZ4b0.png)

![image](https://hackmd.io/_uploads/B1vgObVWR.png)

It's a sigrok file, as a signal capture and there are 2 channel, so I quickly find the tool:

https://sigrok.org/wiki/Main_Page

I think this one is the easiest, so I just used the CLI version and referred to the [documents there](https://github.com/sigrokproject/sigrok-cli/blob/master/doc/sigrok-cli.1), I found it was `uart` one: 

```
sigrok-cli -i minus10.sr -P uart:tx=D0:rx=D1 > decoded.txt
```

`decoded.txt`
```
uart-1: Start bit
uart-1: 0
uart-1: 1
uart-1: 0
uart-1: 1
uart-1: 1
uart-1: 1
uart-1: 0
uart-1: 0
uart-1: 3A
uart-1: Stop bit
uart-1: Start bit
uart-1: 1
uart-1: 0
uart-1: 0
uart-1: 0
uart-1: 1
uart-1: 1
uart-1: 0
uart-1: 0
uart-1: 31
uart-1: Stop bit
uart-1: Start bit
uart-1: 0
```

There are some hex byte, extract them into another file I found:

`extracted.hex`
```hex
:10FD00005542200135D0085A824526023140000470
:10FD10003F4000000F9308249242260220012F83C7
:10FD20009F4F8AFF0002F8233F4026000F930724CD
:10FD30009242260220011F83CF430002F9233B4059
:10FD40003CFE3A403EFE924226022001BB120B9A34
:10FD5000FA233B4000FD3BB00F0012207F403A00E9
:10FD6000B01242FE7F401000B01264FE0F4B8F10A5
:10FD7000B01264FE4F4BB01264FE4F43B01264FEEB
...stripped...
:10FF600058640D161A7B67692300303132333435FB
:10FF7000363738394142434445466763632D6D73D4
:10FF8000703433302D342E362E33FFFFFFFFFFFF4A
:10FF9000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF71
:10FFA000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61
:10FFB000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF51
:10FFC000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF41
:10FFD000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF31
:10FFE0003EFE3EFE3EFE3EFE3EFE3EFE3EFEA8FEC7
:10FFF0003EFE3EFE3EFE3EFE3EFE3EFE3EFE00FD60
:00000001FF

12345612345123456789
:(
passwordiloveyouprincess
:(
1234567rockyou12345678
:(
abc123nicoledaniel
:(
babygirlmonkeylovely

... more
```
This is a Intel hex format for Microchip and I also quickly found [a tool](https://github.com/pda/intelhex) that coneverts it's into binary correctly:

```shell
$ruby intel_hex.rb < extracted.hex > program.bin
$strings program.bin
#?@&
#;@<
 _B$
nO_B
;A0A
KOIONO
NN:@j
9A:A;A0A
OLO_O_O\
,_B
?S?P
<A=A>A?A
e{cv|BWWs^Xd
{gi#
0123456789ABCDEFgcc-msp430-4.6.3
```

Known it was `msp430`, load it into IDA:

![image](https://hackmd.io/_uploads/ByCTsWV-A.png)

Keep in mind this is the easiest one, so, after reverse for a while, I found something:

![image](https://hackmd.io/_uploads/BJ2Z3WEZC.png)

Here's compare 2 buffer, I guess the `0xff4c` one is the encrypted flag and the `0x200` is buffer received input:

![image](https://hackmd.io/_uploads/BJp7hbEWR.png)

Here's the encrypt part:

![image](https://hackmd.io/_uploads/SkV_hbEWA.png)

It's just xor every bytes with `(0xD2 + i*5)` with `i` is the index.

Let decrypt and get flag:

```bash
Python>enc = get_bytes(0xFF4C,29)
Python>bytes([((0xd2+i*5)^enc[i])&0xff for i in range(len(enc))])
b'midnight{warmed_up_on_MSP430}'
```
Flag: `midnight{warmed_up_on_MSP430}`

## roprot

Attachment: [roprot.tar.xz](https://github.com/lephuduc/CTFs-Honors/blob/main/2024-Writeups/MidnightSun2024/roprot/roprot.tar.xz)

The next one is more interest.

![image](https://hackmd.io/_uploads/H1BFJMEZC.png)


`roprot` after load into IDA:

```c
__int64 __fastcall main(int argc, char **argv, char **a3)
{
  int *v3; // rbx
  int i; // [rsp+14h] [rbp-34h]
  void *v6; // [rsp+18h] [rbp-30h] BYREF
  int *v7; // [rsp+20h] [rbp-28h]
  _QWORD *mapped; // [rsp+28h] [rbp-20h]
  void *addr; // [rsp+30h] [rbp-18h]
  unsigned __int64 v10; // [rsp+38h] [rbp-10h]
  unsigned __int16 xored;
  v10 = __readfsqword(0x28u);
  set_handler_and_message();
  if ( argc != 2 )
    goto FAIL;
  v6 = 0LL;
  mapped = 0LL;
  if ( (unsigned int)check(argv[1]) == -1 )
    goto FAIL;
  addr = mmap(0LL, 0x20000000uLL, 2, 34, -1, 0LL);
  v7 = (int *)addr;
  if ( addr == (void *)-1LL )
    goto FAIL;
  for ( i = 0; i <= 0x7FFFFFF; ++i )
  {
    v3 = v7++;
    *v3 = rand();
  }
  mprotect(addr, 0x20000000uLL, 5);
  if ( getrandom(&v6, 8LL, 1LL) != 8
    || (v6 = (void *)((unsigned __int64)v6 & 0x7FFFFFFFF000LL),
        mapped = mmap(v6, 4096uLL, 3, 306, -1, 0LL),
        mapped == (_QWORD *)-1LL) )
  {
FAIL:
    fail("\x1B[1;31mFAIL:\x1B[0m Invalid license key.");
  }
  mov_data(mapped, (__int64)addr);
  return 0LL;
}
__int64 __fastcall check(const char *key)
{
  __int64 n; // rax
  int i; // [rsp+14h] [rbp-14h]
  __int64 seed; // [rsp+18h] [rbp-10h]

  if ( strlen(key) != 0x13 )
    return 0xFFFFFFFFLL;
  seed = 0LL;
  for ( i = 0; i <= 18; ++i )
  {
    if ( i <= 0 || (i + 1) % 5 )
    {
      if ( ((*__ctype_b_loc())[key[i]] & 8) == 0 )
        return 0xFFFFFFFFLL;
      if ( ((*__ctype_b_loc())[key[i]] & 0x400) != 0 && ((*__ctype_b_loc())[key[i]] & 0x100) == 0 )
        return 0xFFFFFFFFLL;
      if ( ((*__ctype_b_loc())[key[i]] & 0x800) != 0 )
        n = key[i] - '0';
      else
        n = key[i] - '7';
      seed = 36 * seed + n;
    }
    else if ( key[i] != '-' )
    {
      return 0xFFFFFFFFLL;
    }
  }
  xored = crc16(HIDWORD(seed) ^ seed);
  if (xored != crc16(0xBAC9AB0C){
      return -1;
  }
  srand(xored);
  return 0LL;
}

__int64 __fastcall mov_data(_QWORD *a1, __int64 a2)
{
  __int64 result; // rax
  unsigned int i; // [rsp+10h] [rbp-18h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= 0x127 )
      break;
    a1[i] = indexs[i] + a2;
  }
  return result;
}
```

The idea:

`check()`

- Check the key with format XXXX-XXXX-XXXX-XXXX, which X from `01234...XYZ`.
- Then get the number calculated from key.
- Check the crc16 of the xored calculated with the given one
- Using the above number as seed into srand()

`main()`
- After check the key, create the buffer with size 0x20000000 and set the random numbers into it.
- mapping new buffer, then call `mov_data`

`mov_data`
- Set values of the buffer with given `indexs` array to the new buffer.
- jump into the buffer.

>The `tool` file is using to generate the buffer and searching buffer, for `xor`: search for 2 buffer that's match with the given bytes after xor, the `find` is find bytes in the generated buffer.

So we need to find the correct seed that get the right buffer (the correct rop-chain)

I guess that rop-chain with print flag or do something not so hard.

First, I can see there are 65536 possibly seeds that make it correct:

`get_seed.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int16_t check_sum(uint32_t a1)
{
  uint16_t checksum; // [rsp+Ch] [rbp-18h]
  int16_t v4; // [rsp+Eh] [rbp-16h]
  int j; // [rsp+10h] [rbp-14h]
  uint64_t i; // [rsp+14h] [rbp-10h]
  uint8_t *v7; // [rsp+1Ch] [rbp-8h]

  checksum = -1;
  v4 = 4129;
  v7 = (uint8_t *)&a1;
  for ( i = 0LL; i <= 3; ++i )
  {
    checksum ^= v7[i] << 8;
    for ( j = 0; j <= 7; ++j )
    {
      if ( (checksum & 0x8000u) == 0 )
        checksum *= 2;
      else
        checksum = (2 * checksum) ^ v4;
    }
  }
  return checksum;
}
int main(){
    for (uint32_t i = 0;i < 4294967295;i++){
        if (check_sum(i)==0x2cc2){ //check_sum(0xBAC9AB0C)
            printf("%u\n",i);
        }
    }
    return 0;
}
```

```
gcc ./get_seed.c -o get_seed && ./get_seed > seed.txt
```

![image](https://hackmd.io/_uploads/rJ8_XfNZR.png)

Then looking at the `indexs`:

![image](https://hackmd.io/_uploads/BkhsNGE-A.png)

I see two numbers: 1355 and 586, so I think to check if every seed is correct or not, we need to generate at least 1355 bytes.

I have some ideas, like finding '0xc3' (the 'ret' opcode) in the buffer, but there are too many occurrences.

So, I quickly found the 'capstone' module, which helped me disassemble these bytes easier.

I also used the CDLL in the 'ctypes' module in Python. The reason I didn't use 'C' to make it faster is because I think 65536 and 1355 are not too big, so it's easier to check.

Full script:

```python
# key format XXXX-XXXX-XXXX-XXXX, number of uppercase -> seed 

# if (check(seed))==0x2c02 -> srand(seed)
# `mmap(addr)`, move every byte in addr, addr[i] = (_DWORD)rand();
# `mmap(mapped)`, then move every possible rop-gadget from `addr` -> exec rop-chain

from ctypes import CDLL
import struct
from capstone import *
import subprocess

libc = CDLL("libc.so.6")
with open('roprot','rb') as f:
    roprot = f.read()
with open('seed.txt','r') as is_good:
    seeds = [int(i[:-1]) & 0xffffffff for i in is_good.readlines()]

def check(seed):
    newb = roprot.replace(b'\x78\x56\x34\x12',struct.pack('<I',seed))
    with open('roprot_new','wb') as wf:
        wf.write(newb)
        wf.close()
    try:
        print(subprocess.check_output(['./roprot_new','0123-5678-ABCD-EFGH']))
        print(f'seed {seed} good.')
        exit(0)
    except Exception as e:
        print(f'seed {seed} fail.')
        pass

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False
possible_seed = []

counter = 0
for seed in seeds:
    idx1 = 1355
    libc.srand(seed)
    buf = b''
    for i in range(idx1//4+4):
        r = libc.rand()
        buf += struct.pack('<i',r)
        # print(hex(r),buf)
        # exit()
    
    # check1
    disassembled = {}
    for i in md.disasm(buf[idx1:idx1+4],0):
        disassembled[i.mnemonic] = i.op_str
    # check 2
    disassembled2 = {}
    idx2 = 586
    for i in md.disasm(buf[idx2:idx2+4],0):
        disassembled2[i.mnemonic] = i.op_str
    
    # final check
    if  disassembled != {} and \
        ('ret' in disassembled.keys() or 'retn' in disassembled.keys()) and\
        disassembled2 != {} and \
        ('ret' in disassembled2.keys() or 'retn' in disassembled2.keys()):
        # print('first',disassembled)
        # print('second',disassembled2)
        print('seed: ',seed,hex(seed))
        check(seed)
        possible_seed.append(seed)

        counter+=1
    # print(buf)
print(f'Found:{counter} possibly seeds.' ) 
print(possible_seed)
# print(hex(libc.rand()))
```

The idea was easy: get the seed, generate a buffer, then check the indexes to find where 'ret' appears after disassembling these bytes.

The `roprot_new` file is patched that not call the function `verifying_key` and directly call `srand()`:

![image](https://hackmd.io/_uploads/BkwevM4bC.png)

Then every check, I'm only replace the bytes with the seed.

Luckly, I found the one that's print the flag:

![image](https://hackmd.io/_uploads/r1zCPfVbA.png)

Flag: `midnight{r0pP1nG_7hr0uGh_rand()}`

## 07u4

This one is the latest reverse challenge released and is easier than the previous one.

The server is turned off, so I can't test it anymore. Luckily, I have some files that we can take a look at:

- The idea is: we need to solve each binary that is given as a gzip from the server. When 25 binaries are solved, we get the flag.

![image](https://hackmd.io/_uploads/Syf7YfVb0.png)

So, I take a look every binary I found. The first of my idea is using `angr` for auto analysis and find the flag in every binary:

```python
import angr
import claripy
from pwn import *

context.log_level='warn'

path_to_binary = 'bins/bin0.elf'
elf_ = ELF(path_to_binary)
start_address = elf_.entry
password_length = 0x28

project = angr.Project(path_to_binary,main_opts={'base_addr':0x00})

password = [claripy.BVS(f"pw_{i}",8) for i in range(password_length)]

# password=claripy.BVS('password',25*8)

def getcwd_hook(state):
    addr_needtofeed = state.regs.rax
    print(addr_needtofeed)
    for i, byte_symbolic in enumerate(password):
        addr_byte = addr_needtofeed + i
        state.memory.store(addr_byte, byte_symbolic)
def hook_func(state):
    addr_needtofeed = state.regs.rdi
    buf = state.memory.load(addr_needtofeed,password_length)
    print(buf)
    addr_needtofeed = state.regs.rax
    buf = state.memory.load(addr_needtofeed,password_length)
    print(buf)
# project.hook_symbol('getcwd',getcwd_hook)
project.hook(0x11FA,getcwd_hook)
project.hook(0x123C,hook_func)
state=project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
        )
sim_manager=project.factory.simgr(state)

sim_manager.explore(find=0x1245)

if(len(sim_manager.found)>0):     
    print(sim_manager.found[0].solver.eval(password,cast_to=bytes))
```

But every password length is random and some binaries are different ways to feed input, differnt ways to check the input. So, this is fail, I give up...

Atleast you think so, I check these binaries and I see that only 3 types of binary, It's also fine if there are 4 or 5.

So, I just wrote the solver for every type of binary.

### Type 1:
This one is simple xor with a single byte.

![image](https://hackmd.io/_uploads/HJ-wxQNWC.png)

So, I checked that using to move these bytes and the byte xor one.

Here is the code.

```python
    if b'\xC6\x45\xEE' in d: # mov [ebp + X], 0x##
        print('Type 1')
        start = d.index(b'\xC6\x45\xEE')
        i = start
        buf = [d[i+3]]
        i+=4
        while d[i]!=0:
            buf.append(d[i+3])
            i += 4
        if b'\x83\xf0' in d: # xor al, 0x##
            xor_val = d[d.index(b'\x83\xf0') + 2]
        else:               # xor eax, 0x##
            xor_val = d[d.index(b'\x0F\xBE\xC0')+4]
        pw = xor(bytes(buf).strip(b'\x00'),xor_val)
        return pw
```


### Type 2:
This is the easiest one:

![image](https://hackmd.io/_uploads/BkBNCzEZC.png)

So, just checked for `strcmp` symbol in the binary, when i use `strings` to binary, the password always appeared after `u+UH`.

```python
### Type2, string cmp
    elif 'strcmp' in elf.symbols:
        print('Type 2')
        res = subprocess.check_output(['strings',file_path]).split(b'\n')
        res = res[res.index(b'u+UH')+1]
        return res
```

### Type 3:

The last one also is create password from 2 buffer, look simple but I have many things to check.

![image](https://hackmd.io/_uploads/BJpNZQVb0.png)

![image](https://hackmd.io/_uploads/BJVxWmEWR.png)

I also check for every opcode and takes these words, then create and get the password.
```python
    ## Type3, word
    elif (b'\x66\xC7\x85' in d) or (b'\x66\xC7\x45' in d): # two types of "mov [rbp+X], 0xABCD"
        print('Type 3')
        if b'\x66\xC7\x85' in d:
            start = d.index(b'\x66\xC7\x85')
        else:
            start = d.index(b'\x66\xC7\x45')
        i = start
        buf = []
        while True: # get these numbers
            if d[i:i+3]==b'\x66\xC7\x45': 
                buf.append(unpack('<H',d[i+4:i+6])[0])
                i+=6
            elif d[i:i+3]==b'\x66\xC7\x85':
                buf.append(unpack('<H',d[i+7:i+9])[0])
                i += 9
            else:
                buf.append(0)
            if buf[-1]==0:
                buf = buf[:-1] # strip
                buf1 = buf[:len(buf)//2]
                buf2 = buf[len(buf)//2:]
                break
        # print(buf,len(buf))
        l = len(buf)
        s = [0 for _ in range(l)]   # create the flag
        for i in range(l//2):
            n = buf2[i] - buf1[i]
            s[2 * i + 1] = n&0xff
            s[2 * i] = (n>>8)&0xff
        return bytes(s)
```

So, here's full script:

`solve_binary.py`
```python
from pwn import *
import subprocess
from struct import unpack
context.log_level='warn'

def solve(i):
    file_path = f'bins/bin{i}.elf'
    with open(file_path,'rb') as f:
        d = f.read()
    elf = ELF(file_path)
    #### Type1, simple xor
    if b'\xC6\x45\xEE' in d: # mov [ebp + X], 0x##
        print('Type 1')
        start = d.index(b'\xC6\x45\xEE')
        i = start
        buf = [d[i+3]]
        i+=4
        while d[i]!=0:
            buf.append(d[i+3])
            i += 4
        if b'\x83\xf0' in d: # xor al, 0x##
            xor_val = d[d.index(b'\x83\xf0') + 2]
        else:               # xor eax, 0x##
            xor_val = d[d.index(b'\x0F\xBE\xC0')+4]
        pw = xor(bytes(buf).strip(b'\x00'),xor_val)
        return pw
    ### Type2, string cmp
    elif 'strcmp' in elf.symbols:
        print('Type 2')
        res = subprocess.check_output(['strings',file_path]).split(b'\n')
        res = res[res.index(b'u+UH')+1]
        return res
    ## Type3, word
    elif (b'\x66\xC7\x85' in d) or (b'\x66\xC7\x45' in d): # two types of "mov [rbp+X], 0xABCD"
        print('Type 3')
        if b'\x66\xC7\x85' in d:
            start = d.index(b'\x66\xC7\x85')
        else:
            start = d.index(b'\x66\xC7\x45')
        i = start
        buf = []
        while True: # get these numbers
            if d[i:i+3]==b'\x66\xC7\x45': 
                buf.append(unpack('<H',d[i+4:i+6])[0])
                i+=6
            elif d[i:i+3]==b'\x66\xC7\x85':
                buf.append(unpack('<H',d[i+7:i+9])[0])
                i += 9
            else:
                buf.append(0)
            if buf[-1]==0:
                buf = buf[:-1] # strip
                buf1 = buf[:len(buf)//2]
                buf2 = buf[len(buf)//2:]
                break
        # print(buf,len(buf))
        l = len(buf)
        s = [0 for _ in range(l)]   # create the flag
        for i in range(l//2):
            n = buf2[i] - buf1[i]
            s[2 * i + 1] = n&0xff
            s[2 * i] = (n>>8)&0xff
        return bytes(s)
    return b'None'

if __name__=='__main__':
    print(solve(8))
```

`auto_script.py`

```python
from pwn import *
from gzip import decompress
from solve_binary import solve
io = remote('07u4-1.play.hfsc.tf', 3991)

io.recvuntil(b'Play\n')

io.sendline(b'2')
i = 0
while True:
    if i==25:
        io.interactive()
    hex_string = io.recvuntil(b'ANSWER:').strip(b'\n\nANSWER:').decode()
    hex_string = hex_string[hex_string.index('1f8b08'):]
    d = decompress(bytes.fromhex(hex_string))
    with open(f'bins/bin{i}.elf','wb') as wf:
        wf.write(d)
        wf.close()
    pw = solve(i)
    print(i,pw)
    io.sendline(pw)
    i += 1
    # io.interactive()
    # break
```

Then I run this script and got the flag.

Flag `*the server turned off`

## Bonus [REDACTED]

<!-- plus907

There is a crypto challenge that required rev/hardware part, so I take a loot at it.

![image](https://hackmd.io/_uploads/ryyOQmVb0.png)


This one is same as the minus10 one, except for the encrypted flag is redacted and it's check the password from the user input with a loop and there are some passwords.

My team's crypto player known it was side channel attack, so look at the signals, we need to find the time respone of every password.

![image](https://hackmd.io/_uploads/Sk5GNQVZC.png)

I think there is an easy way to do it but I was tried by the hard one.

extract timing of each channel -> annotation.txt

then choosing the start time of every channel, then calculate the gaps by adding each timing into the start time.

```python
T1 = 481033500000
with open('annotation1.txt','r') as f:
    d = f.readlines()
    t1 = []
    for l in d:
        l = l.split()
        t1.append(int(l[-1].strip('\n')))

T2 = 481868166667
with open('annotation2.txt','r') as f:
    d = f.readlines()
    t2 = []
    for l in d:
        l = l.split()
        t2.append(int(l[-1].strip('\n')))
gaps = []
i = 0
j = 0
while len(gaps) < 500:
    save_t1 = 0
    save_t2 = 0
    while True:
        n = t1[i]
        if n > 300000000:
            save_t1 = T1
            T1+=n
            i+=1
            break
        T1 += n
        i+=1
    while True:
        if j==0:
            save_t2 = T2
            j+=1
            break
        m = t2[j]
        T2 += m
        if m > 300000000:
            save_t2 = T2
            j+=1
            break
        j+=1
    # print(save_t1,save_t2,T1,T2)
    gaps.append(save_t2-save_t1)

print(i,j)
gaps.append(828617928)
print(gaps,len(gaps))
```
So, we have the correct respone time of every respone in picoseccond

```
[834666667, 964541651, 902958301, 767124954, 821208273, 828166591, ...
```-->

That's all, thanks for reading.