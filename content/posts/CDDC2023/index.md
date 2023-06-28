---
title: "CDDC 2023"
description: "Writeup for rev challenge in CDDC2023"
summary: "Writeup for rev challenge in CDDC2023"
categories: ["Writeup"]
tags: ["Reverse"]
#externalUrl: ""
date: 2023-06-14
draft: false
authors:
  - Jinn
---

## Challenge description

![](https://hackmd.io/_uploads/SyWvCyvv3.png)

Attachment: [tinyx](abcd)

## Overview

Chương trình này là một VM đơn giản được viết bằng golang, tuy nhiên nó đã mất hết symbols. Do đó, việc đầu tiên cần phải làm là khôi khục lại toàn bộ symbols để có thể rev dễ dàng hơn:

![](https://hackmd.io/_uploads/ryZ0XbwP3.png)

Để khôi phục symbol, mình đã dùng tool này: [GoReSym](https://github.com/mandiant/GoReSym)

Mình dùng bản windows build sẵn ở tab release, trước tiên chúng ta cần extract toàn bộ symbol vào 1 file json:

```GoReSym_win64.exe -t -d -p tinyx > syms.json```

![](https://hackmd.io/_uploads/rk5kLbwwh.png)

Có được symbols, việc tiếp theo là load nó vào IDA, mình dùng python script có sẵn trong respos của tool `goresym_rename.py`, dùng script này để load file json vừa extract lúc nãy:

![](https://hackmd.io/_uploads/r1vI8Www2.png)

![](https://hackmd.io/_uploads/SkjFLZPv2.png)

Vậy là xem như đã khôi phục được symbol tiếp theo mình sẽ nói sơ về flow của chương trình này.

## Code flow

Flow bài này cũng khá cơ bản, tuy có nhiều thứ để chúng ta phân tích tuy nhiên dựa trên yêu cầu của bài thì ta chỉ quan tâm 1 số instruction, không cần reverse toàn bộ chương trình. Tất cả tên hàm đều được recover nên bài này reverse khá là thích, ít nhất là mình không phải đoán quá nhiều. :heart:

### Main function

Về phần hàm main hay những hàm khác decompiled của golang thì nó bị strip một vài chổ, nên để chính xác hơn thì mình đọc assembly kết hợp:

Main function:

![](https://hackmd.io/_uploads/rJHG6-Dw3.png)

![](https://hackmd.io/_uploads/rkNThWDDh.png)

Về hàm main, mọi thứ đều clear, btw, chổ khó bài này là nằm ở phần `NewCore`, vì chương trình không chỉ nhận mỗi bytecode mà nó còn nhận bao gồm header, size section... nên nó cần processing chính xác với các thành phần đó.

Hàm `InputProcess` chỉ đơn giản là upper tất cả các kí tự hexadecimal (input), trim các byte thừa và decode thành bytes

### Inside `_NewCore_` function 

Đầu tiên, hàm này sử dụng `mapassign` để map vùng có tên là `GeneralRegister_uint32`, tổng cộng có 8 thanh ghi đánh số từ 0-7, mỗi thanh ghi có `32 bit`.

![](https://hackmd.io/_uploads/H1hSCbDv3.png)

Tiếp theo đó, hàm này sẽ gọi `Memory_Loader` để load memory, phần này đối với mình là cực nhất tại vì lúc debug mình hay bị lỗi 1 vài chổ không rõ nguyên nhân...

![](https://hackmd.io/_uploads/rytaJfwvh.png)

Trong hàm `NewMemory` sẽ quy định các offset của các section, trong đó section .text là nơi chứa đoạn mã thực thi của chương trình sẽ có baseoffset là `0x100000001000` và section .data là `0x100000008000`, do đó tương ứng ta sẽ ghi code vào offset 0x1000 và rất có thể dữ liệu string trả về của hàm main có thể sẽ lấy từ section data là offset 0x8000:

![](https://hackmd.io/_uploads/r1F3vEvDn.png)

Sau đó, đoạn này sẽ lấy bytes input của mình để kiểm tra với các offset của các section .text và .const. Tương ứng là 0x1000 và 0x4000, do đó ta tạm thời có header là: 

```python
header = b'RISCXBIN' + p32(0x1000) + p32(0x4000)
```

![](https://hackmd.io/_uploads/BkEajVDPh.png)

Sau đó chương trình đọc tiếp 8 bytes, mình không rõ chính xác các byte này là gì nhưng nó không ảnh hưởng đến chương trình lắm nên mình để ngẫu nhiên.

Tiếp theo nó sẽ read 4 byte là size, size này sẽ là số byte cần read của các section, tính từ offset 0x00, mà code của mình (section .text) bắt đầu từ offset 0x1000, do đó:

```python
size = len(0x1000*b'\x00' + code)
```

![](https://hackmd.io/_uploads/HkhVANvv2.png)

Vậy là mình đã tóm tắt xong phần header của file. Tiếp theo sẽ là phần thực thi code của chương trình.

### `Core_run` function 

Về phần flow thực thi code của chương trình khá đơn giản, nó chỉ bao gồm một vòng lặp trong đó nó sẽ lần lượt lấy 4 byte tiếp theo của `code` (Instruction fetch), tương ứng với 1 instruction, decode instruction này và bắt đầu excute, lặp lại cho tới khi hết chương trình. 

![](https://hackmd.io/_uploads/SkFyxSDwn.png)

Đầu tiên hàm `decode` sẽ lấy 6 bit đầu (&0x3f) của 4 byte instruction và gọi constructor `NewInstruction()`, được biết 6 bit này sẽ đại diện cho `Instruction type`, mình sẽ nói rõ phần này sau.

![](https://hackmd.io/_uploads/B1Z7ZrvDn.png)

Ở hàm `NewInstruction()`, ta sẽ thấy rằng sẽ có 4 loại instruction tương ứng với 4 type khác nhau:

![](https://hackmd.io/_uploads/B1n_zrPw3.png)

Tương ứng với:

- R-type instruction `0x1b`: Các instruction liên quan đến các toán tử trên thanh ghi hoặc các toán tử so sanh,...
- I-type instruction: Các instruction liên quan đến hằng số (immediate) trong đó Y type gồm 2 loại.
    - Toán hạng thanh ghi `0xB`: Sẽ thực thi các instruction tác động lên thanh ghi.
    - Toán hạng bộ nhớ: `0xA`: Các instruction có tác động tới bộ nhớ.
- B-type instruction `0x3`: Các instruction liên quan đến các nhảy và điều kiện nhảy...

Tuy nhiên suy nghĩ kĩ lại thì trong yêu cầu bài này, sau khi execute, nó sẽ đọc chuỗi từ 1 section và so sánh với `"Hello CDDC2023!"`, do đó ta dường như chỉ cần dùng đến I-type instruction, hoàn toàn không cần dùng các tính toán thanh ghi hoặc các điều kiện nhảy.
Trong đó `DecodeImm`:

![](https://hackmd.io/_uploads/HJgQBSvD2.png)

Tương ứng với 2 hàm decode còn lại,ta biết được các instruction sẽ có cấu trúc như sau:

```
6 bit đầu là instruction type, các bit còn lại là:
0x3:     B type: <>  4 - 4 - 3 - 1 - 14
0xA,0xB: I Type: <>  4 - 4 - 3 - 15
0x1B:    R Type: <>  4 - 4 - 3 - 4 - 11
```

Decode instruction chỉ đơn giản là tách các bit ra, tuy nhiên để hiểu hơn các bit này làm gì thì mình cần phần tích hàm sau.

### `Instruction Exec` function

Tiếp theo mình đã phân tích hàm`tinyx_internal_core_Instruction_Exec`, hàm này sẽ sẽ làm mọi thứ trên 1 lệnh đã decode. Vì chỉ cần quan tâm tới I-type nên mình chỉ phân tích Itype, các ins khác các bạn có thể tự tham khảo thêm. Mình sẽ attach các file ở cuối post này.

Nó sẽ lấy 3 bit của Ins(ở bảng trên) để làm opcode, tuy nhiên có 1 điều khá là chuối bởi vì 3 bit chỉ biểu diễn được 8 opcode, tuy nhiên chương trình lại có 9 case (0-8) => dùng lệnh thứ 9 không được. Trùng hợp thay lúc mình làm bài này lại cần dùng lệnh thứ 9 nhưng mãi mới phát hiện ra là nó không dùng được, thật là sax...

Các toán hạng thanh ghi:

![](https://hackmd.io/_uploads/HyW-wSwPh.png)

Các toán hạng bộ nhớ:

![](https://hackmd.io/_uploads/BJp-DrPD3.png)

Sau 1 vài lần debug và check kĩ, mình đã biết được như sau, cấu trúc của lệnh I type như sau:

`| type | reg_dest | reg | opcode | 15 bit immediate number|`

```python
def ImmIns(_type,dest,reg,opcode,imm):
    ret = imm<<3
    ret |= opcode
    ret <<=4
    ret |= reg
    ret <<=4
    ret |=dest
    ret <<=6
    ret |=_type
    return p32(ret)
```

## Solve

Mình có thể dễ dàng có hết các opcode, giờ chỉ cần việc viết code sao cho nó trả về đúng result nữa là xong.

Đầu tiên mình cần biết chuỗi cần ghi vào chổ nào, sau vài lần debug thì mình biết chuỗi mà chương trình cần kiểm tra lấy từ đầu section .data, tương ứng với offset 0x8000:

![](https://hackmd.io/_uploads/SyO5dBDv3.png)

Tiếp theo chỉ cần viết đoạn code mov từng byte của Chuỗi vào các offset liên tiếp này là xong:

```python
code += ImmIns(0xB,1,1,0,0x3000) # addi reg1, reg1, 0x3000
code += ImmIns(0xB,1,1,0,0x3000) # addi reg1, reg1, 0x3000
code += ImmIns(0xB,1,1,0,0x2000) # addi reg1, reg1, 0x2000  ; reg1 = 0x8000

string = b'Hello CDDC2023!'
for c in string:
    code += ImmIns(0xB,0,0,0,c) # addi reg0, reg0, char
    code += ImmIns(0xA,0,1,5,0)  # sb reg0, [reg1 + 0] ; store byte
    code += ImmIns(0xB,0,0,5,0) # andi reg0, reg0, 0 ; reset register
    code += ImmIns(0xB,1,1,0,1) # addi reg1, reg1, 1
```

Flag: 

![](https://hackmd.io/_uploads/HJrDKHwPh.png)


Full script:

```python
from pwn import *
# fast rev imm:
# 6 bit ins type : 0xb register ins, 0xA memory ins
# 4 dest reg
# 4 reg
# 3 bit opcode
# 15 bit imm

# opcode: 5 store byte, 
# 0: addi, 1 subi
def ImmIns(_type,dest,reg,opcode,imm):
    ret = imm<<3
    ret |= opcode
    ret <<=4
    ret |= reg
    ret <<=4
    ret |=dest
    ret <<=6
    ret |=_type
    return p32(ret)

def convert_hex(x):
    return ''.join('{:02x}'.format(a) for a in list(x)).encode()

# header
to_send = b'RISCXBIN'
#section
to_send += bytes.fromhex('00100000') + bytes.fromhex('00400000') + b'badubadu'
#code
#cay vai opcode 3 bit ma co tan 9 opcode?
#code += ImmIns(0xB,1,1,8,15) # shli reg1, reg1 , 15 ; reg1 = 0x8000

code = b'\x00' * 0x1000    # padding
# imm 15 bit
code += ImmIns(0xB,1,1,0,0x3000) # addi reg1, reg1, 0x3000
code += ImmIns(0xB,1,1,0,0x3000) # addi reg1, reg1, 0x3000
code += ImmIns(0xB,1,1,0,0x2000) # addi reg1, reg1, 0x2000  ; reg1 = 0x8000

string = b'Hello CDDC2023!'
for c in string:
    code += ImmIns(0xB,0,0,0,c) # addi reg0, reg0, char
    code += ImmIns(0xA,0,1,5,0)  # sb reg0, [reg1 + 0] ; store byte
    code += ImmIns(0xB,0,0,5,0) # andi reg0, reg0, 0 ; reset register
    code += ImmIns(0xB,1,1,0,1) # addi reg1, reg1, 1

to_send += p32(len(code)) + code

to_send = convert_hex(to_send)
print(to_send)
# io = process('./tinyx')
io = remote('challenges.pwn.cddc2023.com',5564)
#raw_input('attach please: ') # waiting for attach from debugger
io.sendline(to_send)
io.interactive()
```
File pdb: [tinyx.i64](https://anonfiles.com/89K9G3w7za/tinyx_i64)
