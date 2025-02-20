---
title: "Google CTF 2024"
description: "Writeup for Google CTF 2024"
summary: "Write up all reverse challenges in Tet CTF 2024"
categories: ["Writeup"]
tags: ["Reverse"]
#externalUrl: ""
date: 2024-06-28
draft: false
authors:
  - Jinn
cover: /images/post_covers/googlectf2024.jpeg
---

# Google CTF 2024

## Reverse

### not_obfuscate

Description:
> True story: I had planned on learning to write LLVM passes and use them for obfuscation for this year's gCTF challenge.However, when I compiled this code with optimizations enabled, I decided I didn't need to write an obfuscator.
It's a crackme, you know the drill. GL HF! 


### analysis

After a quick check, I found the code flow is effortless:

First, it reads 32 chars from the console, then converts it from hex bytes. It saves these bytes as a rc4 key. So we know that it takes the 16-byte key from our input.


![image](https://hackmd.io/_uploads/HkCLoJoLR.png)

![image](https://hackmd.io/_uploads/BkFfVeoIA.png)

That key is just used for rc4 to decrypt a given buffer, a.k.a flag.

![image](https://hackmd.io/_uploads/H1fW8liUA.png)

After that, it converts 16 bytes to an array, also a 4x4 matrix (the matrix is that thing I don't think about when doing the challenge, so I got stuck while analyzing and guessing that thing).

![image](https://hackmd.io/_uploads/Bk_kvliL0.png)

![image](https://hackmd.io/_uploads/H1CDdeoIR.png)

So, here is the code flow of the challenge:

```c
matrix_input = convert_fromhex()

matrix_temp = func(matrix_input,given_matrix_1)

...// a whole bunch of code with `matrix_temp`...

result = func(matrix_temp,given_matrix_2)
    
result = substitute(result) // like a AES subbyte 

-> compare `result` with the given result [0x345,0x1,0x215...]

```

To be honest, I didn't solve the challenge but after a quick check of the src, I can't believe that the challenge flow is not hard at all, it's about the math problem. So I decided to test it all.

Okay, just think, if we know that a 16-word array is a matrix, so `do_something` is probably an operation of the matrix, like add, multiply, inverse,...vv.

![image](https://hackmd.io/_uploads/HJ2IpxsU0.png)

So I decided to test it, this one is the input matrix.

![image](https://hackmd.io/_uploads/rkI70xsLR.png)

```python
import numpy as np

def array_to_matrix(a:list):
    return np.matrix([a[0:4],a[4:8],a[8:12],a[12:16]])

inp = [0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201]
inp_matrix = array_to_matrix(inp)
buf1 = [0x49, 0x324, 0x7, 0x22, 0x24b, 0x210, 0x123, 0x17, 0x2b, 0x329, 0x21, 0x3, 0x241, 0x344, 0x330, 0x32a]
given_matrix_1 = array_to_matrix(buf1)

##test
result = inp_matrix+given_matrix_1
result = np.remainder(result,0x400)
print(result)
result = inp_matrix*given_matrix_1
result = np.remainder(result,0x400)
print(result)
```

Here's result in python:
```
[[586 293 520 547]                                                           
 [ 76  17 804 536]                                                           
 [556 298 546 516]                                                           
 [ 66 325 305 299]]
 
[[256 417 635 870]
 [256 417 635 870]
 [256 417 635 870]
 [256 417 635 870]]
```

result in IDA:

```
[586, 293, 520, 547, 76, 17, 804, 536, 556, 298, 546, 516, 66, 325, 305, 299]
```

So, `do_something` seems like a matrix `add` operation. But when I take another `add`, it seems incorrect:

```python
tmp1 = array_to_matrix([0x248, 0x10a, 0x323, 0x230, 0x125, 0x149, 0x206, 0x132, 0x217, 0x10b, 0x312, 0x220, 0x1a, 0x228, 0x46, 0x307])
tmp2 = array_to_matrix([0x308, 0x227, 0x133, 0x1, 0x120, 0x139, 0x205, 0x100, 0x145, 0x221, 0x29, 0x11a, 0x318, 0x13, 0x11a, 0x16])

print(np.remainder(tmp1,tmp2))
```

Result:
```python
[[584 266 189   0]
 [  5  16   1  50]
 [210 267   7 262]
 [ 26   1  70   5]]
```

Result in IDA:
```python
[323, 804, 6, 561, 581, 549, 11, 562, 780, 812, 827, 826, 805, 571, 259, 784]
```

Even `add` operation in a special way, I will explain in [rns](#rns):

So the correct `add` is:

```python
def add(a,b):
    ret = 0
    ret = ((a>>8) + (b>>8))%4
    ret <<= 4
    ret |= (((a>>4)&0xf)+((b>>4)&0xf))%5
    ret <<= 4
    ret |= ((a&0xf) + (b&0xf))%13
    return ret

print([add(x,y) for x,y in zip(tmp1,tmp2)]) # [323, 804, 6, 561, 581, 549, 11, 562, 780, 812, 827, 826, 805, 571, 259, 784] 
```

Then we know:

```
add(inp,matrix1)


...whole bunch of code...

add(inp,matrix2)
```

I found another matrix that I didn't know while doing this challenge (it looked like an unknown xmmword, so I formatted and renamed it):

![image](https://hackmd.io/_uploads/r1mRUbj8C.png)

![image](https://hackmd.io/_uploads/BJbTwbsUA.png)

Do you think a whole bunch of code means just a simple operation? Yes, that's it, the matrix multiplied with the other given matrix I found.

**Testing**
```python!
temp_matrix = inp_matrix+given_matrix_1
temp_matrix = np.remainder(temp_matrix,0x400)
after_shit = np.remainder(temp_matrix*another_matrix,0x400)
print(after_shit)
```

```
[[ 833  772  481   37]
 [ 162  395  832 1005]
 [ 708  856  200   72]
 [ 651  559  943  164]]
```

**Result in IDA:**

```shell
Python>result = [idaapi.get_word(0x7FFDDB69FAA0 + i) for i in range(0,32,2)]
Python>print(result)
[584, 266, 803, 560, 293, 329, 518, 306, 535, 267, 786, 544, 26, 552, 70, 775]
```

It's not working, am I missing something?

After a quick check, I found that `another_matrix` is used for later, and I see that just a simple xor operation but in the form of substitution.

![image](https://hackmd.io/_uploads/Sk29lfsUC.png)


```python!
def rns_xor_with_buf2(buf):
    ret = [0]*16
    for i in range(16):
        num = buf[i]            # decode before xor
        a,b,c = num&0xf,(num>>4)&0xf,(num>>8)&0xf
        d,e,f = buf2[i]&0xf,(buf2[i]>>4)&0xf,(buf2[i]>>8)&0xf
        idx = 0x410 * ((5 * a + b)&0xff) + 0x104 * c + 4 * ((5 * d + e)&0xff) + f
        ret[i] = given_words[idx]
    return ret
```

I know it's xor after checking the src code before it xor before it's pack and decode the matrix. (matrix using a custom base in range 260, instead of 256)

Keep in mind this, the matrix uses `rns`, which is like another base.

#### **rns**
> **Residue number system**
> A residue numeral system (RNS) is a numeral system representing integers by their values modulo several pairwise coprime integers called the moduli. This representation is allowed by the Chinese remainder theorem, which asserts that, if M is the product of the moduli, there is, in an interval of length M, exactly one integer having any given set of modular values. The arithmetic of a residue numeral system is also called multi-modular arithmetic.
    https://en.wikipedia.org/wiki/Residue_number_system
    https://personal.utdallas.edu/~ivor/ce6305/m5p.pdf

```c
conv_from_inp[i] = (hex_byte % 13u) | (16 * ((hex_byte % 5u) | (16 * hex_byte) & 0x30));
```

**which means:**
```python
input_in_hex = [0x61,0x61,0x61,0x61,...] #'aaaaaaaaa'

matrix = rns(input_in_hex) #[rns(0x61),rns(0x61),rns(0x61),...] 
#encode -> [0x12,0x12,......], in base 260

# and the `given_words` also known as `xor_table`
xor_table = [rns(byte_a^ byte_b
                not
xor_table = [rns(byte_a) ^ rns(byte_b)]   

```
That's the reason why I got stuck for a long time...

So, we know the property of xor, then just xor again and we get the original buffer.
```
to_cmp = after_shit ^ another_matrix

=> after_shit = to_cmp ^ another_matrix
```

Just get the xor_table from binary, and then I use this function to operate xor.

I've tried this one but it didn't work when I do it again, even if I patch these words into IDA and let it run, still got the wrong answer.

```python
buf2 = [0x1a, 0x12c, 0x24c, 0x11c, 0x12a, 0x137, 0x210, 0x111, 0x242, 0x31b, 0x126, 0x327, 0x329, 0x20b, 0x3, 0x220]
# `another_buffer` a.k.a `buf2`

def rns_xor_with_buf2(buf):
    ret = [0]*16
    for i in range(16):
        num = buf[i]
        a,b,c = num&0xf,(num>>4)&0xf,(num>>8)&0xf
        d,e,f = buf2[i]&0xf,(buf2[i]>>4)&0xf,(buf2[i]>>8)&0xf
        idx = 0x410 * ((5 * a + b)&0xff) + 0x104 * c + 4 * ((5 * d + e)&0xff) + f
        ret[i] = given_words[idx]
    return ret
```

So I write another function to xor but just using brute foce, and it work:

```python
def another_xor(buf):
    res = []
    for i in range(16):
        res.append(brute(buf2[i],buf[i]))
    return res
def brute(b2,to_cmp):

    for hex_byte in range(256):
        num = 0
        num += hex_byte % 4
        num <<= 4
        num += hex_byte % 5
        num <<= 4
        num += hex_byte % 13

        a,b,c = num&0xf,(num>>4)&0xf,(num>>8)&0xf
        d,e,f = b2&0xf,(b2>>4)&0xf,(b2>>8)&0xf
        idx = 0x410 * ((5 * a + b)&0xff) + 0x104 * c + 4 * ((5 * d + e)&0xff) + f
        if given_words[idx] == to_cmp:
            # print(hex(num),num)
            return num

    return None
def main():

    #recover
    recovered = another_xor(to_cmp_w)
    print(recovered)

    #test
    tmp = rns_xor_with_buf2(recovered) # also check in IDA
    print(tmp==to_cmp_w)
```

```
[771, 282, 38, 267, 39, 299, 819, 576, 770, 843, 529, 32, 837, 323, 315, 257]
True
```

Now, we have completed step 1, and here's the flow we got:

```python!
tmp = (inp + matrix_1)

sus(tmp) #Whole bunch of Code

tmp = add(tmp,matrix_2)
tmp = xor(tmp, another_matrix)

if tmp == buf:
    #we got it
```
and we have: `matrix_1`, `matrix_2`, `another_matrix`, and `buf`

### Whole bunch of Code?

The feeling...

![image](https://hackmd.io/_uploads/Syo9UQjLR.png)

**RULE 35: It just a matrix operation**

Before we reverse, I figure out how it is possible. I mean, How can a simple operation be a bunch of code?

Here's a simple matrix multiply from `programiz` but I'm using built-in type: `long double` instead of `int`:


```cpp
#include <iostream>
using namespace std;

int main()
{
    long double a[10][10], b[10][10], mult[10][10];
    int r1, c1, r2, c2, i, j, k;

    cout << "Enter rows and columns for first matrix: ";
    cin >> r1 >> c1;
    cout << "Enter rows and columns for second matrix: ";
    cin >> r2 >> c2;
    while (c1!=r2)
    {
        cout << "Error! column of first matrix not equal to row of second.";

        cout << "Enter rows and columns for first matrix: ";
        cin >> r1 >> c1;

        cout << "Enter rows and columns for second matrix: ";
        cin >> r2 >> c2;
    }

    // Storing elements of first matrix.
    cout << endl << "Enter elements of matrix 1:" << endl;
    for(i = 0; i < r1; ++i)
        for(j = 0; j < c1; ++j)
        {
            cout << "Enter element a" << i + 1 << j + 1 << " : ";
            cin >> a[i][j];
        }

    // Storing elements of second matrix.
    cout << endl << "Enter elements of matrix 2:" << endl;
    for(i = 0; i < r2; ++i)
        for(j = 0; j < c2; ++j)
        {
            cout << "Enter element b" << i + 1 << j + 1 << " : ";
            cin >> b[i][j];
        }

    // Initializing elements of matrix mult to 0.
    for(i = 0; i < r1; ++i)
        for(j = 0; j < c2; ++j)
        {
            mult[i][j]=0;
        }

    // Multiplying matrix a and b and storing in array mult.
    for(i = 0; i < r1; ++i)
        for(j = 0; j < c2; ++j)
            for(k = 0; k < c1; ++k)
            {
                mult[i][j] += a[i][k] * b[k][j];
            }

    // Displaying the multiplication of two matrix.
    cout << endl << "Output Matrix: " << endl;
    for(i = 0; i < r1; ++i)
    for(j = 0; j < c2; ++j)
    {
        cout << " " << mult[i][j];
        if(j == c2-1)
            cout << endl;
    }

    return 0;
}
```

So, I compiled with Clang++ and see the different between without optimize and optimize flag enabled:

![image](https://hackmd.io/_uploads/rkSrkVi8A.png)

We easily see that optimization makes the code harder. Even if it is just a built-in type, the challenge is using a custom one, which is almost impossible.

It's just a point of view from a reverser, here's more about clang optimize:


> https://www.incredibuild.com/blog/compiling-with-clang-optimization-flags
https://news.ycombinator.com/item?id=28207207
https://www.reddit.com/r/C_Programming/comments/conavx/clangs_optimizer_is_ridiculously_smart_like/

In the challenge, we see it as **SIMD**:
> https://ftp.cvut.cz/kernel/people/geoff/cell/ps3-linux-docs/CellProgrammingTutorial/BasicsOfSIMDProgramming.html
> https://www.codeproject.com/Articles/5298048/Using-SIMD-to-Optimize-x86-Assembly-Code-in-Array

We know that the code just doing some simple operations but is optimized.

After a day I figure out what is it. I finally found it just matrix multiply (as I guess) but it was difficult to find the multiplicand (matrix A)

So, to save time I decided to get it from src code (will be updated later).

Here is the complete flow:

```python
A = Matrix_rns([208, 120, 107, 19, 138, 163, 11, 174, 217, 67, 60, 143, 13, 232, 181, 2],conv=True)  # from source
B = Matrix_rns([0x49, 0x324, 0x7, 0x22, 0x24b, 0x210, 0x123, 0x17, 0x2b, 0x329, 0x21, 0x3, 0x241, 0x344, 0x330, 0x32a],ls=True) #from IDA
C = Matrix_rns([0x308, 0x227, 0x133, 0x1, 0x120, 0x139, 0x205, 0x100, 0x145, 0x221, 0x29, 0x11a, 0x318, 0x13, 0x11a, 0x16],ls=True)#from IDA
D = Matrix_rns([0x1a, 0x12c, 0x24c, 0x11c, 0x12a, 0x137, 0x210, 0x111, 0x242, 0x31b, 0x126, 0x327, 0x329, 0x20b, 0x3, 0x220],ls=True)#from IDA

#### THE FLOW
inp_matrix = Matrix_rns([0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201, 0x201],ls=True) # test input with 'aaaaaaaaaaaaaaaaaaaa'

temp = inp_matrix.add(B)
# print(temp.as_list())
temp = temp.mul(A)
# print(temp.as_list())
temp = temp.add(C)
# print(temp.as_list())
result = temp.xor(D)
```

And here's the way that I operate xor to get the previous buffer before compare (expected_to_cmp):

```python
from given_words import given_words,L

buf2 = [0x1a, 0x12c, 0x24c, 0x11c, 0x12a, 0x137, 0x210, 0x111, 0x242, 0x31b, 0x126, 0x327, 0x329, 0x20b, 0x3, 0x220]
buf1 = [0 for _ in range(16)]
aftershit = [0x143, 0x324, 0x6, 0x231, 0x245, 0x225, 0xb, 0x232, 0x30c, 0x32c, 0x33b, 0x33a, 0x325, 0x23b, 0x103, 0x310]
to_cmp_w = [0x346,1,0x215,0x4C,0x144,0x44,0x10C,0x301,0x125,0x30,0x309,0x31C,0x42,0x328,0x103,0x332]
assert len(to_cmp_w)==16

def get_index(value):
    #rebuild from src
    m = [13,5,4]
    res = [0]*3
    index = 0
    for i in range(3):
        res[2 - i] = (value >> (4 * i)) & 0xF
    for i in range(3):
        index += res[2-i]
        if i+1 < 3:
            index *= m[1-i]
            # index &= 0xff
    return index

def rns_xor_with_buf2(buf):
    ret = [0]*16
    for i in range(16):
        num = buf[i]
        a,b,c = num&0xf,(num>>4)&0xf,(num>>8)&0xf
        d,e,f = buf2[i]&0xf,(buf2[i]>>4)&0xf,(buf2[i]>>8)&0xf
        idx = 0x410 * ((5 * a + b)&0xff) + 0x104 * c + 4 * ((5 * d + e)&0xff) + f
        ret[i] = given_words[idx]
    return ret
def another_xor(buf):
    res = []
    for i in range(16):
        res.append(brute(buf2[i],buf[i]))
    return res
def brute(b2,to_cmp):
    nums = []
    for hex_byte in range(256):
        num = 0
        num += hex_byte % 4
        num <<= 4
        num += hex_byte % 5
        num <<= 4
        num += hex_byte % 13
        a,b,c = num&0xf,(num>>4)&0xf,(num>>8)&0xf
        d,e,f = b2&0xf,(b2>>4)&0xf,(b2>>8)&0xf
        idx = 0x410 * ((5 * a + b)&0xff) + 0x104 * c + 4 * ((5 * d + e)&0xff) + f
        if given_words[idx] == to_cmp:
            # print(hex(num),num)
            nums.append(num)
    print(nums)
    return nums[-1]
            

def main():
    brute(buf2[4],324)

    #recover
    recovered = another_xor(to_cmp_w)
    print(recovered)

    #test
    tmp = rns_xor_with_buf2(to_cmp_w)
    print(tmp)

if __name__=='__main__':
    main()
```

I tried both ways: brute and get xor table, which got me 2 different matrices.

```python
[771, 282, 38, 267, 39, 299, 819, 576, 770, 843, 529, 32, 837, 323, 315, 257]
[771, 282, 38, 267, 76, 299, 819, 576, 770, 843, 529, 32, 837, 323, 315, 257]
```

I've reimplement the rns matrix in python, just need the matrix invert operation.

Here invert from @d4rk9n1ght in sagemath.

```python
def  convert_to_1mod(arr):
    result = []
    for i in arr:
        a,b,c = i&0xf, (i>>4)&0xf, (i>>8)&0xf
        res = crt([c,b,a], [4,5,13])
        result.append(res)
    return result
def convert_to_3mod(arr):
    result = []
    cp = [int(i) for i in arr]
    for i in cp:
        a,b,c = i %4, i%5, i%13 
        hehe = a 
        hehe <<= 4 
        hehe |= b 
        hehe <<= 4 
        hehe |= c 
        result.append(hehe)
    return result

from sage.all import *

gl = GL(3, Zmod(4*5*13))

arr = [48, 3, 803, 838 ,568, 823, 795, 581 ,297, 802, 8, 816, 304, 43, 284, 546]
arr = convert_to_1mod(arr)
A = [arr[:4], arr[4:8], arr[8:12], arr[12:]]

A = Matrix(Zmod(4 * 5 * 13), A)
print(A.is_invertible())
inv_A = A.inverse()

print(A * inv_A)
# print(inv_A)
inv_A_arr = list(inv_A[0]) + list(inv_A[1]) + list(inv_A[2]) + list(inv_A[3])
# print(inv_A_arr)
final = convert_to_3mod(inv_A_arr)
print(final)
```
**output**
```python
[811, 276, 795, 9, 295, 561, 306, 825, 295, 309, 842, 844, 580, 842, 279, 313]
```

Here's script that recover the input:

```pyhon
A_inv = Matrix_rns([811, 276, 795, 9, 295, 561, 306, 825, 295, 309, 842, 844, 580, 842, 279, 313],ls = True)
print(A.mul(A_inv))
# aftershit = Matrix_rns([0x248, 0x10a, 0x323, 0x230, 0x125, 0x149, 0x206, 0x132, 0x217, 0x10b, 0x312, 0x220, 0x1a, 0x228, 0x46, 0x307],ls=True)

x = aftershit.mul(A_inv)
x = x.sub(B)
x = [x.decode(i) for i in x.as_list()]
print(bytes(x).hex())
```
**output**

```
[[273, 0, 0, 0], [0, 273, 0, 0], [0, 0, 273, 0], [0, 0, 0, 273]]
fcedd5ab42f188b49760fca0d51e6fb1
```

So, I finally found the correct input but still the wrong key for decryption. It is probably the problem from 2 matrices that I found above.

![image](https://hackmd.io/_uploads/rJbxDuh8A.png)



Also, I tried to brute force the byte in the matrix and got the result:

```python
A_inv = Inverse(Matrix_rns([208, 120, 107, 19, 138, 163, 11, 174, 217, 67, 60, 143, 13, 232, 181, 2],conv=True).as_list())
A_inv = Matrix_rns(A_inv,ls = True)
print("A_inv: ",A_inv.matrix) ### A_inv is correct
enc_flag = b'\xe8M0a\x19\t\x8e\xac\x99\x8a\x8e:\x0f\xf1\xf6%w9t-h#\xc7{~\xa4\xcb\xbe\xee\xc7E\xff\x1c\x8f-m\xcb\xf5b'
for hex_byte in range(256):
    num = 0
    num += hex_byte % 4
    num <<= 4
    num += hex_byte % 5
    num <<= 4
    num += hex_byte % 13
    aftershit.matrix[3][1] = num ## the wrong number is at matrix[3][1], I've test by each number of matrix.
    x = aftershit.mul(A_inv)
    x = x.sub(B)
    x = [x.decode(i) for i in x.as_list()]
    
    try:
        #print(bytes(x).hex())
        arc = ARC4(bytes(x))
        flag = arc.decrypt(enc_flag)
        if b'CTF' in flag or b'ctf' in flag:
            print(flag)
    except:
        #print(x)
        pass
```

**output**
```
A: [[48, 3, 803, 838], [568, 823, 795, 581], [297, 802, 8, 816], [304, 43, 284, 546]]
B: [[73, 804, 7, 34], [587, 528, 291, 23], [43, 809, 33, 3], [577, 836, 816, 810]]
C: [[776, 551, 307, 1], [288, 313, 517, 256], [325, 545, 41, 282], [792, 19, 282, 22]]
D: [[26, 300, 588, 284], [298, 311, 528, 273], [578, 795, 294, 807], [809, 523, 3, 544]]
A_inv:  [[811, 276, 795, 9], [295, 561, 306, 825], [295, 309, 842, 844], [580, 842, 279, 313]]
b'Flag: ctf{I_pr0mize_its_jUsT_mAtriCeS}\x00'
```


Finally got flag: ```ctf{I_pr0mize_its_jUsT_mAtriCeS}```

In my point, it's the easiest challenge, and not interested at all, but at least, I know that I need to learn more, more, and more math. The new meta of Reverse. Also, I will update the remaining challenge later, pls enjoy.

### X86PERM (will be updated)
### IEEE (will be updated)