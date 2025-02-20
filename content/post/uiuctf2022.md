---
title: "UIUCTF 2022"
description: "Writeup for The UIUCTF 2022"
summary: "Writeup for The UIUCTF 2022"
categories: ["Writeup"]
tags: ["Reverse","Vietnamese"]
#externalUrl: ""
date: 2022-07-30
draft: false
authors:
  - Jinn
cover: /images/post_covers/uiuctf2022.jpeg
---

## Reject to Inject - 197 points

![](https://i.imgur.com/kzr9V9u.png)

> Attachment file: [IV.dll](https://2022.uiuc.tf/files/730b32097be5f04fd5ed3eda799901a0/IV.dll?token=eyJ1c2VyX2lkIjo5MTEsInRlYW1faWQiOjQ0OCwiZmlsZV9pZCI6NjM3fQ.YueAyA.EBvtH750spnAIjVK_1o9C-bl6aE)

![](https://i.imgur.com/bH7RQai.png)


Theo như kinh nghiệm rev windows của mình thì với file dll thì sẽ mở bằng IDA để static analysis trước:

Load file bằng IDA64:
Bật qua tab string, mình thấy một vài string đặt biệt như:

![](https://i.imgur.com/mkRHtyg.png)

Và một cái fake flag như này:

`uiuctf{sorry_im_just_a_fake_flag}`

Xref tới chổ gọi fake flag, ta có được hàm `sub_180013B90()` gọi tới nó:

```c
__int64 __fastcall sub_180013B90(const char *a1, _BYTE *a2)
{
  __int64 result; // rax
  int v3; // [rsp+24h] [rbp+4h]
  int v4; // [rsp+44h] [rbp+24h]
  int i; // [rsp+64h] [rbp+44h]
  int j; // [rsp+64h] [rbp+44h]
  const char *v7; // [rsp+88h] [rbp+68h]
  int v8; // [rsp+154h] [rbp+134h]

  sub_1800114B0(&unk_18002C161);
  sub_180011203((__int64)FakeFlag);
  sub_180011433((__int64)byte_180026590);
  v3 = j_strlen(a1);
  v4 = 5 * v3 / 8;
  v7 = a1;
  for ( i = 0; i < v3; ++i )
  {
    if ( a1[i] == byte_180026000 )
      a1[i] = byte_180026590[0];
  }
  for ( j = 0; j < v4; ++j )
  {
    v8 = j % 5;
    if ( j % 5 )
    {
      switch ( v8 )
      {
        case 1:
          a2[j] = ((int)byte_1800265C0[v7[2]] >> 4) | (2 * byte_1800265C0[v7[1]]) | ((byte_1800265C0[*v7] & 3) << 6);
          v7 += 2;
          break;
        case 2:
          a2[j] = ((int)byte_1800265C0[v7[1]] >> 1) | (16 * (byte_1800265C0[*v7] & 0xF));
          ++v7;
          break;
        case 3:
          a2[j] = ((int)byte_1800265C0[v7[2]] >> 3) | (4 * byte_1800265C0[v7[1]]) | ((byte_1800265C0[*v7] & 1) << 7);
          v7 += 2;
          break;
        case 4:
          a2[j] = byte_1800265C0[v7[1]] | (32 * (byte_1800265C0[*v7] & 7));
          v7 += 2;
          break;
      }
    }
    else
    {
      a2[j] = ((int)byte_1800265C0[v7[1]] >> 2) | (8 * byte_1800265C0[*v7]);
      ++v7;
    }
  }
  result = v4;
  a2[v4] = 0;
  return result;
}
```

Nhìn sơ qua thì đây có vẻ là hàm decrypt một đoạn data nào đó, tạm thời mình đặt tên nó là `decrypt()` tiếp tục trace xem hàm nào gọi cái này:

```c
__int64 __fastcall sub_180013260(HMODULE a1)
{
  char *v1; // rdi
  __int64 i; // rcx
  HANDLE CurrentProcess; // rax
  __int64 v4; // rdi
  char v6[32]; // [rsp+0h] [rbp-20h] BYREF
  char v7; // [rsp+20h] [rbp+0h] BYREF
  WCHAR ProfileDir[1034]; // [rsp+30h] [rbp+10h] BYREF
  int cchSize[9]; // [rsp+844h] [rbp+824h] BYREF
  HANDLE TokenHandle; // [rsp+868h] [rbp+848h] BYREF
  __int64 v11; // [rsp+888h] [rbp+868h]
  const char *Source; // [rsp+8A8h] [rbp+888h]
  const char *v13; // [rsp+8C8h] [rbp+8A8h]
  char Str1[1056]; // [rsp+8F0h] [rbp+8D0h] BYREF
  CHAR Filename[1044]; // [rsp+D10h] [rbp+CF0h] BYREF
  DWORD nSize; // [rsp+1124h] [rbp+1104h]
  int v17; // [rsp+1144h] [rbp+1124h]
  char v18[96]; // [rsp+1168h] [rbp+1148h] BYREF
  char Src[80]; // [rsp+11C8h] [rbp+11A8h] BYREF
  size_t MaxCount; // [rsp+1218h] [rbp+11F8h]
  CHAR Dst[472]; // [rsp+1240h] [rbp+1220h] BYREF
  char v22[1564]; // [rsp+1418h] [rbp+13F8h] BYREF
  unsigned int v23; // [rsp+1A34h] [rbp+1A14h]

  v1 = &v7;
  for ( i = 1300i64; i; --i )
  {
    *(_DWORD *)v1 = -858993460;
    v1 += 4;
  }
  sub_1800114B0(&unk_18002C0A0);
  memset(ProfileDir, 0, 0x800ui64);
  cchSize[0] = 2048;
  TokenHandle = 0i64;
  v11 = 0i64;
  Source = "\\Room2004";
  v13 = "\\sigpwnie.exe";
  memset(Filename, 0, 0x400ui64);
  nSize = 1024;
  v17 = 0;
  strcpy(v18, "IS7WXGC726Z9JZMFPOKWQVMEPJCSU2FIMAC5N2VYIPGFJPCZPROPMYNL");
  memset(Src, 0, 0x38ui64);
  MaxCount = 56i64;
  memset(Dst, 0, 0x1C0ui64);
  CurrentProcess = GetCurrentProcess();
  OpenProcessToken(CurrentProcess, 8u, &TokenHandle);
  GetUserProfileDirectoryW(TokenHandle, ProfileDir, (LPDWORD)cchSize);
  CloseHandle(TokenHandle);
  sub_18001147E(v22, 8i64);
  sub_18001144C(v22, ProfileDir);
  v11 = sub_180011343(v22);
  strcpy(Str1, v11);
  strcat(Str1, Source);
  strcat(Str1, v13);
  GetModuleFileNameA(0i64, Filename, nSize);
  v17 = strncmp(Str1, Filename, nSize);
  if ( v17 )
  {
    sub_180011221("Failed!\n");
    system("pause");
    FreeLibraryAndExitThread(a1, 0);
  }
  j_decrypt((__int64)v18, (__int64)Src);
  memccpy(Dst, Src, 125, MaxCount);
  v23 = MessageBoxA(0i64, Dst, "Success", 0);
  sub_18001141A(v22);
  v4 = v23;
  sub_1800113F2(v6, &unk_180021CA0);
  return v4;
}
```
Thì đây cũng là luồn thực thi chính của chương trình, mình đã đổi tên một số hàm cho dễ hiểu, còn các hàm còn lại tạm thời mình k cần quan tâm.

Thì flow rất dễ hiểu, chương trình check xem có phải mình đang thực thi nó ở đúng file và đường dẫn hay không, cụ thể là: 

`<user_profile_directory>\Room2004\sigpwnie.exe`

Nếu đúng nó sẽ decrypt cái đoạn v18:
`"IS7WXGC726Z9JZMFPOKWQVMEPJCSU2FIMAC5N2VYIPGFJPCZPROPMYNL"` và in `MessageBox`.

Vì file dll không thể chạy trực tiếp được nên đến đây có thể có nhiều hướng:

1. Build lại hàm decrypt và lấy flag
2. Viết 1 chương trình mới gọi tới dll và debug file dll lấy flag
3. Dùng rundll32.exe có sẵn của windows để load dll và debug bằng ida

Về cách thứ 1, lúc mình phân tích thì thấy một vài chổ của hàm decrypt gọi tới để genBytes như:

```c
__int64 __fastcall sub_180013FE0(unsigned int *a1)
{
  char *v1; // rdi
  __int64 i; // rcx
  char v4[32]; // [rsp+0h] [rbp-20h] BYREF
  char v5; // [rsp+20h] [rbp+0h] BYREF
  int v6[15]; // [rsp+28h] [rbp+8h] BYREF
  int j; // [rsp+64h] [rbp+44h]
  unsigned __int64 v8; // [rsp+138h] [rbp+118h]

  v1 = &v5;
  for ( i = 30i64; i; --i )
  {
    *(_DWORD *)v1 = -858993460;
    v1 += 4;
  }
  sub_1800114B0((__int64)&unk_18002C161);
  j = 0;
  j_memset(dword_180026670, 0, 0x40ui64);
  while ( j < 16 )
  {
    dword_180026670[j] = sub_180011177(*a1, (unsigned int)j);
    ++j;
  }
  sub_18001132F(dword_180026670);
  for ( j = 0; j < 100; ++j )
    sub_18001126C();
  v6[0] = -1678030491;
  v6[1] = 1213635701;
  v6[2] = 865493747;
  v6[3] = -1002882818;
  v6[4] = 52570913;
  v6[5] = 15408472;
  v6[6] = -277531332;
  v6[7] = 1883894447;
  v6[8] = 2049029407;
  v6[9] = -595920156;
  for ( j = 0; j < 10; ++j )
  {
    v8 = 4 * j;
    v6[v8 / 4] ^= sub_18001126C();
  }
  sub_18001155F(byte_180026590, 34i64, &unk_180021E58, v6);
  return sub_1800113F2(v4, &unk_180021D00);
}
```

Về chổ hàm `sub_18001126C()` được gọi riêng lẻ và dùng trực tiếp, rất có thể đây là hàm `rand()` và dùng `seed()` dựa trên fakeFlag lúc nãy, nên là việc build lại có vẻ khó, mình không làm theo cách này.

Mình dùng luôn cách 3 vì nó khá tiện lợi, tuy nhiên để debug thành công các bạn cần lưu ý 1 vài điểm như sau:

1. Đặt breakpoint đúng chổ:

Bản thân `rundll32.exe` sẽ load hàm của dll lên để thực thi, và để cho an toàn, ta nên đặt breakpoint ở đầu thân hàm, cụ thể:

![](https://i.imgur.com/Kchvh2m.png)

Hàm ta muốn thực thi sẽ là `sub_180013260()`

2. Setup debugger:

Tại debugger, chọn Select Debugger->Local Windows debugger

Debugger-> Process option mình setup như vầy:

![](https://i.imgur.com/DJcK4aA.png)

Vì mình từng sai chổ đặt breakpoint và setup parameters nên lúc đó mình stuck khá lâu mới có thể tìm đc cách giải quyết như này, xem như qua bài này mình biết thêm được vài điều và có thể debug dll dễ dàng.

> Lưu ý: Có thể chỉnh lại tuỳ theo directory, và bản thân hàm sub_180013260 cũng có thể khác mình.

Vậy là đã debug thành công.

![](https://i.imgur.com/WLlY50i.png)

Tại đoạn này, các bạn có thể bypass qua dễ dàng bằng cách thay đổi zeroFlag:

![](https://i.imgur.com/z0WhyhR.png)

![](https://i.imgur.com/0FmIr6q.png)

Ezflag:

![](https://i.imgur.com/iZtmIai.png)

Go on...

## Pierated Art - 311 points

![](https://i.imgur.com/u5w1QRQ.png)

Sau khi netcat tới địa chỉ ta được thông tin như sau:

![](https://i.imgur.com/4WAjPdy.png)

1 đoạn Torrented picture data bằng base 64 và nó kêu mình nhập flag (1/10) có nghĩa là 10 câu hỏi khác nhau và mỗi câu 15s.

Thử viết script lấy data về và chuyển thành ảnh:

```python
from pwn import *
p = remote("pierated-art.chal.uiuc.tf",1337)
p.recvuntil(b"(Base64):\n")
    dt = p.recvuntil(b"\n")
    dt = (dt.decode().strip('\n')).encode() 
    img_file = open('image.jpeg', 'wb')
    img_file.write(base64.b64decode(dt))
    img_file.close()
```

Run và mở `image.jpeg` lên ta được tấm ảnh như sau:

![](https://i.imgur.com/RQUrQmN.jpg)

Hoặc là như này:)))

![](https://i.imgur.com/fIVWxNf.jpg)

Và còn nhiều tấm khác nữa...

> Sao không thấy bức nào của ông Van Gogh nhờ:v

Tuy là khác nhau và có vẻ ngẫu nhiên nhưng các bạn có thể thấy ngay những điểm ảnh lạ trên hình và đặc biệt là phần góc trái trên cùng luôn có 1 đống pixel ảnh đầy màu sắc

![](https://i.imgur.com/Eb81lMc.png)

Sau khi tìm hiểu và nhận trợ giúp từ trùm forensic @PkNova thì mình biết được đây là `piet code`, link tham khảo [tại đây](https://esolangs.org/wiki/Piet).


> Piet is a stack-based esoteric programming language in which programs look like abstract paintings. 
It uses 20 colors, of which 18 are related cyclically through a lightness cycle and a hue cycle. 
A single stack is used for data storage, together with some unusual operations.

Hiểu cơ bản là nó sẽ chạy đoạn code thực thi dựa theo các pixel màu, cụ thể là những pixel lúc nãy, giờ cân 1 tool để chạy thử đoạn code đó.

@PkNova đưa minh cái này: https://www.bertnase.de/npiet/

Tải về và chạy thử 1 tấm ảnh lúc nãy:

![](https://i.imgur.com/Zik7cgq.png)

Rõ ràng đây là 1 chương trình nhỏ check flag, nhập bừa và xem thử:

![](https://i.imgur.com/jmnJnPX.png)

Chương trình xuất ra 0, nghĩa là flag sai. Dùng thử chức năng trace của npiet:

![](https://i.imgur.com/acVH7M3.png)

Ta sẽ lấy ra được toàn bộ code của chương trình và stack của nó trong lúc thực thi, rất hay.

Thử nhập `abcdefghijk` và sau đó là 1 đoạn code rất dài để check flag, và xuất ra output của chương trình là "0".

![](https://i.imgur.com/2WoiaQt.png)

Copy code và đưa vào code editor để rev,

Để ý thấy đoạn đầu của code sẽ là in ra từng kí tự của chuỗi "enter flag:?"

Và sau khi nhập input của mình vào, nó sẽ load từng kí tự của input lên stack, và bắt đầu đoạn check.

```
action: push, value 2
trace: stack (13 values): 2 1 105 104 103 102 101 100 99 98 97 195 96

trace: step 201  (983,608/d,l dC -> 983,609/d,l lC):
action: push, value 1
trace: stack (14 values): 1 2 1 105 104 103 102 101 100 99 98 97 195 96

trace: step 202  (983,609/d,l lC -> 983,610/d,l nY):
action: roll
trace: stack (12 values): 105 1 104 103 102 101 100 99 98 97 195 96

trace: step 203  (983,610/d,l nY -> 983,612/d,l dY):
action: push, value 22
trace: stack (13 values): 22 105 1 104 103 102 101 100 99 98 97 195 96

trace: step 204  (983,612/d,l dY -> 983,613/d,l dG):
action: add
trace: stack (12 values): 127 1 104 103 102 101 100 99 98 97 195 96

trace: step 205  (983,613/d,l dG -> 983,615/d,l lG):
action: push, value 26
trace: stack (13 values): 26 127 1 104 103 102 101 100 99 98 97 195 96

trace: step 206  (983,615/d,l lG -> 983,616/d,l nB):
action: mod
trace: stack (12 values): 23 1 104 103 102 101 100 99 98 97 195 96

trace: step 207  (983,616/d,l nB -> 983,617/d,l lR):
action: not
trace: stack (12 values): 0 1 104 103 102 101 100 99 98 97 195 96

trace: step 208  (983,617/d,l lR -> 983,618/d,l dY):
action: multiply
trace: stack (11 values): 0 104 103 102 101 100 99 98 97 195 96
trace: entering white block at 983,1193 (like the perl interpreter would)...
```

Và theo như mình rev được thì đây là 1 đoạn để check 1 kí tự của nó

Tạm thời không cần quan tâm đoạn push 2, push 1 và rool, Nó sẽ push 1 giá trị là `22` và cộng với kí tự của input (trong trường hợp này là 105, kí tự "i")

Và sau đó nó `mod` cho 26 và `not` lại ra trị vừa ra và nhân tiếp cho kết quả của đoạn check tiếp theo.

Thì để out put của chương trình là 1, đồng nghĩa với việc (kí tự nhập vào + n mod 26) = 0 (với n là số đề cho theo từng kí tự và <26) và lặp lại với tất cả các kí tự còn lại.

Vì đề bài cho password là lower case nên là trong trường hợp input thuộc [97,122] sẽ có 2 chổ mà khi cộng 1 số n<26 sẽ thoả điều kiện là 130 và 104.

Từ đây, mình thử lấy tất cả các số `n` của nó ra để tìm thử password:

```python
l = [22,19,26,16,7,11,9,4,20,7]
def conv(ls):
    s = ""
    for i in ls:
        if i<8:
            s+=chr(104-i)
        else:
            s+=chr(130-i)
    return s
print(conv(l)[::-1]) #output: andywarhol
```
> Vì cơ chế stack sẽ đảo chiều chuỗi nên output của mình phải đảo lại trước khi in ra

Thử nhập vào chương trình:

![](https://i.imgur.com/Wvc8MSL.png)

Vậy là password đã đúng, chương trình đã xuất ra 1.

Nhưng còn 1 vấn đề là, làm sao để viết 1 script python có thể thực thi được lệnh: `npiet-1.3a-win32>npiet.exe -t image.jpeg` để lấy source code, từ source code lấy được các số `n` và lấy được flag send ngược lại cho server?

Sau 1 khoảng thời gian, mình tìm hiểu rất nhiều module khác nhau như `subprocess`, `pwintools`,`os` thì mình thấy có 1 cái có thể dùng đc là subprocess.

Vậy giờ sau khi có ảnh, mình sẽ dùng subprocess để chạy npiet, và nhập bừa input (vì flag k phụ thuộc vào input), phần stdout sẽ được lưu vào file `source.txt`:

```python
import subprocess
    f = open("source.txt",'wb')
    print("type some thing:")
    subprocess.call(["npiet.exe",'-t','image.jpeg'],stdout=f)
    f.close()
    f = open("source.txt",'r').readlines()
    ls = []
    for i in range(len(f)):
        if f[i]=="action: roll\n" and f[i+4]!="action: duplicate\n" and f[i+4]!="action: out(char)\n":
            x = f[i+4]
            num = int(x.split()[-1])
            ls.append(num)
    p.sendline(conv(ls).encode()[::-1])
```

Đoạn này khá hay ở chổ là mình có thể dùng `sdtout` để lưu thằng output vào file python đang mở. Mình từng stuck rất lâu chổ này và may là mình hiểu ra được stdout nên đã dùng thử và thành công luôn:))

Thêm 1 đặc điểm để lấy được `n`(cái này là tuỳ cơ ứng biến thôi): Để ý rằng sau các lệnh roll 4 lệnh sẽ có chổ lấy `n`, ngoại trừ các lệnh đặc biệt kia.

Việc còn lại là đưa nó vào 10 vòng lặp và thực thi thôi, và đây là script hoàn chỉnh:

```python
from pwn import *
import base64

def conv(ls):
    s = ""
    for i in ls:
        if i<8:
            s+=chr(104-i)
        else:
            s+=chr(130-i)
    return s
p = remote("pierated-art.chal.uiuc.tf",1337)
for n in range(10):
    p.recvuntil(b"(Base64):\n")
    dt = p.recvuntil(b"\n")
    dt = (dt.decode().strip('\n')).encode() 
    img_file = open('image.jpeg', 'wb')
    img_file.write(base64.b64decode(dt))
    img_file.close()


    import subprocess
    f = open("source.txt",'wb')
    print("Type something: ",end ="")
    subprocess.call(["npiet.exe",'-t','image.jpeg'],stdout=f)
    f.close()
    f = open("source.txt",'r').readlines()
    ls = []
    for i in range(len(f)):
        if f[i]=="action: roll\n" and f[i+4]!="action: duplicate\n" and f[i+4]!="action: out(char)\n":
            x = f[i+4]
            num = int(x.split()[-1])
            ls.append(num)
    p.sendline(conv(ls).encode()[::-1])
    print(f"Password {n+1}/10 accepted!")
p.interactive()
```

![](https://i.imgur.com/7gHWQPZ.png)

Flag: `uiuctf{m0ndr14n_b3st_pr0gr4mm3r_ngl}`


...
## Vast Cornfields - 223 points

![](https://i.imgur.com/zfrvovc.png)

>Attachment file: [vast_cornfields](https://2022.uiuc.tf/files/58e0a9b722cc6928c417967341f0b356/vast_cornfields?token=eyJ1c2VyX2lkIjo5MTEsInRlYW1faWQiOjQ0OCwiZmlsZV9pZCI6Njc4fQ.Yufm6Q.FBPEUfI8_cXDqDAOzgkMfmceXz4)

Theo mình thấy thì câu này là câu dễ nhất trong 4 bài.

![](https://i.imgur.com/tgIKw9l.png)

Mở bằng IDA64:

```c=
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  unsigned int v4; // eax
  unsigned int v5; // eax
  int v6; // eax
  size_t v7; // rax
  unsigned __int64 v8; // rax
  void *v9; // rsp
  unsigned int v10; // eax
  unsigned int v11; // eax
  char v13[15]; // [rsp+8h] [rbp-490h] BYREF
  char v14; // [rsp+17h] [rbp-481h]
  unsigned int v15; // [rsp+18h] [rbp-480h]
  unsigned int i; // [rsp+1Ch] [rbp-47Ch]
  unsigned int j; // [rsp+20h] [rbp-478h]
  unsigned int k; // [rsp+24h] [rbp-474h]
  size_t v19; // [rsp+28h] [rbp-470h]
  char *dest; // [rsp+30h] [rbp-468h]
  char v21[47]; // [rsp+38h] [rbp-460h] BYREF
  char v22[8]; // [rsp+67h] [rbp-431h] BYREF
  char s[1000]; // [rsp+78h] [rbp-420h] BYREF
  unsigned __int64 v24; // [rsp+460h] [rbp-38h]

  v24 = __readfsqword(0x28u);
  v14 = 1;
  while ( v14 )
  {
    printf("[$] Enter your input in the form: words_with_underscores_and_letters: ");
    __isoc99_scanf("%s", s);
    v15 = 0;
    for ( i = 0; ; i = ::s(i) )
    {
      v3 = strlen(s);
      if ( !(unsigned __int8)l(i, v3) )
        break;
      if ( (unsigned __int8)eq((unsigned int)s[i], 95LL) != 1 )
        v15 = ::s(v15);
    }
    v4 = strlen(s);
    if ( (unsigned __int8)ev(v4) != 1
      || (v5 = strlen(s), v6 = su(v5, 1LL), (unsigned __int8)eq((unsigned int)s[v6], 95LL))
      || (unsigned __int8)v(s) != 1
      || (unsigned __int8)ev(v15) != 1 )
    {
      puts("[$] This won't do...");
    }
    else
    {
      v7 = strlen(s);
      v19 = v7 - 1;
      v8 = 16 * ((v7 + 15) / 0x10);
      while ( v13 != &v13[-(v8 & 0xFFFFFFFFFFFFF000LL)] )
        ;
      v9 = alloca(v8 & 0xFFF);
      if ( (v8 & 0xFFF) != 0 )
        *(_QWORD *)&v13[(v8 & 0xFFF) - 8] = *(_QWORD *)&v13[(v8 & 0xFFF) - 8];
      dest = v13;
      strcpy(v13, s);
      for ( j = 0; ; j = encode(dest, j) )
      {
        v10 = strlen(dest);
        if ( !(unsigned __int8)l(j, v10) )
          break;
      }
      v11 = strcmp(dest, "odt_sjtfnb_jc_c_fiajb_he_ciuh_nkn_atvfjp");
      if ( (unsigned __int8)eq(v11, 0LL) )
      {
        puts("[$] Correct!");
        v14 = 0;
      }
      else
      {
        puts("[$] Incorrect...");
      }
    }
  }
  qmemcpy(v21, "uiuctf{", 7);
  for ( k = 0; (unsigned __int8)l(k, 40LL); k = ::s(k) )
    v21[k + 7] = s[k];
  strcpy(v22, "}");
  printf("[$] %s\n", v21);
  return 0;
}
```

Nhìn sơ qua thì rất may, các tên hàm dường như đã được đặt như ban đầu, khi mình rev thì hầu như không cần phải rev từng hàm mà dễ dàng đoán xem hàm đó làm gì.

Đầu tiên, khi chạy file lên sẽ có đoạn :

`"[$] Enter your input in the form: words_with_underscores_and_letters: `

Vì biết được format flag là những kí tự lowercase và underscores, vậy nên ta không cần rev đoạn từ dòng 48 trở lên nữa, đơn giản là nó chỉ check xem có thoả format hay không thôi, số lượng chữ cái sẽ là số chẳn(tí mình sẽ nói sau về cái này).

Sau khi nhập input và chạy qua vòng lặp `encode()` và sau đó input sẽ được so sánh với chuỗi "odt_sjtfnb_jc_c_fiajb_he_ciuh_nkn_atvfjp". Khá dễ hiểu.

Thử check hàm encode():

```c
__int64 __fastcall encode(__int64 a1, unsigned int a2)
{
  unsigned int v2; // eax
  char v5; // [rsp+12h] [rbp-3Eh]
  char v6; // [rsp+13h] [rbp-3Dh]
  unsigned int i; // [rsp+14h] [rbp-3Ch]
  unsigned int v8; // [rsp+18h] [rbp-38h]
  unsigned int v9; // [rsp+1Ch] [rbp-34h]
  unsigned int j; // [rsp+20h] [rbp-30h]
  unsigned int k; // [rsp+24h] [rbp-2Ch]
  unsigned int v12; // [rsp+28h] [rbp-28h]
  unsigned int v13; // [rsp+2Ch] [rbp-24h]
  unsigned int m; // [rsp+30h] [rbp-20h]
  unsigned int n; // [rsp+34h] [rbp-1Ch]
  unsigned int v16; // [rsp+38h] [rbp-18h]
  unsigned int v17; // [rsp+40h] [rbp-10h]
  int v18; // [rsp+44h] [rbp-Ch]
  unsigned int v19; // [rsp+48h] [rbp-8h]
  int v20; // [rsp+4Ch] [rbp-4h]

  while ( (unsigned __int8)eq((unsigned int)*(char *)((int)a2 + a1), 95LL) )
    a2 = s(a2);
  for ( i = s(a2); (unsigned __int8)eq((unsigned int)*(char *)((int)i + a1), 95LL); i = s(i) )
    ;
  v5 = *(_BYTE *)((int)a2 + a1);
  for ( j = 0; (unsigned __int8)l(j, 5LL); j = s(j) )
  {
    for ( k = 0; (unsigned __int8)l(k, 5LL); k = s(k) )
    {
      v19 = ::m(j, 5LL);
      v20 = a(v19, k);
      if ( (unsigned __int8)eq((unsigned int)aAbcdefghijklmn[v20], (unsigned int)v5) )
      {
        v8 = j;
        v9 = k;
      }
    }
  }
  v6 = *(_BYTE *)((int)i + a1);
  for ( m = 0; (unsigned __int8)l(m, 5LL); m = s(m) )
  {
    for ( n = 0; (unsigned __int8)l(n, 5LL); n = s(n) )
    {
      v17 = ::m(m, 5LL);
      v18 = a(v17, n);
      if ( (unsigned __int8)eq((unsigned int)aAbcdefghijklmn[v18], (unsigned int)v6) )
      {
        v12 = m;
        v13 = n;
      }
    }
  }
  v2 = ::m(v8, 5LL);
  *(_BYTE *)(a1 + (int)a2) = aVastbcdefghijk[(int)a(v2, v13)];
  v16 = ::m(v12, 5LL);
  *(_BYTE *)(a1 + (int)i) = aCornfieldsabgh[(int)a(v16, v9)];
  return s(i);
}
```

> Giải thích: 
> Sau khi rev về một số hàm mà `encode()` dùng như 
> 
> `a()` thì sẽ là add, nghĩa là cộng.
> 
> `s()` sẽ là tăng lên 1 đơn vị.
> 
> `l()` sẽ là so sánh < hơn.
> 
> `m()` sẽ là nhân
> 
> Và `eq()` sẽ là so sánh =

Đoạn while và đoạn for đầu sẽ là skip qua các dấu "_". Bởi vậy mình xem như khi input đưa vào encode thì không có các dấu gạch dưới.

```c
__int64 __fastcall encode(_BYTE *input, unsigned int a2)
{
  unsigned int v2; // eax
  char first_char; // [rsp+12h] [rbp-3Eh]
  char second_char; // [rsp+13h] [rbp-3Dh]
  unsigned int i; // [rsp+14h] [rbp-3Ch]
  unsigned int x1; // [rsp+18h] [rbp-38h]
  unsigned int y1; // [rsp+1Ch] [rbp-34h]
  unsigned int j; // [rsp+20h] [rbp-30h]
  unsigned int k; // [rsp+24h] [rbp-2Ch]
  unsigned int x2; // [rsp+28h] [rbp-28h]
  unsigned int y2; // [rsp+2Ch] [rbp-24h]
  unsigned int m; // [rsp+30h] [rbp-20h]
  unsigned int n; // [rsp+34h] [rbp-1Ch]
  unsigned int v16; // [rsp+38h] [rbp-18h]
  unsigned int v17; // [rsp+40h] [rbp-10h]
  int v18; // [rsp+44h] [rbp-Ch]
  unsigned int v19; // [rsp+48h] [rbp-8h]
  int v20; // [rsp+4Ch] [rbp-4h]

  while ( equal(input[a2], '_') )
    a2 = increase(a2);
  for ( i = increase(a2); equal(input[i], '_'); i = increase(i) )
    ;
  first_char = input[a2];
  for ( j = 0; less(j, 5LL); j = increase(j) )
  {
    for ( k = 0; less(k, 5LL); k = increase(k) )
    {
      v19 = mul(j, 5LL);
      v20 = add(v19, k);
      if ( equal(aAbcdefghijklmn[v20], first_char) )
      {
        x1 = j;
        y1 = k;
      }
    }
  }
  second_char = input[i];
  for ( m = 0; less(m, 5LL); m = increase(m) )
  {
    for ( n = 0; less(n, 5LL); n = increase(n) )
    {
      v17 = mul(m, 5LL);
      v18 = add(v17, n);
      if ( equal(aAbcdefghijklmn[v18], second_char) )
      {
        x2 = m;
        y2 = n;
      }
    }
  }
  v2 = mul(x1, 5LL);
  input[a2] = aVastbcdefghijk[add(v2, y2)];
  v16 = mul(x2, 5LL);
  input[i] = aCornfieldsabgh[add(v16, y1)];
  return increase(i);
}
}
```

Mình đã đổi tên hàm cho dễ hiểu. Cơ bản là

Nó sẽ lấy lần lượt 2 kí tự của input, đó là lí do tại sao input của chúng ta bắt buộc số lượng kí tự phải là số chẳn, nên có thể lúc đầu bạn nhập bừa đúng format nhưng chương trình lại báo sai.

2 vòng lặp đâu tiên sẽ sử lí cho kí tự thứ 1.

Nó tìm ra cặp x1,y1 sao cho `aAbcdefghijklmn[x1*5+y1]=first_char`

Tương tự với kí tự x2,y2 và tìm ra được cặp x2,y2.

Sau đó nó sẽ gán `first_char = aVastbcdefghijk[x1*5+y2]`, `second_char =aCornfieldsabgh[x2*5+y1]`

Mà 2 đoạn encode mình đã biết trước nên mình có thể dễ dàng viết đoạn scipt để lấy lại x1,y1,x2,y2 từ đó tìm ra kí tự gốc.

```python
import string
encrypted = "odt_sjtfnb_jc_c_fiajb_he_ciuh_nkn_atvfjp"
s1 = "vastbcdefghijklmnopruwxyz"
s2 = "cornfieldsabghjkmptuvwxyz"
s3 = "abcdefghijklmnoprstuvwxyz"

fl = "odt_sjtfnb_jc_c_fiajb_he_ciuh_nkn_atvfjp"
s = 'odtsjtfnbjccfiajbheciuhnknatvfjp'
res = ""
for i in range(0,len(s),2):
    x1,y1 = s1.index(s[i])//5,s1.index(s[i])%5
    x2,y2 = s2.index(s[i+1])//5,s2.index(s[i+1])%5
    res+=s3[x1*5+y2]+s3[x2*5+y1]             
i = 0
k = 0
while i<len(fl):
    if fl[i]=="_":
        print("_",end = "")
    else:
        print(res[k],end = "")
        k+=1
    i+=1
#the_inside_of_a_field_of_corn_and_dreams
```
> Lưu ý: cái đoạn s3 các bạn phải copy từ trong ida ra chứ không sẽ bị dư:))), nhìn kĩ lại thì cái chuỗi nó chỉ có 25 kí tự do bị thiếu chữ "q", nên là lúc đầu mình dùng `string.ascii_lowercase` bị sai, lừa:)))

Có được password, đó cũng là flag.

![](https://i.imgur.com/IXgtFCe.png)

Flag: `uiuctf{the_inside_of_a_field_of_corn_and_dreams}`

## Library of Babel - 371 points

![](https://i.imgur.com/sab1UlB.png)

> Attachment file: [library_of_babel](https://2022.uiuc.tf/files/d33a7479bfaeb41d27255eb8e79dd732/library_of_babel?token=eyJ1c2VyX2lkIjo5MTEsInRlYW1faWQiOjQ0OCwiZmlsZV9pZCI6NjYyfQ.YufxAw.szdIjQyHxkRcYfgT7d4n5Jkc6Pk)

Thử netcat tới server:

![](https://i.imgur.com/U7FnVce.png)

Đầu tiên là nó kêu mình nhập 4 số w,x,y,z và side,shelf,book,page

Sau đó nó sẽ cho mình 1 trang kí tự nhìn rất là lạ...

Thử mở file bằng IDA:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *ptr[11]; // [rsp+0h] [rbp+0h] BYREF

  ptr[9] = (void *)__readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  puts(
    "Welcome to the Library of Babel!\n"
    "We have every possible book in the world.\n"
    "You are using the online demo version, which only has every possible page.\n"
    "There are 3200 characters on each page.\n"
    "Each character can be a lowercase letter, a space, a period, or a comma.\n"
    "Feel free to browse around!");
  get_input(ptr);
  puts("Searching...");
  babel_lookup(ptr);
  puts("Here is your page:");
  print_page(ptr);
  check_correct_page((char *)ptr);
  free(ptr);
  free(ptr[0]);
  free(ptr[1]);
  free(ptr[2]);
  free(ptr[3]);
  return 0;
}
```
Rất may là code này giữ nguyên được hầu như các tên hàm, và flow chương trình rất đơn giản.

Kiểm tra hàm `get_input()`:

```c
unsigned __int64 __fastcall get_input(_QWORD *a1)
{
  int v1; // eax
  __int64 v3; // [rsp+8h] [rbp-40h] BYREF
  __int64 v4; // [rsp+10h] [rbp-38h] BYREF
  __int64 v5; // [rsp+18h] [rbp-30h] BYREF
  __int64 v6; // [rsp+20h] [rbp-28h] BYREF
  unsigned __int64 v7; // [rsp+28h] [rbp-20h]

  v7 = __readfsqword(0x28u);
  puts("\nWhich hexagon would you like to visit?");
  puts("Please enter the (w, x, y, z) coordinates of the hexagon.");
  *a1 = get_big_int("w");
  a1[1] = get_big_int(aXyz);
  a1[2] = get_big_int(&aXyz[1]);
  a1[3] = get_big_int(&aXyz[2]);
  puts("Finding the hexagon...");
  sleep(1u);
  puts("Located!");
  puts("Which page would you like to see?");
  while ( 1 )
  {
    __printf_chk(1LL, "%s (%lu-%lu): ", "side", 1LL, 4LL);
    if ( (unsigned int)__isoc99_scanf("%lu", &v6) == -1 )
LABEL_21:
      exit(1);
    if ( (unsigned __int64)(v6 - 1) <= 3 )
      break;
    __printf_chk(1LL, "Please enter a number between %lu and %lu.\n", 1LL, 4LL);
  }
  a1[4] = v6;
  while ( 1 )
  {
    __printf_chk(1LL, "%s (%lu-%lu): ", "shelf", 1LL, 5LL);
    if ( (unsigned int)__isoc99_scanf("%lu", &v5) == -1 )
      goto LABEL_21;
    if ( (unsigned __int64)(v5 - 1) <= 4 )
      break;
    __printf_chk(1LL, "Please enter a number between %lu and %lu.\n", 1LL, 5LL);
  }
  a1[5] = v5;
  while ( 1 )
  {
    __printf_chk(1LL, "%s (%lu-%lu): ", "book", 1LL, 32LL);
    if ( (unsigned int)__isoc99_scanf("%lu", &v4) == -1 )
      goto LABEL_21;
    if ( (unsigned __int64)(v4 - 1) <= 0x1F )
      break;
    __printf_chk(1LL, "Please enter a number between %lu and %lu.\n", 1LL, 32LL);
  }
  a1[6] = v4;
  while ( 1 )
  {
    __printf_chk(1LL, "%s (%lu-%lu): ", "page", 1LL, 410LL);
    if ( (unsigned int)__isoc99_scanf("%lu", &v3) == -1 )
      goto LABEL_21;
    if ( (unsigned __int64)(v3 - 1) <= 0x199 )
      break;
    __printf_chk(1LL, "Please enter a number between %lu and %lu.\n", 1LL, 410LL);
  }
  a1[7] = v3;
  putchar(10);
  do
    v1 = getc(stdin);
  while ( v1 != -1 && v1 != 10 );
  return __readfsqword(0x28u) ^ v7;
}
```

Dù nhìn rắc rối nhưng không cần rev nhiều, mình thấy rằng nó sẽ nhập `w,x,y,z và side,shelf,book,page` từ input của người dùng vào lần lượt theo thứ tự ptr[0],ptr[1],ptr[2],...ptr[7].

Về hàm `babel_lookup()`, hàm này sẽ tạo page(1 chuỗi kí tự dài) dựa trên 8 số lúc nãy

Còn về `print_page()` chỉ đơn giản là print ra cho có khung mà như ta đã thấy.

Còn hàm `check_correct_page()` thì nó check cái chuỗi (page) có chứa `this page cannot be found.` ở đầu không và phần còn lại có phải là khoảng trắng không.
```c
char __fastcall check_correct_page(char *s)
{
  bool v2; // zf
  size_t v3; // rax
  unsigned int i; // ecx

  v2 = memcmp(s, "this page cannot be found.", 0x1AuLL) == 0;
  LOBYTE(v3) = !v2;
  if ( v2 )
  {
    v3 = strlen(s);
    for ( i = 26; i < v3; ++i )
    {
      if ( s[i] != 32 )
        return v3;
    }
    puts("You have found a secret page!");
    __printf_chk(1LL, "Flag: ");
    LOBYTE(v3) = print_flag("flag.txt");
  }
  return v3;
}
```
Vậy nếu page là `"this page cannot be found." + (3200-26)*" "` thì sẽ tim được flag.

Quay trở lại hàm `babel_lookup()`:

```c
void *__fastcall babel_lookup(_QWORD *a1)
{
  const char *str; // r12
  size_t v2; // r13
  char *v3; // rbp
  char v4; // al
  char *i; // rcx
  unsigned __int8 v6; // dl
  unsigned __int8 v7; // al
  void *v8; // r12
  __int64 v10; // [rsp-10h] [rbp-138h]
  __int64 v11; // [rsp-10h] [rbp-138h]
  char v12[16]; // [rsp+30h] [rbp-F8h] BYREF
  char v13[16]; // [rsp+40h] [rbp-E8h] BYREF
  char v14[16]; // [rsp+50h] [rbp-D8h] BYREF
  char v15[16]; // [rsp+60h] [rbp-C8h] BYREF
  char v16[16]; // [rsp+70h] [rbp-B8h] BYREF
  char v17[16]; // [rsp+80h] [rbp-A8h] BYREF
  char v18[16]; // [rsp+90h] [rbp-98h] BYREF
  char v19[16]; // [rsp+A0h] [rbp-88h] BYREF
  char v20[16]; // [rsp+B0h] [rbp-78h] BYREF
  char v21[16]; // [rsp+C0h] [rbp-68h] BYREF
  char v22[24]; // [rsp+D0h] [rbp-58h] BYREF
  unsigned __int64 v23; // [rsp+E8h] [rbp-40h]

  v23 = __readfsqword(0x28u);
  __gmpz_inits(v18, v22, v19, v20, v21, 0LL);
  __gmpz_ui_pow_ui(v21, 39LL, 3200LL);
  __gmpz_ui_pow_ui(v22, 2LL, 512LL);
  __gmpz_set_ui(v19, 39LL * a1[4] * a1[5] + 1);
  __gmpz_set_ui(v20, a1[6] + 32LL * a1[7]);
  __gmpz_init_set_ui(v12, 0LL);
  __gmpz_inits(v13, v14, v15, v16, v17, 0LL);
  __gmpz_ui_pow_ui(v13, 39LL, 800LL);
  __gmpz_set_str(v14, *a1, 10LL);
  __gmpz_set_str(v15, a1[1], 10LL);
  __gmpz_set_str(v16, a1[2], 10LL);
  __gmpz_set_str(v17, a1[3], 10LL);
  __gmpz_mod(v14, v14, v13);
  __gmpz_mod(v15, v15, v13);
  __gmpz_mod(v16, v16, v13);
  __gmpz_mod(v17, v17, v13);
  __gmpz_add(v12, v12, v14);
  __gmpz_mul(v12, v12, v13);
  __gmpz_add(v12, v12, v15);
  __gmpz_mul(v12, v12, v13);
  __gmpz_add(v12, v12, v16);
  __gmpz_mul(v12, v12, v13);
  __gmpz_add(v12, v12, v17);
  __gmpz_set(v18, v12);
  __gmpz_clears(v12, v13, v14, v15, v16, v17, 0LL);
  __gmpz_inits(v13, v14, v15, v16, v17, 0LL);
  __gmpz_sub_ui(v13, v19, 1LL);
  __gmpz_mul(v14, v13, v21);
  __gmpz_powm(v15, v19, v22, v14);
  __gmpz_sub_ui(v15, v15, 1LL);
  __gmpz_tdiv_q(v15, v15, v13);
  __gmpz_mul(v15, v15, v20);
  __gmpz_powm(v16, v19, v22, v21);
  __gmpz_mul(v16, v16, v18);
  __gmpz_add(v17, v15, v16);
  __gmpz_mod(v17, v17, v21);
  __gmpz_set(v18, v17);
  __gmpz_clears(v13, v14, v15, v16, v17, 0LL, v10);
  str = (const char *)__gmpz_get_str(0LL, 39LL, v18);
  v2 = strlen(str) + 1;
  v3 = (char *)malloc(v2);
  memcpy(v3, str, v2);
  v4 = *v3;
  for ( i = v3; v4; v4 = *++i )
  {
    while ( 1 )
    {
      v6 = v4 - 48;
      if ( (unsigned __int8)(v4 - 48) <= 9u )
        break;
      if ( (unsigned __int8)(v4 - 65) > 0x19u )
      {
        if ( (unsigned __int8)(v4 - 97) > 2u )
        {
          __printf_chk(1LL, "error: invalid base39 char '%c' in num_to_str\n", (unsigned int)v4);
          exit(1);
        }
        v7 = v4 - 61;
LABEL_13:
        *i = v7 + 84;
        goto LABEL_6;
      }
      v6 = v4 - 55;
      *i = v4 - 55;
      v7 = v6;
      if ( v6 > 0xCu )
        goto LABEL_13;
LABEL_5:
      *i = v6 + 45;
LABEL_6:
      v4 = *++i;
      if ( !v4 )
        goto LABEL_10;
    }
    if ( v4 != 48 )
    {
      if ( v4 == 49 )
      {
        *i = 46;
        goto LABEL_6;
      }
      if ( v4 == 50 )
      {
        *i = 44;
        goto LABEL_6;
      }
      goto LABEL_5;
    }
    *i = 32;
  }
LABEL_10:
  v8 = malloc(0xC81uLL);
  __snprintf_chk(v8, 3201LL, 1LL, 3201LL, "%*s", 3200, v3);
  free(v3);
  __gmpz_clears(v18, v22, v19, v20, v21, 0LL, v11);
  return v8;
}
```

Flow chương trình cũng khá đơn giản mà nó cũng làm mất thời gian mình rev khá lâu:

Chương trình sẽ lấy 8 số input của mình nhập vào và qua 1 loạt các thao tác xử lí như `__gmpz_mul,__gmpz_set,...` sau đó nó sẽ trả về 1 con số, từ con số này sẽ được qua hàm `__gmpz_get_str()` để chuyển nó thành hệ cơ số 39(hơi lạ:v).

Theo như thông tin mình debug được thì hệ cơ số của nó sẽ là:
`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabc`

Và hơn thế nữa, đoạn số này sẽ được hệ cơ số này sang hệ cơ số hiển thị khác của 39:

```c
for ( i = v3; v4; v4 = *++i )
  {
    while ( 1 )
    {
      v6 = v4 - 48;
      if ( (unsigned __int8)(v4 - 48) <= 9u )
        break;
      if ( (unsigned __int8)(v4 - 65) > 0x19u )
      {
        if ( (unsigned __int8)(v4 - 97) > 2u )
        {
          __printf_chk(1LL, "error: invalid base39 char '%c' in num_to_str\n", (unsigned int)v4);
          exit(1);
        }
        v7 = v4 - 61;
LABEL_13:
        *i = v7 + 84;
        goto LABEL_6;
      }
      v6 = v4 - 55;
      *i = v4 - 55;
      v7 = v6;
      if ( v6 > 0xCu )
        goto LABEL_13;
LABEL_5:
      *i = v6 + 45;
LABEL_6:
      v4 = *++i;
      if ( !v4 )
        goto LABEL_10;
    }
    if ( v4 != 48 )
    {
      if ( v4 == 49 )
      {
        *i = 46;
        goto LABEL_6;
      }
      if ( v4 == 50 )
      {
        *i = 44;
        goto LABEL_6;
      }
      goto LABEL_5;
    }
    *i = 32;
  }
```

Thì đoạn này sẽ ảnh hưởng lên từng kí tự của chuỗi trên, cụ thể là từ các char hệ cơ số 39 `"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabc"` thành `" .,0123456789abcdefghijklmnopqrstuvwxyz"` theo đúng thứ tự, đó cũng là thứ mà ta thấy trên màn hình.

Vậy nhiệm vụ của mình bây giờ tìm 8 con số sao cho nó tạo ra 1 con số, sau khi đổi sang hệ cơ số 39 cuối cùng thì nó được một chuỗi `"this page cannot be found." + (3200-26)*" "`

 Vậy trước hết, mình cần đưa cái chuỗi đó thành con số decimal để dễ thao tác.
 
 ```python
tab = " .,0123456789abcdefghijklmnopqrstuvwxyz"
text = "this page cannot be found."+ " "*(3200-26)
j = 0
num = 0
for i in text[::-1]:
    num+= (39**i)*tab.index(i)
print(num)
#num = 2127766132501039548212702343076538022407545838378956777990575547195039593608131882680898512924846182271059680607660363575091361538875742728417262173698534132996106325961032023087317414058617517904590416173550624723505662190984056353520220339605799860860446739374496896373628110633039435121067203549605287129819008010099114601202360647553321689238453254765810615233094054858382531895644798795796905342419610237108094993937145762273860282625969085247245581119080219817699246304264023016219423281024399400172656492813747707815090305289241483134451297499998041336917849345450200947716188382284794895066564303934542472605866427030801452155686014241848345373673372618013066172897874139672184706284085009807146106577006215037426627341283754286673897062012736018265455147876254646220352007339703909884074999733584276294860990845461720756822761150413043075741418535046926238280883461979258847650590909568898238367584658512561277496681862224176017447639581716165407580162310190775892932646854398445220226667135294114273408717779561629114556232881346199832669031059735021581250621497963963027016261707679671440516512566341808868812555228015662831942627979590577766158280304918274897264805670237352705603872911918201776985924854674391794512996671727537939216573688223290897543254196525446006655277282760821688998287416426169035466808882114006036210845828153171825328595568502280341999551167084693083434654830505781037367803464401820102185843011244012394715408096456233128557778533978907989292741179946286358164625576133974126219474894536945991734105236401926845061619645541938999589033763171289380632512654484607815821825268927549298354968181596100905296829306519313957716677237374933823506406007377464850141639060438362948636639435205592436498583965559160339182711744583366650002976589633993958106186986090814520784524575818157884193304725189292045111282966240464746837355028480458404993016014363586945342356508618669352528261705907766608761459763095797604621499051228105319863451730577069883662635311246986365890151624875046487050623131584941616163815075611488133771939926252747966549645362599181218839760232265122755450363483652091516016808652668764563555103028113184676226435414809904993850846640215212889139519789048935321711888660046455873095860866701772295768772687801943022725593055880242710182336201502082835284060466180767522151521078532138230069483684294609277704885191841813986528190942927064551839635709612734034132671714314077302728984873262933535376895351255629732120566231399463836019036004998887298808311250898590715440852909624706515108888761254780808640051345202814005798418837437898227447611433032577160772693805737878775706156445159255416002161634340533166535304039219106012853698918998970951994554358937648141884585091521738570887579013802830354220625125267495615819034086661870908183246629530686643076534821122748387256004401056699701439757331807234668133290930038527847157782107901961273261382761124782850483461281714395089720911122374742416446469553890894118874755032523910200525980046421853609432878080390633586422108106078134979848829531508268699982571034371662940697389414193942354974659665137525038696698077137069073912739636798653965164868703046437951329609378433025818743419347446314843653411336840705407126969785226524240671724310096897033296563743560768084216675698516968405506705905989771676836881336835409780715828786210320348123138950479237400426149432542185436345923981324255034385808786042450502220367776511713711835918713046635915355410608033612429423403965191135012317670256915297530611517764585090388181122589637339933185682290864448031824799465505246427695069270912931103357579463324837945022038773294680012514062755211439970479406667387773359876419423515766260369350083098283960228270984431875769798619901133258786311811186566480888425486271684954537013606890222114073868053341681453931845561019815725251328527318525596290070435066980276296886725793060176016508254434945273646443249277579470770303214209285508177357966774110354054005663477833579721947014429053742757028261821477750431805113351097674396796505052769808113207944448491128036976835061201918240475785204445249798628061849427168367543122043234836603157945110092111056496209959465062475356143217286878570932209531383812040846629811699805064106031451164173703074449632053650043843149492753077151973134666858851718490106201168644429373445369635349411455760357181252910025066638469507218450293574012799222237964512308398543843430731220250924746724238286547819199164862188848781057075620429355904988353856284883004427011501828444537534655290994051936476029684899677680508350708628954908653697569254764070649100808196930628811331402840745532184945750098569279338001877442653574262536437916359445253429206799570527947238781146524591170122796951184434655182810759938138204161389011000189921904463694673552293835941869432691384458621622368275991361850395641297761031492003518102336292094874600393942423086811329599499046645298861203445676552203596449465995399175776769534990343435008622602538815051401986846830822249169371355535509278263121660413939804075404730557212033751463093300952090525970787102075092202
```

Con số num có vẻ khá là lớn, có lẽ đó là lí do tại sao mà w,x,y,z của đề yêu cầu mình nhập vào thì nó dùng hàm bigint.

Tiếp tục rev tại chổ xử lí input để tìm hiểu cách mà nó tạo ra input của mình:

```c
__gmpz_inits(v18, v22, v19, v20, v21, 0LL);
  __gmpz_ui_pow_ui(v21, 39LL, 3200LL);
  __gmpz_ui_pow_ui(v22, 2LL, 512LL);
  __gmpz_set_ui(v19, 39LL * a1[4] * a1[5] + 1);
  __gmpz_set_ui(v20, a1[6] + 32LL * a1[7]);
  __gmpz_init_set_ui(v12, 0LL);
  __gmpz_inits(v13, w, x, y, z, 0LL);
  __gmpz_ui_pow_ui(v13, 39LL, 800LL);
  __gmpz_set_str(w, *a1, 10LL);
  __gmpz_set_str(x, a1[1], 10LL);
  __gmpz_set_str(y, a1[2], 10LL);
  __gmpz_set_str(z, a1[3], 10LL);
  __gmpz_mod(w, w, v13);
  __gmpz_mod(x, x, v13);
  __gmpz_mod(y, y, v13);
  __gmpz_mod(z, z, v13);
  __gmpz_add(v12, v12, w);
  __gmpz_mul(v12, v12, v13);
  __gmpz_add(v12, v12, x);
  __gmpz_mul(v12, v12, v13);
  __gmpz_add(v12, v12, y);
  __gmpz_mul(v12, v12, v13);
  __gmpz_add(v12, v12, z);
  __gmpz_set(v18, v12);
  __gmpz_clears(v12, v13, w, x, y, z, 0LL);
  __gmpz_inits(v13, w, x, y, z, 0LL);
  __gmpz_sub_ui(v13, v19, 1LL);
  __gmpz_mul(w, v13, v21);
  __gmpz_powm(x, v19, v22, w);
  __gmpz_sub_ui(x, x, 1LL);
  __gmpz_tdiv_q(x, x, v13);
  __gmpz_mul(x, x, v20);
  __gmpz_powm(y, v19, v22, v21);
  __gmpz_mul(y, y, v18);
  __gmpz_add(z, x, y);
  __gmpz_mod(z, z, v21);
  __gmpz_set(v18, z);
  __gmpz_clears(v13, w, x, y, z, 0LL, v10);
  str = (const char *)__gmpz_get_str(0LL, 39LL, v18);
```

Chổ này thì mình dùng python để mô phỏng lại từng bước như sau:

```python
ptr = [1,1,1,1,1,1,1,1] #input

n1 = 39*ptr[4]*ptr[5]+1
n2 = ptr[6] + 32 * ptr[7]

const = 39**800
w = ptr[0]
x = ptr[1]
y = ptr[2]
z = ptr[3]
w %=const
x %=const
y %=const
z %=const
v18 = ((w*const+x)*const + y)*const+z
const = w=x=y=z=0 #clear
const = n1-1
w = 39**4000
x = pow(n1,(2**512),w)
x-=1
x = x//const
x*=n2
y = pow(n1,(2**512),(39**3200))
y*=v18
z = x+y
z = z%(39**3200)
```
Và để thuận tiện cho việc kiểm tra nên mình đã kết hợp debug rất nhiều và script này để kiểm tra rằng mọi thao tác đều chính xác:
```python
import string
digs = string.digits+ string.ascii_uppercase+"abc"
tab = " .,0123456789abcdefghijklmnopqrstuvwxyz"
text = "this page cannot be found."+ " "*(3200-26)
def int2base(x, base):
    if x < 0:
        sign = -1
    elif x == 0:
        return digs[0]
    else:
        sign = 1

    x *= sign
    digits = []

    while x:
        digits.append(digs[x % base])
        x = x // base

    if sign < 0:
        digits.append('-')

    digits.reverse()

    return ''.join(digits)
b39_of_num = ""
for c in text:
    b39_of_num += digs[tab.index(c)]
j = 0
num = 0
for i in b39_of_num[::-1]:
    num+=pow(39,j)*digs.index(i)
    j+=1

ptr = [1,1,1,1,1,1,1,1]

n1 = 39*ptr[4]*ptr[5]+1
n2 = ptr[6] + 32 * ptr[7]

const = 39**800
w = ptr[0]
x = ptr[1]
y = ptr[2]
z = ptr[3]
w %=const
x %=const
y %=const
z %=const
v18 = ((w*const+x)*const + y)*const+z
const = w=x=y=z=0 #clear
const = n1-1
w = 39**4000
x = pow(n1,(2**512),w)
x-=1
x = x//const
x*=n2
y = pow(n1,(2**512),(39**3200))
y*=v18
z = x+y
z = z%(39**3200)

#z = 2127766132501039548212702343076538022407545838378956777990575547195039593608131882680898512924846182271059680607660363575091361538875742728417262173698534132996106325961032023087317414058617517904590416173550624723505662190984056353520220339605799860860446739374496896373628110633039435121067203549605287129819008010099114601202360647553321689238453254765810615233094054858382531895644798795796905342419610237108094993937145762273860282625969085247245581119080219817699246304264023016219423281024399400172656492813747707815090305289241483134451297499998041336917849345450200947716188382284794895066564303934542472605866427030801452155686014241848345373673372618013066172897874139672184706284085009807146106577006215037426627341283754286673897062012736018265455147876254646220352007339703909884074999733584276294860990845461720756822761150413043075741418535046926238280883461979258847650590909568898238367584658512561277496681862224176017447639581716165407580162310190775892932646854398445220226667135294114273408717779561629114556232881346199832669031059735021581250621497963963027016261707679671440516512566341808868812555228015662831942627979590577766158280304918274897264805670237352705603872911918201776985924854674391794512996671727537939216573688223290897543254196525446006655277282760821688998287416426169035466808882114006036210845828153171825328595568502280341999551167084693083434654830505781037367803464401820102185843011244012394715408096456233128557778533978907989292741179946286358164625576133974126219474894536945991734105236401926845061619645541938999589033763171289380632512654484607815821825268927549298354968181596100905296829306519313957716677237374933823506406007377464850141639060438362948636639435205592436498583965559160339182711744583366650002976589633993958106186986090814520784524575818157884193304725189292045111282966240464746837355028480458404993016014363586945342356508618669352528261705907766608761459763095797604621499051228105319863451730577069883662635311246986365890151624875046487050623131584941616163815075611488133771939926252747966549645362599181218839760232265122755450363483652091516016808652668764563555103028113184676226435414809904993850846640215212889139519789048935321711888660046455873095860866701772295768772687801943022725593055880242710182336201502082835284060466180767522151521078532138230069483684294609277704885191841813986528190942927064551839635709612734034132671714314077302728984873262933535376895351255629732120566231399463836019036004998887298808311250898590715440852909624706515108888761254780808640051345202814005798418837437898227447611433032577160772693805737878775706156445159255416002161634340533166535304039219106012853698918998970951994554358937648141884585091521738570887579013802830354220625125267495615819034086661870908183246629530686643076534821122748387256004401056699701439757331807234668133290930038527847157782107901961273261382761124782850483461281714395089720911122374742416446469553890894118874755032523910200525980046421853609432878080390633586422108106078134979848829531508268699982571034371662940697389414193942354974659665137525038696698077137069073912739636798653965164868703046437951329609378433025818743419347446314843653411336840705407126969785226524240671724310096897033296563743560768084216675698516968405506705905989771676836881336835409780715828786210320348123138950479237400426149432542185436345923981324255034385808786042450502220367776511713711835918713046635915355410608033612429423403965191135012317670256915297530611517764585090388181122589637339933185682290864448031824799465505246427695069270912931103357579463324837945022038773294680012514062755211439970479406667387773359876419423515766260369350083098283960228270984431875769798619901133258786311811186566480888425486271684954537013606890222114073868053341681453931845561019815725251328527318525596290070435066980276296886725793060176016508254434945273646443249277579470770303214209285508177357966774110354054005663477833579721947014429053742757028261821477750431805113351097674396796505052769808113207944448491128036976835061201918240475785204445249798628061849427168367543122043234836603157945110092111056496209959465062475356143217286878570932209531383812040846629811699805064106031451164173703074449632053650043843149492753077151973134666858851718490106201168644429373445369635349411455760357181252910025066638469507218450293574012799222237964512308398543843430731220250924746724238286547819199164862188848781057075620429355904988353856284883004427011501828444537534655290994051936476029684899677680508350708628954908653697569254764070649100808196930628811331402840745532184945750098569279338001877442653574262536437916359445253429206799570527947238781146524591170122796951184434655182810759938138204161389011000189921904463694673552293835941869432691384458621622368275991361850395641297761031492003518102336292094874600393942423086811329599499046645298861203445676552203596449465995399175776769534990343435008622602538815051401986846830822249169371355535509278263121660413939804075404730557212033751463093300952090525970787102075092202
print(num)
for c in int2base(num,39):
    print(tab[digs.index(c)],end = "")
```

Sau khi thu gọn code cho dễ hiểu thì mình được đoạn check này:
```python
const1 = 39**800
const2 = 39**4000
const3 = 39**3200
def check(ptr):
    n1 = 39*ptr[4]*ptr[5]+1
    n2 = ptr[6] + 32 * ptr[7]

    w = ptr[0]
    x = ptr[1]
    y = ptr[2]
    z = ptr[3]

    sus = ((w*const1+x)*const1 + y)*const1+z

    tmp = n1-1
    t1 = ((powmod(n1,exp,const2)-1)//tmp)*n2
    t2 = powmod(n1,exp, const3)

    res = t1+t2*sus
    res = res%const3
    return res
```
Giờ mục tiêu của mình phải là tìm được input hợp lí sao cho giá trị trả về `res` sẽ bằng với `num` lúc nãy. 

Tới lúc này thì rev coi như xong, phần còn lại là crypto thôi:))

Mình đã nhờ trợ giúp từ chúa tể crypto @m1dm4n, vì 4 số cuối nhỏ nên mình có thể bruteforce để tìm ra được sus, từ đó tìm ra w,x,y,z.

Có được ý tưởng, sau đó mình đã thử viết script bruteforce nhưng brute lâu quá nên thôi không viết nữa:))), còn đây là script đó sau khi được @m1dm4n fix và hoàn chỉnh bằng gmpy2:

```python
from gmpy2 import mpz, powmod, invert
#int=mpz
ptr=[mpz(0) for i in range(8)]
exp=mpz(2**512)
const1 = mpz(39**800)
const2 = mpz(39**4000)
const3 = mpz(39**3200)
def check(ptr):
    n1 = 39*ptr[4]*ptr[5]+1
    n2 = ptr[6] + 32 * ptr[7]

    w = ptr[0]
    x = ptr[1]
    y = ptr[2]
    z = ptr[3]

    sus = ((w*const1+x)*const1 + y)*const1+z

    tmp = n1-1
    t1 = ((powmod(n1,exp,const2)-1)//tmp)*n2
    t2 = powmod(n1,exp, const3)

    res = t1+t2*sus
    res = res%const3
    return res


res = 2127766132501039548212702343076538022407545838378956777990575547195039593608131882680898512924846182271059680607660363575091361538875742728417262173698534132996106325961032023087317414058617517904590416173550624723505662190984056353520220339605799860860446739374496896373628110633039435121067203549605287129819008010099114601202360647553321689238453254765810615233094054858382531895644798795796905342419610237108094993937145762273860282625969085247245581119080219817699246304264023016219423281024399400172656492813747707815090305289241483134451297499998041336917849345450200947716188382284794895066564303934542472605866427030801452155686014241848345373673372618013066172897874139672184706284085009807146106577006215037426627341283754286673897062012736018265455147876254646220352007339703909884074999733584276294860990845461720756822761150413043075741418535046926238280883461979258847650590909568898238367584658512561277496681862224176017447639581716165407580162310190775892932646854398445220226667135294114273408717779561629114556232881346199832669031059735021581250621497963963027016261707679671440516512566341808868812555228015662831942627979590577766158280304918274897264805670237352705603872911918201776985924854674391794512996671727537939216573688223290897543254196525446006655277282760821688998287416426169035466808882114006036210845828153171825328595568502280341999551167084693083434654830505781037367803464401820102185843011244012394715408096456233128557778533978907989292741179946286358164625576133974126219474894536945991734105236401926845061619645541938999589033763171289380632512654484607815821825268927549298354968181596100905296829306519313957716677237374933823506406007377464850141639060438362948636639435205592436498583965559160339182711744583366650002976589633993958106186986090814520784524575818157884193304725189292045111282966240464746837355028480458404993016014363586945342356508618669352528261705907766608761459763095797604621499051228105319863451730577069883662635311246986365890151624875046487050623131584941616163815075611488133771939926252747966549645362599181218839760232265122755450363483652091516016808652668764563555103028113184676226435414809904993850846640215212889139519789048935321711888660046455873095860866701772295768772687801943022725593055880242710182336201502082835284060466180767522151521078532138230069483684294609277704885191841813986528190942927064551839635709612734034132671714314077302728984873262933535376895351255629732120566231399463836019036004998887298808311250898590715440852909624706515108888761254780808640051345202814005798418837437898227447611433032577160772693805737878775706156445159255416002161634340533166535304039219106012853698918998970951994554358937648141884585091521738570887579013802830354220625125267495615819034086661870908183246629530686643076534821122748387256004401056699701439757331807234668133290930038527847157782107901961273261382761124782850483461281714395089720911122374742416446469553890894118874755032523910200525980046421853609432878080390633586422108106078134979848829531508268699982571034371662940697389414193942354974659665137525038696698077137069073912739636798653965164868703046437951329609378433025818743419347446314843653411336840705407126969785226524240671724310096897033296563743560768084216675698516968405506705905989771676836881336835409780715828786210320348123138950479237400426149432542185436345923981324255034385808786042450502220367776511713711835918713046635915355410608033612429423403965191135012317670256915297530611517764585090388181122589637339933185682290864448031824799465505246427695069270912931103357579463324837945022038773294680012514062755211439970479406667387773359876419423515766260369350083098283960228270984431875769798619901133258786311811186566480888425486271684954537013606890222114073868053341681453931845561019815725251328527318525596290070435066980276296886725793060176016508254434945273646443249277579470770303214209285508177357966774110354054005663477833579721947014429053742757028261821477750431805113351097674396796505052769808113207944448491128036976835061201918240475785204445249798628061849427168367543122043234836603157945110092111056496209959465062475356143217286878570932209531383812040846629811699805064106031451164173703074449632053650043843149492753077151973134666858851718490106201168644429373445369635349411455760357181252910025066638469507218450293574012799222237964512308398543843430731220250924746724238286547819199164862188848781057075620429355904988353856284883004427011501828444537534655290994051936476029684899677680508350708628954908653697569254764070649100808196930628811331402840745532184945750098569279338001877442653574262536437916359445253429206799570527947238781146524591170122796951184434655182810759938138204161389011000189921904463694673552293835941869432691384458621622368275991361850395641297761031492003518102336292094874600393942423086811329599499046645298861203445676552203596449465995399175776769534990343435008622602538815051401986846830822249169371355535509278263121660413939804075404730557212033751463093300952090525970787102075092202

for i in range(1,5,1):
    for j in range(1,6,1):
        for k in range(1,33,1):
            for l in range(1,411,1):
                n1 = mpz(39*i*j+1)
                n2 = mpz(k + 32 * l)
                t1 = ((powmod(n1,exp,const2)-1)//(n1-1))*n2
                t2 = powmod(n1,exp, const3)
                tmp = (res - t1)%const3
                try:sus=(tmp*invert(t2, const3))%const3
                except:continue
                z=sus%const1
                sus//=const1
                y=sus%const1
                sus//=const1
                x=sus%const1
                w=sus//const1
                if (check([w,x,y,z,i,j,k,l])==res):
                    print([w,x,y,z,i,j,k,l])
                    
                    exit()
```

Và đây là kết quả:

```
[mpz(316184409190683187412951370144439538281283173517348388320629529533575869351056544895293252189409029827821178467376073572229045930771835710485586862556359336173738968489771390354380456414225599670565686382389272784573596114338534992673994971448198486357871601516786162166095562077867867110781946171060753233319423759384009204361627090009731543792267339158761359020346152499515802516337198180627537263170865735643152221896078068370074148422728599863876302130435870382324127651093157127624596986859504051329491278357931858202937613342127718001712271685096375412715049966337771341162053026352261415305391031502744244713590693721870144099399950210997073682670564146680671482831597891228059038652147527440757993243729161861577478359633129126535875633802200922493198303754106309428942845424344779575867138512095160218534497982769611344595536006588422196653775241670049007664754699353281035630515859142984534654260131230524441588241435552434734100561526822047243096241140747255000270622387474419184609892919543263865126218166442205164495639463105888975487221452769868917364870504044767352953632998247818974447472440498511305063622021672785567887380186080872281583154609524106004792254475130977480355802560150269604516720066525037815242827686493502716525532639845341730081340577745), mpz(2213208764529808286177004926010221176854162648304135202566769781169347934702820480318181488121276034961212702589874304047642755582317406109581185874666430277110407560370537631006885540043622019353325433050193593105265492365440081536572358936706709658335757423938279005536010829390769724829042337977655072359977763766836319095374972663789326739582833158853434584671709001574367835195190964329061802414371011139459592131405867864845403096467070924897385403698808592496189725632776217653600285319046462470305765806180273946911536270125420230410603443615999028926086447501347177879923895590772561900863064461281537060693441971966141074264099101295681388388099540992719770771613091727903223251994176407468864949778159615688302403686253229825472213869812757643203717698849117689738220386997120467762626901643381369005952623624946066009188627081817629609678272937838978871674953951088788227375438521464687603470859853576299212361947392360055272425469679366816431604966880424803916653595567971662755866416914919292140984944655924207845276684109171977502224815041039040879325158631655147737865338063647800338865334017555694198647315118914821491592094367090095694296461823343645876553269930308776016998583794624953420126895168216002554359889643474085048052684196292157930717590904695), mpz(2021751459144012056494172212082632961083334776342846280626894359612935712158178527867952919481158259621178722623062905158964605275493382642800953692169895562900922870280829429946010339162863124575406026543991537874137119904380375464197276828251316673002983865000424804278583172167899964729909729184991695324306049902809932999623328059550396751576085382683248385781757660767748315654992645625317704770661849246038089400420871194933539567160818953511426589216367734818756867547126849149650121870090219928926740229004527614409747100724067476346481108979493586683182598204458599663258920642588369266321254066380786106075313331443402456752317187380050989733718865772860003405358201973060700643599384300211883862744850618921948972264656503554568410329795067913071597830221149872488076045101648872805080515968112800891327393346832778595384193162201195055889688266387109897265981071884167460014060031011848333470090404240268050080459116430611081960951824425766711488981679820023736674729173413702005677446583796581665844635338792384427087965052427679056394839852690759465577081204612275264245913694957769785568893364728486061101917765274555650472643833492812234136023964113738362641115652337065228414968095385543574930654426424052428164288582962602298361900243966317565220805073685), mpz(1332046819820300203032372473565914181965588990155083756558446585547388679170066839328466685378129154741251314053999540367134484799206827636688435867375685256013871338203153108617330576189445900439907097735184879128244916532769165639292826861234156596145107197803013983635710992376505460501646584435709050631418157098533699433913689645719676230783339242488338337180003578459210852806493497194614996676209753653428248212005678901713552970991517411026726154010342173445361479985829577045465223655402012785105742992083327220133871478159842001861444902369098872639908710167269022594406254498076189747045074851914432101965534918576363516690416024451744179488524275469667209253839129756111614438478276278787952482912609573829267450907248014267100811037412111782405376045794034108015704303025150461028927879561507458155746211716426559808207072037274151724343805484190136218022188311575340110325096082181227042320856960404205570385275572961983030939687938623117517382389955242798599312251956485574878227266116734939204266740861021896849389436861843010240001235768435906939290285087830637794756175668712634838327699652452571560512311104725083434111133998346091408513088645242118274466533506152692104843922365201817705083964740833828707575181427633270715247887243233590743409958797668), 1, 1, 1, 1]
```

Netcat trên server và nhập 8 số đó vào:

![](https://i.imgur.com/1hxZ1DL.png)

Flag: `uiuctf{th3_l18br4ry_1s_unlim1t3d_bu7_p3r10d1c_c9176412}`

Vậy là đã xong 4 challenge của UIU ^ ^
