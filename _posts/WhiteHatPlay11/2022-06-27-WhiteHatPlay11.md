---
layout: post
title:  "WhiteHatPlay11"
date:   2022-06-27 09:29:20 +0700
modified: 2022-06-28 16:49:47 +07:00
categories: WriteUp
tags: [ctf, rev]
description: Write up revering challenge for WhiteHatPlay11!
---

## re01-WhiteHatPlay11v1 - 128pts

![image](https://user-images.githubusercontent.com/88520787/176362334-f62ca54b-7199-4390-bdeb-75aa199397a9.png)

Check file bằng DiE và mở bằng IDA32:


![image](https://user-images.githubusercontent.com/88520787/176362651-4d7a4132-625c-4791-a4b9-88158a776cb6.png)

![image](https://user-images.githubusercontent.com/88520787/176362692-c2a3fb01-4ab1-437b-9922-53e77fcfb1a8.png)

Input của mình sau khi nhập vào Buffer thì sẽ được đưa vào hàm `sub_4010A0()` xử lí:

![image](https://user-images.githubusercontent.com/88520787/176364687-3f06681f-2516-455b-b5b6-521989231b96.png)

Trong hàm này, mình đã đổi 0x55 thành 85 cho dễ nhìn, tới đây mình thấy nghi nghi, thử bấm vào `byte_40EFB0` xem nó là gì:

![image](https://user-images.githubusercontent.com/88520787/176364926-60f8f87b-dacd-4b27-9618-9696508c4dcb.png)

Rồi luôn, tới đây thì mình khá chắc là chương trình này dùng `base85`, mình thử kiếm `cipher` trong string và xref, mình thấy 2 đoạn này khá phù hợp:

![image](https://user-images.githubusercontent.com/88520787/176365158-adfc5d6c-e8bb-4822-a7d9-8ede8bd1b5b3.png)

Thử trên cyber chef và bùm:

![image](https://user-images.githubusercontent.com/88520787/176365683-f833a682-0b13-4e6a-8f7c-ea689e946f3e.png)

Flag: WhiteHat{Whit3H4t11H4v34N1C3D4yR3VeRs31!}

## re02-WhiteHatPlay11v2 - 256pts

Lần này đề cho mình file dll, tiếp tục check và mở bằng IDA32 lên xem:

![image](https://user-images.githubusercontent.com/88520787/176366203-b72bd7b1-8378-4564-b947-399a4e7fb6c4.png)
 
Trong IDA mình thấy 1 hàm tên là WhiteHat khá là khả nghi:

```c
char WhiteHat()
{
  int v0; // edi
  int v1; // esi
  int v2; // kr04_4
  char *v3; // eax
  char *v4; // ecx
  void *v5; // eax
  void **v6; // eax
  int v7; // eax
  int i; // ecx
  int v10; // [esp+0h] [ebp-4B4h]
  int v11; // [esp+10h] [ebp-4A4h]
  int v12[14]; // [esp+14h] [ebp-4A0h]
  void *v13[4]; // [esp+4Ch] [ebp-468h] BYREF
  int v14; // [esp+5Ch] [ebp-458h]
  unsigned int v15; // [esp+60h] [ebp-454h]
  void *v16; // [esp+64h] [ebp-450h]
  int v17; // [esp+74h] [ebp-440h]
  unsigned int v18; // [esp+78h] [ebp-43Ch]
  char Str[264]; // [esp+7Ch] [ebp-438h] BYREF
  char v20; // [esp+184h] [ebp-330h] BYREF
  char v21[263]; // [esp+185h] [ebp-32Fh] BYREF
  char Destination[264]; // [esp+28Ch] [ebp-228h] BYREF
  char v23[268]; // [esp+394h] [ebp-120h] BYREF
  int v24; // [esp+4B0h] [ebp-4h]

  v11 = 1887667281;
  v12[0] = 1882219565;
  v12[1] = 743254827;
  v12[2] = 762456936;
  v12[3] = -2105317328;
  v12[4] = 1865175935;
  v12[5] = -2004341935;
  v12[6] = 2139565390;
  v12[7] = 1848467079;
  v20 = 0;
  memset(v21, 0, 0x103u);
  memset(Str, 0, 260);
  memset(Destination, 0, 260);
  memset(v23, 0, 260);
  v0 = 0;
  v18 = 15;
  v17 = 0;
  LOBYTE(v16) = 0;
  v24 = 1;
  v15 = 15;
  v14 = 0;
  LOBYTE(v13[0]) = 0;
  sub_10003997("___________________________________________________________________________\n");
  sub_10003997("                                                         __                \n");
  sub_10003997(" _ _ _ _   _ _       _____     _      _____ _           |  |   ___   ___   \n");
  sub_10003997("| | | | |_|_| |_ ___|  |  |___| |_   |  _  | |___ _ _   |  |  |_  | |_  |  \n");
  sub_10003997("| | | |   | |  _| -_|     | .'|  _|  |   __| | .'| | |  |__|   _| |_ _| |_ \n");
  sub_10003997("|_____|_|_|_|_| |___|__|__|__,|_|    |__|  |_|__,|_  |  |__|  |_____|_____|\n");
  sub_10003997("                                                 |___|                     \n");
  sub_10003997("___________________________________________________________________________\n");
  sub_10003997("\n********Let's Play!********\n");
  sub_10003997("Try to guess the flag: ");
  gets_s(Str, 0x104u);
  v1 = strlen(Str);
  if ( v1 < 40 )
  {
    while ( 1 )
    {
      sub_10003997("\nHmm, enter something more interesting: ");
      gets_s(Str, 0x104u);
      v2 = strlen(Str);
      v1 = v2;
      if ( v2 > 41 )
        break;
      if ( v2 >= 40 )
        goto LABEL_6;
    }
    sub_10003997("Great! It may be the right flag :)\n");
  }
LABEL_6:
  sub_10003997("Checking...\n");
  Sleep(0x3E8u);
  strncpy_s(Destination, 0x104u, Str, 0x24u);
  if ( !strstr(Str, "@") )
    goto LABEL_41;
  v3 = strrchr(Str, 64);
  strncpy_s(v23, 0x104u, v3, 5u);
  v4 = Str;
  if ( dword_10018FD4 != 1 )
    v4 = Destination;
  sub_10001EC0(v4, &v20);
  sub_100017A0("QDIwMjI=", 8u);
  v5 = (void *)sub_10001430(v10);
  sub_100023E0(v13, v5);
  if ( v12[13] >= 0x10u )
    j__free((void *)v12[8]);
  v6 = v13;
  if ( v15 >= 0x10 )
    v6 = (void **)v13[0];
  v7 = strcmp(v23, (const char *)v6);
  if ( v7 )
    v7 = v7 < 0 ? -1 : 1;
  if ( v7 )
  {
LABEL_41:
    sub_10003997("Oh no! That is a wrong flag! Try again!!1\n");
  }
  else
  {
    sub_10003997("Great! Keep moving...\n");
    Sleep(0x3E8u);
    if ( FindWindowA("OllyDbg", 0) )
      ExitProcess(0);
    if ( FindWindowA("x32dbg", 0) || sub_10001DA0(L"OllyDbg.exe") || sub_10001DA0(L"x32dbg.exe") )
      ExitProcess(0);
    if ( dword_10018FD4 == 1 || v1 != 41 )
    {
      sub_10003997("\nOops! Did you forget anything?\n");
      sub_10003997("That is a wrong flag! Try again!!1\n");
    }
    else
    {
      for ( i = 0; i < 36; i += 6 )
      {
        if ( v21[i - 1] == *((_BYTE *)&v12[-1] + i) )
          ++v0;
        if ( v21[i] == *((_BYTE *)&v11 + i + 1) )
          ++v0;
        if ( v21[i + 1] == *((_BYTE *)&v11 + i + 2) )
          ++v0;
        if ( v21[i + 2] == *((_BYTE *)&v11 + i + 3) )
          ++v0;
        if ( v21[i + 3] == *((_BYTE *)v12 + i) )
          ++v0;
        if ( v21[i + 4] == *((_BYTE *)v12 + i + 1) )
          ++v0;
      }
      if ( v0 == 36 )
      {
        sub_10003997("\nGreat Flag!\n");
        sub_10003997("Congratulations!\n");
      }
    }
  }
  sub_10003997("\n");
  system("pause");
  if ( v15 >= 0x10 )
    j__free(v13[0]);
  v15 = 15;
  v14 = 0;
  LOBYTE(v13[0]) = 0;
  if ( v18 >= 0x10 )
    j__free(v16);
  return 1;
}
```
Đoạn này sẽ check len của input

```c
LABEL_6:
  print("Checking...\n");
  Sleep(0x3E8u);
  strncpy_s(Destination, 0x104u, Str, 0x24u);
  if ( !strstr(Str, "@") )
    goto FAIl;
  v3 = strrchr(Str, 64);
  strncpy_s(v22, 0x104u, v3, 5u);
  v4 = Str;
  if ( dword_10018FD4 != 1 )
    v4 = Destination;
  sub_10001EC0(v4, &v19);
  sub_100017A0(v16, "QDIwMjI=", 8u);
  v5 = sub_10001430(v10);
  sub_100023E0(v13, v5);
  if ( v12[13] >= 0x10u )
    j__free(v12[8]);
  v6 = v13;
  if ( v15 >= 0x10 )
    v6 = v13[0];
  v7 = strcmp(v22, v6);
  if ( v7 )
    v7 = v7 < 0 ? -1 : 1;
  if ( v7 )
  {
FAIl:
    print("Oh no! That is a wrong flag! Try again!!1\n");
```
Đoạn check này chương trình sẽ lấy 36 kí tự đầu và lưu vào v4, còn 5 kí tự cuối, 5 kí tự cuối sẽ được `cmp` với b64decode của `QDIwMjI=`:

![image](https://user-images.githubusercontent.com/88520787/176368660-d98ec1ad-ed2f-4808-8911-2bf4afc1b816.png)

36 kí tự đầu sẽ được xử lí qua hàm `sub_10001EC0`:
```c
int __fastcall sub_10001EC0(const char *a1, _BYTE *a2)
{
  unsigned int v4; // eax
  _BYTE *v5; // edx
  int v6; // esi
  unsigned int v7; // ebx

  v4 = strlen(a1);
  if ( v4 )
  {
    v5 = a2;
    v6 = a1 - a2;
    v7 = v4;
    do
    {
      *v5 = (v5[v6] ^ 0x11) + 11;
      ++v5;
      --v4;
    }
    while ( v4 );
    a2[v7] = 0;
    return 1;
  }
  else
  {
    *a2 = 0;
    return 1;
  }
}
```
Cụ thể thì hàm này chỉ là `xor` từng kí tự input với lại 0x11 và cộng thêm 11

Tại dòng 119, ta sẽ thấy đoạn check 36 kí tự đầu:

```c
for ( i = 0; i < 36; i += 6 )
      {
        if ( v20[i - 1] == *(&v12[-1] + i) )
          ++v0;
        if ( v20[i] == *(&v11 + i + 1) )
          ++v0;
        if ( v20[i + 1] == *(&v11 + i + 2) )
          ++v0;
        if ( v20[i + 2] == *(&v11 + i + 3) )
          ++v0;
        if ( v20[i + 3] == *(v12 + i) )
          ++v0;
        if ( v20[i + 4] == *(v12 + i + 1) )
          ++v0;
      }
```
Sau khi mình xem trên stack thì mình `v11` nằm ngay trước `v12` nên là khi viết script mình sẽ gộp 2 bytes này chung:

![image](https://user-images.githubusercontent.com/88520787/176369395-a6cc72a5-a033-4b0e-88af-5da7aa0cf2de.png)

```py
x= [0x70,0x83,0x84,0x51,0x70,0x30,0x64,0x2D,0x2C,0x4D,0x2B,0x2B,0x2D,0x72,0x2B,0x68,0x82,0x83,0x68,0x30,0x6F,0x2C,0x53,0x7F,0x88,0x88,0x2B,0x51,0x7F,0x87,0x2D,0x4E,0x6E,0x2D,0x5E,0x87]
for i in range(0,len(x),4):
    t = x[i:i+4][::-1]
    for c in t:
        print(chr((c-11)^0x11),end = "") #Whit3H4t11S0L1v34LifeY0uW1llR3memB3r
```
Flag: `WhiteHat{Whit3H4t11S0L1v34LifeY0uW1llR3memB3r@2022}`

## re03-startr3 - 32pts

Bài này thì là bài free flag nên là, mở bằng ida64 thấy luôn flag:

![image](https://user-images.githubusercontent.com/88520787/176370995-7ca6fa5e-e820-4fb1-9966-f9b16dc388fe.png)

Flag: `WhiteHat{start_r3_ez_game}`

## re04-Baby RE - 128pts

Đề cho mình 1 file exe như này: 

![image](https://user-images.githubusercontent.com/88520787/176371449-4fff20c9-78e1-423f-b864-b00b94290379.png)

Nhìn icon nên mìn chắc chắn là ông ra đề dùng pyinstaller luôn:)), ngay lập tức mình đi tìm tools để decompile ra:

Đầu tiên mình dùng [Pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) để extract file này ra, sau khi extract nó sẽ trông như này:

![image](https://user-images.githubusercontent.com/88520787/176371888-8798c18c-f081-4bc2-af6f-b0a70000a9c2.png)

Tiếp tục mình dùng [Uncompyle6](https://github.com/rocky/python-uncompyle6) để uncompyle file `quewridg.pyc` ra thành code python:

```py
import base64, os, time
str1 = []
str2 = []
k = None
h = None

def re():
    global h
    global k
    s = 'VOhEdHV0YIRVVLF0S9'
    x = '92Mp5GXI5XV79DMO1F'
    for i in range(len(s)):
        if i % 2 != 0:
            str1.append(s[i])
            str2.append(x[i])
        else:
            str1.append(x[i])
            str2.append(s[i])

    k = ''.join(str1)
    h = ''.join(str2)


def write_1():
    with open(os.environ['USERPROFILE'] + str(base64.b64decode('XEFwcERhdGFcTG9jYWxcVGVtcFw='), 'utf-8') + k + str(base64.b64decode('LnR4dA=='), 'utf-8'), 'w') as (f):
        f.write('YmFuIGNvIHRoYXkgY29uIGJhY2ggdHVvYyBrZXUga2hvbmc=')
    with open(os.environ['USERPROFILE'] + str(base64.b64decode('XEFwcERhdGFcUm9hbWluZ1w='), 'utf-8') + h + str(base64.b64decode('LnR4dA=='), 'utf-8'), 'w') as (f):
        f.write('dGltIHRodSB4ZW0=')


def content():
    banner = ".__   __.  __    ______   ___   .___________.____    _  _    .___  ___. \n|  \\ |  | /_ |  /      | / _ \\  |           |___ \\  | || |   |   \\/   | \n|   \\|  |  | | |  ,----'| | | | `---|  |----` __) | | || |_  |  \\  /  | \n|  . `  |  | | |  |     | | | |     |  |     |__ <  |__   _| |  |\\/|  | \n|  |\\   |  | | |  `----.| |_| |     |  |     ___) |    | |   |  |  |  | \n|__| \\__|  |_|  \\______| \\___/      |__|    |____/     |_|   |__|  |__|"
    print(banner)
    print('=======================================================================================')
    print('                      https://www.youtube.com/shorts/t1u-h4rlNSY                       ')
    print('=======================================================================================')
    time.sleep(5)


if __name__ == '__main__':
    content()
    re()
    write_1()
```
Sau khi chuyển base64 thành ascii, mình thấy là khi chạy file lên, nó sẽ tạo ra 2 tệp với nội 2 nội dung:

```
ban co thay con bach tuoc keu khong
tim thu xem
```

Và mình để ý là tên của 2 cái file kia cũng là base64:

```py
def re():
    global h
    global k
    s = 'VOhEdHV0YIRVVLF0S9'
    x = '92Mp5GXI5XV79DMO1F'
    for i in range(len(s)):
        if i % 2 != 0:
            str1.append(s[i])
            str2.append(x[i])
        else:
            str1.append(x[i])
            str2.append(s[i])

    k = ''.join(str1)
    h = ''.join(str2)
    print(base64.b64decode(h+k+"=").decode())
re()         #WhiteHat{T1NH_N0NG_NHU_K3M}
```
Flag: `WhiteHat{T1NH_N0NG_NHU_K3M}`
Trong lúc làm bài này nóng thiệt=)), vì rating bài này 1* nên mình cũng không nói gì thêm, next thôi=))

## re05-Lucky Ticket - 64pts
```
Find the password of the mystery box
nc 164.92.81.231 9012
```
![image](https://user-images.githubusercontent.com/88520787/176375704-57efd22e-b14b-404e-b726-28c7e9444a74.png)

Sau khi mình chạy file thì nó dừng luôn, thử đưa vào IDA:

![image](https://user-images.githubusercontent.com/88520787/176376052-46441a43-05be-4b29-b81f-a3b1c6ea1129.png)

Ý của bài này là mình có 2 lựa chọn `1: Lucky Ticket`,`2: Mystery Box 600$`, Sau khi kiếm đủ 600$ bằng việc đoán chữ số thì mình sẽ được mở `Mystery Box`:

Đặt breakpoint tại đây và setup debug thôi:)

![image](https://user-images.githubusercontent.com/88520787/176377090-d6a11dff-9bd2-49cd-841b-563d2fa7e890.png)

Tại đây sẽ có lệnh nhảy có điều kiện `jnz` (jump if not zero)

![image](https://user-images.githubusercontent.com/88520787/176377521-e2d87189-12c8-484a-b5cb-1c62c61ec2eb.png)

Mình muốn nhảy vào thì chỉnh lại `ZeroFlag = 0`:

![image](https://user-images.githubusercontent.com/88520787/176377630-612c906a-e01f-4ad3-8328-612d247de5bd.png)

Tới đây các bạn chọn option 2 luôn:

![image](https://user-images.githubusercontent.com/88520787/176377784-5912b29b-7558-430f-9a2e-aaed73b04c7f.png)

![image](https://user-images.githubusercontent.com/88520787/176377836-2d07d817-52b7-4e2c-8531-5d677c95fed8.png)

Còn đây sẽ là đoạn so sánh số tiền hiện tại với 599, nếu lớn hơn thì sẽ nhảy vào chổ mở box, muốn pass qua lệnh này, mình cần chỉnh `OF = SF`:

![image](https://user-images.githubusercontent.com/88520787/176378396-07a5d2c1-c29a-4e22-b4fd-409e49cc6c89.png)

![image](https://user-images.githubusercontent.com/88520787/176378445-8f23aa5d-82e8-4bd9-9eec-48b2344744f8.png)

```c
__int64 __fastcall open(int a1)
{
  __int64 result; // rax
  _BOOL4 v2; // [rsp+14h] [rbp-9Ch]
  int v3; // [rsp+18h] [rbp-98h]
  int v4; // [rsp+1Ch] [rbp-94h]
  int v5[34]; // [rsp+20h] [rbp-90h] BYREF
  unsigned __int64 v6; // [rsp+A8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v3 = 3 * a + 5;
  for ( i = 0; i <= 9; ++i )
  {
    v5[i] = (int)(a * keypublic[i] + a1) % v3;
    printf("%d\n", keypublic[i]);
  }
  puts("-----------------------------");
  puts("\nYour key : ");
  for ( i = 0; i <= 9; ++i )
  {
    __isoc99_scanf("%2d", &v5[i + 12]);
    putchar(10);
  }
  v4 = module_reverse((unsigned int)a);
  v2 = 0;
  for ( i = 0; i <= 9; ++i )
    v5[i + 24] = v4 * (v5[i + 12] - a1) % v3;
  for ( i = 0; i <= 9; ++i )
    v2 = v5[i + 24] == keypublic[i];
  if ( v2 )
  {
    printf("\tCongratulate!!!!");
    printf("\nYour password : ");
    for ( i = 0; ; ++i )
    {
      result = (unsigned int)i;
      if ( i > 9 )
        break;
      printf("%d", (unsigned int)v5[i]);
    }
  }
  else
  {
    printf("Key not true");
    return 0LL;
  }
  return result;
}
```

Hàm này trước khi in ra password thì cần bạn nhập key vào, phân tích 1 chút hàm này sẽ hoạt đông như sau:

9 kí tự đầu của `v5` sẽ lưu 1 dãy số gì đó:

```v5[i] = (int)(a * keypublic[i] + a1) % v3;```

9 kí tự ở giữa sẽ lưu key các bạn nhập vào:

```c
for ( i = 0; i <= 9; ++i )
  {
    __isoc99_scanf("%2d", &v5[i + 12]);
    putchar(10);
  }
```
9 kí tự ở cuối sẽ là nơi chứa key sau khi mã hóa, và được so sánh với public key có sẵn:

```c
for ( i = 0; i <= 9; ++i )
    v5[i + 24] = v4 * (v5[i + 12] - a1) % v3;
  for ( i = 0; i <= 9; ++i )
    v2 = v5[i + 24] == keypublic[i];
```
Nếu đúng hết thì nó sẽ in password ra, mà password lại là 9 kí tự đầu của v5 =)))

Nên là khúc này mình chỉ cần chạy hết đoạn này, xong lấy pass ra thôi:))

```c
for ( i = 0; i <= 9; ++i )
  {
    v5[i] = (int)(a * keypublic[i] + a1) % v3;
    printf("%d\n", keypublic[i]);
  }
```
![image](https://user-images.githubusercontent.com/88520787/176380198-0142d478-c827-4886-8aa6-93fbe6c3bb8b.png)

Lấy 9 số đầu chuyển thành decimal và nối lại thì mình được password: `76725167175623`

Lúc đầu mình nhập vào thì không đc, sau khi ib hỏi admin và thảo luận 1 hồi lâu thì admin mới sửa lại và có đc flag, rồi tới đây mìnht thấy cái netcat nó cứ sao sao, không biết nó giúp gì trong trường hợp này =))

Nhập pass và get flag:

![image](https://user-images.githubusercontent.com/88520787/176380588-754d84d2-b3a8-47f2-9f12-892de9e424e6.png)

Flag: `Whitehat{I_n33d_v1t4m1n_s34}`

## re07-flagcheck - 64pts

![image](https://user-images.githubusercontent.com/88520787/176381355-a6890ae7-0b84-425b-919f-06f7cd7d7d56.png)

Sau khi mình enter thì nó mất tiêu luôn

![image](https://user-images.githubusercontent.com/88520787/176381394-dc08a6e2-8e06-464d-af9e-8b7ca7f4b161.png)

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  char Buffer[48]; // [rsp+20h] [rbp-60h] BYREF
  char cipher[44]; // [rsp+50h] [rbp-30h] BYREF
  unsigned int i; // [rsp+7Ch] [rbp-4h]

  _main();
  qmemcpy(cipher, "Vjjp`Nf|roqSua}Ow}aKg%H{q{wpxpxE~mLTX", 37);
  printf("Input flag: ");
  v3 = __iob_func();
  fgets(Buffer, 38, v3);
  for ( i = 0; i <= 0x24; ++i )
    Buffer[i] ^= (_BYTE)i + 1;
  for ( i = 0; i <= 0x24; ++i )
  {
    if ( Buffer[i] != cipher[i] )
    {
      puts("Incorrect flag!");
      return 0;
    }
  }
  puts("\nCongratulation! You have flag.");
  return 1;
}
```
Bài này khá cơ bản, sau khi nhập input thì nó sẽ lấy input của mình `xor` với lại index của kí tự đó + 1, tới đây thì không nói nhiều nữa viết script luôn:

```py
t = "Vjjp`Nf|roqSua}Ow}aKg%H{q{wpxpxE~mLTX"
for i in range(len(t)):
    print(chr((i+1)^ord(t[i])),end = "") #WhiteHat{ez_xor_for_r3_challenge_Oop}
```
Flag: `WhiteHat{ez_xor_for_r3_challenge_Oop}`
