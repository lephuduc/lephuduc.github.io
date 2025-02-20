---
title: "HITCON CTF 2022"
description: "Write up for rev problem in HITCON CTF 2022"
summary: "Write up for rev problem in HITCON CTF 2022"
categories: ["Writeup"]
tags: ["Reverse","Vietnamese"]
#externalUrl: ""
date: 2022-11-27
draft: false
authors:
  - Jinn
cover: /images/post_covers/hitconctf2022.jpeg
---

Đây sẽ là write-up về trải nghiệm cá nhân mình khi tham gia giải [HITCON CTF 2022](https://scoreboard.hitconctf.com/campaigns/1). Đầu tiên, có một bất ngờ nhỏ đối với mình là bài mình làm đa số rất nhiều solve nhưng cách giải thì không đơn giản như mình nghĩ. (giải 100kg:v)
Nhưng nhờ vậy mà qua giải này mình đã được mở mang kiến thức khá là nhiều, đặt biệt là mình đã học được cách debug windows drivers, thứ mà trước giờ mình chỉ static analysis, hơn nữa hiểu hơn về cách hoạt động của driver và biết được thêm 1 số kĩ thuật như [Heaven's gate](https://www.malwarebytes.com/blog/news/2018/01/a-coin-miner-with-a-heavens-gate) trong malware.

![](https://i.imgur.com/Jo4Fmcz.png)

# checker - 198pts
Có thể nói, đây là câu mà đa số các top team đều làm nó đầu tiên, vì trông nó rất là dễ, nhưng vì lúc này mình còn thiếu kiến thức nên giải quyết mọi chuyện có phần hơi khó khăn:v

Đây cũng không phải là lần đầu mình làm bài có driver trước đó, mình đã từng làm một bài driver từ giải WMCTF [tại đây](https://lephuduc.github.io/WMCTF2022/). Nhưng khác với những giải trước, thứ mà mình có thể static analysis hoàn toàn để ra flag riêng với bài này, setup một debugger là điều BẮT BUỘC để có flag một cách hợp lí nhất.

![](https://i.imgur.com/ZcuD1id.png)

Đây là toàn bộ những gì đề cho mình, cơ bản là có 1 file PE và 1 file driver .sys, tại đây cũng có thể đoán rằng luồn thực thi cũng như check flag chắc chắn sẽ nằm chủ yếu ở file .sys, và tất nhiên lúc mình chạy kiểm file checker.exe thì nó báo là `driver not found`

## file checker.exe

`checker.exe` là file PE64 bình thường và đây là toàn bộ code của nó, mình cũng không phân tích gì nhiều ở file này.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  HANDLE FileW; // rax
  char *v4; // rcx
  char OutBuffer[4]; // [rsp+40h] [rbp-18h] BYREF
  DWORD BytesReturned; // [rsp+44h] [rbp-14h] BYREF

  FileW = CreateFileW(L"\\\\.\\hitcon_checker", 0xC0000000, 0, 0i64, 3u, 4u, 0i64);
  qword_140003620 = (__int64)FileW;
  if ( FileW == (HANDLE)-1i64 )
  {
    sub_140001010("driver not found\n");
    exit(0);
  }
  OutBuffer[0] = 0;
  DeviceIoControl(FileW, 0x222080u, 0i64, 0, OutBuffer, 1u, &BytesReturned, 0i64);
  v4 = "correct\n";
  if ( !OutBuffer[0] )
    v4 = "wrong\n";
  sub_140001010(v4);
  system("pause");
  return 0;
}
```
Cơ bản là nó yêu cầu device có tên là `hitcon_checker`, sau đó nó dùng DeviceIoControl() để tương tác với driver này.

Mình có đọc document về hàm này [tại đây](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol) và nó có structure như sau:

```cpp
BOOL DeviceIoControl(
  [in]                HANDLE       hDevice,
  [in]                DWORD        dwIoControlCode,
  [in, optional]      LPVOID       lpInBuffer,
  [in]                DWORD        nInBufferSize,
  [out, optional]     LPVOID       lpOutBuffer,
  [in]                DWORD        nOutBufferSize,
  [out, optional]     LPDWORD      lpBytesReturned,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```
Riêng về chổ này mình chỉ cần nhớ tham số `dwIoControlCode`, thứ mà sẽ sử dụng để driver xử lí theo đúng tín hiệu này, và tham số trả về `lpBytesReturned`, nếu bằng 1, xem như mình check đúng.

Có một điều khá là lạ khi mà không có chổ để mình nhập input, chỉ có gửi code cho driver và nhận bytes trả về thôi.

## file checker_drv.sys

Đây là toàn bộ code của hàm main
```c=
__int64 __fastcall sub_140001B50(struct _DRIVER_OBJECT *driverObj)
{
  unsigned int v2; // edi
  _BYTE *DriverSection; // rcx
  PHYSICAL_ADDRESS PhysicalAddress; // rax
  PHYSICAL_ADDRESS v5; // rax
  unsigned __int8 v6; // al

  driverObj->DriverUnload = (PDRIVER_UNLOAD)unload_func;
  v2 = Create_n_Init(driverObj);
  driverObj->MajorFunction[0] = (PDRIVER_DISPATCH)proc_func;
  driverObj->MajorFunction[2] = (PDRIVER_DISPATCH)proc_func;
  driverObj->MajorFunction[3] = (PDRIVER_DISPATCH)proc_func;
  driverObj->MajorFunction[4] = (PDRIVER_DISPATCH)proc_func;
  DriverSection = driverObj->DriverSection;
  driverObj->MajorFunction[14] = (PDRIVER_DISPATCH)proc_func;
  DriverSection[104] |= 0x20u;
  sub_140001040();
  PhysicalAddress = MmGetPhysicalAddress((char *)sub_140001490 + 7024);
  qword_140013170 = (__int64)MmMapIoSpace(PhysicalAddress, 0x1000ui64, MmNonCached);
  qword_140013178 = qword_140013170 + 48;
  v5 = MmGetPhysicalAddress((char *)sub_140001490 - 96);
  qword_140013188 = (__int64)MmMapIoSpace(v5, 0x1000ui64, MmNonCached);
  susBytes = qword_140013188 + 1792;
  v6 = sub_140001490();
  *(_BYTE *)susBytes ^= *(_BYTE *)qword_140013188;
  *(_BYTE *)(susBytes + 1) ^= *(_BYTE *)(qword_140013188 + 1);
  *(_BYTE *)(susBytes + 2) ^= *(_BYTE *)(qword_140013188 + 2);
  *(_BYTE *)(susBytes + 3) ^= *(_BYTE *)(qword_140013188 + 3);
  *(_BYTE *)(susBytes + 4) ^= *(_BYTE *)(qword_140013188 + 4);
  *(_BYTE *)(susBytes + 5) ^= *(_BYTE *)(qword_140013188 + 5);
  *(_BYTE *)(susBytes + 6) ^= *(_BYTE *)(qword_140013188 + 6);
  *(_BYTE *)(susBytes + 7) ^= *(_BYTE *)(qword_140013188 + 7);
  *(_BYTE *)(susBytes + 8) ^= *(_BYTE *)(qword_140013188 + 8);
  *(_BYTE *)(susBytes + 9) ^= *(_BYTE *)(qword_140013188 + 9);
  *(_BYTE *)(susBytes + 10) ^= *(_BYTE *)(qword_140013188 + 10);
  *(_BYTE *)(susBytes + 11) ^= *(_BYTE *)(qword_140013188 + 11);
  *(_BYTE *)(susBytes + 12) ^= *(_BYTE *)(qword_140013188 + 12);
  *(_BYTE *)(susBytes + 13) ^= *(_BYTE *)(qword_140013188 + 13);
  *(_BYTE *)(susBytes + 14) ^= *(_BYTE *)(qword_140013188 + 14);
  *(_BYTE *)(susBytes + 15) ^= *(_BYTE *)(qword_140013188 + 15);
  *(_BYTE *)susBytes ^= *(_BYTE *)(qword_140013188 + 16);
  *(_BYTE *)(susBytes + 1) ^= *(_BYTE *)(qword_140013188 + 17);
  *(_BYTE *)(susBytes + 2) ^= *(_BYTE *)(qword_140013188 + 18);
  *(_BYTE *)(susBytes + 3) ^= *(_BYTE *)(qword_140013188 + 19);
  *(_BYTE *)(susBytes + 4) ^= *(_BYTE *)(qword_140013188 + 20);
  *(_BYTE *)(susBytes + 5) ^= *(_BYTE *)(qword_140013188 + 21);
  *(_BYTE *)(susBytes + 6) ^= *(_BYTE *)(qword_140013188 + 22);
  *(_BYTE *)(susBytes + 7) ^= *(_BYTE *)(qword_140013188 + 23);
  *(_BYTE *)(susBytes + 8) ^= *(_BYTE *)(qword_140013188 + 24);
  *(_BYTE *)(susBytes + 9) ^= *(_BYTE *)(qword_140013188 + 25);
  *(_BYTE *)(susBytes + 10) ^= *(_BYTE *)(qword_140013188 + 26);
  *(_BYTE *)(susBytes + 11) ^= *(_BYTE *)(qword_140013188 + 27);
  *(_BYTE *)(susBytes + 12) ^= *(_BYTE *)(qword_140013188 + 28);
  *(_BYTE *)(susBytes + 13) ^= *(_BYTE *)(qword_140013188 + 29);
  *(_BYTE *)(susBytes + 14) ^= *(_BYTE *)(qword_140013188 + 30);
  *(_BYTE *)(susBytes + 15) ^= *(_BYTE *)(qword_140013188 + 31);
  sub_1400014B0(v6);
  return v2;
}
```

Mình đã rename một số hàm, tuy nhiên một số biến nhưng mà mình chỉ cần phân tích một phần và hiểu là được.

Đầu tiên, driverObj có một thuộc tính là `DriverUnload`, đây sẽ là hàm được driver gọi lúc driver stop, có thể xem như là một destructor trong c++ 

Bỏ qua dòng thứ 10, tiếp xem là thuộc tính `MajorFunction`, mình dựa theo list này và hiểu cơ bản như sau:
![](https://i.imgur.com/RC4q8XS.png)
Major function sẽ dựa vào IRP_MJ_* để xác định chức năng nào sẽ được hàm nào xử lí. Hay nói cách khác `MajorFunction[14]` hoặc DEVICE_CONTROL sẽ được `proc_func` (mình đã rename) đảm nhiệm, tương tự với CREATE, CLOSE,..

Có thể nói, `proc_func` sẽ là hàm xử lí khi giao tiếp với `checker.exe` lúc nãy, nhưng mình sẽ nói về hàm này sau, vì nó cũng không quá rắc rối.

Tiếp tục với hàm main, 
```c
  PhysicalAddress = MmGetPhysicalAddress((char *)sub_140001490 + 7024);
  qword_140013170 = (__int64)MmMapIoSpace(PhysicalAddress, 0x1000ui64, MmNonCached);
  qword_140013178 = qword_140013170 + 48;
  v5 = MmGetPhysicalAddress((char *)sub_140001490 - 96);
  qword_140013188 = (__int64)MmMapIoSpace(v5, 0x1000ui64, MmNonCached);
  susBytes = qword_140013188 + 1792;
```
PhysicalAddress sẽ là biến lưu giá trị chính xác của (sub_140001490 + 7024) được lưu trong RAM, địa chỉ này được map 0x1000 bytes.

Có thể hiểu rằng khi được map như vậy, có một hàm nào năm trên vùng map thì khi các bits vật lí ở memory bị thay đổi đồng nghĩa với nội dung của hàm đó cũng bị thay đổi.
```c
qword_140013178 = qword_140013170 + 48;
```
qword_70 lúc này là một vùng 0x1000 bytes, mà qword_78 trỏ tới qword_70 + 48, mà đồng thời độ dài của flag là 48 bytes => qword_70 là vùng nhớ của flag, mình sẽ rename lại thành `flag`, còn `qword_140013170` mình sẽ gọi là space1

Tương tự với 2 câu lệnh tiếp theo, đặc biệt địa chỉ của qword_140013188 + 1792 trùng với địa chỉ của hàm 

```c
char __fastcall sub_140001B30(char a1)
{
  return -98 - 17 * ((a1 - 34) ^ 0xAD);
}
```
Mình tạm gọi nó là space2, còn susBytes sẽ trỏ tới vị trí trong memory của hàm này. Nghĩa là khi susBytes thay đổi thì nội dung hàm cũng bị thay đổi.

Còn `qword_140013188` mình sẽ rename thành space2.

```c
  *(_BYTE *)susBytes ^= *(_BYTE *)space2;
  *(_BYTE *)(susBytes + 1) ^= *(_BYTE *)(space2 + 1);
  *(_BYTE *)(susBytes + 2) ^= *(_BYTE *)(space2 + 2);
  *(_BYTE *)(susBytes + 3) ^= *(_BYTE *)(space2 + 3);
  *(_BYTE *)(susBytes + 4) ^= *(_BYTE *)(space2 + 4);
  *(_BYTE *)(susBytes + 5) ^= *(_BYTE *)(space2 + 5);
  *(_BYTE *)(susBytes + 6) ^= *(_BYTE *)(space2 + 6);
  *(_BYTE *)(susBytes + 7) ^= *(_BYTE *)(space2 + 7);
  *(_BYTE *)(susBytes + 8) ^= *(_BYTE *)(space2 + 8);
  *(_BYTE *)(susBytes + 9) ^= *(_BYTE *)(space2 + 9);
  *(_BYTE *)(susBytes + 10) ^= *(_BYTE *)(space2 + 10);
  *(_BYTE *)(susBytes + 11) ^= *(_BYTE *)(space2 + 11);
  *(_BYTE *)(susBytes + 12) ^= *(_BYTE *)(space2 + 12);
  *(_BYTE *)(susBytes + 13) ^= *(_BYTE *)(space2 + 13);
  *(_BYTE *)(susBytes + 14) ^= *(_BYTE *)(space2 + 14);
  *(_BYTE *)(susBytes + 15) ^= *(_BYTE *)(space2 + 15);
  *(_BYTE *)susBytes ^= *(_BYTE *)(space2 + 16);
  *(_BYTE *)(susBytes + 1) ^= *(_BYTE *)(space2 + 17);
  *(_BYTE *)(susBytes + 2) ^= *(_BYTE *)(space2 + 18);
  *(_BYTE *)(susBytes + 3) ^= *(_BYTE *)(space2 + 19);
  *(_BYTE *)(susBytes + 4) ^= *(_BYTE *)(space2 + 20);
  *(_BYTE *)(susBytes + 5) ^= *(_BYTE *)(space2 + 21);
  *(_BYTE *)(susBytes + 6) ^= *(_BYTE *)(space2 + 22);
  *(_BYTE *)(susBytes + 7) ^= *(_BYTE *)(space2 + 23);
  *(_BYTE *)(susBytes + 8) ^= *(_BYTE *)(space2 + 24);
  *(_BYTE *)(susBytes + 9) ^= *(_BYTE *)(space2 + 25);
  *(_BYTE *)(susBytes + 10) ^= *(_BYTE *)(space2 + 26);
  *(_BYTE *)(susBytes + 11) ^= *(_BYTE *)(space2 + 27);
  *(_BYTE *)(susBytes + 12) ^= *(_BYTE *)(space2 + 28);
  *(_BYTE *)(susBytes + 13) ^= *(_BYTE *)(space2 + 29);
  *(_BYTE *)(susBytes + 14) ^= *(_BYTE *)(space2 + 30);
  *(_BYTE *)(susBytes + 15) ^= *(_BYTE *)(space2 + 31);
```
Ngay bên dưới thì hàm sub_140001B30 (tạm gọi là decrypt) đã bị xor với space2 và bị thay đổi, nhưng lúc này mình không biết space2 là gì và đoạn code này được chạy khi mà mình load driver xuống tầng kernel, do đó mình phải setup debug mới biết được space2 là gì.

Tiếp tục quay lại hàm `proc_func` là nơi xử lí chính của chương trình:

```c
__int64 __fastcall proc_func(struct _DEVICE_OBJECT *a1, __int64 a2)
{
  ULONG Length; // esi
  PIO_STACK_LOCATION CurrentIrpStackLocation; // rax
  char v7; // cl
  __int64 v8; // rax
  int v9; // ecx

  Length = 0;
  CurrentIrpStackLocation = IoGetCurrentIrpStackLocation((PIRP)a2);
  if ( a1 != DeviceObject )
    return 3221225473i64;
  if ( CurrentIrpStackLocation->MajorFunction )
  {
    if ( CurrentIrpStackLocation->MajorFunction == 14 )
    {
      Length = CurrentIrpStackLocation->Parameters.Read.Length;
      switch ( CurrentIrpStackLocation->Parameters.Read.ByteOffset.LowPart )
      {
        case 0x222000u:
          susFunc(0);
          byte_140013190[0] = 1;
          break;
        case 0x222010u:
          susFunc(32u);
          byte_140013191 = 1;
          break;
        case 0x222020u:
          susFunc(64u);
          byte_140013192 = 1;
          break;
        case 0x222030u:
          susFunc(96u);
          byte_140013193 = 1;
          break;
        case 0x222040u:
          susFunc(128u);
          byte_140013194 = 1;
          break;
        case 0x222050u:
          susFunc(160u);
          byte_140013195 = 1;
          break;
        case 0x222060u:
          susFunc(192u);
          byte_140013196 = 1;
          break;
        case 0x222070u:
          susFunc(224u);
          byte_140013197 = 1;
          break;
        case 0x222080u:
          if ( !Length )
            goto LABEL_15;
          v7 = 1;
          v8 = 0i64;
          while ( byte_140013190[v8] )
          {
            if ( ++v8 >= 8 )
              goto LABEL_21;
          }
          v7 = 0;
LABEL_21:
          if ( v7 )
          {
            v9 = dword_140003000 - 'ctih';
            if ( dword_140003000 == 'ctih' )
              v9 = (unsigned __int16)word_140003004 - 'no';
            **(_BYTE **)(a2 + 24) = v9 == 0;
          }
          else
          {
LABEL_15:
            **(_BYTE **)(a2 + 24) = 0;
          }
          break;
        default:
          break;
      }
    }
  }
  else
  {
    byte_140003170[(_QWORD)PsGetCurrentProcessId()] = 1;
  }
  *(_QWORD *)(a2 + 56) = Length;
  *(_DWORD *)(a2 + 48) = 0;
  IofCompleteRequest((PIRP)a2, 0);
  return 0i64;
}
```
Tại đây ta sẽ thấy cấu trúc của nó là 1 switch case, mà lúc nãy checker.exe có sử dụng code là 0x222080 => chỉ có `case 0x222080u` được gọi.

Ở case này thì nó check xem đã gọi 8 case ở trên chưa (0x222000->0x222070), Nếu có thì nó sẽ tiến hành kiểm tra dword_140003000 có bằng "hitcon" hay không, nếu có thì nó sẽ trả về byte 1 cho checker.exe

Tại bytes dword_140003000, ta thấy nó là flag 



















ed với length là 48 (lý do mình biết flaglength là 48 lúc nãy)

![](https://i.imgur.com/f2FQcGy.png)

Quay lại các case ở trên, nó gọi 1 hàm duy nhất nhưng có tham số khác nhau 

![](https://i.imgur.com/yYFe804.png)


Trong hàm này nó xor function decrypt (susBytes) với 16 bytes đầu của space 1 kể từ idx sau đó nó dùng hàm `decrypt` để decrypt 48 bytes của flag, sau đó lại xor `decrypt` với 16 bytes tiếp theo kể tử idx+16.

## take note
Vậy thì cơ bản flow chương trình đã có thể rõ, có thể tóm tắt lại như sau:

- checker.exe có sử dụng driver check flag, khi flag trên driver đúng thì sẽ trả về correct
- driver có 8 hàm xử lí flag và 1 hàm check (case 0x222080)
- Khi mà driver gọi đủ 8 hàm trên thì mới kiểm tra flag được, trong mỗi hàm lần lượt xor bytes rồi gọi hàm decrypt flag, sau đó xor hàm decrypt flag tiếp

## Solution

Vậy để được flag đúng, ta phải tìm được đúng thứ tự gọi 8 hàm ở trên, vậy việc đầu tiên là ta phải lấy được space1 và bytes của function decrypt sau khi chạy hết hàm main.

Giờ mình sẽ setup debug:

Máy ảo mình đang sử dụng là Windows 10 22H2 và flare-vm, tools dùng để debug là Windbg, vì ban đầu mình dùng windbg bản cũ nên là hầu như rất khó và không thể làm được. Mình dùng WinDbg Preview trên `Microsoft Store`.

Đầu tiên phải cài đặt được driver để test trước:

Mình dùng OSR Driver Loader để dùng GUI hoặc cũng có thể dựa theo [link này](https://stackoverflow.com/questions/7828663/how-do-i-install-a-custom-windows-driver):

Đối với OSR Driver Loader:

![](https://i.imgur.com/fjrYKrv.png)

Chọn `[Resgiser Service]` để tạo service cho driver này, sau đó chọn `[Start Service]` để khởi động service, tương từ bấm stop và Unregister để dừng và huỷ bỏ.

Tương tự cách trên nhưng cùng cmd:

Register Service: `sc create hitcon_checker binPath= [full path to your .sys file] type= kernel`

Start service: `sc start hitcon_checker`

>Đối với các bạn không resgister được vì driver không có signature, hay nói cách khác Windows nói đó là driver không rõ nguồn gốc nên không cài được, tuy nhiên có thể tắt chức năng này khi khởi động windows, mình làm theo hướng dẫn ở link này hoặc các bạn có thể dùng [VirtualKD-Redux](https://github.com/4d61726b/VirtualKD-Redux) -> taget64 -> vminstall.exe, Sau đó bấm F8 và chọn [Disable driver signature enforcement]

Sau khi khởi động service thì khi chạy checker.exe sẽ có thông báo như sau là thành công:

![](https://i.imgur.com/P5qG7Nt.png)

Tiến hành debug driver thôi, bây giờ các bạn làm lại bước `taget64 -> vminstall.exe -> install `, tiếp tục F8 và chọn [Disable driver signature enforcement] tuy nhiên cùng lúc này, khi mà Icon windows hiện lên thì ở máy host mở vmmon64.exe lên:

![](https://i.imgur.com/6IoXMjc.png)

Chọn WinDbg Preview và Chọn [Run debugger]

![](https://i.imgur.com/KPLVolL.png)

Lúc này setup màn hình disassembly và máy ảo đứng như thế này xem như thành công:v

![](https://i.imgur.com/4VBruAn.png)

Bấm go để máy tiếp tục chạy

![](https://i.imgur.com/c4dsopH.png)

Lúc này, khởi động lại driver của bài, nếu thành công ta sẽ thấy checker_drv.sys trong driver list:

![](https://i.imgur.com/VRVGgOK.png)

Quay lại Windbg, dựa vào địa chỉ base của driver, tìm dược vị trí của driver đó trong memory:

![](https://i.imgur.com/Z553fu3.png)

Dựa vào địa chỉ của hàm decrypt trong IDA, mình tìm được hàm `decrypt` trong màn hình memory là `base + 0x1b30`

```c
char __fastcall sub_140001B30(char a1)
{
  return -98 - 17 * ((a1 - 34) ^ 0xAD);
}
```
![](https://i.imgur.com/Er6xSsv.png)
Lúc này, rõ ràng nó đã đi qua hàm main nên bytes của nó đã bị thay đổi so với ban đầu, vì cần lưu bytes này lại tính toán, nên mình dùng lệnh db để lấy bytes này ra:

![](https://i.imgur.com/bNhf02y.png)

```python
func = bytes.fromhex('88 31 20 13 55 b4 4f 48 f3 18 4f 5b b0 29 9e c7 00 2a c1 c3')
```
Tương tự mình cần lấy ra 0xe0 + 32 bytes của space2

![](https://i.imgur.com/6ilI7Bt.png)


```python
space2 = bytes.fromhex("""
19 bc 8f 82 d0 2c 61 34 c0 9f f6 50 d5 fb 0c 6e
d0 eb e5 e3 ce b5 4c ca 45 aa 11 b2 3e 62 6f 7d
d0 eb a9 e3 b2 2f 06 47 7c 28 c5 de de 1a 4e d6
d8 2d 93 4f 82 65 64 fd 08 62 4b 87 7e 52 47 30
b7 ba d0 39 68 53 50 ab 20 d5 ca 84 26 71 6f 91
1b 36 46 11 a5 f1 4e 58 6c 74 d4 9c 15 e2 28 d5
d9 0f 3d 83 f3 fc d1 13 1a 62 12 40 aa ea cd cb
e1 c6 08 81 98 f6 68 88 be 23 b5 9e 55 b9 e2 7d
5a da 39 07 f0 2e 32 20 59 56 4c b4 8f 3e 07 61
d9 0f 2d 61 f1 91 33 14 cb 49 68 fe 1f d4 8a fe
e1 c6 18 63 9a 9b 8a 8a 7f 08 c3 e8 e1 ec 0b 8f
3b 00 94 a5 11 e7 47 66 c4 9f 98 18 70 f0 30 f6
94 71 b1 95 d1 f0 6f b7 d9 3d 05 9e c1 53 33 76
9b 4b 69 ca de fd 7d 67 b8 29 2b c7 c5 84 2c d1
87 87 f1 98 97 74 ad 4b 32 f0 4a 51 72 ea 09 f7
38 fd 27 bd 1c 52 71 43 95 9c 1a 86 f2 c0 f9 f8""")
```

Tới đây thì mình có thể tìm thứ tự các hàm trong switch case hoạt động bằng cách bruteforce các opcode các hàm, vì sau khi xử lí xong, các bytes của hàm bị biến đổi sau cho có thể sử dụng được hàm sau sử dụng được, nên tổng số lần mình cần brute rất ít (2+3+4+5+6+7+8) = 35 lần

```python
from pwn import *
# print(xor(x2[:16],b2[:16]).hex() + x2[16:].hex())
#important offset
#0xfffff80664800000
#1b30 miniencrypt
#3000 flag
# origin = b'\x80\xe9"\x80\xf1\xad\x0f\xb6\xc1k\xc8\x11\xb8\x9e\x00\x00\x00*\xc1\xc3'
func = bytes.fromhex('88 31 20 13 55 b4 4f 48 f3 18 4f 5b b0 29 9e c7 00 2a c1 c3')

space2 = bytes.fromhex("""
19 bc 8f 82 d0 2c 61 34 c0 9f f6 50 d5 fb 0c 6e
d0 eb e5 e3 ce b5 4c ca 45 aa 11 b2 3e 62 6f 7d
d0 eb a9 e3 b2 2f 06 47 7c 28 c5 de de 1a 4e d6
d8 2d 93 4f 82 65 64 fd 08 62 4b 87 7e 52 47 30
b7 ba d0 39 68 53 50 ab 20 d5 ca 84 26 71 6f 91
1b 36 46 11 a5 f1 4e 58 6c 74 d4 9c 15 e2 28 d5
d9 0f 3d 83 f3 fc d1 13 1a 62 12 40 aa ea cd cb
e1 c6 08 81 98 f6 68 88 be 23 b5 9e 55 b9 e2 7d
5a da 39 07 f0 2e 32 20 59 56 4c b4 8f 3e 07 61
d9 0f 2d 61 f1 91 33 14 cb 49 68 fe 1f d4 8a fe
e1 c6 18 63 9a 9b 8a 8a 7f 08 c3 e8 e1 ec 0b 8f
3b 00 94 a5 11 e7 47 66 c4 9f 98 18 70 f0 30 f6
94 71 b1 95 d1 f0 6f b7 d9 3d 05 9e c1 53 33 76
9b 4b 69 ca de fd 7d 67 b8 29 2b c7 c5 84 2c d1
87 87 f1 98 97 74 ad 4b 32 f0 4a 51 72 ea 09 f7
38 fd 27 bd 1c 52 71 43 95 9c 1a 86 f2 c0 f9 f8""")

print(space2)
print(hex(len(space2)))
#0 32 224

def decryptflag(idx):
    tmpFunc = xor(func[:16],space2[idx:idx+16]) + func[16:]
    print(idx,tmpFunc.hex())
    tmpFunc = xor(tmpFunc[:16],space2[idx+16:idx+32]) + func[16:]
    return tmpFunc
for i in [0,32,64,96,128,160,192,224]:
    decryptflag(i)
```
```
0 918daf9185982e7c3387b90b65d292a9002ac1c3                                                                                         
32 58da89f0e79b490f8f308a856e33d011002ac1c3                                                                                       
64 3f8bf02a3de71fe3d3cd85df9658f156002ac1c3
96 513e1d90a6489e5be97a5d1b1ac3530c002ac1c3
128 d2eb1914a59a7d68aa4e03ef3f1799a6002ac1c3
160 69f73870cf2fc5c28c108cb351c59548002ac1c3
192 1c409186844420ff2a254ac5717aadb1002ac1c3
224 0fb6d18bc2c0e203c1e8050ac2c39730002ac1c3
```

Thử 8 shellcode này trên https://onlinedisassembler.com/odaweb/ thì mình thấy 224 là hợp lí nhất, tương ứng với code 0x222070u

![](https://i.imgur.com/yT4Fhgp.png)

Tương tự với 27 lần nữa, mình tìm được thứ tự rất hợp lí khi mà hàm cuối khi disassembly như này:

![](https://i.imgur.com/3F1Mgn4.png)

Đây là thứ tự của các tham số:

`[224,64,192,0,32,128,96,160]`

Tương ứng với các code \

```
[0x222070u,0x222020u,0x222050u,0x222000u,0x222010u,0x222040u,0x222030u,0x222060u]
```
Để gửi các code này lên driver thì mình có 1 cách là tạo ra 8 cái file khác nhau, mỗi file có 1 số 0x2220_0 thay đổi từ file gốc là 
```c
DeviceIoControl(FileW, 0x222080u, 0i64, 0, OutBuffer, 1u, &BytesReturned, 0i64);
```
Đây là script của mình
```py
f = open('checker.exe','rb')
b = f.read()
# for i in range(len(b)-5):
#     if b[i:i+5]==b'\xba\x80\x20\x22\x00':
#         print(i)
print(b[1290])
order = [0,32,64,96,128,160,192,224]
x = [b'\x00',b'\x10',b'\x20',b'\x30',b'\x40',b'\x50',b'\x60',b'\x70']
for i in range(len(order)):
    tmpFile = open(f'checker{order[i]}.exe','wb')
    tmpFile.write(b[:1290] + x[i]+b[1291:])
    tmpFile.close()    
```

![](https://i.imgur.com/a49jjGL.png)

Load file vào Máy ảo và chạy lần lượt theo thứ tự ở trên, nếu thành công, khi chạy file checker.exe nó sẽ thông báo như thế này:

![](https://i.imgur.com/OCkQzsG.png)

Đồng nghĩa là flag đã đúng và nằm trong memory.

Check địa chỉ base + 0x3000 ta sẽ thấy flag:

![](https://i.imgur.com/HVLwiVt.png)

Flag: `hitcon{r3ally_re4lly_rea11y_normal_checker}`

# Meow Way - 193pts

Về cơ bản thì bài này dễ hơn bài trước khá nhiều flow cũng dễ đọc hơn, chỉ khác là nó áp dụng một kĩ thuật đặc biệt có tên là [heaven's gate](https://www.malwarebytes.com/blog/news/2018/01/a-coin-miner-with-a-heavens-gate) mình biết được từ a @mochi và anh gửi cho mình blog này.

Trước hết xem qua thử file duy nhất mà đề bài cho mình:

Load file bằng IDA32 và đây là toàn bộ hàm main của nó

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+0h] [ebp-24h]
  int v5; // [esp+0h] [ebp-24h]
  int v6; // [esp+14h] [ebp-10h]
  int v7[2]; // [esp+18h] [ebp-Ch] BYREF

  v7[0] = -1;
  v7[1] = -1;
  if ( argc < 2 )
  {
    sub_401340("Usage: %s <flag>\n", (char)*argv);
    exit(1);
  }
  if ( strlen(argv[1]) != 48 )
  {
    sub_401340("Wrong length\n", v4);
    exit(1);
  }
  v6 = (int)argv[1];
  dword_40544C(v6, v6 >> 31, v6, v6 >> 31, 196, 0, v7, (int)v7 >> 31);
  ++v6;
  dword_4053A8(v6, v6 >> 31, v6, v6 >> 31, 22, 0, v7, (int)v7 >> 31);
  ++v6;
  dword_4053B4(v6, v6 >> 31, v6, v6 >> 31, 142, 0, v7, (int)v7 >> 31);
  ++v6;
  dword_4053F0(v6, v6 >> 31, v6, v6 >> 31, 119, 0, v7, (int)v7 >> 31);
  ++v6;
  dword_405448(v6, v6 >> 31, v6, v6 >> 31, 5, 0, v7, (int)v7 >> 31);
  ++v6;
 ...
  ++v6;
  dword_405428(v6, v6 >> 31, v6, v6 >> 31, 254, 0, v7, (int)v7 >> 31);
  ++v6;
  dword_405460(v6, v6 >> 31, v6, v6 >> 31, 151, 0, v7, (int)v7 >> 31);
  ++v6;
  dword_40540C(v6, v6 >> 31, v6, v6 >> 31, 249, 0, v7, (int)v7 >> 31);
  ++v6;
  dword_4053F4(v6, v6 >> 31, v6, v6 >> 31, 152, 0, v7, (int)v7 >> 31);
  dword_405438(v6 + 1, (v6 + 1) >> 31, v6 + 1, (v6 + 1) >> 31, 101, 0, v7, (int)v7 >> 31);
  v5 = memcmp(&unk_405018, argv[1], 0x30u);
  if ( v5 )
  {
    sub_401340("Wrong\n", v5);
    exit(-1);
  }
  sub_401340("I know you know the flag!\n", 0);
  return 0;
}
```
Đầu tiên là chương trình check length của flag xem có bằng 48 kí tự không, sau đó thì với mỗi kí tự có 1 hàm encrypt riêng biệt với các tham số khác nhau.

Sau cùng là compare với unk_405018(encryted flag) và thông báo kết quả.

Từng dword_* sẽ trỏ về 1 hàm bất kì:

```c
void sub_401060()
{
  dword_405400 = (int (__cdecl *)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD))"j3è";
}
```

Và đây là nội dung của hàm đó:

![](https://i.imgur.com/vHenZ2B.png)

Lúc này mình thử debug mới xem được từng hàm nó làm gì:
Set Parameter là 1 chuỗi bất kì có lenght = 48

![](https://i.imgur.com/l6DNkpd.png)

![](https://i.imgur.com/qJfOtA8.png)

Khi mình stepinto và đi hết đoạn này thì chương trình tự out luôn, chắc là có lỗi gì đó ở chổ này

Nếu kiểm tra kĩ, ta sẽ thấy phía dưới thực sự còn 1 đoạn code nữa nhưng nó không chạy

![](https://i.imgur.com/VKabHAP.png)

Mình thử kiểm tra tương tự với các hàm khác, thì nó cũng ra kết quả tương tự, tuy nhiên chỉ khác nhau một vài chổ như `xor cl, <num>`, và một số hàm sub thay vì add, ...

Cơ bản là đoạn code phía trên làm nhiễu khá nhiều, khiến mình không thực sự biết là nó thực sự làm gì.

Như đầu bài mình đã nói, file này là file PE32 nhưng dùng kĩ thuật `heaven's gate` nên đoạn đó nó có thể chạy được code của 64bits (mình biết sơ như vậy:v). Do đó đoạn shellcode phía sau là của 64bit. Mình dùng web này để disassemble:

[onlinedisassembler](https://onlinedisassembler.com/odaweb/)

Đối với function đầu tiên:

![](https://i.imgur.com/v4EMYz9.png)

```
6a33e80000000083042405cb4831c065488b4060480fb64002678b4c241c67890185c07518678b7c2404678b74240c678b4c241467020e80f1ba67880fe800000000c7442404230000008304240dcbc30000000000000000
```

![](https://i.imgur.com/XdXqHaj.png)

Có một điều thú vị là kĩ thuật này chỉ anti debug thui, còn đọc thì cơ bản vẫn đọc được =)), thế mà không hiểu sao lúc đầu đọc không ra, chuyển qua x64 cũng thấy không khác gì nhiều nhưn mà lại làm ra =)), tâm lí quá.

Mình chỉ cần quan trọng đoạn này thôi:

![](https://i.imgur.com/ts4J1xW.png)

dựa vào thanh ghi esi, edi, và cl có thể suy ra nó encrypt byte của flag như sau:

![](https://i.imgur.com/GUc0nTE.png)

Đối với hàm này thì sẽ dịch sang python như này:

```python
def add(para,func,encrypted):
    return ((para+i)^func)&0xff
```

Tương tự với các hàm cho đến khi hàm thứ 6 thì nó sẽ khác đi 1 chút là thay vì cộng sẽ hành phép trừ:

```python
def sub(para,func,encrypted):
    return ((para-i)^func)&0xff
```

Tới đây mình thử giải ra flag

Trước tiên mình cần phải có tất cả các tham số mà nó truyền vào và flag encrypted:

```python
para=[196,22,142,119,5,185,13,107,36,85,18,53,118,231,251,160,218,52,132,180,200,155,239,180,185,10,87,92,254,197,106,115,73,189,17,214,143,107,10,151,171,78,237,254,151,249,152,101]
encrypted=b"\x96P\xcf,\xeb\x9b\xaa\xfbS\xabs\xddl\x9e\xdb\xbc\xee\xab#\xd6\x16\xfd\xf1\xf0\xb9u\xc3(\xa2t}\xe3'\xd5\x95\\\xf5vu\xc9\x8c\xfbB\x0e\xbdQ\xa2\x98"
```

Tiếp theo là tìm cách lấy các tham số nằm bên trong hàm:

![](https://i.imgur.com/2NDMnlw.png)

Dựa vào các địa chỉ này, ta lấy 4 bytes đầu là được địa chỉ của hàm
```python
int.from_bytes(get_bytes(i,4),'little')
```
Từ 4 bytes này mình sẽ lấy được toàn bộ hàm, tuy nhiên ta chỉ cần lấy bytes mà lúc nó xor, dựa vào opcode và thanh ghi của lệnh `xor cl, <num>`, mình biết được chỉ cần lấy byte nằm sau b'\xf1' là có được số cần xor.

Tới đây chỉ cần rev lại 2 hàm sub và add rồi decrypt flag ra thôi:v.

```python
from pwn import *
encrypted=b"\x96P\xcf,\xeb\x9b\xaa\xfbS\xabs\xddl\x9e\xdb\xbc\xee\xab#\xd6\x16\xfd\xf1\xf0\xb9u\xc3(\xa2t}\xe3'\xd5\x95\\\xf5vu\xc9\x8c\xfbB\x0e\xbdQ\xa2\x98"
para=[196,22,142,119,5,185,13,107,36,85,18,53,118,231,251,160,218,52,132,180,200,155,239,180,185,10,87,92,254,197,106,115,73,189,17,214,143,107,10,151,171,78,237,254,151,249,152,101]

offset = [0x77544C,0x7753A8,0x7753B4,0x7753F0,0x775448,0x7753FC,0x775400,0x775410,0x7753F8,0x775430,0x7753D0,0x775434,0x77545C,0x775454,0x7753C0,0x7753E4,0x7753C4,0x775440,0x7753BC,0x7753AC,0x775408,0x7753D8,0x7753B8,0x7753C8,0x7753E0,0x775418,0x7753EC,0x775414,0x775450,0x7753E8,0x7753D4,0x77541C,0x77542C,0x775444,0x775458,0x775420,0x7753B0,0x7753DC,0x775464,0x7753CC,0x775424,0x77543C,0x775404,0x775428,0x775460,0x77540C,0x7753F4,0x775438]
#[get_bytes(int.from_bytes(get_bytes(i,4),'little') + 0x30,16) for i in offset]
func = [186, 47, 205, 246, 159, 208, 34, 247, 208, 31, 168, 61, 199, 165, 71, 104, 215, 74, 150, 145, 46, 25, 197, 227, 136, 189, 78, 147, 19, 241, 204, 71, 171, 201, 72, 43, 9, 80, 79, 233, 192, 94, 239, 139, 133, 203, 85, 112]

def add(para,func,encrypted):
    for i in range(0x2f,0x7f):
        if ((para+i)^func)&0xff==encrypted:
            print(chr(i))
            return i
def sub(a,b,c):
    for i in range(0x2f,0x7f):
        if ((a-i)^b)&0xff==c:
            print(chr(i))
            return i

flag = ""
for i in range(len(func)):
    try:
        flag+=chr(add(para[i],func[i],encrypted[i]))
    except:
        flag+=chr(sub(para[i],func[i],encrypted[i]))
print(flag)
#hitcon{___7U5T_4_S1mpIE_xB6_M@G1C_4_mE0w_W@y___}
```
Sorry mọi người vì lúc đó mình làm ngược lại không ra mà mình gấp quá nên dùng cách brute luôn =))).

Flag: ```hitcon{___7U5T_4_S1mpIE_xB6_M@G1C_4_mE0w_W@y___}```