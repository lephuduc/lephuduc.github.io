---
title: "PicoCTF 2022"
description: "Write up for rev problem in PicoCTF 2022"
summary: "Write up for rev problem in PicoCTF 2022"
categories: ["Writeup"]
tags: ["Reverse", "Vietnamese","Wargame"]
#externalUrl: ""
date: 2021-03-09
draft: false
authors:
  - Jinn
cover: /images/post_covers/picoctf2021.jpeg
---


Mục lục:

1. [file-run1](https://github.com/lephuduc/Write-up-PicoCTF2022#file-run1)
2. [file-run2](https://github.com/lephuduc/Write-up-PicoCTF2022#file-run2)
3. [GDB Test Drive](https://github.com/lephuduc/Write-up-PicoCTF2022#gdb-test-drive)
4. [patchme.py](https://github.com/lephuduc/Write-up-PicoCTF2022#patchmepy)
5. [Safe Opener](https://github.com/lephuduc/Write-up-PicoCTF2022#safe-opener)
6. [unpackme.py](https://github.com/lephuduc/Write-up-PicoCTF2022#unpackmepy)
7. [bloat.py](https://github.com/lephuduc/Write-up-PicoCTF2022#bloatpy)
8. [Fresh Java](https://github.com/lephuduc/Write-up-PicoCTF2022#fresh-java)
9. [Bbbbloat](https://github.com/lephuduc/Write-up-PicoCTF2022#bbbbloat)
10. [Unpackme](https://github.com/lephuduc/Write-up-PicoCTF2022#unpackme)
11. [Keygenme](https://github.com/lephuduc/Write-up-PicoCTF2022#keygenme)
12. [Wizardlike](https://github.com/lephuduc/Write-up-PicoCTF2022#wizardlike)

**Trước hết bạn cần có các tools cần thiết để dùng reverse:**
- IDA Pro
- Detect it easy (DIE)
- Máy ảo (Ubuntu 20.04 hoặc Kali Linux)

## file-run1

![Untitled](https://user-images.githubusercontent.com/88520787/168028354-0cda410a-efc5-479b-99fe-f3ada12b311c.png)

Đây chỉ là bài warm-up nên sẽ khá là dễ nên ta chỉ cần dùng các lệnh mà `hints` có:

![Untitled 1](https://user-images.githubusercontent.com/88520787/168028410-0e48b03f-5754-49d2-84f6-4fe8fd5e3b26.png)

GIải thích:

- `chmod +x <file>`: cấp quyền chạy cho file
- `./<file>`: chạy file thực thi trên linux

## file-run2

![Untitled 2](https://user-images.githubusercontent.com/88520787/168029042-b0b17508-7c59-41b1-ad1a-698fd1b86e77.png)

Ở bài này, ta không thể chạy như bài trước nữa

![Untitled 3](https://user-images.githubusercontent.com/88520787/168029245-aab0128b-9b19-419f-a86d-6e64b47ec981.png)

thay vào đó ta cần truyền cho file một `parameter` là “Hello!” (theo như đề bài gợi ý), cú pháp như sau:

![Untitled 4](https://user-images.githubusercontent.com/88520787/168029278-1b5cc365-0345-45cd-ad4c-025fcaf93e59.png)

Giải thích:

Cú pháp truyền **parameter** khi chạy chương trình: 

`./<file> <parameter1> <parameter2> ...`

trong đó ta có hàm `main` như sau:

```python
int main(int argc, char *argv[]) {
//something
}
```

Các parameter này sẽ lưu theo thứ tự vào `argv[1] argv[2]... ...` , mặc định `argv[0]` sẽ là file chương trình. Các parameter sẽ được lưu vào argv[] dưới kiểu chuỗi và được sử dụng vào các mục đích khác nhau tùy người viết chương trình. 

## **GDB Test Drive**

![Untitled 5](https://user-images.githubusercontent.com/88520787/168029388-274cb749-50b6-4f09-a4a3-a01d63294b34.png)

Bài này ta chỉ cần dùng các câu lệnh có sẵn của đề, nhưng sau đây tôi sẽ kèm theo các lời giải thích

![Untitled 6](https://user-images.githubusercontent.com/88520787/168029421-5a59ed3f-cf1e-4690-aff5-44a215d99beb.png)

Tại đây, đối với những bạn chưa cài `gdb` và bị báo lỗi thì dùng lệnh`sudo apt-get install gdb` linux để cho máy tự cài gdb, sau đó chạy lại các lệnh trên.

> BTW, [pwndbg](https://github.com/pwndbg/pwndbg#:~:text=Pwndbg%20is%20a%20Python%20module,to%20fill%20some%20these%20gaps.) cũng là một tools quan trọng nếu bạn muốn chơi reverse tốt, sử dụng kết hợp cùng với IDA
> 

Dùng `layout asm` ta được màn hình như sau:

![Untitled 7](https://user-images.githubusercontent.com/88520787/168029460-1f7632b8-b94f-4757-8f32-3f497c7765f9.png)

`break *(main+99):` đặt breakpoint tại vị trí (`main` +99)

Sau khi dùng `run`: ta được màn hình như sau:

![Untitled 8](https://user-images.githubusercontent.com/88520787/168029494-0d26b0ce-dae4-475d-a6ca-7464e779aafe.png)

Tại đây, để bỏ qua lời gọi hàm `sleep` thì ta dùng `jump *(main+104)` để nhảy trực tiếp đến câu lệnh tiếp theo, từ đây, chương trình sẽ có thể in ra flag.

![Untitled 9](https://user-images.githubusercontent.com/88520787/168029522-fc033623-5294-44df-b8e1-0c5dcc48c351.png)

## patchme.py

![Untitled 10](https://user-images.githubusercontent.com/88520787/168029787-625b25ef-2dcf-4ccd-a2a2-f515bd040236.png)

Ở bài này ta tải 2 file về và đặt chung vào cùng 1 folder, và bạn cần cài thêm [python](http://python.org) phiên bản 3. trở lên

![Untitled 11](https://user-images.githubusercontent.com/88520787/168029816-49d8046b-c2a7-48ed-98ae-4409bfa89ab6.png)

Chạy file, ta thấy file kiểm tra password ta nhập vào, mở file bằng [VScode](https://code.visualstudio.com/):

![Untitled 12](https://user-images.githubusercontent.com/88520787/168029837-d31a03a3-df98-4eed-ad36-e00ccdd232af.png)

Ta không cần phải rev hàm str_xor, chương trình này khi ta nhập đúng `password` , flag sẽ tự động được giải mã và in ra màn hình.

Chương trình sẽ lấy input của chúng ta và so sánh với chuỗi khác:

![Untitled 13](https://user-images.githubusercontent.com/88520787/168029868-689e06a0-d1f8-4438-aee1-5132d5b00b53.png)

ta có password: `ak98-=90adfjhgj321sleuth9000`

Nhập password, ta được flag:

![Untitled 14](https://user-images.githubusercontent.com/88520787/168029897-86ce1665-03e3-46c6-b127-39cf44074994.png)

## Safe Opener

![Untitled 15](https://user-images.githubusercontent.com/88520787/168029922-8f1ef4a9-a4b1-44a8-989f-957b918d563a.png)

Tải file về ta thấy đó là 1 file java, nhưng trong bài này ta không cần phải chạy file

![Untitled 16](https://user-images.githubusercontent.com/88520787/168029944-ca2dedba-ad73-42cd-844f-0d34531ea757.png)

Đọc code ta thấy đề sẽ lấy `password` từ input của người dùng sau đó mã hóa và so sánh với chuỗi đã được mã hóa sẵn của chương trình.

Để ý ta sẽ thấy chương trình dùng base64 để encode

![Untitled 17](https://user-images.githubusercontent.com/88520787/168029994-3ac8aa39-5d14-442a-86e7-e0ad1a31e8ef.png)

Đồng nghĩa với ta sẽ có đoạn mã base64 của password:

![Untitled 18](https://user-images.githubusercontent.com/88520787/168030029-8c806226-8fed-4b7d-9868-0d2bff554508.png)

Decode base64 của đoạn này ta được password: 

![Untitled 19](https://user-images.githubusercontent.com/88520787/168030048-983835a2-7658-4a5a-ae07-df4840824099.png)

Flag: `picoCTF{pl3as3_l3t_m3_1nt0_th3_saf}`

## unpackme.py

![Untitled 20](https://user-images.githubusercontent.com/88520787/168030086-0d9a9dbb-24eb-4cfd-8abd-a7c9d91cc4c9.png)

![Untitled 21](https://user-images.githubusercontent.com/88520787/168030116-9867be62-c66a-4753-a8f4-e280d38f0114.png)

Mở file lên ta thấy chương trình dịch mã đoạn text dài trên và dùng hàm `exec()` để thực thi đoạn mã đó, thay vì thực thi, ta thử `print` nó ra:

![Untitled 22](https://user-images.githubusercontent.com/88520787/168030155-143eed9a-1d5c-4960-9245-3f9ec0552c9e.png)

Và thay vì chạy, ta có ngay flag của bài!

## bloat.py

![Untitled 23](https://user-images.githubusercontent.com/88520787/168030186-287bb97a-2832-49b0-a4b9-64b511963950.png)

Tải 2 file về đặt trong cùng 1 thư mục:

Mở file `[bloat.flag.py](http://bloat.flag.py)` ta được đoạn code đã bị [obfuscate](https://en.wikipedia.org/wiki/Obfuscation_(software))

```python
import sys
a = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"+ \
            "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ "
def arg133(arg432):
  if arg432 == a[71]+a[64]+a[79]+a[79]+a[88]+a[66]+a[71]+a[64]+a[77]+a[66]+a[68]:
    return True
  else:
    print(a[51]+a[71]+a[64]+a[83]+a[94]+a[79]+a[64]+a[82]+a[82]+a[86]+a[78]+\
a[81]+a[67]+a[94]+a[72]+a[82]+a[94]+a[72]+a[77]+a[66]+a[78]+a[81]+\
a[81]+a[68]+a[66]+a[83])
    sys.exit(0)
    return False
def arg111(arg444):
  return arg122(arg444.decode(), a[81]+a[64]+a[79]+a[82]+a[66]+a[64]+a[75]+\
a[75]+a[72]+a[78]+a[77])
def arg232():
  return input(a[47]+a[75]+a[68]+a[64]+a[82]+a[68]+a[94]+a[68]+a[77]+a[83]+\
a[68]+a[81]+a[94]+a[66]+a[78]+a[81]+a[81]+a[68]+a[66]+a[83]+\
a[94]+a[79]+a[64]+a[82]+a[82]+a[86]+a[78]+a[81]+a[67]+a[94]+\
a[69]+a[78]+a[81]+a[94]+a[69]+a[75]+a[64]+a[70]+a[25]+a[94])
def arg132():
  return open('flag.txt.enc', 'rb').read()
def arg112():
  print(a[54]+a[68]+a[75]+a[66]+a[78]+a[76]+a[68]+a[94]+a[65]+a[64]+a[66]+\
a[74]+a[13]+a[13]+a[13]+a[94]+a[88]+a[78]+a[84]+a[81]+a[94]+a[69]+\
a[75]+a[64]+a[70]+a[11]+a[94]+a[84]+a[82]+a[68]+a[81]+a[25])
def arg122(arg432, s):
    arg433 = arg423
    i = 0
    while len(arg433) < len(arg432):
        arg433 = arg433 + arg423[i]
        i = (i + 1) % len(arg423)        
    return "".join([chr(ord(arg422) ^ ord(arg442)) for (arg422,arg442) in zip(arg432,arg433)])
arg444 = arg132()
arg432 = arg232()
arg133(arg432)
arg112()
arg423 = arg111(arg444)
print(arg423)
sys.exit(0)
```

Quan sát ta thấy có 1 hàm dùng để kiểm tra 2 chuỗi có bằng nhau hay không, ta tạm đặt tên hàm là check:

![Untitled 24](https://user-images.githubusercontent.com/88520787/168030218-f7ce1874-4a1f-409a-9b31-7ac236f4d1df.png)

`print` chuỗi đó ra, ta được: `happychance`

![Untitled 25](https://user-images.githubusercontent.com/88520787/168030247-8a7ed01a-7a32-4ee0-a984-cf04adeeb261.png)

Nhập password vào chương trình, ta được flag:

![Untitled 26](https://user-images.githubusercontent.com/88520787/168030264-7bd58267-4ae7-4329-83da-dead21db2086.png)

## **Fresh Java**

![Untitled 27](https://user-images.githubusercontent.com/88520787/168030294-66b52661-b99d-47ca-a948-ee1dda05ae83.png)

Đề sẽ cho mình một file `.class`, chúng ta có thể dùng tool để phân tích thành file `.java`

hoặc dùng [Java Decompier Online](http://www.javadecompilers.com/) này.

Ta có file `.java` như sau:

```java
import java.util.Scanner;

// 
// Decompiled by Procyon v0.5.36
// 

public class KeygenMe
{
    public static void main(final String[] array) {
        final Scanner scanner = new Scanner(System.in);
        System.out.println("Enter key:");
        final String nextLine = scanner.nextLine();
        if (nextLine.length() != 34) {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(33) != '}') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(32) != '7') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(31) != '0') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(30) != '6') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(29) != '5') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(28) != '7') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(27) != '4') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(26) != '2') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(25) != 'c') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(24) != '_') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(23) != 'd') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(22) != '3') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(21) != 'r') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(20) != '1') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(19) != 'u') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(18) != 'q') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(17) != '3') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(16) != 'r') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(15) != '_') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(14) != 'g') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(13) != 'n') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(12) != '1') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(11) != 'l') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(10) != '0') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(9) != '0') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(8) != '7') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(7) != '{') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(6) != 'F') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(5) != 'T') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(4) != 'C') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(3) != 'o') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(2) != 'c') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(1) != 'i') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(0) != 'p') {
            System.out.println("Invalid key");
            return;
        }
        System.out.println("Valid key");
    }
}
```

Tại đây, ta sẽ dễ dàng nhìn thấy các kí tự của flag, Sắp xếp các kí tự theo index từ 0→33 ta được flag cần tìm.

## Bbbbloat

![Untitled 28](https://user-images.githubusercontent.com/88520787/168030356-b55bd50e-8953-4566-8e79-d6de649f15b8.png)

![Untitled 29](https://user-images.githubusercontent.com/88520787/168030395-3a3400a8-41b5-443e-bc61-dbff914742a8.png)

Kiểm tra file bằng Detect it Easy, ta biết được đây là file ELF64, mở file bằng IDA64bit:

![Untitled 30](https://user-images.githubusercontent.com/88520787/168030417-bb3f38ac-999b-417d-a697-65458c2965cf.png)

Chọn hàm main và bấm `F5` ta được đoạn code C như trên;

Phân tích code ta thấy chương trình bắt ta nhập vào 1 con số, nếu đúng với số của chương trình thì sẽ trả về flag, ta dễ dàng thấy con số đó cũng chính là `549255`

Chạy file và nhập `549255` ta được flag:

![Untitled 31](https://user-images.githubusercontent.com/88520787/168030457-4f7091c7-b9ff-49b7-8477-22318fadf70d.png)

## unpackme

![Untitled 32](https://user-images.githubusercontent.com/88520787/168030479-1ec0a026-1363-47f4-9a34-956898c5df5e.png)

Mở file bằng Detect it Easy:

![Untitled 33](https://user-images.githubusercontent.com/88520787/168030502-16ba62d1-3ad6-4a8f-9f5f-598607c0644e.png)

Ta thấy vẫn là file ELF64 và bị pack bởi UPX 3.95

UPX: một chương trình được sử dụng để nén các tệp thực thi, chứa một tệp thực thi được đóng gói.

Để unpack file này, ta dùng [UPX](https://github.com/upx/upx/releases/tag/v3.96) (tải và giải nén):

![Untitled 34](https://user-images.githubusercontent.com/88520787/168030528-0aac90fe-8ccc-48dd-bd33-52ac5b1c983e.png)

copy file `unpackme-upx` và để chung thư mục với upx, mở cmd tại folder đó lên:

dùng câu lệnh: `upx.exe -d unpackme-upx`

![Untitled 35](https://user-images.githubusercontent.com/88520787/168030565-1f65f09a-a895-4555-96ff-3f728aebc315.png)

ta được file mới đã unpack, mở file này bằng IDA64:

![Untitled 36](https://user-images.githubusercontent.com/88520787/168030591-837a67f1-e5b4-4058-a121-6238eeee85f9.png)

Tương tự với bài trước ta tìm thấy con số cần nhập là `754653`:

Chạy chương trình và nhập số vào ta được flag

![Untitled 37](https://user-images.githubusercontent.com/88520787/168030850-54b583e7-a9c3-40b1-bbd5-bd670f8b9d8d.png)

## **Keygenme**

![Untitled 38](https://user-images.githubusercontent.com/88520787/168030873-e1d25493-d592-49e6-abbd-582806e442e0.png)

Xem thông tin file bằng Detect it Easy:

![Untitled 39](https://user-images.githubusercontent.com/88520787/168030900-02d5605d-b374-449e-a0d5-bd2a94ea8368.png)

Mở file bằng IDA64, ta có hàm main:

![Untitled 40](https://user-images.githubusercontent.com/88520787/168030923-d26f50f4-17e2-4a5b-9e3a-5758da31128f.png)

và ta thấy hàm kiểm tra cũng chưa thấy gì:

![Untitled 41](https://user-images.githubusercontent.com/88520787/168030945-fe153bb6-192b-4e26-9f45-edca73f2a450.png)

Đặt breakpoint tại lệnh `if` và thử debug bằng Remote Linux debuger:

- Vào thư mục `dbgsrv` trong folder chứa IDA, tìm file `linux_server64` và đưa vào máy ảo
- trên máy ảo: dùng lệnh `ifconfig` ,copy ip tìm được
- Chạy file `linux_server64` trên linux
- tại IDA, chọn Debugger→Process Option: paste ip tìm được vào ô Hostname, bấm `Ok, use found`.

![Untitled 42](https://user-images.githubusercontent.com/88520787/168030968-22500ce0-e41a-41b9-8cc9-855cc15ec618.png)

Kết quả là file đang được debug, nhập key rác bất kì

  
![Untitled 43](https://user-images.githubusercontent.com/88520787/168030994-5afffbaf-8379-45c7-97ac-ded02a66e14e.png)


Khi chương trình chạy đến dòng lệnh `if` ta bấm F7 để step into (vào bên trong hàm) `sub_5621D0987208()`

![Untitled 44](https://user-images.githubusercontent.com/88520787/168031029-477a3593-41b8-40ba-9347-0c7b38bc167e.png)

ta sẽ thấy xuất hiện nhiều lệnh `mov` và lệnh `lea` 2 lệnh này 

Khi chạy hết các lệnh cho đến lệnh `jump` thì ta dừng lại để kiểm tra, lúc này trên stack ta xem thanh ghi `rax` thì ta thấy 1 phần của flag:

![Untitled 45](https://user-images.githubusercontent.com/88520787/168031071-e8587d7b-8f79-47b8-b56a-1b7aea0b2cdb.png)

Khi decompile được hàm trên, ta được đoạn code C như sau:

![Untitled 46](https://user-images.githubusercontent.com/88520787/168031102-fb233e09-dcfe-419e-ac5e-14f784f01839.png)

ta sẽ thấy tại đây khúc cuối có 1 loạt phép gán được thực hiện, kiểm tra phần giá trị gán thì ta thấy đó là những kí tự cuối cùng của flag

Chạy hết đoạn này và ta xem giá trị của`v17`, và nó cũng chứa flag:

![Untitled 47](https://user-images.githubusercontent.com/88520787/168031122-61aa105a-5bb1-4f2a-927c-83c88b62863a.png)

## Wizardlike

![Untitled 48](https://user-images.githubusercontent.com/88520787/168031149-5c928715-d125-426c-8313-aaa03c54447c.png)

Chạy file, ta được 1 trò chơi như sau:

![Untitled 49](https://user-images.githubusercontent.com/88520787/168031185-8ae26fb3-de9c-46f6-a38e-b802c9eaa7e5.png)

![Untitled 50](https://user-images.githubusercontent.com/88520787/168031190-bb6cf1c6-7d71-492f-9e5c-e6913db08302.png)

Khi nhân vật di chuyển đến `>` sẽ qua màn chơi tiếp theo, `<` sẽ quay lại màn chơi phía trước

Tuy nhiên tại màn chơi thứ 4, ta không tiếp cận đươc `>`

![Untitled 51](https://user-images.githubusercontent.com/88520787/168031220-501e3239-f212-4bbf-9e39-580f442314c6.png)

Mình thử kiểm tra file thì vẫn là ELF64 và không bị pack, đưa vào IDA64 ta được đoạn code như sau:

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int v3; // eax
  int v4; // eax
  WINDOW *v5; // rdi
  __int64 v6; // rdx
  __int64 v7; // rdx
  __int64 v8; // rdx
  __int64 v9; // rdx
  __int64 v10; // rdx
  __int64 v11; // rdx
  __int64 v12; // rdx
  __int64 v13; // rdx
  __int64 v14; // rdx
  __int64 v15; // rdx
  char v17; // [rsp+16h] [rbp-2Ah]
  char v18; // [rsp+17h] [rbp-29h]
  int i; // [rsp+18h] [rbp-28h]
  int j; // [rsp+1Ch] [rbp-24h]
  int k; // [rsp+20h] [rbp-20h]
  int m; // [rsp+24h] [rbp-1Ch]
  int v23; // [rsp+28h] [rbp-18h]
  int v24; // [rsp+2Ch] [rbp-14h]
  int v25; // [rsp+30h] [rbp-10h]
  char v26[2]; // [rsp+36h] [rbp-Ah] BYREF
  unsigned __int64 v27; // [rsp+38h] [rbp-8h]

  v27 = __readfsqword(0x28u);
  v17 = 1;
  sub_1291(asc_7740, a2, a3);
  ((void (__fastcall *)(char *))((char *)&sub_1228 + 1))(asc_7740);
  initscr();
  if ( stdscr )
    v3 = stdscr->_maxy + 1;
  else
    v3 = -1;
  v23 = v3;
  if ( stdscr )
    v4 = stdscr->_maxx + 1;
  else
    v4 = -1;
  v24 = v4;
  dword_1FE98 = v4;
  dword_1FE9C = v23;
  noecho();
  v5 = 0LL;
  curs_set(0);
  while ( v17 )
  {
    if ( dword_1FE78 != tele )
    {
      switch ( tele )
      {
        case 1:
          ((void (__fastcall *)(WINDOW *))((char *)&sub_1228 + 1))(v5);
          sub_1291(asc_7740, a2, v6);
          dword_1FE70 = 2;
          dword_1FE74 = 1;
          dword_1FE90 = 0;
          dword_1FE94 = 0;
          dword_1FE78 = 1;
          break;
        case 2:
          ((void (__fastcall *)(WINDOW *))((char *)&sub_1228 + 1))(v5);
          sub_1291(asc_9E60, a2, v7);
          dword_1FE70 = 1;
          dword_1FE74 = 2;
          dword_1FE90 = 0;
          dword_1FE94 = 0;
          dword_1FE78 = 2;
          break;
        case 3:
          ((void (__fastcall *)(WINDOW *))((char *)&sub_1228 + 1))(v5);
          sub_1291(asc_C580, a2, v8);
          dword_1FE70 = 2;
          dword_1FE74 = 1;
          dword_1FE90 = 0;
          dword_1FE94 = 0;
          dword_1FE78 = 3;
          break;
        case 4:
          ((void (__fastcall *)(WINDOW *))((char *)&sub_1228 + 1))(v5);
          sub_1291(asc_ECA0, a2, v9);
          dword_1FE70 = 2;
          dword_1FE74 = 1;
          dword_1FE90 = 0;
          dword_1FE94 = 0;
          dword_1FE78 = 4;
          break;
        case 5:
          ((void (__fastcall *)(WINDOW *))((char *)&sub_1228 + 1))(v5);
          sub_1291(asc_113C0, a2, v10);
          dword_1FE70 = 2;
          dword_1FE74 = 1;
          dword_1FE90 = 0;
          dword_1FE94 = 0;
          dword_1FE78 = 5;
          break;
        case 6:
          ((void (__fastcall *)(WINDOW *))((char *)&sub_1228 + 1))(v5);
          sub_1291(asc_13AE0, a2, v11);
          dword_1FE70 = 2;
          dword_1FE74 = 1;
          dword_1FE90 = 0;
          dword_1FE94 = 0;
          dword_1FE78 = 6;
          break;
        case 7:
          ((void (__fastcall *)(WINDOW *))((char *)&sub_1228 + 1))(v5);
          sub_1291(asc_16200, a2, v12);
          dword_1FE70 = 2;
          dword_1FE74 = 1;
          dword_1FE90 = 0;
          dword_1FE94 = 0;
          dword_1FE78 = 7;
          break;
        case 8:
          ((void (__fastcall *)(WINDOW *))((char *)&sub_1228 + 1))(v5);
          sub_1291(asc_18920, a2, v13);
          dword_1FE70 = 1;
          dword_1FE74 = 2;
          dword_1FE90 = 0;
          dword_1FE94 = 0;
          dword_1FE78 = 8;
          break;
        case 9:
          ((void (__fastcall *)(WINDOW *))((char *)&sub_1228 + 1))(v5);
          sub_1291(asc_1B040, a2, v14);
          dword_1FE70 = 2;
          dword_1FE74 = 1;
          dword_1FE90 = 0;
          dword_1FE94 = 0;
          dword_1FE78 = 9;
          break;
        case 10:
          ((void (__fastcall *)(WINDOW *))((char *)&sub_1228 + 1))(v5);
          sub_1291(&unk_1D760, a2, v15);
          dword_1FE70 = 1;
          dword_1FE74 = 1;
          dword_1FE90 = 0;
          dword_1FE94 = 0;
          dword_1FE78 = 10;
          break;
      }
    }
    for ( i = 0; i < v23; ++i )
    {
      for ( j = 0; j < v24; ++j )
        mvprintw(i, j, (const char *)&off_3000 + 4);
    }
    for ( k = 0; k < v23; ++k )
    {
      for ( m = 0; m < v24; ++m )
      {
        if ( dword_1FE90 + m > 99 || dword_1FE94 + k > 99 || dword_1FE90 + m < 0 || dword_1FE94 + k < 0 )
        {
          mvprintw(k, m, (const char *)&off_3000 + 4);
        }
        else if ( (unsigned __int8)sub_1332(
                                     (unsigned int)dword_1FE70,
                                     (unsigned int)dword_1FE74,
                                     (unsigned int)(m + dword_1FE90),
                                     (unsigned int)(dword_1FE94 + k))
               || byte_225C0[100 * dword_1FE94 + 100 * k + dword_1FE90 + m] )
        {
          byte_225C0[100 * dword_1FE94 + 100 * k + dword_1FE90 + m] = 1;
          *(_WORD *)v26 = 0;
          v26[0] = byte_1FEA0[100 * dword_1FE94 + 100 * k + dword_1FE90 + m];
          mvprintw(k, m, v26);
        }
      }
    }
    a2 = (char **)(unsigned int)(dword_1FE70 - dword_1FE90);
    mvprintw(dword_1FE74 - dword_1FE94, (int)a2, (const char *)&off_3000 + 6);
    wrefresh(stdscr);
    v5 = stdscr;
    v25 = wgetch(stdscr);
    switch ( v25 )
    {
      case 'Q':
        v17 = 0;
        break;
      case 'w':
        up(v5);
        break;
      case 's':
        down(v5);
        break;
      case 'a':
        left(v5);
        break;
      case 'd':
        right(v5);
        break;
    }
    v18 = byte_1FEA0[100 * dword_1FE74 + dword_1FE70];
    if ( v18 == '>' )
    {
      ++tele;
    }
    else if ( v18 == 60 )
    {
      --tele;
    }
  }
  endwin();
  return 0LL;
}
```

Bài này sử dụng `switch case` để di chuyển giữa các màn chơi, `case 1→10` tương ứng với 10 màn chơi, khi nhân vật gặp `>` thì biến `tele` tăng lên để di chuyển đến màn tiếp theo.

```c
switch ( v25 )
    {
      case 'Q':
        v17 = 0;
        break;
      case 'w':
        up(v5);
        break;
      case 's':
        down(v5);
        break;
      case 'a':
        left(v5);
        break;
      case 'd':
        right(v5);
        break;
    }
```

switch còn được sử dụng để gọi các hàm di chuyển cho nhân vật, ta xem thử hàm `up()`:

```c
__int64 up()
{
  __int64 result; // rax

  result = check((unsigned int)dword_1FE70, (unsigned int)(dword_1FE74 - 1));
  if ( (_BYTE)result )
  {
    if ( dword_1FE74 > dword_1FE9C / 2 && dword_1FE74 <= dword_1FE9C / -2 + 100 )
      --dword_1FE94;
    return (unsigned int)--dword_1FE74;
  }
  return result;
}
```

Trong hàm `up,down,...` còn có 1 hàm giống nhau là `check` :

```c
_BOOL8 __fastcall check(int a1, int a2)
{
  if ( a1 > 99 || a2 > 99 || a1 < 0 || a2 < 0 )
    return 0LL;
  return byte_1FEA0[100 * a2 + a1] != '#' && byte_1FEA0[100 * a2 + a1] != ' ';
}
```

Hàm này kiểm tra rằng bước tiếp theo có phải là `" "` hay là `"#"` không, nếu không thì sẽ thực hiện di chuyển, ngược lại thì không

Việc của mình bây giờ đơn giản chỉ cần vô hiệu hóa đoạn kiểm tra này để cho nhân vật có để đến mọi nơi trong game.

Có nhiều cách tiếp cận bài này, có thể chỉnh sửa byte trực tiếp bằng IDA:

![Untitled 52](https://user-images.githubusercontent.com/88520787/168031289-55ad12c0-524b-4418-917f-1e7f32f321fb.png)

Xem hàm `up` dưới dạng asm, ta để ý lệnh `jz` (jump if zero) sẽ là đoạn kiểm tra của `if` trong code C, ta có thể bỏ qua lệnh bằng cách: chọn vào lệnh cần chỉnh sửa, vào Edit→Patch Program→Assemble

![Untitled 53](https://user-images.githubusercontent.com/88520787/168031316-d13bea85-43d5-48ec-a544-a347fc054e27.png)
![Untitled 54](https://user-images.githubusercontent.com/88520787/168031329-917a4be8-b7a4-4ae0-af78-83c525871c90.png)

chỉnh sửa `Instruction` thành `nop`. Sau đó vào Edit→Patch Program→ Apply patches to input file để lưu thay đổi này vào file gốc.

Làm tương tự với các hàm `left(),right(),...` 

Ngoài ra, các bạn còn có thể làm bằng cách sử dụng plugin [keypatch](https://github.com/keystone-engine/keypatch) (lưu ý kĩ cách cài đặt để cài đặt thành công) để chỉnh sửa các lệnh một cách dễ dàng hơn, ví dụ:

Chọn 1 dòng code C cần thay đổi, bấm tổ hợp `Ctrl + Alt + K`, cửa sổ hiện lên:

![Untitled 55](https://user-images.githubusercontent.com/88520787/168031356-829917fb-f55a-4d14-8608-ad37e2fdd69c.png)

thay đổi thành `nop` và dùng `Apply patches to input file` để lưu file lại.

Và đây là thành quả sau khi chạy file.

![Untitled 56](https://user-images.githubusercontent.com/88520787/168031385-5b92932d-6474-401c-b272-62708c029af1.png)

10 Màn chơi sẽ chứa các kí tự của flag theo thứ tự nhé. Chúc bạn thành công!

## Cảm ơn các bạn đã xem!