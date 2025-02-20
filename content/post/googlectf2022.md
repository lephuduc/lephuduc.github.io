---
title: "Google CTF 2022"
description: "Writeup for Google CTF 2022"
summary: "Writeup for Google CTF 2022"
categories: ["Writeup"]
tags: ["Reverse","Vietnamese"]
#externalUrl: ""
date: 2022-06-29
draft: false
authors:
  - Jinn
cover: /images/post_covers/googlectf2022.jpeg
---

## JS SAFE 4.0 
![](https://i.imgur.com/HhKIUby.png)

Tuy nhiên khi mở file chạy và mở devtools thì nó không hiện gì (f5 là lag luôn):

![](https://i.imgur.com/jCyShIZ.png)

### Code and overview:

![](https://i.imgur.com/I6F9D7k.png)

Ban đầu mình bị thu hút bởi đoạn code này:

```javascript=

var code = `\x60
  console.log({flag}); 
  for (i=0; i<100; i++) setTimeout('debugger');
  if ("\x24\x7B\x22   .?  K 7 hA  [Cdml<U}9P  @dBpM) -$A%!X5[ '% U(!_ (]c 4zp$RpUi(mv!u4!D%i%6!D'Af$Iu8HuCP>qH.*(Nex.)X&{I'$ ~Y0mDPL1 U08<2G{ ~ _:h\ys! K A( f.'0 p!s    fD] (  H  E < 9Gf.' XH,V1 P * -P\x22\x7D" != ("\x24\x7B\x22" + checksum(code) + "\x22\x7D")) while(1);
  flag = flag.split('');
  i‍ = 1337;
  pool = 'c_3L9zKw_l1HusWN_b_U0c3d5_1'.split('');
  while (pool.length > 0) if(flag.shift() != pool.splice((i = (i || 1) * 16807 % 2147483647)%pool.length, 1)[0]) return false;
  return true;
\x60`;
setTimeout("x = Function('flag', " + code + ")");  
```
Và mấy cái comment kiểu vầy:

```
WARNING: Do NOT modify your HTML once downloaded. Otherwise, it'll stop working
(it'll not accept the correct password) and might compromise your stored data.
-->
...
// TODO: Whole document integrity check: if (document.documentElement.outerHTML.length == 23082) //...
// TODO: Utility function for detecting the opening of DevTools, https://stackoverflow.com/q/7798748
// TODO: Create wrapper function to support async/await for setTimeout
//       E.g. something like https://stackoverflow.com/q/33289726
// TODO: Checksum check for the utility funcitons themselves, e.g. (checksum(' ' + checksum)) == '...'
```

## First approach


Sau đó mình trace ra và rev hàm `open_safe()` trước:

Thì `keyhold.value` là giá trị từ hộp thoại mình nhập vào, sau đó được check regex:

Nói chung là sau khi tìm hiểu thì đoạn regex này sẽ lấy password = "CTF{...}" và password[1] sẽ là content bên trong {}, sau đó nó sẽ được đưa vào x để xử lí.

Tới đây, mình đã thư copy hàm `x()` sang file mới và run thử:

```javascript=
  function x(){ 
    i = 1337;
    pool = 'c_3L9zKw_l1HusWN_b_U0c3d5_1'.split('');
    while (pool.length > 0) 
        process.stdout.write(pool.splice((i = (i || 1) * 16807 % 2147483647)%pool.length, 1)[0]);
}
x(); //01Kb3W_5l__9LUzNcH3cu1dw_s_
```
`01Kb3W_5l__9LUzNcH3cu1dw_s_`

Nhìn có vẻ không giống password lắm nhưng mình từng nghĩ là nó đúng, tuy nhiên:

![](https://i.imgur.com/aqgYFVF.png)

Mình có thắc mắc là chương trình này dùng `splice()` built-in hay là của code chương trình nên mình thử copy `splice()` của qua file khác chạy và kết quả cũng tương tự.  

Mình ban đầu thử xóa `ChecksumError()` và mấy hàm lạ lạ ở phía dưới, xong thử viết lại code và debug trên browser:

![](https://i.imgur.com/3XFTNlA.png)

![](https://i.imgur.com/7UNUgB2.png)

Lần này kết quả có vẻ khác nhưng nó cũng không phải là flag.

Vậy là các hàm `checksum(),...` có ảnh hưởng đến đoạn `x()` này và hơn nữa là code của đoạn hàm `x()` sẽ không được sửa vì sửa sẽ ảnh hưởng đến kết quả

Sau khi hỏi anh `Mochi` thì mình mới biết là chỉ có dòng này là antidebug, và mình đã tìm hiểu thử:



```javascript=
Object.defineProperty(Object.prototype, 'splice', {get:splice});
```
> Nó sẽ phát hiện devtools có đang mở hay không bằng gợi ý trong comment này:
>
>`// TODO: Utility function for detecting the opening of DevTools, https://stackoverflow.com/q/7798748`
>
> Và nó sẽ phát hiện và gọi getter liên tục tạo thành vòng lặp vô tận khiến browser bị đơ không debug được



Mình đã thử download file mới và xóa mỗi dòng này thì debug được:

Thử đặt breakpoint và trace tới đoạn so sánh:

![](https://i.imgur.com/fodvvZR.png)

Ban đầu mình bị stuck và không biết làm sao để lấy giá trị đoạn code phía sau, mình thử tìm kiếm check funtion retrun value,... nhưng không được. Sau một khoảng thời gian lâu, mình đưa chuột vào để kiểm tra cái khúc này thì mình thấy có chữ cái hiện lên, mình thử vài lần thì nó là một chuỗi có nghĩa:

![](https://i.imgur.com/wN1IQ6z.png)

Thì ra là mình có thể debug bằng cách này, lần tiếp theo sẽ là kí tự tiếp theo, sau 1 hồi thì mình thu được đoạn này:

`W0w_5ucH_N1c3_d3bU9_sK1lLz_`

Được đoạn này nhưng lúc mình nhập vào file gốc thì vẫn bị **`Access Denied`**

## Second approach

Và tới đây mình thấy đoạn mâu thuẫn nếu mà file chỉ có đoạn check là hàm `x()` mà hàm này chỉ check đoạn đầu, vậy thì còn đoạn check ở phía sau đâu?

Mình luôn nghĩ là điều gì đó có đoạn checksum ảnh hưởng tới chổ checkflag nhưng vẫn không biết nó là gì:

![](https://i.imgur.com/89Im5kr.png)

Quay lại đoạn comment ở trên, vẫn còn vài chổ mình chưa khai thác:

```
// TODO: Whole document integrity check: if (document.documentElement.outerHTML.length == 23082) //...
// TODO: Create wrapper function to support async/await for setTimeout
//       E.g. something like https://stackoverflow.com/q/33289726
// TODO: Checksum check for the utility funcitons themselves, e.g. (checksum(' ' + checksum)) == '...'
```
Đầu tiên là file cần check length và bài này yêu cầu mình làm một cái hàm hỗ trợ async/await cho `setTimeout` và checksum cho chính bản thân nó

Đầu tiên mình giữ nguyên length file (sau này mình mới biết là nó không ảnh hưởng lắm), mình không làm hàm settime out mà dùng thẳng `(checksum(' ' + checksum)) == '...'` luôn:

Mình thử sửa từ đoạn này:

`console.log("checksum test", checksum(checksum + ' '));` 

thành đoạn này: 

`console.log("checksum test", checksum(' ' + checksum));` 

Và đây là kết quả:

![](https://i.imgur.com/4bZXq8Z.png)


```javascript=
checksum test pA: Object.defineProperty(document.body, 'className', {
    get() {
        return this.getAttribute('class') || ''
    },
    set(x) {
        this.setAttribute('class', (x != 'granted' || (/^CTF{([0-9a-zA-Z_@!?-]+)}$/.exec(keyhole.value) || x)[1].endsWith('Br0w53R_Bu9s_C4Nt_s70p_Y0u')) ? x : 'denied')
    }
}) //
```
Đoạn hidden code này chính là những gì mình nhìn thấy khi mà checksum checksum chính bản thân nó, nó sẽ làm hiện lên những kí tự không nhìn thấy trong VScode:

![](https://i.imgur.com/M4B3Epm.png)

Có thể thấy đoạn checkflag ở khúc cuối bằng `endsWith()` và tổng hợp lại mình có được flag.

Flag: `CTF{W0w_5ucH_N1c3_d3bU9_sK1lLz_Br0w53R_Bu9s_C4Nt_s70p_Y0u}`