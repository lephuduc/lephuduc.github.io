---
title: "Hack.lu CTF 2022"
description: "Writeup for Hack.lu CTF 2022"
summary: "Writeup for Hack.lu CTF 2022"
categories: ["Writeup"]
tags: ["Reverse","Vietnamese"]
#externalUrl: ""
date: 2022-10-28
draft: false
authors:
  - Jinn
cover: /images/post_covers/hackluctf2022-ori.jpeg
---

## FingerFood - rev

#### Description

> Reversing Finger Food with a twist.

#### Attachment file
[Download challenge files](https://flu.xxx/static/chall/FingerFood_f46ffce06df8d82671be57300485a83e.zip)

### Overview
![](https://i.imgur.com/TQkQroL.png)

Thử chạy file và không có thông tin gì, tiến hành dùng IDA để phân tích

![](https://i.imgur.com/MvfriMB.png)

Bài này về cơ bản hướng giải cũng nhiều và cũng khá là dễ

![](https://i.imgur.com/bVLwdOo.png)

Đối với các bài không có pdb nên nhiều hàm không rõ tên, việc để tìm hàm main là tìm hàm `start` hoặc là dùng shortcut `Ctrl + E` để đi tới entry point:

![](https://i.imgur.com/EGwZSWT.png)

![](https://i.imgur.com/ZHDBHss.png)

### Approach

Đập vào mắt mình là một dãy các số khởi tạo `v10` và vòng lặp dùng để so sánh `v3`
```if ( v3 != (unsigned __int8)sub_405080(v10, v6) ```

Nên tới đây mình đoán luôn, `v10` có thể là flag encrypted vậy `sub_405080(v10, v6)` có thể là hàm decrypt `v10` (kí tự của flag) trước khi dùng so sánh với `v3`, tạm thời bỏ qua các hàm khác, vì nó không ảnh hướng nhiều tới `v10`

Xem sơ qua `sub_405080()` thì mình thấy cũng không rắc rối lắm, mình đã comment trong code về tất cả những gì nó làm
```c
__int64 __fastcall sub_405080(__int64 a1, unsigned int a2)
{
  char v3; // [rsp+Ch] [rbp-24h]

  *(_DWORD *)qword_5CE518 = 0x90909090;
  if ( a2 < 0x27uLL )
  {
    v3 = *(_BYTE *)sub_405100(a1, a2);
    return (unsigned __int8)(v3 - *(_BYTE *)sub_405100(a1 + 39, a2));
     //return a1[a2] - a1[a2+39];
  }
  else
  {
    return 0;
  }
}
```
### Solve
Để decrypt mình chỉ cần viết 1 scipt nhỏ như sau:

```python
v10 = b'\n\x9b\xf7\xff\xbbz\x89\xbc\xb3g\x18\xaed@h\xd8\x89\x06\x91y\x91]\x80\xa1\x13V\xc4F\xf5\x84mb\xc6(\x93\x1f\xfc\xe9\xd6\xa4/\x96\x98@DR\x85~/\xe5}3\xdf\x06uQ\xd1+A-\xfcJ;\xae \x8d\x11\x93N;-`\xc31\xb9\xcal\xcc\x00\x00'
for i in range(40):
    print(chr((v10[i]-v10[i+39])&0xff),end = "")
#flag{67758311abc85f8da6fe675b625febf2}
```

Flag: `flag{67758311abc85f8da6fe675b625febf2}`

### Update:

![](https://i.imgur.com/K2Dfr6Z.png)

Để lấy được các bytes của v10 thì chúng ta chỉ cần đặt breakpoint sau khi hoàn tất mảng `v10`:

![](https://i.imgur.com/dioKJpK.png)

Sau đó dùng `get_bytes(<v10 address>,80)` để lấy các bytes ra

Ngoài ra trong lúc mình debug tới hàm decrypt thì ngay tại chổ này nó sẽ có SIGNAL

![](https://i.imgur.com/xkiDU6w.png)

Nhưng đối với cách làm của mình thì chỉ cần patch chổ này thành nop là xong

![](https://i.imgur.com/T3FUSOg.png)


> Hơi đáng tiếc là giải này còn có 2 bài rev khác mình có khả năng solve nhưng lại chưa solve được, do mình mải mê tập trung vào bài `LeakyOrders` mà quên mất là còn `Cocktail Bar` release sau và dễ hơn, lúc làm thì cũng đã muộn rồi. Bù lại mình được học thêm nhiều thứ mới khá hữu ích, mong rằng những giải khác sẽ cải thiện hơn :VV

---

## Pazzzi - misc

#### Description

> I would like to order Hawaiian pizza at my favourite pizza shop again. But the owner changed the website after my last order and now I am unable to order it. But I really want one more. Can you make it happen for me?

#### Attachment files

> [Pazzzi Shop](https://pazzzi.flu.xxx/pizzarestaurant.lp)
> [Download challenge files](https://flu.xxx/static/chall/pazzzi_722669956884f35cbb152a6bee911c22.zip)

### Overview
Bài này có lẽ hơi thiên về web nhiều hơn

![](https://i.imgur.com/kOW1wfS.png)

Mở source html lên thì mình cũng không thấy gì quan trọng, chỉ có đoạn js và mục đích chính của nó là làm cho mình chỉ chọn được 1 trong 2 "Ham" hoặc "Pineapple"

```javascript
ham.addEventListener('click', function() {
            document.getElementById("pineapple").checked = false;
});
pineapple.addEventListener('click', function() {
            document.getElementById("ham").checked = false;
});
```

Sau khi `submit` thì nó sẽ đưa mình tới file `handle_pizzarestaurant.lua`, có lẽ đây là source cần phân tích đầu tiên của chương trình

![](https://i.imgur.com/9vVrorz.png)

Hoặc sau khi thử xoá endpoint và click thẳng vào `handle_pizzarestaurant.lua` thì chúng ta sẽ được `bad request`.

![](https://i.imgur.com/sHu6PN7.png)

Tới đây có thể hình dung được thứ mà mình kiểm soát chính là request nên là trong bài này mình sẽ dùng `burpsuit`

### Approach

Phân tích file `public\pizzza_webroot\handle_pizzarestaurant.lua` sẽ thấy ngoài các parameter như `mushroom,...` thì lúc gửi đi thì `userIsDangerous` cũng được gửi theo.

```lua
local convert_str_to_bool = function()
    if all_the_data["userIsDangerous"] then
        return true
    elseif all_the_data["userIsDangerous"] == 'false' then
        return false
    end
end
userIsDangerous = convert_str_to_bool(all_the_data["userIsDangerous"])

local doAdminStuff = function()
    --Note: we have not been using this for a long time, so better disable it
    --assert if we are admin, then exit for safety reasons
    if userIsDangerous == false then
        mg.write('admin is currently disabled' .. '\n')
        return
    end
    --Now we are admin
    -- mg.write('hello Admin' .. '\n')

    -- In order to speed up the processing of the order significantly, we process the order
    -- in our custom-crafted library written in C
    mg.process_order(
        setContains(all_the_data, "check_mushroom"),
        setContains(all_the_data, "check_pepperoni"),
        setContains(all_the_data, "check_olives"),
        setContains(all_the_data, "check_garlic"),
        setContains(all_the_data, "check_ham"),
        setContains(all_the_data, "check_pineapple"),
        all_the_data["comment"]
    )
end

-- only allow if user is safe
if not(userIsDangerous) then
    doAdminStuff()
else
    mg.write('Sorry, but this action is not allowed for ordinary users.' .. '\n')
end
```
Mình thử mở burpsuit và chỉnh request

![Uploading file..._rjkmh4o4l]()

Mặc định value của `userIsDangerous` sẽ là true, mình thử chỉnh thành false nhưng kết quả vẫn tương tự

![](https://i.imgur.com/TCHKYCv.png)

Tới đây thì để bypass được chổ này thì mình chỉ cần gửi request nhưng không kèm theo `userIsDangerous`

Và đây là kết quả:

![](https://i.imgur.com/64BZV8F.png)

Tạm thời thì mình đã có thể send request một cách bình thường. Tuy nhiên đoạn `Success! The pizza will soon be delivered to you! ` sẽ không nằm trong `handle_pizzarestaurant.lua` mà nằm ở 1 file khác `mod_lua.inl`.

Code của file này cũng khá dài nhưng chúng ta chỉ cần quan tâm hàm `lsp_process_order()`:

Cơ bản là sau khi order xong thì nó sẽ gọi `congratulate_customer_for_successful_order()` để lấy flag:
```c
const char* congratulate_customer_for_successful_order(struct order customer_pizza)
{
    const char *flag = "flag{fake_flag}";
    if (
    !customer_pizza.ingredient_mushroom &&
    !customer_pizza.ingredient_pepperoni &&
    !customer_pizza.ingredient_olives &&
    !customer_pizza.ingredient_garlic &&
    customer_pizza.ingredient_ham && customer_pizza.ingredient_pineapple) {
        return flag;
    } else {
        return " ";
    }
}
```

Nhìn ta sẽ thấy ngay là điều kiện có flag sẽ là không order `Mushroom
Pepperoni
Olives
Garlic`

và order`Ham Pineapple`cùng lúc. Tất nhiên mình không thể thao tác trên browser nhưng có thể làm request này dễ dàng bằng cách sửa trong `burpsuit`:

![](https://i.imgur.com/OTeNwKd.png)

Và đây là kết quả trả về:

![](https://i.imgur.com/iXDZkxk.png)

Quay lại hàm `lsp_process_order()` ta sẽ thấy nó gọi hàm này:

```cpp
static bool check_if_incompatible_selection(struct order *some_order)
{
    if (some_order->ingredient_ham && some_order->ingredient_pineapple) {
        some_order->incompatible_selection = true;
    }
}
```

Wait what? Tới đây sẽ có mâu thuẫn, nghĩa là mình phải order 2 cái cùng lúc nhưng không được order 2 cái cùng lúc ??

Chắc chắn phải còn thứ gì đó chưa khai thác.

Xem kĩ trong struct `order` có biến `incompatible_selection` dùng để check xem nó có thoã mãn hay không.

```cpp
struct order
{
    // If the checkbox for the ingredient was ticked
    bool ingredient_mushroom;
    bool ingredient_pepperoni;
    bool ingredient_olives;
    bool ingredient_garlic;
    bool ingredient_ham;
    bool ingredient_pineapple;

    // Further important information by the customer regarding the order
    char comment[COMMENT_LEN];

    // Some combination of ingredients are forbidden
    bool incompatible_selection;
};
```
Và đây là chổ gọi hàm của nó:
```c
check_if_incompatible_selection(&customer_pizza);

	i = 7;
	if (lua_isstring(L, i)) {
		size_t size;
		str = lua_tolstring(L, i, &size);
		// mg_write(conn, str, size);

		if (size > COMMENT_LEN) {
			print_output(conn, "Fail!\n");
			print_output(conn, "Your comment can at most be 500 characters!\n");
			return 1;
		}
		strncat(customer_pizza.comment, str, sizeof(customer_pizza.comment));
	}


	if (customer_pizza.incompatible_selection) {
		print_output(conn, "Fail!\n");
		print_output(conn, "This combination of ingredients is not allowed!\n");
		return 1;
	}


	print_output(conn, "Success!\n");
```
### Solve

Trước tiên ta có thể thấy, nó gọi `check_if_incompatible_selection()` nhưng không check `incompatible_selection` ngay lập tức mà còn check length của comment trước.

Tuy nhiên lúc khởi tạo thì `char comment[COMMENT_LEN];` lớn hơn nhưng lúc check lại dùng `strncat` và length comment có thể tối da 500 kí tự. Cộng thêm việc `incompatible_selection` đứng ngay sau `comment[]` trong struct, vậy chúng ta sẽ có thể thay đổi `incompatible_selection` trước khi nó check combination.

Vậy nên ta chỉ cần sửa lại comment trong lúc request = 500 kí tự:

![](https://i.imgur.com/u7hul0F.png)


Flag: `flag{Hawaii_served_with_Lua_and_C_Yummy_yummy_yummyXD}`

---


