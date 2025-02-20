---
title: "The Plaid Flag CTF 2023"
description: "Writeup for The Plaid CTF 2023"
summary: "Writeup for The Plaid CTF 2023"
categories: ["Writeup"]
tags: ["Reverse"]
#externalUrl: ""
date: 2023-04-17
draft: false
authors:
  - Jinn
cover: /images/post_covers/plaidctf2023-ori.jpeg
---

# Rev/CSS-crimes - 200pts

Description:
>I found this locked chest at the bottom o' the ocean, but the lock seems downright... criminal. Think you can open it? We recommend chrome at 100% zoom. Other browsers may be broken.

The challenge link [here](https://plaidctf.com/files/css.74486b61b22e49b3d8c5afebee1269e37b50071afbf1608b8b4563bf8d09ef92.html)

## First look
At the first look, it seems like a simple flag checker, but after I inspect this page, there is no ``<script>`` tag here. That why this challenge little hard.

Page:
![](https://i.imgur.com/Ch4F4FN.png)

Source:
![](https://i.imgur.com/wt2JeFO.png)
    
## Approach

After I did a quick check, I found the message "Correct" here, but this `z-index:0`. That mean it's covered by some things.

![](https://i.imgur.com/AbAELOY.png)

Also, there is no `<button>` tag here, I was figout what how we can choose the letter, I found this:

![](https://i.imgur.com/F4iC6Ou.png)

There are `27*3` `<details>` tags and followed by 4 `svg`

![](https://i.imgur.com/Pegl11S.png)

So, when we choose letter, those `<details>` tag will open, it was check 3 characters 1 time. This mean, if we choosed 3 character `_`, all details tag will open:

![](https://i.imgur.com/VZtZNho.png)

So what does opening these tags mean to check flags?

![](https://i.imgur.com/0i1Jo1T.png)

When these `details` have different size, so, when we open one of these, the page size was changed, that mean it affect on the svg position (top position):

![](https://i.imgur.com/yBGMJdA.png)

But what was that svg background image? 

![](https://i.imgur.com/t720seV.png)

I changed the `fill` from `#fff` to `#111`(black). As we can see, it's a image with a part missing in the middle. 

![](https://i.imgur.com/UlkFFGv.png)

I changed `z-index` of the correct message to `1`, and it matches the missing part of our svg image.

We know we can move the image up and down, so how did it move?

Let me example with the first image, this is base positon of this image:

![](https://i.imgur.com/7rQUevl.png)

and the calculated top position was -300:

![](https://i.imgur.com/irzDIWp.png)

I changed the first letter from `a` to `b`, and here is the result:

![](https://i.imgur.com/cB516zy.png)

It was changed from -300 to -160, call first letter as `x` we now coefficient of x is 140

Reset that letter to `a`, do the same with the 2nd character (y), we can see the top position was change fromm -300 to -140, that mean coefficient of y is 160

![](https://i.imgur.com/nbuYYQo.png)

and coefficient of z is 20

And we know exactly the pixel was change of the first image:

`d = 140x + 160y + 20z`

but when the top position >= 80, they will reset to base top positon (-300 as example), that mean we need modulo right side by `80 - (-300) = 380px`.

But how we know what is the goal of `top position` in that case? I was do it by hand but it little hard, so I created the formula :

![](https://i.imgur.com/mE8ltUW.png)

![](https://i.imgur.com/z7zzc9v.png)


As we can see `62` was the first position the missing part was appear. And it same with the correct message.

So the correct top position of this image was ``(60 - 60) = 0``

And the formula for this goal was: `goal = 60 - start_postition`

Do the same thing with 3 orther image we have this equations:

```python
####################-------------------------  test, first brute
start = -300
goal = 0
mod = (goal - start) + 100
import string
m = string.ascii_lowercase + '_'
for x in range(27):
    for y in range(27):
        for z in range(27):
            if (140*x+160*y+20*z)%380 == (0 - (-300))\
            and (60*x +100*y+20*z)%220 == (20 - (-140))\
            and (320*x+80*y+ 20*z)%460 == (380 - 380)\
            and ( 300*x+200*y+20*z)%340 == (-60 - (-260)):
                print_chr(x,y,z) 
                
#output : "you"
```
## Solve this stuff

So we confirm that the 3 letter was correct, all you need to do is find the remaining characters

Each 3 letter, we need to find the following number:

4 start top position of 4 image

```python
start = [-180,-300,-140,-260]
```
The top position of image when we change the first letter from `a` to `b` is present in p1[0], p2[0],... in order to caculate coefficient of `x` later.
And similar with the second letter. Also, cofficient of `z` alway 20.
```python
p1,p2,p3,p4 = [
    [-160,-160,20],
    [-160,-140,20],
    [-80,-40,20],
    [40,-60,20],
    ]
```
And the goal are the first position the missing part was appear. (rounded)
```python
goal = [80,300,200,160]
```

Put things together:

```python

def brute(start,p1,p2,p3,p4,goal):
    p1[0],p1[1] = p1[0] - start[0], p1[1] - start[0] # calc the coefficient of x, y of equation 1
    p2[0],p2[1] = p2[0] - start[1], p2[1] - start[1]
    p3[0],p3[1] = p3[0] - start[2], p3[1] - start[2]
    p4[0],p4[1] = p4[0] - start[3], p4[1] - start[3]
    goal = [60 - i for i in goal] # calc goal of top positio
    mod1,mod2,mod3,mod4 = [0 - start[i]+80 for i in range(4)] # find the mod
    dis1,dis2,dis3,dis4 = [goal[i] - start[i] for i in range(4)] #find the correct distance
    for x in range(27):
        for y in range(27):
            for z in range(27): 
                if (p1[0]*x+p1[1]*y+p1[2]*z)%mod1 == dis1\
                and (p2[0]*x+p2[1]*y+p2[2]*z)%mod2 == dis2\
                and (p3[0]*x+p3[1]*y+p3[2]*z)%mod3 == dis3\
                and (p4[0]*x+p4[1]*y+p4[2]*z)%mod4 == dis4:
                    print_chr(x,y,z)
```
Do the same with the remaining characters we will get flag.

Full script here:
https://github.com/lephuduc/CTFs-Honors/blob/main/The%20Plaid%20Flag/solve.py
