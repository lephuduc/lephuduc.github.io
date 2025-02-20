---
title: "Angstrom CTF 2023"
description: "Writeup for Angstrom CTF 2023"
summary: "Writeup for Angstrom CTF 2023"
categories: ["Writeup"]
tags: ["Reverse"]
#externalUrl: ""
date: 2023-04-27
draft: false
authors:
  - Jinn
cover: /images/post_covers/angstromctf2023.jpeg
---

First of all, I'm very excited because my team made it into the top ten. Thanks to my teammate. Keep it up, **The Council of Sheep** !!!!

![](https://i.imgur.com/VetZWRd.png)

I am responsible for all reversing challenge that my team solved. But there are some challenge I collab with my teammate. So, let's see how we did it!

## checkers

>20 points, 828 solves
[checkers](https://files.actf.co/f0dbcf2e7bd063c49de33b14e5360c79c6b7c669af69a88983c649b8da6a9245/checkers)
Author: JoshDaBosh

This one very easy, just look into IDA or using anything to view strings.
Flag: `actf{ive_be3n_checkm4ted_21d1b2cebabf983f}`

## zaza 
>50 points, 525 solves
Bedtime!
`nc challs.actf.co 32760`
[zaza]()
Author: JoshDaBosh

This challenge have 3 check, a number, sussy check, and a string:
![](https://i.imgur.com/XpZrZE5.png)
That number is 4919 and the second number is any.
After that, This challenge get our input and xor with string:
`"anextremelycomplicatedkeythatisdefinitelyuselessss"`
and compare with: 
`"2& =$!-( <*+*( ?!&$$6,. )' $19 , #9=!1 <*=6 <6;66#"`
![](https://i.imgur.com/FpFrpB3.png)

![](https://i.imgur.com/JmXwSg5.png)

So, by the property of xor, we can get back our string easy:
```python
from pwn import xor
x1 = b"2& =$!-( <*+*( ?!&$$6,. )' $19 , #9=!1 <*=6 <6;66#"
x2 = b"anextremelycomplicatedkeythatisdefinitelyuselessss"
print(xor(x1,x2)) #output: b'SHEEPSHEEPSHEEPSHEEPSHEEPSHEEPSHEEPSHEEPSHEEPSHEEP'
```
Put things into the server:

![](https://i.imgur.com/r9gdeSu.png)

Flag: `actf{g00dnight_c7822fb3af92b949}`

## Bananas

>100 points, 213 solves
A friend sent [this](https://files.actf.co/8ab8e79a482fd97ef1d2621dd1102278b24270edd5abb024d6c294f927122b68/Elixir.Bananas.beam) to me. Can you help me find out what they want?
`nc challs.actf.co 31403`
Author: cavocado
Hint: Elixir is awesome :)

Let check that file:

![](https://i.imgur.com/wAkegcN.png)

This challenge was written in Erlang, I spent minutes to find a decompiler
I found this decompile, easy to build and use: https://github.com/aerosol/decompilerl

And here is the result:

![](https://i.imgur.com/RRpmz8I.png)

So, in order to the function `check()` return true, we need passing 2 arguments, first one is a number and second is string "banana"

The number is very easy to calculate, It was 103

Put things into the server:

![](https://i.imgur.com/fxT2CL4.png)

Flag: `actf{baaaaannnnananananas_yum}`

## Word Search

>110 points, 47 solves
I decided to put a few puzzles in the [kids' menu](https://files.actf.co/c5bcdf7f0684413da86c21eefb099881f03d76db8df6e00891a561082eba4163/wordsearch.pdf) for the new AngstromCTF restaurant, but nobody has been able to solve it. Maybe you could [take a crack at it](https://files.actf.co/ba9b6902712f88ea3fb8e1f259b5645205f51a528d4486e136e698ee846b6037/wordsearch).
Author: rous
Hint: The flag is composed of only English words and underscores.

This one like a programing challenge than reverse challenge, so I was collab with @d4rkn19ht to solve this.
I am confused what is the hint and this maze.

![](https://i.imgur.com/ZI7YjT2.png)

Let look in to the binary, It was renamed and look clean, but still hard to understand:
The main function as sus function take 2 command-line arguments and do something
![](https://i.imgur.com/yvm2BHX.png)

After I researched, one of them is Hint from pdf file and another is our input (flag):

So, that mean this program do something with the hint from pdf file to check our input, let's figout what does it do!

![](https://i.imgur.com/CI1Zmpn.png)

This program check char by char with the hint, some important symbol like "(" or "?" will appear often.

After a lot of times debugging and testing, I found the rules, let's me explain:

First, suppose () is a block, this will be this format:

`(char + somechar)char ... 'char`

Example:

![](https://i.imgur.com/fmKXVqw.png)

That somechar = 'h', and I think `(k` is start of our block, `'k` is end of the block. Continue,

![](https://i.imgur.com/68WQHqm.png)

The format is: `?sometext?`

![](https://i.imgur.com/BA9CYSb.png)

This progam take each char from our flag and compare with rule: char of flag not in `somechar`(blue) and must be in `sometext`(yellow), after that, we will obtain only 1 char, this will compare with our flag.

So, in this case, this char was `b`.

I called blacklist is the buffer saved "hjU5fl", after check with `sometext`,
remaining buffer will be "fl".

The main flow: 
`take somechar from block -> put it into buffer -> take char from sometext -> check that char (if that char in buffer delete this char from buffer, if not, compare this char with flag)`

That mean, we need a code to get the char to compared, this is my optimized code:

```python
buffer = []
enc = "(kh)k'k(Qj)Q'Q(2U)2'2(35)3'3(Ff)F(ul)u?hbjU5?'F(9M)9'9(4 C)4'4(iv)i?ofM?'u?tCl?(SP)S'S'i?Pvh?_(k4)k'k(Q0)Q'Q(2Y)2'2(9 j)9'9(uB)u(S I)S(N7)N(oH)o?40Yi?(3a)3'3(Fi)F'F'S(XG)X'o?arij?(4k)4'4'u(fs)f(d f)d?kBr?(ix)i'i'X(cH)c'd(VZ)V(q x)q'q(DJ)D(W B)W?eIxG?(sp)s's(xN)x'x(pD)p'p'N'W?pND7g?(Mq)M'M?uqH?'c'f'V?HsfZl?'D(eT)e'e(j N)j'j?xJaT??BNr?_(kh)k'k(QS)Q'Q(2U)2'2(32)3'3(FZ)F(4s)4(XG)X?hSaU2?'F(97)9'9'4(Sw)S'S?nZ7s?(uc)u'u(iQ)i'i'X?cdwQG?_(k6)k'k(Qq)Q'Q(F8)F(9 8)9(i v)i(e4)e?i6q?(2t)2'2(3i)3'3'F'9(4 u)4'4(p R)p(oK)o(f b)f(Vr)V(D8)D?tin8?(us)u'u(SF)S'i(X 1)X'X(sS)s(NR)N(c 9)c(q o)q?8eus?'S'p(M X)M'f(W f)W(jm)j?Fvx1?'s(xo)x'x'c?Sop?'M'e'j?rR?'N(d8)d?eRX?'o?sK9?'d'q'W?sb8?'V?iro?'D?8v4??efm?"
i = 0
def remove_one(c):
    global buffer
    for i in range(len(buffer)):
        if c==buffer[i]:
            buffer = buffer[:i] + buffer[i+1:]
            return
flag = ""
while i < len(enc):
    if enc[i]==')':
        buffer.append(enc[i-1])
    if enc[i]=='?':
        tmp = []
        n = enc[i+1:].index('?')
        for j in range(i+1,i+n+1):
            tmp.append(enc[j])
        i+=n+1
        for c in tmp:
            if c in buffer:
                remove_one(c)
            else:
                flag+=c
    if enc[i]=='_':
        flag+='_'
    i+=1
print(flag) #both_irregular_and_inexpessire
```
Flag: `actf{both_irregular_and_inexpessive}`

## TI

>80 points, 40 solves
My friend sent me this [town simulator](https://files.actf.co/e93c52090cfe5c3de858bebee79af67066b825afa84ead4f1488b274f72000fb/TOWN.8xp). I can't seem to beat it. Can you help me?
Author: awesomeguy

This one little guessy, so I don't like it so much.

First of all, I figiout what is this file with extension `.8xp` of the file given?

>Program or data file used by the Texas Instruments TI-83 Plus and TI-84 series calculators; can be transferred to the calculator from a computer using a TI Connectivity Cable and the included software.

![](https://i.imgur.com/X4kDxzN.png)

To run an 8XP file on your PC, you'll need to use an emulator that can simulate a Texas Instruments graphing calculator.

So I found some emulator like this: wabbitemu, tiemu, vti, ...

I trying many times to run this file but I alway got an error:

When I run with TI-83 plus rom:

![](https://i.imgur.com/3iXy7tN.png)

![](https://i.imgur.com/MnoclvT.png)

I also try many rom, like ti-83, ti84, ti-83 ce,... and still got an error:

![](https://i.imgur.com/5pqOxKt.png)

So, before reversing the code, I was figout how to run that file, it's the time to find the correct version of calculator and emulator support it.

And I was excited that @Nova found this one: https://cemu.info/

After download and run with ti-84ce.rom, download library`clibs.8xg` and send it to emulator. Finally, it's worked:

![](https://i.imgur.com/PLo81iT.png)

Before this, I view this file (TOWN.8xp) as hex and I found some interested string:

![](https://i.imgur.com/9XfYFkJ.png)


So, I think the correct name is somewhere on this file.
I decided to debug this program and bypass the first check:

![](https://i.imgur.com/ySM8C3l.png)

Stop the program, Step out ultil it requires our input, type some text and step over to debug.
After some times, I found that address D1AB38 is the jump check (jump to fail, print "I think you are lying...") for name; So, to bypass this check, we easily turn on the zero flag:

![](https://i.imgur.com/noiRB93.png)

![](https://i.imgur.com/LWhAabj.png)

And  got into the TOWN:

![](https://i.imgur.com/yNniFPC.png)

After this, I figout something about these option:

Option 5: Input a string, and print this string with reverse string after that, I enter "11112222":

![](https://i.imgur.com/4j6hWt5.png)

Option 4: 

![](https://i.imgur.com/FGZIhAL.png)

Option 3:

![](https://i.imgur.com/e7Qmn4v.png)

Option 2:

![](https://i.imgur.com/c8zAxSO.png)

Option 1:

This one happen when you enter nothing:

![](https://i.imgur.com/82Zz0iZ.png)

If your enter sometext:

![](https://i.imgur.com/YCIrYfp.png)

And the program exit.

I figout that the 5 option just the hint to obtain flag, not process our flag. Follow option 2, we need to find the correct name first:

![](https://i.imgur.com/vu3oG6L.png)

I try with this input and try to find where our input saved on memory:

>D1A820 address of first name input
D1AB38 check name
D1A7E4 input address of code talk to guard
D1A7C0 address of printed string option 1
$DIA968: get input function
$021D2C: print str function

![](https://i.imgur.com/2OicVzZ.png)

After some times trying to debug, I found this:

![](https://i.imgur.com/MyebTAf.png)

It seem the program load some thing from memory, and it was "CE C RELEASE"

Try it as a name and it correct:

![](https://i.imgur.com/zNvUx7U.png)

![](https://i.imgur.com/YZkwt0t.png)

So, we find the correct name, but where flag?

At the time I view the find as hex, I also found this sussy string:

![](https://i.imgur.com/HCSK3LR.png)

This like our flag but encrypted, I trying to xor with the flag format and this happened:

![](https://i.imgur.com/IF82R8t.png)

As we can see, xored string was RRRLL..., but R is index 5 at of the string "CE C RELEASE".

I try it with string like "RRRLLL" + "AAA" or "RRRLLL" + "EEE",...(follow on option 4 and 3) and this is result:

![](https://i.imgur.com/CCGtjlH.png)

So there is a string I found:

```python
x = bytes.fromhex('33 31 26 2A 37 29 75 32 38 1A 7D 75 1A 71 36 32 72 24 21 2E 05 2B 65 2F 32') 
guess = b"RRRLLLAAAEEEEEEAAALLLRRR2"
b =   guess + b'\x00'*(25 - len(guess))
print(len(guess),len(x))
print(xor(x,b)) #ouput: b'actf{e4sy_80_4ss3embIy7}\x00'
```

Flag: `actf{e4sy_80_4ss3embIy7}`


## Moon

>130 points, 55 solves
To the moon! The correct sequence of inputs is the flag in ASCII.
[moon](https://files.actf.co/9534f0c764e0c99695fa7118dbe1adeedf6fc98968fb38da02e634584d39b925/moon)
Author: JoshDaBosh

This main funtion is to big, so we can't decompile this code:
![](https://i.imgur.com/8akezYd.png)

To view it as graph, we need to change the max node to 10000:

![](https://i.imgur.com/4nnPeyV.png)

![](https://i.imgur.com/UIyErZl.png)

After a first look, I see this program get 1293 number. Each number (n), for each number, it will call the corresponding function the number of times (n).

Example, with at funtion 0, and n0 = 120, it will call func0 120 times, and there is inside func0:

![](https://i.imgur.com/frMsaEw.png)

There are 1293 global variable, after call func1292, this will check with constants, so this like a matrix multiply:

![](https://i.imgur.com/tE2Rcf0.png)

First try, I using get_bytes() to get all byte of each function, then check them to get these constant, but it incorrect.

So I decided to create asm file, then parse constant on this.

![](https://i.imgur.com/9twYQ7d.png)

![](https://i.imgur.com/93WkDTr.png)

I use this script:

```python
from pwn import *
with open('moon.asm','r') as f:
    ins = f.readlines()
cons = []
for n in range(1293):
    var= 0x23AB900
    idx = ins.index(f'func{n} proc near\n') + 5
    ls = []
    while idx < len(ins) and f'func{n}' not in ins[idx]:
        if f'rax, cs:qword_{hex(var)[2:].upper()}' in ins[idx]:
            nextline = ins[idx+1]
            try:
                number = int(nextline.split(' ')[6].replace('h','').strip('\n'),16)
            except:
                ls.append(0)
                var+=8
                idx+=1
                continue
            if 'add' in nextline:
                ls.append(number)
            elif 'sub' in nextline:
                ls.append((~number+1)&(2**64-1))
            var+=8
        idx+=1
    assert(var==0x23AE168)
    # cons.append(ls)
print(cons)
```

And here is the result:

![](https://i.imgur.com/w49Mk5w.png)

Now I have matrix 1293x1293, we(m1dm4n) use sagemath to solve it:

![](https://i.imgur.com/chpk3jU.png)

```python
from ast import literal_eval
from sage.all import matrix, vector

x =[63393110, 58886046, 67388269, 63461910, 67974569, 60993599, 67115864, 65470744, 66191693, 64407727, 62057872, 61486263, 64907821, 58373354, 64768373, 59683813, 63725637, 72094089, 61331703, 68980247, 66685884, 57971615, 64038009, 61162051, 66550714, 62707285, 69620832, 64209208, 65650269, 66386253, 65096786, 63795576, 63701384, 61965114, 66725179, 62279606, 61438421, 66127795, 60091704, 68532768, 63203223, 66066067, 62951475, 58143520, 63211575, 64079813, 65363478, 69322487, 63916034, 66942647, 70386888, 61094871, 66223409, 68766697, 66485027, 59883256, 57160034, 58089614, 62666296, 61833179, 61580490, 66266430, 69522914, 70210323, 54901539, 65461415, 58573227, 68323975, 59777456, 67938344, 58876260, 66793117, 61596319, 59203560, 58628036, 61772847, 66619886, 63149749, 66355939, 61266423, 58991064, 64601226, 66989008, 60434116, 67827499, 67584476, 58802564, 66843272, 65963725, 63570581, 61116828, 71261997, 69478738, 65316131, 70294335, 63203329, 65114038, 67993300, 56103231, 60341681, 62992943, 58697987, 62835605, 68570464, 57459465, 66127858, 63146318, 68614022, 58734257, 63036806, 64538253, 56068970, 63653137, 60327882, 68296125, 71865536, 65626317, 68816304, 58679314, 63352410, 70154891, 62936398, 61748954, 58898280, 60996317, 56631617, 56644617, 71009917, 69966086, 68681903, 59700700, 61535451, 55690965, 58947926, 58793481, 63069002, 64275033, 62215388, 60115793, 63124349, 69986678, 69411299, 67530443, 63730621, 65055498, 70043043, 62670977, 69001174, 63181872, 62269354, 65954864, 62804013, 65119689, 62468267, 63540301, 67965533, 62643943, 62332625, 69719564, 57857109, 55843853, 66766315, 57377721, 68843621, 63178360, 60793568, 58640375, 65608923, 71633486, 64441495, 63150215, 59260189, 67796620, 66053370, 68301238, 62928535, 71236589, 66199794, 61910903, 58391902, 60648945, 56141696, 70969476, 66343227, 61502729, 68525235, 66198293, 66942508, 64340209, 62982385, 64031650, 58011320, 67265701, 65362374, 59794852, 61591197, 64404489, 63316494, 62319358, 63445445, 58352667, 63082260, 65255867, 61265446, 58845803, 65562972, 70037593, 71132109, 65507136, 68189067, 66382708, 62189035, 64460646, 59879304, 67087877, 62257722, 57302811, 62239780, 63803838, 64664146, 67165718, 65696383, 61959416, 62907666, 63964334, 59828944, 61597321, 67912593, 63482202, 62178713, 60092005, 59701215, 63943967, 62509855, 66116266, 65437589, 63899800, 60139233, 65293339, 57335738, 59589223, 68945985, 63932367, 66781353, 65921842, 59605275, 61144244, 62442386, 66848033, 65723791, 63475692, 70572960, 65709089, 62588500, 68746336, 59794119, 63029650, 63321427, 63496482, 57521905, 72055618, 60000693, 62741235, 58827637, 62675830, 70872414, 61950549, 61878697, 68636636, 64505071, 68317055, 67685794, 60246794, 59848833, 60249967, 62995099, 66986046, 66655346, 65577991, 66155927, 58690559, 66201543, 61710155, 63714967, 60759398, 58429218, 65228584, 62469345, 63437707, 63322269, 65522877, 61156110, 58823896, 69092681, 67888109, 63417654, 63175290, 62113113, 61460206, 64883652, 61913508, 66863077, 59133427, 67950357, 59455812, 64363967, 60446995, 61009720, 62409918, 60529864, 61663777, 65496176, 62923009, 63070442, 68312324, 63185532, 67094260, 66481714, 63666841, 62995259, 65303691, 63139855, 68799250, 59247590, 63655839, 65696661, 60671850, 62871537, 64741237, 66766319, 64090332, 61181100, 59720153, 61762493, 68425714, 70557785, 62677730, 61901946, 68718380, 64641148, 62657424, 60013121, 70238319, 56094545, 62607485, 66870263, 61756975, 62355157, 67360262, 58942315, 59602883, 63462338, 59481837, 68091157, 72287977, 70334331, 62927116, 65259307, 62040210, 64232408, 64442117, 67947419, 64160185, 63366312, 59946214, 61026456, 58741830, 62960766, 66450728, 66505938, 67149530, 61072357, 69434685, 60357789, 67573561, 69023002, 59730941, 58935616, 66378831, 61108903, 61409883, 71671845, 63927404, 66501530, 62338630, 65906841, 69391288, 61597802, 65706606, 65497799, 65756436, 65097328, 60313432, 61925794, 66750668, 58520439, 68490328, 65331837, 69255180, 61137234, 64880920, 64932335, 66865669, 59564266, 68440338, 67997315, 57055156, 63180971, 65505869, 60964787, 67326648, 67998107, 58019084, 66959614, 64328778, 58933843, 61772014, 58724642, 64902089, 70739221, 62149916, 59910691, 68365922, 59059516, 64020707, 65351622, 66306822, 59543949, 58946162, 56491796, 62667863, 63810898, 63656212, 66060791, 68839747, 59648441, 64197215, 65805560, 63753048, 65665786, 65160325, 62906786, 59879406, 59685602, 61672831, 62561035, 57239715, 63965352, 67955093, 65170239, 63315100, 63323141, 65829596, 63927013, 58863641, 63994605, 62391436, 66428499, 64595315, 62497257, 61620428, 63335006, 62720621, 65982147, 61113620, 61288231, 59742953, 67736553, 67951407, 64365570, 69788971, 69879395, 67431800, 69115881, 64562804, 68024779, 63338825, 67337833, 71832964, 65794390, 65628954, 61222148, 65671258, 60456543, 63677791, 66152886, 58045838, 59839857, 64446131, 66346357, 60030406, 69225422, 58963891, 64701931, 65486215, 64468588, 62540974, 62756799, 64683470, 62403153, 67190555, 63042724, 68225539, 70260132, 59411467, 66327868, 57911187, 62070454, 63434516, 61672692, 58539958, 65924384, 62533988, 57143065, 65806188, 65949606, 70548213, 58946142, 70004508, 61948315, 60119035, 64951496, 57778508, 66952030, 67051608, 66421165, 57825664, 67125584, 59374065, 64915709, 64560757, 64154276, 67041884, 62148937, 65915582, 62443792, 61719110, 64778207, 63247675, 66355317, 67560388, 67299326, 61350675, 57814218, 64915724, 61022577, 63576217, 60633687, 65174267, 60905016, 57624439, 61529215, 71540159, 61684732, 63749566, 65123039, 59362785, 61663653, 70674926, 65102966, 65708452, 60136201, 61637743, 57725710, 67827598, 67507688, 60563794, 63612363, 55231545, 62172587, 71086047, 64107426, 60069087, 62992579, 63253365, 64096981, 62516293, 64320626, 61562154, 71698176, 64577215, 65811115, 62432412, 72558354, 60990113, 70861623, 58141358, 68522570, 66276658, 66749904, 64598466, 59342460, 63733141, 65458800, 62198507, 65971378, 68368967, 57706820, 61553810, 65276070, 61878245, 69081411, 58797147, 66155886, 63574184, 66431844, 64499077, 65383330, 66426836, 68588212, 63755094, 63394198, 68109115, 68268956, 58349221, 60191212, 58947992, 64663574, 66249731, 68942368, 62864378, 67260033, 63365125, 64173411, 63485552, 63793557, 63542929, 64677648, 63044471, 67893258, 61874609, 59820527, 63618300, 68570248, 60301843, 59297598, 67821801, 55070536, 58259904, 64399005, 64377201, 65672298, 65630841, 62935180, 66982480, 62577326, 63479803, 65495968, 61625540, 61309023, 61972539, 62697119, 64977834, 61825094, 58771305, 62970866, 65826654, 62792345, 69084263, 69910343, 57541923, 66552410, 65643064, 68787174, 62362145, 65982831, 67346973, 61932619, 67973985, 62322824, 65616933, 67548663, 67024029, 67246683, 64792744, 67119347, 58815015, 69627024, 60560699, 67649584, 63880450, 65202240, 62306622, 65527240, 66114026, 66070381, 64688779, 66972213, 60341445, 66058724, 68623345, 66555932, 59437122, 61723449, 66310846, 58875973, 59528145, 66102516, 63259011, 67142825, 64120753, 66745601, 71152953, 63524056, 59587602, 61488955, 64682112, 63642139, 67775297, 65278369, 63240216, 60078915, 65803512, 69119349, 62693018, 64398584, 62458955, 71036231, 58733198, 65735399, 63063132, 61793143, 67984823, 67810447, 63276784, 64880968, 61957930, 64328577, 64913156, 64199943, 60687258, 63119964, 61963604, 62834612, 64629283, 69335683, 65343092, 69292433, 64220379, 64575298, 63007466, 70698100, 65520916, 63108451, 61703192, 62803405, 58393116, 62397295, 65539148, 57445311, 67006048, 62133729, 59435381, 65387910, 66735213, 65744719, 62429520, 61398907, 64157879, 64702252, 61385630, 59789788, 62134162, 60278381, 57635866, 65459395, 66486830, 57595243, 63099046, 60898412, 66904367, 63773349, 63511825, 57028226, 60856751, 63545666, 71623472, 65231758, 61850509, 59788938, 68536427, 64523947, 62866475, 69401218, 61886474, 62580520, 65651667, 58858406, 64583938, 64502037, 59023982, 67142564, 57180424, 62659998, 63315915, 63973801, 62946402, 62402120, 64685052, 66880846, 65055053, 70921211, 66296346, 61641404, 61116543, 63356623, 56583804, 66455163, 65315624, 70640356, 61966120, 66176030, 59226249, 67434530, 70874682, 68492529, 63880921, 58493546, 64631727, 61161474, 66349920, 65286853, 65287128, 65721654, 68971371, 68858452, 71860280, 59758346, 63458431, 68771044, 63299519, 70515653, 69474259, 61879136, 61822690, 61475742, 64952547, 68666602, 65665224, 59886692, 61837505, 60276848, 64288884, 66669554, 68079823, 62391729, 68350841, 62247001, 60186351, 67364395, 65720731, 63610260, 71070984, 64941837, 68323806, 64337360, 63281518, 58847534, 64295557, 65230303, 56504147, 70608348, 64287747, 57968093, 59355459, 67832972, 69309803, 62354379, 65382321, 68982293, 65138255, 65736303, 67047003, 59616125, 65438071, 64074701, 63125468, 67104202, 57339620, 69262389, 62632124, 66339499, 61398893, 61507376, 57835509, 61610354, 57325557, 68370866, 68581960, 59750453, 64440728, 60395454, 63984770, 60036834, 63809497, 58319627, 66324106, 65378683, 63361855, 64403076, 64035143, 67092982, 63303125, 63728233, 64168106, 64039635, 67080786, 64076386, 59996644, 59878626, 68501368, 60791159, 65573102, 68251111, 60449159, 61320211, 66174591, 64130387, 68825504, 66404519, 61261735, 67259534, 66279175, 68247330, 66546879, 61146981, 62783716, 64642481, 62228998, 64958114, 63582167, 66645336, 63562460, 70915819, 58498774, 73345342, 62451456, 68162332, 66581518, 60221360, 60644964, 72588520, 65012795, 63756243, 59691866, 71350499, 61243014, 65443056, 64212632, 71585482, 64438118, 61901529, 68162667, 63504371, 67061811, 64611349, 61595811, 68261827, 64251173, 70976178, 66928294, 60556196, 62630812, 62513720, 61588800, 65818751, 59989252, 62313318, 64841680, 61505489, 65599862, 66891354, 64299474, 63929603, 62735748, 60023471, 60806829, 64644240, 67061124, 64539318, 64560037, 63798301, 60089887, 66577770, 64449575, 63712105, 60668002, 68170241, 64496459, 64981855, 64001244, 67201096, 64877985, 68961593, 67093753, 70594163, 64231731, 62960920, 63346755, 65049580, 64619044, 67798649, 66753396, 56641105, 60079487, 62399786, 69040678, 64968096, 61368027, 67156445, 58589688, 66374354, 66923296, 67187007, 57221360, 69400344, 61452586, 60561301, 63745871, 62401654, 57905635, 70711289, 71739876, 62689268, 65616981, 63764296, 68775654, 60905723, 65234499, 66126094, 63615750, 60750598, 60875584, 64732830, 72160942, 65304181, 63640175, 65956966, 64084769, 63306358, 68964218, 67006036, 61693648, 64719348, 58892500, 57173868, 68636342, 65825351, 69018293, 64239085, 67811872, 65909394, 68908485, 65340332, 60898563, 56371321, 63914361, 58201012, 57671664, 60073909, 71024380, 62599650, 59596612, 68324686, 60901052, 66939589, 64773073, 65262783, 63566973, 60148082, 68526829, 64805766, 62796988, 62024872, 61797643, 65028249, 59257568, 68113793, 68491842, 63153830, 66690286, 68775332, 66266514, 63254842, 63130917, 65593302, 63182667, 63768876, 67767200, 64109437, 64381504, 72201385, 67152768, 60841307, 66800358, 61947130, 64569744, 69834736, 69845345, 66108859, 59823511, 61424884, 68779195, 59809936, 61719208, 64179793, 69550658, 60155480, 62360267, 68143105, 69061770, 68249232, 66404459, 66966499, 65711841, 62749629, 60944249, 66024271, 67896753, 59078835, 64479608, 69072797, 71592027, 64824277, 62179662, 61133810, 69460076, 62959793, 60586792, 63626388, 67787832, 63148236, 68028357, 63140007, 67034764, 61601083, 61035415, 65735182, 59771131, 64355082, 63615917, 65697689, 64252820, 65727243, 65757176, 65674788, 64811824, 66540130, 56962628, 61273162, 64722521, 59986785, 68880683, 64602213, 65575139, 66570840, 66835867, 66141525, 66455992, 61114307, 67042048, 65122125, 64685224, 65705181, 70862867, 64968513, 68388371, 63168135, 66017478, 66197152, 63397210, 65012292, 58084142, 63476327, 63757101, 63777473, 61029451, 67501439, 64810124, 57805337, 62001667, 60304571, 61212696, 70907445, 66499657, 63667208, 64770038, 63074909, 63372274, 60106009, 63552277, 64111671, 66744147, 71354153, 66812994, 61093570, 67393117, 65291204, 64897365, 60822946, 68142213, 62028544, 67726158, 63130222, 64278258, 69386949, 57828324, 59976769, 64174153, 64426136, 59610026, 62670269, 61393249, 65526473, 58350005, 60830239, 56981028, 65898704, 63481409, 63559057, 66450103, 65886675, 64272274, 62972970, 60808619, 60137341, 65333639, 63861224, 66150677, 68517483, 59793918, 62825513, 65272405, 58852528, 61204741, 60327327, 65641981, 63550731, 57206292, 69422190, 63609112, 64224337, 71601367, 61159395, 63619876, 64330679, 61405309, 70082641, 63752794, 63156002, 69010303, 63197830, 64593898, 64859103, 67765582, 65401404, 63564640, 66498670, 67379786, 62900928, 66594632, 64566572, 62837912, 71342632, 72967396, 67851757, 65819307, 68444173, 69887757, 67477826, 71228352, 60042915, 61547268, 64207493, 58124059, 64028190, 61742897, 64786994, 61966640, 62471227, 62746390, 61650413, 65212275, 63419941, 61777360, 60800092, 65494190, 67202755, 63501212, 65078012, 67079286, 59084245, 65591500]
with open('parse.py', 'r') as f:
    dat = f.read().strip('\n')

mat = literal_eval(dat)

mat = matrix(mat).T
print(mat.rank())
x = vector(x)

flag = ""
print(mat.solve_right(x).list())
for i in mat.solve_right(x).list():
    flag += chr(int(i))
print(flag)
```

![](https://i.imgur.com/pgVA8qz.png)

Flag: `actf{3verything_is_just_linear_algebr4_33e431e52e896c92}`

## giza

>100 points, 19 solves
Can you make it to the top of [giza](https://files.actf.co/729061ede815b931cd7cd2b151f6573725b49501e72c478717be74502e6f8ead/giza)?
Author: evilmuffinha
Hint: you got this

![](https://i.imgur.com/STrmU4Z.png)

This function has stack frame too big, so I can't decompile with IDA.

After some times trying to debug, I got something like this:

This program takes 428 input numbers, then it has an x matrix, it subtracts cumulatively the x-matrix diagonal for each input number, this matrix will be processed and do a few things and then check (supose our input is `i`):

![](https://i.imgur.com/K0ebo0z.png)

![](https://i.imgur.com/2AguiaF.png)

I use Ghidra and I decompiled this function, here is the code:

![](https://i.imgur.com/3sSdu8I.png)

And we must get out the loop with the check = 0.

![](https://i.imgur.com/LzyjUZh.png)

In sometime, I think about using side channel attack, but I alway got SIGNAL when get into the function FUN_00101b50(). So that failed.

Another time, I see the matrix subtracts cumulatively on diagonal, so, what happend if after that, the diagonal equal to 0?

To do that, we need the diagonal of x:

![](https://i.imgur.com/DWXVIA2.png)

Start with base offset of x, I used get_bytes to get number on the diagonal:

`[get_bytes(0x55F234BA0040 + i*428*4 + i*4,4) for i in range(0x1ac)]`

May you can convert it into int:

And I wrote this script to subtract from the end to the top (Same with name giza:v )

```python
sus = [b'A\x00\x00\x00', b'\xa4\x00\x00\x00', b'\x07\x01\x00\x00', b'v\x01\x00\x00', b'\xe8\x01\x00\x00', b'L\x02\x00\x00', b'\xb5\x02\x00\x00', b'#\x03\x00\x00', b'\x8a\x03\x00\x00', b'\xaa\x03\x00\x00', b'\x1e\x04\x00\x00', b'\x8d\x04\x00\x00', b'\xad\x04\x00\x00', b'\x0e\x05\x00\x00', b'z\x05\x00\x00', b'\xe6\x05\x00\x00', b'\x06\x06\x00\x00', b'q\x06\x00\x00', b'\xdf\x06\x00\x00', b'N\x07\x00\x00', b'\xc5\x07\x00\x00', b'3\x08\x00\x00', b'S\x08\x00\x00', b'\xbf\x08\x00\x00', b' \t\x00\x00', b'\x97\t\x00\x00', b'\n\n\x00\x00', b'\x14\n\x00\x00', b'\x83\n\x00\x00', b'\xe9\n\x00\x00', b'\t\x0b\x00\x00', b'j\x0b\x00\x00', b'\xe0\x0b\x00\x00', b'I\x0c\x00\x00', b'\xaa\x0c\x00\x00', b'\x1e\r\x00\x00', b'\x87\r\x00\x00', b'\xf6\r\x00\x00', b'd\x0e\x00\x00', b'\x90\x0e\x00\x00', b'\x9a\x0e\x00\x00', b'\x0e\x0f\x00\x00', b'v\x0f\x00\x00', b'\xdb\x0f\x00\x00', b'M\x10\x00\x00', b'\xb2\x10\x00\x00', b'\xd2\x10\x00\x00', b';\x11\x00\x00', b'\xae\x11\x00\x00', b'\xce\x11\x00\x00', b'<\x12\x00\x00', b'\xab\x12\x00\x00', b'\xcb\x12\x00\x00', b'B\x13\x00\x00', b'\xa3\x13\x00\x00', b'\x1c\x14\x00\x00', b'<\x14\x00\x00', b'\x9d\x14\x00\x00', b'\xbd\x14\x00\x00', b'\x1f\x15\x00\x00', b'\x84\x15\x00\x00', b'\xe9\x15\x00\x00', b'\xf3\x15\x00\x00', b'f\x16\x00\x00', b'\xce\x16\x00\x00', b'=\x17\x00\x00', b'\xb2\x17\x00\x00', b'\x1e\x18\x00\x00', b'\x82\x18\x00\x00', b'\xa2\x18\x00\x00', b'\x04\x19\x00\x00', b'i\x19\x00\x00', b'\x89\x19\x00\x00', b'\xea\x19\x00\x00', b'L\x1a\x00\x00', b'\xb8\x1a\x00\x00', b'\x1d\x1b\x00\x00', b'=\x1b\x00\x00', b'\xb1\x1b\x00\x00', b' \x1c\x00\x00', b'@\x1c\x00\x00', b'\xa6\x1c\x00\x00', b'\x12\x1d\x00\x00', b'\x8b\x1d\x00\x00', b'\xb9\x1d\x00\x00', b'\xc3\x1d\x00\x00', b'\x0c\x1e\x00\x00', b'\x80\x1e\x00\x00', b'\xf3\x1e\x00\x00', b'\x13\x1f\x00\x00', b'\x8a\x1f\x00\x00', b'\xf3\x1f\x00\x00', b'a \x00\x00', b'\xc8 \x00\x00', b';!\x00\x00', b'[!\x00\x00', b'\xbc!\x00\x00', b'."\x00\x00', b'\x93"\x00\x00', b'\xb3"\x00\x00', b"'#\x00\x00", b'\x96#\x00\x00', b'\x05$\x00\x00', b'%$\x00\x00', b'\x98$\x00\x00', b'\x05%\x00\x00', b'f%\x00\x00', b'\xd2%\x00\x00', b'>&\x00\x00', b'^&\x00\x00', b'\xd2&\x00\x00', b"A'\x00\x00", b"a'\x00\x00", b"\xc8'\x00\x00", b'-(\x00\x00', b'\xa1(\x00\x00', b'\xab(\x00\x00', b'\x14)\x00\x00', b'\x88)\x00\x00', b'\xfb)\x00\x00', b'\x1b*\x00\x00', b'\x81*\x00\x00', b'\xe2*\x00\x00', b'V+\x00\x00', b'v+\x00\x00', b'\xe2+\x00\x00', b'K,\x00\x00', b'\xbf,\x00\x00', b'3-\x00\x00', b'\x9f-\x00\x00', b'\x04.\x00\x00', b'$.\x00\x00', b'\x86.\x00\x00', b'\xf5.\x00\x00', b'Y/\x00\x00', b'\xd2/\x00\x00', b'\xf2/\x00\x00', b'a0\x00\x00', b'\xc70\x00\x00', b'-1\x00\x00', b'M1\x00\x00', b'\xc11\x00\x00', b')2\x00\x00', b'\x8e2\x00\x00', b'\xae2\x00\x00', b'\x153\x00\x00', b'\x873\x00\x00', b'\xf63\x00\x00', b'k4\x00\x00', b'\xd94\x00\x00', b'=5\x00\x00', b'k5\x00\x00', b'u5\x00\x00', b'\xc95\x00\x00', b'16\x00\x00', b'\x966\x00\x00', b'\xb66\x00\x00', b'\x187\x00\x00', b'}7\x00\x00', b'\xe27\x00\x00', b'\x0e8\x00\x00', b'.8\x00\x00', b'\x9d8\x00\x00', b'\x039\x00\x00', b'#9\x00\x00', b'\x869\x00\x00', b'\xf59\x00\x00', b'j:\x00\x00', b'\xdc:\x00\x00', b'O;\x00\x00', b'\xb4;\x00\x00', b'\xe0;\x00\x00', b'\x00<\x00\x00', b'f<\x00\x00', b'\xd2<\x00\x00', b';=\x00\x00', b'\xa0=\x00\x00', b'\x13>\x00\x00', b'3>\x00\x00', b'\x94>\x00\x00', b'\x02?\x00\x00', b'{?\x00\x00', b'\xf2?\x00\x00', b'S@\x00\x00', b'\xcc@\x00\x00', b'\xd6@\x00\x00', b'8A\x00\x00', b'\x9dA\x00\x00', b'\x00B\x00\x00', b'aB\x00\x00', b'\xd6B\x00\x00', b'IC\x00\x00', b'\xaeC\x00\x00', b'\xceC\x00\x00', b'0D\x00\x00', b'\x95D\x00\x00', b'\xfaD\x00\x00', b'mE\x00\x00', b'\x8dE\x00\x00', b'\xf1E\x00\x00', b'`F\x00\x00', b'\xceF\x00\x00', b'\xf5F\x00\x00', b'iG\x00\x00', b'\x89G\x00\x00', b'\xecG\x00\x00', b'MH\x00\x00', b'\xbfH\x00\x00', b'$I\x00\x00', b'.I\x00\x00', b'\xa5I\x00\x00', b'\rJ\x00\x00', b'nJ\x00\x00', b'\xe2J\x00\x00', b'\x02K\x00\x00', b'jK\x00\x00', b'\xdfK\x00\x00', b'LL\x00\x00', b'\xadL\x00\x00', b'\x1bM\x00\x00', b'\x8eM\x00\x00', b'\xaeM\x00\x00', b'"N\x00\x00', b'\x8aN\x00\x00', b'\xf3N\x00\x00', b'aO\x00\x00', b'\xccO\x00\x00', b'\xecO\x00\x00', b'UP\x00\x00', b'\xc8P\x00\x00', b'\xe8P\x00\x00', b'QQ\x00\x00', b'\xbeQ\x00\x00', b'.R\x00\x00', b'\x9dR\x00\x00', b'\x10S\x00\x00', b'\x83S\x00\x00', b'\xecS\x00\x00', b'NT\x00\x00', b'\xbaT\x00\x00', b'\x1fU\x00\x00', b'MU\x00\x00', b'WU\x00\x00', b'\xb0U\x00\x00', b'\x15V\x00\x00', b'\x81V\x00\x00', b'\xedV\x00\x00', b'\\W\x00\x00', b'\xd3W\x00\x00', b'\xffW\x00\x00', b'\x1fX\x00\x00', b'\x81X\x00\x00', b'\xedX\x00\x00', b'NY\x00\x00', b'\xb1Y\x00\x00', b'\x1cZ\x00\x00', b'JZ\x00\x00', b'jZ\x00\x00', b'\xc3Z\x00\x00', b'([\x00\x00', b'\x94[\x00\x00', b'\x00\\\x00\x00', b'o\\\x00\x00', b'\xe6\\\x00\x00', b'\x12]\x00\x00', b'2]\x00\x00', b'\x94]\x00\x00', b'\x00^\x00\x00', b'a^\x00\x00', b'\xc4^\x00\x00', b'/_\x00\x00', b']_\x00\x00', b'g_\x00\x00', b'\xc0_\x00\x00', b'%`\x00\x00', b'\x91`\x00\x00', b'\xfd`\x00\x00', b'la\x00\x00', b'\xe3a\x00\x00', b'\x0fb\x00\x00', b'/b\x00\x00', b'\x91b\x00\x00', b'\xfdb\x00\x00', b'^c\x00\x00', b'\xc1c\x00\x00', b',d\x00\x00', b'Zd\x00\x00', b'zd\x00\x00', b'\xd3d\x00\x00', b'8e\x00\x00', b'\xa4e\x00\x00', b'\x10f\x00\x00', b'\x7ff\x00\x00', b'\xf6f\x00\x00', b'"g\x00\x00', b'Bg\x00\x00', b'\xa4g\x00\x00', b'\x10h\x00\x00', b'qh\x00\x00', b'\xd4h\x00\x00', b'?i\x00\x00', b'mi\x00\x00', b'wi\x00\x00', b'\xc6i\x00\x00', b'5j\x00\x00', b'\x9dj\x00\x00', b'\xc9j\x00\x00', b'\xe9j\x00\x00', b'Kk\x00\x00', b'\xb7k\x00\x00', b'\x18l\x00\x00', b'{l\x00\x00', b'\xe6l\x00\x00', b'\x06m\x00\x00', b'gm\x00\x00', b'\xd5m\x00\x00', b'9n\x00\x00', b'Yn\x00\x00', b'\xd2n\x00\x00', b'7o\x00\x00', b'\xa3o\x00\x00', b'\x0fp\x00\x00', b'~p\x00\x00', b'\xf5p\x00\x00', b'\x16q\x00\x00', b' q\x00\x00', b'lq\x00\x00', b'\xd1q\x00\x00', b'Er\x00\x00', b'lr\x00\x00', b'\xdfr\x00\x00', b'\xffr\x00\x00', b'rs\x00\x00', b'\xdas\x00\x00', b';t\x00\x00', b'\xa6t\x00\x00', b'\x0bu\x00\x00', b'+u\x00\x00', b'\x94u\x00\x00', b'\x08v\x00\x00', b'(v\x00\x00', b'\x9dv\x00\x00', b'\rw\x00\x00', b'-w\x00\x00', b'\x8ew\x00\x00', b'\xaew\x00\x00', b'\x1ax\x00\x00', b'\x83x\x00\x00', b'\xf7x\x00\x00', b'ky\x00\x00', b'\xd7y\x00\x00', b'<z\x00\x00', b'jz\x00\x00', b'tz\x00\x00', b'\xd5z\x00\x00', b'8{\x00\x00', b'\xac{\x00\x00', b'\x12|\x00\x00', b'\x8d|\x00\x00', b'\xfa|\x00\x00', b'[}\x00\x00', b'\xc6}\x00\x00', b'/~\x00\x00', b'\x9d~\x00\x00', b'\x04\x7f\x00\x00', b'c\x7f\x00\x00', b'\xcc\x7f\x00\x00', b'@\x80\x00\x00', b'\x9f\x80\x00\x00', b'\x13\x81\x00\x00', b'\x82\x81\x00\x00', b'\xe1\x81\x00\x00', b'U\x82\x00\x00', b'\xbd\x82\x00\x00', b'"\x83\x00\x00', b'\x81\x83\x00\x00', b'\xf5\x83\x00\x00', b'd\x84\x00\x00', b'\xd4\x84\x00\x00', b'3\x85\x00\x00', b'\x9c\x85\x00\x00', b'\x0f\x86\x00\x00', b'n\x86\x00\x00', b'\xd9\x86\x00\x00', b'B\x87\x00\x00', b'\xb0\x87\x00\x00', b'\x14\x88\x00\x00', b'u\x88\x00\x00', b'\xd4\x88\x00\x00', b'9\x89\x00\x00', b'\xb1\x89\x00\x00', b'\x19\x8a\x00\x00', b'z\x8a\x00\x00', b'\xef\x8a\x00\x00', b'b\x8b\x00\x00', b'\xd6\x8b\x00\x00', b'?\x8c\x00\x00', b'\xad\x8c\x00\x00', b'\x14\x8d\x00\x00', b's\x8d\x00\x00', b'\xdb\x8d\x00\x00', b'P\x8e\x00\x00', b'\xb8\x8e\x00\x00', b'\x17\x8f\x00\x00', b'c\x8f\x00\x00', b'\xb0\x8f\x00\x00', b'\x04\x90\x00\x00', b'G\x90\x00\x00', b'\x89\x90\x00\x00', b'\xff\x90\x00\x00', b'i\x91\x00\x00', b'\xdf\x91\x00\x00', b'+\x92\x00\x00', b'~\x92\x00\x00', b'\xf6\x92\x00\x00', b'-\x93\x00\x00', b'^\x93\x00\x00', b'\xa4\x93\x00\x00', b'\x19\x94\x00\x00', b'\x89\x94\x00\x00', b'\xdf\x94\x00\x00', b'\x14\x95\x00\x00', b'b\x95\x00\x00', b'\xa5\x95\x00\x00', b'\x1a\x96\x00\x00', b'p\x96\x00\x00', b'\xc2\x96\x00\x00', b'?\x97\x00\x00']
sus = sus[::-1]
las = int.from_bytes(sus[0],'little')
x =""
for i in range(1,len(sus)):
     n = int.from_bytes(sus[i],'little')
     x += chr(las - n)
     las = n
print(x[::-1])
```

And this happened:

![](https://i.imgur.com/xkDQWid.png)

Flag: `actf{making_it_to_the_top_is_kinda_exhausting_huh_LMTCBvjvLSx71FupV5NCuVR}`

The hardest challenge of this contest is `Uncertainty-rev` but I see it guessy, so I don't do this.
