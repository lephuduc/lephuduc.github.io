---
title: "Note"
description: "Just a simple note"
summary: "Just a simple note"
categories: ["Writeup"]
tags: ["Note"]
#externalUrl: ""
date: 2021-01-01
draft: false
authors:
  - Jinn
---

# Note

## Setup Kernel Debug

1. Download [Virtual-KD redux](https://github.com/4d61726b/VirtualKD-Redux).
2. Install [Windbg Preview](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwi11Myk0Ob7AhXltlYBHeXlDsgQFnoECAsQAQ&url=https%3A%2F%2Fwww.microsoft.com%2Fstore%2Fapps%2F9pgjgd53tn86&usg=AOvVaw3WMwYktm6pOGcpYO-JxdQ3).
3. In the guest machine, run `target64\install.exe` and wait for computer restart. Then press F8 and chose `Disable enforcement driver signature`.
4. In the host machine, run `vmon64.exe` to attach debugger to VM kernel.

There are some useful command in Windebugger:

| command | function |
|:-------- |:--------:|
| g     |  go   |
|  ctrl + break     |   break   |
| db <start> <end> | view raw bytes from start to end |


Cheat sheet here: https://github.com/repnz/windbg-cheat-sheet
    
## Run dll function in C
    
Sample program in Flare-on challenge:

```c
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

int main(){
	FARPROC func;
	HMODULE hLib = LoadLibraryA("flareon2016challenge.dll");
	int ord = 30;
	while (ord!=51){
		func = GetProcAddress(hLib, MAKEINTRESOURCE(ord));
		ord = func();
	}
	printf("%d\n",ord); // check
	func = GetProcAddress(hLib, MAKEINTRESOURCE(ord));
	func();
	return 0;
}
```

Then, if we want to dump bytes from this program, try to attach by debugger and use `get_bytes(indx,len)` with IDAPthon or using this script:
    
```c
    //dump plaintext to file
	plaintxt = *(uint32_t*)((uint32_t)exp+0x2e);
	hFile = CreateFile("out", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 
	FILE_ATTRIBUTE_NORMAL, 0);
	WriteFile(hFile, (LPCVOID)plaintxt, 0x1A10, 0, 0);
	CloseHandle(hFile);
```

Define prototype of our function:
    
```c
typedef VOID (*FunctionName)(
<TypeData1> <Name arg1>,    //can be DWORD, BYTE *, ...
<TypeData2> <Name arg2>,    //
...
);
```
Note: We can using `GetProcAddress(hDll,"nameOfFunction")` to reference function from dll.

# Tips while using z3

Using z3 to find the flag:
    
```python
import z3
FLAGLENGTH = ...
flag = []
for i in range(FLAGLENGTH):
    flag.append(z3.BitVec('f'+str(i),8))

s.add(...)

while s.check()==sat:
    m = m.model()
    print(m)
```
    
When we have a model contain flag, using this code to print flag:
```python
for i in range(FLAGLENGTH):
    print(chr(m[flag[i]].as_long()),end = "")
print()
```

# Linux kernel

Decompress kernel:

```bash
mkdir initramfs
cd initramfs
cp ../initramfs.cpio.gz .
gunzip ./initramfs.cpio.gz
cpio -idm < ./initramfs.cpio
rm initramfs.cpio
```

Debug kernel with gdb:
```bash
gdb -q vmlinux

target remote:1234
```
At VM startup time by appending "-s -S" to the QEMU command line

For more information: https://docs.kernel.org/dev-tools/gdb-kernel-debugging.html