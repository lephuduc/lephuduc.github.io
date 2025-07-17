---
title: "CODEGATE in Korea"
description: "My trip to Korea and participating on CODEGATE 2025 Final"
summary: "My trip to Korea and participating on CODEGATE 2025 Final"
categories: ["Writeup"]
tags: ["Reverse","Blogs"]
#externalUrl: ""
date: 2025-07-12
draft: false
authors:
  - Jinn
cover: /images/post_covers/codegate_banner.jpg
---


## Overview

Here you are:

Recent days, I was traveling to South Korea and participating in CODEGATE 2025 Final, and that was really, really fun.

So, today I will talk about the one Reversing challenge that I managed to solve and my trip in Seoul.

### Table of Content

1. [Write-up for Reverse Challenge](#reverse-lowmaze)
2. [Traveling in Korea](#the-travel-competition-korea-trip)

## Reverse: LowMaze

Since you're here, I will discuss one interesting challenge in CODEGATE Final (also the only one I solved :D), LowMaze.

Actually, there are 4 different challenges in the Rev category: LowMaze, once golang-stripped, once rust-stripped, and the last one is python native Nuitka. All challenges are stripped and statically linked (so painful).

But it's a 24-hour competition. I spent a few first hours looking at all of these challenges and taking some notes. And the LowMaze is the last one I looked at, and I saw it was doable.

Then I spent the next several hours focusing on this challenge, and it's very interesting. I was only able to be the 4th solver of the challenge, but it's still meaningful to me.

![image](/images/codegate2025/challenge.png)
*(it's 290 points at the end of the contest but the "4 Solves" is not correct at that time.)*

### First look

**Challenge description:**

> Low And Deeeeeep MAZE
> ssh user@3.35.228.48 -p 2222 -i key
> Attachment:
> [for_user.zip]()


After extracting the file, we will have something like this:

![image](/images/codegate2025/image2.png)

It's a full system that is emulated using the given QEMU.

Since I can't connect (by using `conn.sh`) to the server at the time I wrote this blog, I will modify the `run.sh` to run it directly instead.

**run.sh**
```bash
#!/bin/bash
./qemu-install/bin/qemu-system-x86_64 -bios OVMF.fd -drive file="./app.disk",format=raw -m 64M -nographic
```
After running it, I see it's a normal maze game.

![alt text](/images/codegate2025/image.png)

![alt text](/images/codegate2025/image-1.png)

We can use WASD or arrow buttons to move the "Y", also known as the Player. We must avoid "E" (enemy) and get to the "D" (also the goal).

After we finish the first level, in level 2 we are blind, which means we can no longer see the enemies.


![alt text](/images/codegate2025/image-2.png)

I guess we need to solve about 20 blind maze to get the flag.

### Approach

There are 2 files that we need to focus on: `app.disk` and `OVMF.fd`.

**app.disk**

For a while, I was doing something weird with the file. I figured out this file was literally a disk, so we can mount it easily with the **mount** command:

```bash
mount 
```

I see the file `BOOTx64.EFI`, and it contains the main logic of our program. So I loaded it into IDA with the default configuration.

Here is the main function:

![alt text](/images/codegate2025/image-3.png)

The binary is also fully stripped, so I already renamed local variables and function names for easier understanding.

After some stuff like getting the random generator, there's a loop inside the main function that we'll focus on. That handles the maze levels.

```clike
if ( (unsigned int)maze_level_handler() )
  {
    while ( 1 )
    {
      ++level;
      if ( !(unsigned int)maze_level_handler() )
        break;
      if ( level == 20 )
      {
        print_text_at_pos(0, 7u, "You win!");
        show_flag();
        goto LABEL_18;
      }
    }
  }
```

We see that if the level reaches 20, we will get the flag.

Here's the code of `maze_level_handler()`:


```c
__int64 maze_level_handler()
{
    
... stripped ...

  v0 = 256i64;
  clear_counter = 0;
  grid_ptr = game_grid;
  while ( v0 )
  {
    *grid_ptr++ = 0;
    --v0;
  }
  do
  {
    for ( i = 0; i != 25; ++i )
      console_output(0, 9u, 32);
    ++clear_counter;
  }
  while ( clear_counter != 80 );
  print_status(stage_buffer, 100i64, "Stage: %02d", stage_num);
  enemy_ptr = &enemy_list[4];
  enemy_iter = enemy_list;
  print_text_at_pos(0, 4u, stage_buffer);
  player_pos = (*(__int64 (**)(void))get_player_pos)();
  aYou = 'Y';
  SEED = player_pos;
  cur_Y = (player_pos >> 4) & 0xF;
  cur_X = player_pos & 0xF;
  game_grid[16 * cur_Y + (player_pos & 0xF)] = 'Y';// player position
  do
  {
    do
    {
      enemy_pos = ((__int64 (*)(void))get_enemy_pos)();// only 1 byte
      goal_pos = enemy_pos;
      SEED = enemy_pos;
      enemy_y = (enemy_pos >> 4) & 0xF;
      enemy_x = goal_pos & 0xF;
      enemy_iter->y = enemy_y;
      enemy_iter->x = enemy_x;
    }
    while ( game_grid[16 * enemy_y + enemy_x] );
    LOBYTE(enemy_iter->char) = 'E';
    ++enemy_iter;
  }
  while ( enemy_iter != enemy_ptr );
  do
  {
    SEED = ((__int64 (*)(void))get_enemy_pos)();
    goal_Y = ((unsigned __int16)SEED >> 4) & 0xF;
    goal_X = SEED & 0xF;
    grid_cell_value = game_grid[16 * goal_Y + (SEED & 0xF)];
  }
  while ( grid_cell_value );
  aGoal = 'D';
  while ( 2 )
  {
    for ( row_counter = 0; row_counter != 16; ++row_counter )
    {
      do
        print_cell(0i64, 32);
      while ( v20 != 15 );
    }
    ui_counter = 4;
    do
    {
      console_output(8u, 0, 32);
      ++ui_counter;
      console_output(8u, 0, 32);
      print_text_at_pos(8u, 0, "   ");
      print_text_at_pos(8u, 0, "   ");
    }
    while ( ui_counter != 20 );
    console_output(8u, 0, 32);
    console_output(8u, 0, 32);
    console_output(8u, 0, 32);
    console_output(8u, 0, 32);
    if ( Normal_mode == 1 )
    {
      enemy_display_ptr = enemy_list;
      do
      {
        v15 = enemy_display_ptr->char;
        ++enemy_display_ptr;
        print_cell(4i64, v15);
      }
      while ( enemy_display_ptr != enemy_ptr );
      print_cell(1i64, aGoal);
    }
    else
    {
      print_text_at_pos(4u, 9u, "You BLIND...");
    }
    print_cell(2i64, aYou);
    print_status(status_buffer, 100i64, "STEP: %02d", step_count);
    print_text_at_pos(0, 7u, status_buffer);
    if ( cur_X != goal_X || cur_Y != goal_Y )
    {
      enemy = enemy_list;
      do
      {
        if ( cur_X == enemy->x && cur_Y == enemy->y )
          return grid_cell_value;
        ++enemy;
      }
      while ( enemy != enemy_ptr );
      user_input = Get_user_input();
      switch ( user_input )
      {
        case '\0':
          sub_1B50();
        case '\x04':
        case 'a':
          if ( cur_X <= 0 )
            goto DO_NOTTHING;
          --cur_X;
          break;
        case '\x03':
        case 'd':
          if ( cur_X <= 14 )
            ++cur_X;
          goto DO_NOTTHING;
        case '\x01':
        case 'w':
          if ( cur_Y <= 0 )
            goto DO_NOTTHING;
          new_y = cur_Y - 1;
          goto LABEL_47;
      }
      if ( user_input != 2 && user_input != 's' )
      {
        if ( user_input == 23 )
          return grid_cell_value;
DO_NOTTHING:
        if ( remaining_steps - 1 )
          continue;
        return grid_cell_value;
      }
      if ( cur_Y > 14 )
        goto DO_NOTTHING;
      new_y = cur_Y + 1;
LABEL_47:
      cur_Y = new_y;
      goto DO_NOTTHING;
    }
    return 1;
  }
}
```

I already renamed all the variables inside the function, so it's readable.

The first part of the function is doing some stuff to generate the maze and print it. The remaining part is a loop that gets our input and handles the movement.

We see some global variables that store the current location of the player (`cur_X`, `cur_Y`). And remember, we only have 40 moves before being eliminated.

So, this time I spent several hours understanding the maze generator.

You can see there are 2 functions that look like they get random numbers.


- **get_player_pos**
- **get_enemy_pos**

**get_player_pos** seems to be called only once, and it returns a random number along with the player position. We will figure out this function later.

**get_enemy_pos** is called in a loop:

There is an array that I've defined as a struct; each element contains the character "E" and the position (x, y) itself.

![alt text](/images/codegate2025/image-4.png)

```cpp
do
  {
    do
    {
      enemy_pos = ((__int64 (*)(void))get_enemy_pos)();// only 1 byte
      goal_pos = enemy_pos;
      SEED = enemy_pos;
      enemy_y = (enemy_pos >> 4) & 0xF;
      enemy_x = goal_pos & 0xF;
      enemy_iter->y = enemy_y;
      enemy_iter->x = enemy_x;
    }
    while ( game_grid[16 * enemy_y + enemy_x] );
    LOBYTE(enemy_iter->char) = 'E';
    ++enemy_iter;
  }
  while ( enemy_iter != enemy_ptr );
```

This one iterates through the array and keeps generating enemy positions until it finds 4 different enemy positions.

```cpp
do
  {
    SEED = ((__int64 (*)(void))get_enemy_pos)();
    goal_Y = ((unsigned __int16)SEED >> 4) & 0xF;
    goal_X = SEED & 0xF;
    grid_cell_value = game_grid[16 * goal_Y + (SEED & 0xF)];
  }
  while ( grid_cell_value );
```

Next, it will loop to generate the win position ("D"). It keeps looping until it gets a position that does not occur in the grid before.

```cpp
if ( Normal_mode == 1 )
    {
      enemy_display_ptr = enemy_list;
      do
      {
        v15 = enemy_display_ptr->char;
        ++enemy_display_ptr;
        print_cell(4i64, v15);
      }
      while ( enemy_display_ptr != enemy_ptr );
      print_cell(1i64, aGoal);
    }
    else
    {
      print_text_at_pos(4u, 9u, "You BLIND...");
    }
    print_cell(2i64, aYou);
    print_status(status_buffer, 100i64, "STEP: %02d", step_count);
    print_text_at_pos(0, 7u, status_buffer);
    if ( cur_X != goal_X || cur_Y != goal_Y ){
        
        ... stripped ...
    }
        
```

Once the maze is completely generated, it will handle the player’s movement and check if we win, lose, or hit an enemy,...

The program seems straightforward until we look at `get_player_pos` and `get_enemy_pos`.

These two functions are just undecompilableeven disassemblable.


![alt text](/images/codegate2025/image-5.png)

And even the code that handles the initialization of the random is unreadable:

![alt text](/images/codegate2025/image-6.png)

I thought this was a decompiler error, so I didn't think too much and got stuck for a while until I tried another approach.

### Debugging

The binary is the UEFI BootLoader and runs with QEMU, so we can debug it in IDA like a normal program.

To debug it, we need to modify the run script for QEMU to suspend the program and wait for the attach connection using the `-S -s` flags.

**run.sh**

```bash
#!/bin/bash
./qemu-install/bin/qemu-system-x86_64 -bios OVMF.fd -drive file="app.disk",format=raw -m 64M -nographic -s -S
```
Once it runs, it will hang and wait for the debugger to attach.

Then, I'll use **gdb** with pwndbg to debug this program.

Start **gdb** with our `.EFI` file, then use the command below to attach, and press `C` to continue the program after attaching successfully.

```bash
pwndbg> target remote localhost:1234 
```

![alt text](/images/codegate2025/image-7.png)

Since the program will wait for our input at this screen, we need to find its base address.

![alt text](/images/codegate2025/image-8.png)

Reference by this [blog](https://blog.randorisec.fr/fr/ctf-ecw-2022/), I was do a trick that find the imagebase by looking at the string.


![alt text](/images/codegate2025/image-9.png)

Interrupt the program, then find the string we saw in the main function.

![alt text](/images/codegate2025/image-10.png)

![alt text](/images/codegate2025/image-11.png)

Then take the first result and subtract the offset of the string, and we can find the image base.

![alt text](/images/codegate2025/image-12.png)

Once we have the image base, we can easily place a breakpoint. I’ve tried placing breakpoints at both instructions that call **get_player_pos()** and **get_enemy_pos()** to see what they do.

```
Num     Type           Disp Enb Address            What
...
2       breakpoint     keep y   0x0000000001d761f7 -< (call    near ptr get_player_pos)
3       breakpoint     keep y   0x0000000001d76240 -< (call    near ptr get_enemy_pos)
```

Continue the program and press any key, and we will see the first breakpoint hit:

![alt text](/images/codegate2025/image-13.png)

At this point, we can note the values of these registers, then use `si` to step into the function:

![alt text](/images/codegate2025/image-14.png)

This time, we receive a message saying "Invalid instructions," but surprisingly, if we continue to step out of the function, it still runs correctly and does not crash.

![alt text](/images/codegate2025/image-15.png)

And we can see that `RAX` is now `0x7322003992`, which means the function still works. Weird.

The same thing happens with `get_enemy_pos`, but with a different return value.

So from there, I got stuck again and spent the next few hours trying to figure it out.


#### get_enemy_pos
Then I start my guess:

- Firstly, from this definition: http://en.wikipedia.org/wiki/Linear_congruential_generator and [this question](https://stackoverflow.com/questions/3062746/special-simple-random-number-generator), the sample generator could look like this:

```c
int seed = 123456789;

int rand()
{
  seed = (a * seed + c) % m;
  return seed;
}
```

I suppose the `get_enemy_pos` function is structured like that, and since we're debugging, we know the input seed and the next calculated seed. Our mission is to find `a` and `c` (`m` is 2^64 since `RAX` is 64-bit).

I tried to set the `RIP` multiple times and debug to get the input–return value pairs, then tried to solve it with `z3`:

```python
from z3 import *

x = BitVec('x', 64)
y = BitVec('y', 64)
s = Solver()

# get enemy position
s.add(0x179b*x + y == 0xd68ee94eccf10b40)
s.add(0x4642*x + y == 0x2de5569e9f51179b)
s.add(0x6fe5*x + y == 0x8a2f10ba53df4642)

if s.check() == sat:
    m = s.model()
    print(f"x: {m[x]}, y: {m[y]}")
```

And we found the result:
```
x: 6364136223846793005, y: 1
```
That mean `get_enemy_pos()` is:

```python
def get_enemy_pos(seed):
    return 6364136223846793005*seed + 1
```

I've tested several time and sure it correct.

#### get_player_pos

I also did the same thing to figure out the remaining function, but it didn't work.

```python
# get player position
s.add(0x1234*x + y == 0x2468001235)
s.add(0x4567*x + y == 0x8ace004563)
s.add(0x89ab*x + y == 0x113560089a3)
s.add(0x7890*x + y == 0xf120007897)
```

Z3 was unable to solve it anymore. I tried many, many guesses like:

- Taking the returned value, then dividing it by the seed to see the difference.
- Trying AND/OR/NOT and modular operations.

Every guess gave me more clues about the operator, until I finally found the correct function is:

```python
def get_player_pos(seed):
    return (seed*0x2000001)^(seed>>12)
```

### Solve

To solve this challenge, we need to find the correct initial seedthe first seed that is passed into `get_player_pos` at level 1.

To find that seed, I took the first level state (enemy positions, player position, and destination), then tried to brute-force (0x1000) seeds until I found one that generated the exact same map as level 1 (the only level visible to us).

To try this, I copied the first level into `sample_state.txt`, then wrote a Python script that parses the level state and finds the seed.

```python

def get_sample_state(): 
    with open('sample_state.txt','r') as f:
        data = f.readlines()
        assert len(data) == 16

    enemy_pos = []
    player_pos = None
    goal = None
    for i in range(len(data)):
        for j in range(len(data[i])):
            if data[i][j] == 'E':
                enemy_pos.append(((j-15)//3,i))
                continue
            elif data[i][j] == 'Y':
                player_pos = ((j-15)//3,i)
                continue
            elif data[i][j] == 'D':
                goal = ((j-15)//3,i)
                continue
    print(f"Sample: Enemy Position: {enemy_pos}")
    print(f"Sample: Player Position: {player_pos}")
    print(f"Sample: Goal Position: {goal}")
    return enemy_pos, player_pos, goal

... stripped ...
def get_stage(seed):
    current_player_pos = get_player_pos(seed)
    seed = current_player_pos & 0xffff
    current_player_pos = (current_player_pos & 0xf, (current_player_pos >> 4) & 0xf)
    
    enemy_positions = []
    
    while len(enemy_positions) < 4:
        enemy_pos = get_enemy_pos(seed)
        seed = enemy_pos & 0xffff
        enemy_pos = (enemy_pos & 0xf, (enemy_pos >> 4) & 0xf)
        
        if enemy_pos not in enemy_positions and enemy_pos != current_player_pos:
            enemy_positions.append(enemy_pos)
    goal_pos = ()
    while True:
        seed = get_enemy_pos(seed)
        seed = seed & 0xffff
        
        x = seed & 0xf
        y = (seed >> 4) & 0xf
        if (x,y) not in enemy_positions and (x,y) != current_player_pos:
            goal_pos = (x, y)
            break
        
    return current_player_pos, enemy_positions, goal_pos, seed

## too many valid seeds, need to filter them
def find_seed(enemy_pos, player_pos,goal):
    seed_found = None
    for i in range(0x10000):
        cur_pp, enemy_positions, goal_pos, _ = get_stage(i)

        if enemy_pos[0] in enemy_positions and \
           enemy_pos[1] in enemy_positions and \
           enemy_pos[2] in enemy_positions and \
           enemy_pos[3] in enemy_positions and \
           cur_pp == player_pos and goal_pos == goal and \
           enemy_positions[0] != enemy_positions[1] and \
           enemy_positions[0] != enemy_positions[2] and \
           enemy_positions[0] != enemy_positions[3] and \
           enemy_positions[1] != enemy_positions[2] and \
           enemy_positions[1] != enemy_positions[3] and \
           enemy_positions[2] != enemy_positions[3]:

            next_player_pos,next_seed = get_next_player_pos(i)
            level2_player_pos = get_level_state('sample_state2.txt')
            if next_player_pos == level2_player_pos:
                print(f"2 Valid seed found: {i:#04x}")
                seed_found = i
                level3_player_pos = get_level_state('sample_state3.txt')
                next_player_pos,next_seed = get_next_player_pos(next_seed)
                if next_player_pos == level3_player_pos:
                    print(f"3 Truly Valid seed found: {i:#04x}")
                    seed_found = i
                    level4_player_pos = get_level_state('sample_state4.txt')
                    next_player_pos,next_seed = get_next_player_pos(next_seed)
                    if next_player_pos == level4_player_pos:
                        print(f"4 Truly Valid seed found: {i:#04x}")
                        seed_found = i
                        break

    return seed_found
```

Let's talk about `next_player_pos`:

After trying with the first state, it gave me too many correct seedsmeaning there's not only one seed that can generate the same level 1.

So from there, I took the found seeds to generate the level 2 maze and checked the player position ("Y", the only visible element) to filter the seeds.

I did the same with level 3 and level 4, and eventually, we filtered it down to only one correct seed.

Once we have the correct seed, we can generate all 20 levels and use BFS to find the path easily:

```python
from collections import deque

def find_path(start, enemies, goal, max_moves=40):
    directions = {'a': (-1, 0), 'd': (1, 0), 'w': (0, -1), 's': (0, 1)}
    enemy_set = set(enemies)

    queue = deque()
    queue.append((start, ""))  # (current_position, path_taken)
    visited = set()
    visited.add(start)

    while queue:
        (x, y), path = queue.popleft()
        
        if len(path) > max_moves:
            continue
        
        if (x, y) == goal:
            return path 

        for move, (dx, dy) in directions.items():
            nx, ny = x + dx, y + dy
            if 0 <= nx < 16 and 0 <= ny < 16 and (nx, ny) not in visited and (nx, ny) not in enemy_set:
                visited.add((nx, ny))
                queue.append(((nx, ny), path + move))

    return None
```

Then, after combining all these things together, I wrote a script that is semi-automated to solve the challenge. You can find it here:

```python
from collections import deque

def find_path(start, enemies, goal, max_moves=40):
    directions = {'a': (-1, 0), 'd': (1, 0), 'w': (0, -1), 's': (0, 1)}
    enemy_set = set(enemies)

    queue = deque()
    queue.append((start, ""))  # (current_position, path_taken)
    visited = set()
    visited.add(start)

    while queue:
        (x, y), path = queue.popleft()
        
        if len(path) > max_moves:
            continue
        
        if (x, y) == goal:
            return path  # return the first valid path found

        for move, (dx, dy) in directions.items():
            nx, ny = x + dx, y + dy
            if 0 <= nx < 16 and 0 <= ny < 16 and (nx, ny) not in visited and (nx, ny) not in enemy_set:
                visited.add((nx, ny))
                queue.append(((nx, ny), path + move))

    return None

def get_enemy_pos(seed,debug=False):
    if debug:
        print(f"Seed: {seed:#04x}")
    return 6364136223846793005*seed + 1

def get_player_pos(seed,debug=False):
    if debug:
        print(f"Seed: {seed:#04x}")
    return (seed*0x2000001)^(seed>>12)

def get_sample_state(): 
    with open('sample_state.txt','r') as f:
        data = f.readlines()
        assert len(data) == 16

    enemy_pos = []
    player_pos = None
    goal = None
    for i in range(len(data)):
        for j in range(len(data[i])):
            if data[i][j] == 'E':
                enemy_pos.append(((j-15)//3,i))
                continue
            elif data[i][j] == 'Y':
                player_pos = ((j-15)//3,i)
                continue
            elif data[i][j] == 'D':
                goal = ((j-15)//3,i)
                continue
    print(f"Sample: Enemy Position: {enemy_pos}")
    print(f"Sample: Player Position: {player_pos}")
    print(f"Sample: Goal Position: {goal}")
    return enemy_pos, player_pos, goal

def get_level_state(filename):
    with open(filename,'r') as f:
        data = f.readlines()
    player_pos = None
    for i in range(len(data)):
        for j in range(len(data[i])):
            if data[i][j] == 'Y':
                player_pos = ((j-15)//3,i)
                # print(f"Player Position: {player_pos}")
    return player_pos

def get_next_player_pos(valid_seed):
    _,_,_,next_seed = get_stage(valid_seed)
    next_player_pos = get_player_pos(next_seed) & 0xffff
    return (next_player_pos & 0xf, (next_player_pos >> 4) & 0xf),next_seed

def get_stage(seed):
    current_player_pos = get_player_pos(seed)
    seed = current_player_pos & 0xffff
    current_player_pos = (current_player_pos & 0xf, (current_player_pos >> 4) & 0xf)
    
    enemy_positions = []
    
    while len(enemy_positions) < 4:
        enemy_pos = get_enemy_pos(seed)
        seed = enemy_pos & 0xffff
        enemy_pos = (enemy_pos & 0xf, (enemy_pos >> 4) & 0xf)
        
        if enemy_pos not in enemy_positions and enemy_pos != current_player_pos:
            enemy_positions.append(enemy_pos)
    goal_pos = ()
    while True:
        seed = get_enemy_pos(seed)
        seed = seed & 0xffff
        
        x = seed & 0xf
        y = (seed >> 4) & 0xf
        if (x,y) not in enemy_positions and (x,y) != current_player_pos:
            goal_pos = (x, y)
            break
        
    return current_player_pos, enemy_positions, goal_pos, seed

## too many valid seeds, need to filter them
def find_seed(enemy_pos, player_pos,goal):
    seed_found = None
    for i in range(0x10000):
        cur_pp, enemy_positions, goal_pos, _ = get_stage(i)

        if enemy_pos[0] in enemy_positions and \
           enemy_pos[1] in enemy_positions and \
           enemy_pos[2] in enemy_positions and \
           enemy_pos[3] in enemy_positions and \
           cur_pp == player_pos and goal_pos == goal and \
           enemy_positions[0] != enemy_positions[1] and \
           enemy_positions[0] != enemy_positions[2] and \
           enemy_positions[0] != enemy_positions[3] and \
           enemy_positions[1] != enemy_positions[2] and \
           enemy_positions[1] != enemy_positions[3] and \
           enemy_positions[2] != enemy_positions[3]:

            next_player_pos,next_seed = get_next_player_pos(i)
            level2_player_pos = get_level_state('sample_state2.txt')
            if next_player_pos == level2_player_pos:
                print(f"2 Valid seed found: {i:#04x}")
                seed_found = i
                level3_player_pos = get_level_state('sample_state3.txt')
                next_player_pos,next_seed = get_next_player_pos(next_seed)
                if next_player_pos == level3_player_pos:
                    print(f"3 Truly Valid seed found: {i:#04x}")
                    seed_found = i
                    level4_player_pos = get_level_state('sample_state4.txt')
                    next_player_pos,next_seed = get_next_player_pos(next_seed)
                    if next_player_pos == level4_player_pos:
                        print(f"4 Truly Valid seed found: {i:#04x}")
                        seed_found = i
                        break

    return seed_found

def print_level(seed, debug=False):

    cur_pp, enemy_positions, goal_pos, next_seed = get_stage(seed)
    
    if debug:
        print(cur_pp, enemy_positions, goal_pos)
        for i in range(16):
            for j in range(16):
                if j == goal_pos[0] and i == goal_pos[1]:
                    print('D', end='')
                elif j == cur_pp[0] and i == cur_pp[1]:
                    print('Y', end='')
                elif j == enemy_positions[0][0] and i == enemy_positions[0][1]:
                    print('E', end='')
                elif j == enemy_positions[1][0] and i == enemy_positions[1][1]:
                    print('E', end='')
                elif j == enemy_positions[2][0] and i == enemy_positions[2][1]:
                    print('E', end='')
                elif j == enemy_positions[3][0] and i == enemy_positions[3][1]:
                    print('E', end='')
                else:
                    print('-', end='')
            print()
    return cur_pp,enemy_positions,goal_pos,next_seed

def print_found(seed,solved_levels):
    _aseed = seed
    large_path = ''

    for i in range(20):
        current_pos, enemy_positions, goal_pos, next_seed = print_level(_aseed, debug=False)
        path = find_path(current_pos, enemy_positions, goal_pos, max_moves=40)
        if path is not None:
            if i >= solved_levels:
                large_path += path
            print(f"Path found for Level {i+1}, seed {_aseed:#04x}: {path}")
            _aseed = next_seed
        else:
            print(f"No path found for Level {i+1}, seed {_aseed:#04x}")
            break
    
    print(f"Large path: {large_path}")

if __name__ == "__main__":

    enemy_pos, player_pos, goal = get_sample_state()
    
    level1_seed = find_seed(enemy_pos, player_pos,goal)
    
    print(f"Found Level 1 Seed: {level1_seed:#04x}")
    
    # Print the first level   
    cur_pp,enemy_positions,goal_pos, level2_seed = print_level(level1_seed, debug=True)
    print("Path:", find_path(cur_pp, enemy_positions, goal_pos, max_moves=40))
    
    print(f"Level 2 Seed: {level2_seed:#04x}")
    cur_pp,enemy_positions,goal_pos, level3_seed = print_level(level2_seed, debug=True)
    print("Path:", find_path(cur_pp, enemy_positions, goal_pos, max_moves=40))
    
    print(f"Level 3 Seed: {level3_seed:#04x}")
    cur_pp,enemy_positions,goal_pos, level4_seed = print_level(level3_seed, debug=True)
    print("Path:", find_path(cur_pp, enemy_positions, goal_pos, max_moves=40))

    print(f"Level 4 Seed: {level4_seed:#04x}")
    cur_pp,enemy_positions,goal_pos, level5_seed = print_level(level4_seed, debug=True)
    print("Path:", find_path(cur_pp, enemy_positions, goal_pos, max_moves=40))

    print_found(0x47de,3)
    
```

Flag: **codegate2025{0c41c07e519a86b5552781a59fcbace7}**

Thanks to the author for the interesting challenge :D

## The Travel-Competition Korea Trip

### First time coming to Korea

I stayed 5 days and 4 nights in Korea, but one of them was spent on CODEGATE.

This is not the first time I’ve participated in an international CTF competition, but this time it was 24 hours straight without sleeping, lying down, or returning to the hotel at night. It started exactly at 10:00 AM on July 10 and ended at 10:00 AM on July 11.

Fortunately, I came to Korea on July 8, and Myeongdong was the first place I stayed.

![alt text](/images/codegate2025/myeongdong_street.JPEG)

The first impressive thing is that the air is so fresh and the streets are so clean.

But on the other hand, the weather at the time I arrived was very hot. It was around ~36 degrees, and you couldn't stay under the sunlight for too long (for sure).

### Lunch

The first food I tried in Korea was called ...

You can find it here:

### Changdeokgung Palace

Since we arrived on Tuesday, the **Gyeongbokgung Palace** was closed, so we went to **Changdeokgung Palace** instead.

It was 1:00 PM, and it was crazy walking under the sunlight at 35°C while taking picturesbut it was still fun though.

![alt text](/images/codegate2025/palace.JPEG)

I even rented a Hanbok to take pictures, and surprisingly, some Japanese tourists thought I was Korean. They asked me to take some pictures with them, and we took a lot of photos together. It was really nice. (Sorry for censoring the face.)

![alt text](/images/codegate2025/taking_picture.JPEG)

We also bought tickets to the Secret Garden to explore more, and it was beautiful there:

![alt text](/images/codegate2025/secret_garden.JPEG)

Then, we got back to the hotel at 5:00 PM to check in (check-in had to be after 3:00 PM, really!!) and rested until the evening.

### Myeong-dong Shopping Street

After waking up, we saw a little rainand fortunately, it was over before we arrived at the street, which made it even more beautiful and pleasant.

![alt text](/images/codegate2025/myeongdong_street_night.JPEG)

There wasn’t much going on here since we were just exploring and buying some souvenirs.

![alt text](/images/codegate2025/shopping_street.JPEG)

Thankfully, we found a restaurant and had some fried chicken. There was so much chicken, and it was even cheap!

![alt text](/images/codegate2025/fried_chicken.JPEG)

### Namsan Mountain

The next morning, we spent some time going to Namsan Mountain and enjoying the view. Here’s the beautiful scenery from the cable car.

![alt text](/images/codegate2025/cable_cabin.JPEG)

![alt text](/images/codegate2025/mountain_view.JPEG)

We didn’t go to Namsan Tower because we didn’t have enough time (or money :D).

Then we had a good lunch (at the shopping street again).

![alt text](/images/codegate2025/lunch.JPEG)

### COEX

Then we went to Gangnam, took a rest there, and found some local food (it was too expensive but good tho :D):

![alt text](/images/codegate2025/local_food.JPEG)

After that, we went to the COEX Mall, especially the Starfield Library:

![alt text](/images/codegate2025/starfield_library.JPEG)

The mall is just soooo bigI couldn't even explore all of it in several hours. But at least, we visited many stores and bought some interesting things. I even found LEGO thereone of my favorite things, haha.

![alt text](/images/codegate2025/lego.JPEG)

### CODEGATE Venue

CODEGATE was held in the Grand Ballroom inside COEX. It's big though.

![alt text](/images/codegate2025/room.JPEG)

You know? 24 hours straight with this view is crazyyyy...

![alt text](/images/codegate2025/laptop_view.JPEG)

But they also had a food table and gave us some food at nightI almost forgot to eat because I was so focused on solving a challenge :D

![alt text](/images/codegate2025/foot_table.JPEG)

I also went outside and saw some 8-bit arcade gamesit was fun.

![alt text](/images/codegate2025/8bit.JPEG)

Then we came back to attend the award ceremony.

![alt text](/images/codegate2025/award_ceremony.JPEG)

And after that, we had a Hacker Networking Lunch.

![alt text](/images/codegate2025/hacking-network-lunch.JPEG)

We took a rest in another room, then I came back to another hotel in Myeong-dong again.

### LoL Park – T1 Basecamp

On the last day in Seoul, I met up with my friend and explored LoL Park.

There’s a cute Yuumi!!!

![alt text](/images/codegate2025/yummi.JPEG)

And we also visited the T1 Basecamp:

![alt text](/images/codegate2025/t1basecamp.JPEG)

Then, we had our last lunch before heading back to Vietnam:

![alt text](/images/codegate2025/last_lunch.JPEG)

## The End

Thank you for reading my blog. Since this is a technical blog, I just briefly covered the trip and some highlights.

I hope you guys enjoyed it, and feel free to let me know if I missed or got anything wrong.

Love you all ❤️
