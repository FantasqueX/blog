---
title: "Secconctf2022 Writeup"
date: 2022-11-13T15:57:27+08:00
summary: eguite
categories: ["writeup"]
---

# SECCON CTF 2022 Writeup

## eguite

This is a rust gui binary which accepts a string and check it. First, we need to find the main logic of check function. Luckily, the binary isn't stripped. We can get some information from function names. Search "click" in function names and figured out that the main logic is located in `eguite::Crackme::onclick::ha26112793d42c9d8`.

IDA thinks this function has one argument. The next thing we should do is to find where is the input. After searching memory using pwndbg, the input string pointer is located at `rdi + 128`. Now,the second check becomes easy. It checks whether the string is wrapped by "SECCON{}". The first check is confusing at first. I thought "43" should be char "+". After several attempts, I realized it checks the length of string.

![alt First Check](/seccon2022/eguite-first-check.webp)

The second check is kind of wierd. If the input string is all printable, the first while loop is trivial and unable to branch into the next if. All it does is check whether `input[v3] == '-'`. The next two checks are just the same. So, we know that `input[19] == '-' and input[26] == '-' and input[33] == '-'`.

The last check has four similar parts which alloc some memory, call some rust core functions and dealloc. In the last, it checks using some equations which can be solved by z3.

The z3 script is as follows.

```python
from z3 import *

x, y, z, w = BitVecs('x y z w', 64)
solve(x + y == 0x8B228BF35F6A, y + z == 15172161, z + w == 4199291551, w + x == 0x8B238557F7C8, y ^ z ^ w == 4184371021)
```

Because there are four similar parts, we can assume they are divided by `-`. And we can notice `from_str_radix`. Maybe it converts four hex string to integers.

I think source code maybe something like the following code snippets

```rust
use std::u64;

fn main() {
    let x = u64::from_str_radix("1f", 16);
    let y = x.unwrap_or(0);
    println!("{:?}", y);
}
```

Let's try it and we can get flag `SECCON{8b228b98e458-5a7b12-8d072f-f9bf1370}`.
