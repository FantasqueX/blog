---
title: "Dcctf2022q Writeup"
date: 2022-06-02T20:25:01+08:00
summary: ncuts
categories: ["writeup"]
---

# DefconCTF2022Quals Writeup

Played DefconCTF2022 Quals last weekend with Water Paddler and made some little contribution to the solution of ncuts.

## ncuts

We can download a 7zip file which contains 24315 binary files. After looking through these binary files, we can notice that these binary files cover a lot of architectures, almost every architecture supported by qemu. Although it is easy to solve just one binary, it is quite a difficult task to solve all of them. The first idea is to use angr to solve these binary files automatically. One of our teammates SuperFashi wrote one angr scripts which is able to solve some challenges. However, nobody went further using angr. We tried to solve some binary files manually and figured out they used three obvious templates except for Crystal. So we can solve each template each architecture by one script. We listed a matrix whose column represents architecture and whose row represents template. This task can be parallelized and the difficulty is to find many players to fill out the matrix. How to solve one pattern of one architecture specifically? I use regex to parse the output of objdump to extract the data and calculate the answer. The script is listed as follows.

```python
import subprocess
import re
import ctypes
import sys

known = {}

with open("combined_21627.txt", "r", encoding='utf-8') as f:
    for i in f:
        res = i.strip().split(" ")
        known[int(res[0])] = int(res[1])

re_mipsel = re.compile('ncuts\/(\d*): ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1 \(SYSV\), statically linked, BuildID\[sha1\]=([a-f0-9]*), for GNU\/Linux 3\.2\.0, stripped')
re_sparc64 = re.compile('ncuts\/(\d*): ELF 64-bit MSB executable, SPARC V9, Sun UltraSPARC1 Extensions Required, relaxed memory ordering, version 1 \(SYSV\), statically linked, BuildID\[sha1\]=([a-f0-9]*), for GNU\/Linux 3\.2\.0, stripped')
re_hppa = re.compile('ncuts\/(\d*): ELF 32-bit MSB executable, PA-RISC, 1\.1 version 1 \(GNU\/Linux\), statically linked, BuildID\[sha1\]=([a-f0-9]*), for GNU\/Linux 3\.2\.0, stripped')
re_alpha = re.compile('ncuts\/(\d*): ELF 64-bit LSB executable, Alpha \(unofficial\), version 1 \(SYSV\), statically linked, BuildID\[sha1\]=([a-f0-9]*), for GNU\/Linux 3\.2\.0, stripped')
re_aarch64 = re.compile('ncuts\/(\d*): ELF 64-bit LSB executable, ARM aarch64, version 1 \(GNU\/Linux\), statically linked, BuildID\[sha1\]=([a-f0-9]*), for GNU\/Linux 3\.7\.0, stripped')
re_m68k = re.compile('ncuts\/(\d*): ELF 32-bit MSB executable, Motorola m68k, 68020, version 1 \(SYSV\), statically linked, BuildID\[sha1\]=([a-f0-9]*), for GNU\/Linux 3\.2\.0, stripped')
re_ppc = re.compile('ncuts\/(\d*): ELF 32-bit MSB executable, PowerPC or cisco 4500, version 1 \(SYSV\), statically linked, BuildID\[sha1\]=([a-f0-9]*), for GNU\/Linux 3\.2\.0, stripped')
re_riscv64 = re.compile('ncuts\/(\d*): ELF 64-bit LSB executable, UCB RISC-V, RVC, double-float ABI, version 1 \(SYSV\), statically linked, BuildID\[sha1\]=([a-f0-9]*), for GNU\/Linux 4\.15\.0, stripped')
re_ppc64 = re.compile('ncuts\/(\d*): ELF 64-bit MSB executable, 64-bit PowerPC or cisco 7500, Power ELF V1 ABI, version 1 \(GNU\/Linux\), statically linked, BuildID\[sha1\]=([a-f0-9]*), for GNU\/Linux 3\.2\.0, stripped')
re_sh4 = re.compile('ncuts\/(\d*): ELF 32-bit LSB executable, Renesas SH, version 1 \(SYSV\), statically linked, BuildID\[sha1\]=([a-f0-9]*), for GNU\/Linux 3\.2\.0, stripped')
re_mips = re.compile('ncuts\/(\d*): ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 \(SYSV\), statically linked, BuildID\[sha1\]=([a-f0-9]*), for GNU\/Linux 3\.2\.0, stripped')
re_s390x = re.compile('ncuts\/(\d*): ELF 64-bit MSB executable, IBM S\/390, version 1 \(GNU\/Linux\), statically linked, BuildID\[sha1\]=([a-f0-9]*), for GNU\/Linux 3\.2\.0, stripped')
re_mips64 = re.compile('ncuts\/(\d*): ELF 64-bit MSB executable, MIPS, MIPS64 rel2 version 1 \(SYSV\), statically linked, BuildID\[sha1\]=([a-f0-9]*), for GNU\/Linux 3\.2\.0, stripped')
pattern = re.compile("\s*[a-f0-9]*:\s*[a-f0-9]*\s*lui\sa\d,(0x[a-f0-9]*)(?:\n|\s*#\s*0x[a-f0-9]*\n)\s*[a-f0-9]*:\s*[a-f0-9]*\s*xor\sa\d,a\d,a\d(?:\n|\s*#\s*0x[a-f0-9]*\n)\s*[a-f0-9]*:\s*[a-f0-9]*\s*addi\sa\d,a\d,(-?[0-9]*)(?:\n|\s*#\s*0x[a-f0-9]*\n)\s*[a-f0-9]*:\s*[a-f0-9]*\s*bne\sa\d,a\d,0x[a-f0-9]*(?:\n|\s*#\s*0x[a-f0-9]*\n)\s*[a-f0-9]*:\s*[a-f0-9]*\s*lui\sa\d,(0x[a-f0-9]*)(?:\n|\s*#\s*0x[a-f0-9]*\n)\s*[a-f0-9]*:\s*[a-f0-9]*\s*addi\sa\d,a\d,(-?[0-9]*)(?:\n|\s*#\s*0x[a-f0-9]*\n)\s*[a-f0-9]*:\s*[a-f0-9]*\s*bne\sa\d,a\d,0x[a-f0-9]*(?:\n|\s*#\s*0x[a-f0-9]*\n)")


for i in range(24315):
    if i in known:
        continue
    file_output = subprocess.run(["file", f"ncuts/{i}"], capture_output=True).stdout.decode().strip()

    # print(f'{i}: ', end='')
    if res_alpha := re_alpha.match(file_output):
        # print("alpha")
        pass
    elif res_mipsel := re_mipsel.match(file_output):
        # print(f'{i}: ', end='')
        # print("mipsel")
        pass
    elif res_sparc64 := re_sparc64.match(file_output):
        # print("sparc64")
        pass
    elif res_hppa := re_hppa.match(file_output):
        # print('hppa')
        pass
    elif res_aarch64 := re_aarch64.match(file_output):
        # print(f'{i}: ', end='')
        # print('aarch64')
        pass
    elif res_m68k := re_m68k.match(file_output):
        # print('m68k')
        pass
    elif res_ppc := re_ppc.match(file_output):
        # print('ppc')
        pass
    elif res_riscv64 := re_riscv64.match(file_output):
        output = subprocess.run(["riscv64-linux-gnu-objdump", "-d", f"ncuts/{i}"], capture_output=True).stdout.decode()
        res = pattern.search(output)
        if res:
            # print(res.group(0))
            # print(res.group(1))
            # print(res.group(2))
            # print(res.group(3))
            # print(res.group(4))
            lo = ctypes.c_long(int(res.group(3), 16) << 12).value + int(res.group(4))
            # print(hex(lo))
            hi = (ctypes.c_long(int(res.group(1), 16) << 12).value + int(res.group(2))) ^ lo
            # print(hex(hi))

            ans = (hi << 32) + lo
            print(f"{i} {ans}")

            # result = subprocess.run(["qemu-riscv64", f"./ncuts/{i}"],
            #                         capture_output=True).stdout.decode()
            # print(result)
        pass
    elif res_ppc64 := re_ppc64.match(file_output):
        # print('ppc64')
        pass
    elif res_sh4 := re_sh4.match(file_output):
        # print('sh4')
        pass
    elif res_mips := re_mips.match(file_output):
        # print(f'{i}: ', end='')
        # print('mips')
        pass
    elif res_s390x := re_s390x.match(file_output):
        # print('s390x')
        pass
    elif res_mips64 := re_mips64.match(file_output):
        # print(f'{i}: ', end='')
        # print('mips64')
        pass
    else:
        pass
        # print(f"{i}: unknown")
        # break

```



I must admit that this script is definitely ugly, although it works well to solve challenges.

I think I should learn angr which helps solve challenges automatically. Just extract output of objdump is far from enough.

It's my first time to qualify to participate in Defcon Final, although my output isn't much. Anyway, wish Water Paddler get a good rank in the final.
