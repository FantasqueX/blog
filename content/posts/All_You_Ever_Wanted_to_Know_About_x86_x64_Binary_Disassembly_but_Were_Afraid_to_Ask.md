---
title: "All You Ever Wanted to Know About x86 x64 Binary Disassembly but Were Afraid to Ask"
date: 2022-07-18T16:39:53+08:00
summary: Algorithms and Heuristics in Disassembly
categories: ["Paper"]
---
# All You Ever Wanted to Know About x86 x64 Binary Disassembly but Were Afraid to Ask

最近在读 paper ，找一些 binary analysis 的文章看一看，在 blog 里写点笔记，原文在 https://oaklandsok.github.io/papers/pang2021.pdf
大概看了除 evaluation 的部分，这篇文章分析了不同 disassembly software 使用了哪些算法和猜测，覆盖率如何，错误率如何。常见的开源软件（ghidra r2 angr objdump）基本都包含了，闭源软件（ida binary ninja）在 evaluation 部分有分析。众所周知，逆向这个活七分靠猜，因为在 compilation 的过程中大量信息丢失了，如分支跳转，类型，oop里的跳转表，尾递归优化，死码消除等，所以逆向不可能完全靠精确无误的 algorithm，还需要可能出错但是大部分时候正确的 heuristic。

## Disassembly

 这一部分最大的挑战是如何区分 data 和 instruction。

### Linear Sweep

`objdump` 采用的是 Linear Sweep 特点是对于给定的区域顺序 disassemble 这类算法的区别在于如何确定扫描哪些区域，以及极大概率遇到无法 disassemble 的情况，应该如何错误处理，常用的确定扫描区域的办法是看 elf header 中规定的区域，大概率不会出错，对于错误处理，可能的错误是跳转指令所要跳转的地址需要对齐，这时候需要 padding，`PSI` 的解决方法是倒着找到最靠前的正确指令，把中间的无效字节全部填充为 nop 重新扫描。

### Recursive Descent

另一种方法是 Recursive Descent，基本思想是从给定的起点出发，根据 CFG 分析哪些地方可能是代码。这里有三个需要解决的问题，如何确定起点，如何确定 CFG，CFG没有覆盖到的地方怎么办。第一个问题容易解决，从 _start 和 export symbol 出发，第二个问题比较复杂，但是这个问题已经被大量分析了，需要解决的问题有 indirect jump, tail call, non-return function 第三个问题是覆盖率不足，大多数的解决方法是模式匹配 function prologue ，也有一些（如 angr）较为暴力，直接在空隙进行 `Linear Sweep`，覆盖率提高了，但是错误率也提高了

## 符号化

### 如何提取数据单元（数据或者指针字面量）

可以先找指令中的常量，通常数据单元是连续的n字节起始地址对齐。一般假设n为机器的字长，当然也有可能不是，有些跳转表的地址很短。地址对齐也只是可能，大部分对齐，少部分不对齐。

### 推断数据单元接口

这个我理解是上一步数据的类型，如果出现在浮点运算指令的操作数中，则可以推断为浮点；如果每一个字节都是 ascii 或 unicode 并且以 NULL 结尾，则有可能是字符串；如果数据值大于 4096 且指向已知函数，或者指向数据，且这个数据没有覆盖其他数据，则很可能是指针。

### XREF

首先猜测数据单元是代码指针，如果指向的位置是合法指令，GHIDRA 会做一些额外的限制，如不能是 0xffff 等特殊值，必须是函数的 entry point，这一部分不是很靠谱，也有不少在函数中间的情况。如果是代码指针的情况被排除，则猜测是数据指针，这个需要指向的地址在数据段，但是允许有一定的偏差，为了适应如数组的指针加偏移的情况。

### Address Table

一般是连续的多个指针，我对于 Address Table 的理解有限，这里就不写了，感兴趣可以看原文。

## 判断函数入口

### 寻找 main 函数

首先找到 _start 如果其中有 `__libc_start_main`，则其第一个参数就是 `main` 函数。

### 一般函数

如果可以在 .symtab 和 dynsym 找到函数符号，那么可以准确判断函数入口，GHIDRA 使用了 存储 unwind 信息的 .eh_frame 段，因此会更准确（存疑，里面只是有调试信息，符号在 .symtab 里应该都有，为什么会更准确呢）缺点，strip 之后除了 dynsym 全都没了，剩下的这个段几乎没有用。`call` 的操作数是函数，tail call 也是函数。其他一些方法包括，模式匹配 prologue，训练模型等

## 最后是CFG 重建

### Indirect Jump（jump table）

最原始的思想就是寻找 jmp base+idx*size 的模式，找到之后需要确定 idx 的取值范围，会用到 VSA，这个不太了解

### Indirect Call

利用常数传播识别间接调用（不是，这个编译器优化应该可以做到啊，那就是直接调用了，为啥会需要 disassembly 工具做常数传播啊）

### Tail Call

这个的问题是，如果是 Tail Call，那么编译器会把 call 优化为 jmp 减少栈操作。常见的操作有：如果 jmp 的间隔很远，或是隔了很多个函数，jmp 之前会增加 rsp 来弹栈，以及许多不知道为什么的判断规则。这个问题还是编译器在优化时减少了信息，复原时就只能靠猜。

### Non-returning Function

预先识别一组不会返回的库函数，根据这些库函数，识别更多不返回的函数。这个问题似乎 trivial，如果搜索到不返回的函数，那么递归标记父亲也是不返回就好了。

## Findings

1. 复杂的结构（如代码中的数据，跳转表，尾调用，不返回函数）是常见的，识别他们必须用到启发式方法。
2. 启发式方法是覆盖率和准确率的 tradeoff
3. 不同的工具由于采用的方式不同，在一定程度上可以互补。

这篇文章最大的价值在于解释开源 disassembly tool 如何处理常见的问题，这样在逆向的时候，看到逆向工具出错的时候可以倒推工具作者为什么会出错，以及更好地处理一些常见的但是工具没有识别出来的 pattern。我现在很悲观，二进制分析看起来最靠谱的方法是对着编译器的优化 case-by-case 写分析，或者寻求人工智能，处理这些需要靠猜来解决的问题。
