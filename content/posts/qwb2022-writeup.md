---
title: "QWB2022 Writeup"
date: 2022-08-03T15:54:41+08:00
summary: Dieyingchongchong and some random thoughts about vmess and hatch
categories: ["writeup"]
---
Last week, I played QWB2022 with Redbud. There was a quite interesting MISC challenge called dieyingchongchong. I was given a [pcapng file](/qwb2022-writeup/Route.pcapng). According to challenge description and the [configuration file](/qwb2022-writeup/config.json), I can guess major traffic is vmess. So the problem how to decode the plain traffic with only client's uuid.

## Solution

The first step is to find the document about vmess protocol. Luckily, I find one [here](https://www.v2fly.org/developer/protocols/vmess.html). With the help of this document, it's not hard to decode some metadata such as body_iv, body_key, source_ip, source_key etc. However, I met an error when decoding the length part in body. Because unfamiliarity with golang, I failed to solve the problem before the game finished.

The key part is show in the following list taken from [auth.go](https://github.com/v2fly/v2ray-core/blob/master/common/crypto/auth.go). if `w.padding != nil`, the length will be xored with the third and fourth bytes of output of SHAKE hash instead of the first two bytes. And this option is turn on automatically if "M" option is turned on and body is encrypted using ChaCha20-Poly1305 or AES-128-GCM. Another point is the definition of `SecurityType` in document is not the same as in [code](https://github.com/v2fly/v2ray-core/blob/master/common/protocol/headers.pb.go). For this challenge, body is encrypted using AES-128 instead of ChaCha20-Poly1305.

```go
encryptedSize := int32(len(b) + w.auth.Overhead())
var paddingSize int32
if w.padding != nil {
    paddingSize = int32(w.padding.NextPaddingLen())
}

sizeBytes := w.sizeParser.SizeBytes()
totalSize := sizeBytes + encryptedSize + paddingSize
if totalSize > buf.Size {
    return nil, newError("size too large: ", totalSize)
}

eb := buf.New()
w.sizeParser.Encode(uint16(encryptedSize+paddingSize), eb.Extend(sizeBytes))
if _, err := w.auth.Seal(eb.Extend(encryptedSize)[:0], b); err != nil {
    eb.Release()
    return nil, err
}
```
In conclusion, this challenge is confusing because of the outdated document. If you're familiar with golang and spend some time reading source code of vmess protocol, then the challenge is not a hard one.

Because I or somebody else might see challenges about vmess in the future and don't want to work from scratch, I created a library called [Pyvmess](https://github.com/fantasquex/pyvmess) which can decode data from raw data extracted from a pcap package using client uuid. Although a lot of features of vmess hasn't been implemented, I hope it may save somebody's time in the future.

How to decode the pcap is shown in the Pyvmess library. Client made a HTTP request, and server responded a large HTML file. BTW, there are two turns in the pcapng file, but I cannot decode the last turn. There is a doc file linked to the HTML file.

```html
</script>
</body><meta http-equiv='refresh' content='0;url=https://key.xn--nvigators-key-if2g.com/ktt/cmd/logon0208_54741869750132.doc'>

```

It's strange. Upload the doc file to [VirusTotal](https://www.virustotal.com/gui/home/upload) and we can get the api address. So the password of zip file is known.

![alt Gob](/qwb2022-writeup/gob.png)

We might guess this is a [gob file](https://go.dev/blog/gob). It's an encoding to transmit a data structure across a network or store to a file but can only be used in golang. If we know the type definition of the data structure, we can easily decode it. Let's guess. They are some binary files with a string file name. The data structure might be `map[string]([]byte)`.
```go
package main

import (
	"encoding/gob"
	"fmt"
	"os"
)

func main() {
	var res map[string]([]byte)
	file, _ := os.Open("./flag")
	decoder := gob.NewDecoder(file)
	decoder.Decode(&res)

	for k, v := range res {
		fmt.Println(k)
		os.WriteFile(k, v, 0644)
	}
}
```

OK, now we get two text files and one binary file. One text file records a timestamp. The last part is noot something fun, but just CTF tricks. So I won't explain in detail. Deshuffle the binary file, and we'll get a PNG file. The flag is encoded in the alpha channel.

## Vmess

Ok, let's talk about design of vmess protocol. The first time I saw vmess, it is propagated as the next generation proxy protocol, the successor of shadowsocks. Because I didn't have any cryptographic knowledge at that time, I simply adored vmess protocol. Now I'm regretful.

The first strange thing is vmess uses different cipher in header and body of client request. Because the length of header is variable, decoder must decrypt the whole package, which is inefficient.

What's more, in header, vmess first calculates fnvhash of header metadata, then encrypts metadata and hash using AES-CFB. MAC then Encrypt is always not recommended in cryptography. Fnvhash is not even a cryptographic hash.

The final thing is about metadata obfuscation and global padding. Metadata obfuscation is not to store real length data instead to store the result of real length data xor with SHAKE output. That's confused. If length data will be encrypted using AES-128-GCM or ChaCha20-Poly1305, why to encrypted again with output of SHAKE? Global padding is to pad some random bytes less than 64 to each part in body. Obfuscate the length of the package? Is it so important?

In conclusion, I don't think vmess is a well-designed protocol. A lot of patches make the configuration even complicated. Some of them are just irrational. Shadowsocks maybe a better protocol. We only need some encrypted bytes with MAC instead of some much complicated protocol such as vmess.

## Hatch

In pyvmess, I use [hatch](https://hatch.pypa.io/) as the project manager, because it is used in [python official packaging tutorial](https://packaging.python.org/en/latest/tutorials/packaging-projects/) and I just dislike setuptools. Now, no more setup.py and only one pyproject.toml, much greater, isn't it? Standard build system and a great cli which can scaffold the project. Sounds like some frontend tools :) My experience with hatch is short, and I cannot make  more comments. Currently, I'm quite satisfied with hatch. Good job, hatch team!
