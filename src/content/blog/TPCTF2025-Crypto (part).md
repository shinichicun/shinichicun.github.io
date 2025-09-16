---
title: TPCTF2025-Crypto (part)
pubDate: 2025-03-10
description: '就看了MT, 但没打出来, 所以按别的师傅的想法复现了下'
image: /image/image.png
categories:
  - CTF
tags:
  - Crypto
---

就看了MT, 但没打出来, 所以按别的师傅的想法复现了下

# randomized random

## 题目

```python
# FROM python:3
import random
with open("flag.txt","rb") as f:
    flag=f.read()
for i in range(2**64):
    print(random.getrandbits(32)+flag[random.getrandbits(32)%len(flag)])
    input()

```



## 题目分析

因为题目有用到random库，所以这是MT19937问题，可以参考Xenny师傅的文章：[MT19937 分析 | Xenny 的博客](https://xenny.wiki/posts/crypto/PRNG/MT19937.html)。

而题目每次交互里的遍历都会返回`random.getrandbits(32)+flag[random.getrandbits(32)%len(flag)` ，也就是**一个随机32bit数与flag里的一个随机字节的和**。

题目需要我们通过$2^{64}$次遍历去还原出flag。

而每次得到的信息（即这个随机32bit数）不仅会因为加法而影响一定的bit数，还是不连续的（因为加flag里的一个随机字节那个地方也用了getrandbits）；所以得取前面一部分bit来打MT19937。

我跟naby师傅当时是想着取前16bit应该是没问题的，但没打出来（今天赛后听Dexter师傅他们说，他们测试发现——影响的bit挺多的，所以取前10bit好点）。

之后就是造矩阵来打MT19937，这个思路的原理可以参考鸡块师傅的这篇文章：[2024-同济大学第二届网络安全新生赛CatCTF-wp-crypto](https://tangcuxiaojikuai.xyz/post/69eaef2e.html#Random-game-3-Solves-376-500-pts)

（关键还是在数据量上，数据量不够确实还原不出来正确的state，算是我们当时没注意到的一个问题）

![image-20250310140621926](assets/image-20250310140621926.png)

打出来后就是整理出flag了

首先肯定是相减得到flag的那些字符，但单单这样肯定还不能得到flag（毕竟是随机的，所以得到的都是随机的flag字符），但这些随机的flag字符的顺序与flag的长度有关。

而我们知道——flag里的左括号和右括号肯定不会有很多，所以我们分别找两组左括号和右括号所对应的getrandbits，然后相减做gcd就能得到长度，然后就根据长度去整理出flag即可。

---

## exp

因为整的时候Dexter、鸡块、Lst4r几位师傅他们说了些不同的方式（但都是同一种思路），用时都差不多

第一种就是刚刚说的造矩阵：

<details>
    <summary><b>点击展开代码</b></summary>

```python
# sage 10.5
import random
from sage.all import *
from Crypto.Util.number import *
from random import *
from tqdm import *
from pwn import *

# 1, get data
x,c=[],[]
sh = remote("1.95.57.127", 3001)
for i in trange(2500):
    tmp1=eval(sh.recvline())
    sh.send(b"\n")
    x.append(tmp1)
    c.append(tmp1>>22)


# 2, recover MT and get random bytes of (f_inf, f_len)
RNG = Random()
length = 19968
def construct_a_row(RNG):
    # 这里是关键, 一定要跟你已知数据的生成方式一致
    row = []
    for i in range(2500):
        row+=list(map(int, (bin(RNG.getrandbits(32) >> 22)[2:].zfill(10))))
        RNG.getrandbits(32)
    return row

L = []
for i in trange(length):
    state = [0]*624
    temp = "0"*i + "1"*1 + "0"*(length-1-i) 
    for j in range(624):
        state[j] = int(temp[32*j:32*j+32],2)
    RNG.setstate((3,tuple(state+[624]),None))
    L.append(construct_a_row(RNG))
L = Matrix(GF(2),L)

known = []
for i in c:
    known+=list(map(int, (bin(i)[2:].zfill(10))))
print("solve_left")
s = L.solve_left(vector(GF(2),known))
print("ok")
init = "".join(list(map(str,s)))
print("init")
state = []
for i in range(624):
    state.append(int(init[32*i:32*i+32],2))
print("state")

prng = Random()
prng.setstate(tuple([3, tuple(state+[624]), None]))
f_inf = []
f_loc = []
for i in range(2500):
    x1 = long_to_bytes(x[i]-prng.getrandbits(32))
    x2 = prng.getrandbits(32)
    # print(x1, x2)
    f_inf.append(x1)
    f_loc.append(x2)


# 3, get flag_len and recover flag
loc1, loc2 = [], []
i = 0
while len(loc1) < 2 or len(loc2) < 2:
    if f_inf[i].decode() == "{":
        loc1.append(f_loc[i])
    if f_inf[i].decode() == "}":
        loc2.append(f_loc[i])
    i += 1
f_len = GCD(loc1[0]-loc1[1], loc2[0]-loc2[1])
i = 0
flag = ["*"]*f_len
while 1:
    if all(i != "*" for i in flag):
        print("".join(flag))
        break
    if flag[f_loc[i]%f_len] == "*":
        flag[f_loc[i]%f_len] = f_inf[i].decode()
    i += 1
'''
100%|███████████████████████████████████████████████████████████████████████████████| 2500/2500 [01:34<00:00, 26.46it/s]
100%|████████████████████████████████████████████████████████████████████████████| 19968/19968 [01:41<00:00, 197.41it/s]
solve_left
ok
init
state
TPCTF{Ez_MTI9937_pr3d1cTi0n}
TPCTF{Ez_MTI9937_pr3d1cTi0n}
'''
```

</details>

第二种是使用maple师傅之前整的[gf2bv](https://github.com/maple3142/gf2bv)库，算是比较无脑?（不过就是需要多堆点数据）：

<details>
    <summary><b>点击展开代码</b></summary>

```python
# gf2bv
# python3
import random
from gf2bv import LinearSystem
from gf2bv.crypto.mt import MT19937
from tqdm import *
from pwn import *
from Crypto.Util.number import *
import pickle


def mt19937(bs, out):
    lin = LinearSystem([32] * 624)
    mt = lin.gens()

    rng = MT19937(mt)
    zeros = []
    for o in out:
        zeros.append((rng.getrandbits(32)>>22) ^ int(o))
        rng.getrandbits(32)
    sol = lin.solve_one(zeros)

    rng = MT19937(sol)
    pyrand = rng.to_python_random()
    return pyrand

if(0):
    print(random.getstate()[1])
    x,c=[], []
    for i in trange(3500):
        tmp1=random.getrandbits(32)
        random.getrandbits(32)
        x.append(tmp1)
        c.append(tmp1>>22)
    RNG = mt19937(int(10), c)
    for i in trange(832):
        xx = RNG.getrandbits(32)
        assert x[i] == xx and c[i] == (xx>>22)
        RNG.getrandbits(32)

if(1):
    # 1, get data
    nums = 5000
    sh = remote("1.95.57.127", 3001)
    out = []
    cout = []
    for _ in trange(nums):
        x = eval(sh.recvline())
        out.append(x)
        cout.append(x>>22)
        sh.send(b"\n")
    # 2, recover MT and get random bytes of (f_inf, f_len)
    RNG = mt19937(16, cout)
    f_inf = []
    f_loc = []
    for i in range(nums):
        x1 = long_to_bytes(out[i]-RNG.getrandbits(32))
        x2 = RNG.getrandbits(32)
        f_inf.append(x1)
        f_loc.append(x2)
    # 3, get flag_len and recover flag
    loc1, loc2 = [], []
    i = 0
    while len(loc1) < 2 or len(loc2) < 2:
        if f_inf[i].decode() == "{":
            loc1.append(f_loc[i])
        if f_inf[i].decode() == "}":
            loc2.append(f_loc[i])
        i += 1
    f_len = GCD(loc1[0]-loc1[1], loc2[0]-loc2[1])
    i = 0
    flag = ["*"]*f_len
    while 1:
        if all(i != "*" for i in flag):
            print("".join(flag))
            break
        if flag[f_loc[i]%f_len] == "*":
            flag[f_loc[i]%f_len] = f_inf[i].decode()
        i += 1
'''
100%|███████████████████████████████████████████████████████████████████████████████| 5000/5000 [02:59<00:00, 27.93it/s]
TPCTF{Ez_MTI9937_pr3d1cTi0n}
'''
```

</details>

<hr style="border: 0.5px solid black;"/>

# 后记

这次算是对MT19937这个问题有了一点理解，希望下次能会分析吧

![image-20250310140736800](assets/image-20250310140736800.png)

(至于后面的题，因为当时没全部下载，所以等后面看别的师傅的blog里有没有再接着复现吧)
