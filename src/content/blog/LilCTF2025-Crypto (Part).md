---
title: "LilCTF2025-Crypto (Part)"
pubDate: "Aug 19 2025"
description: '这次稍微去看了下密码, 有两道算是我做的时候感觉比较吃力或是看不出来的, 故复现一下'
image: /image/image.png
categories:
  - CTF
tags:
  - Crypto
---

# Linear

## **题目：**

<details>
    <summary><b>点击展开代码</b></summary>
```python
import os
import random
import signal
```python
import os
import random
import signal


signal.alarm(10)

flag = os.getenv("LILCTF_FLAG", "LILCTF{default}")

nrows = 16
ncols = 32

A = [[random.randint(1, 1919810) for _ in range(ncols)] for _ in range(nrows)]
x = [random.randint(1, 114514) for _ in range(ncols)]

b = [sum(A[i][j] * x[j] for j in range(ncols)) for i in range(nrows)]
print(A)
print(b)

xx = list(map(int, input("Enter your solution: ").strip().split()))
if xx != x:
    print("Oh, your linear algebra needs to be practiced.")
else:
    print("Bravo! Here is your flag:")
    print(flag)
```

## 解题

题目是关于一个矩阵方程：
$$
\mathbf{A}\mathbf{x}=\mathbf{b}
$$
但是A矩阵对应的方程组个数少于变量个数（行为16， 列为32），而且直接尝试`A.solve_right(b)`得到的也不是整数域下的矩阵。

所以我们这里就需要对这个矩阵方程进行转换：
$$
\mathbf{A}\mathbf{x}=\mathbf{b}\Rightarrow \mathbf{A}\mathbf{x}-\mathbf{b}=\mathbf{0}
$$
从而我们有这样一个矩阵：

## exp

<details>
    <summary><b>点击展开代码</b></summary>

```python

```

</details>

<hr style="border: 0.5px solid black;"/>

# Space Travel

**题目：**

<details>
    <summary><b>点击展开代码</b></summary>

```python
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import random
from secret import flag
m = bytes_to_long(flag)
key = RSA.generate(1024)
passphrase = str(random.randint(0,999999)).zfill(6).encode()
output = key.export_key(passphrase=passphrase).split(b'\n')
for i in range(7, 15):
    output[i] = b'*' * 64
with open("priv.pem", 'wb') as f:
    for line in output:
        f.write(line + b'\n')
"""
私钥文件
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,435BF84C562FE793

9phAgeyjnJYZ6lgLYflgduBQjdX+V/Ph/fO8QB2ZubhBVOFJMHbwHbtgBaN3eGlh
WiEFEdQWoOFvpip0whr4r7aGOhavWhIfRjiqfQVcKZx4/f02W4pcWVYo9/p3otdD
ig+kofIR9Ky8o9vQk7H1eESNMdq3PPmvd7KTE98ZPqtIIrjbSsJ9XRL+gr5a91gH

****************************************************************

****************************************************************

****************************************************************

****************************************************************

****************************************************************

****************************************************************

****************************************************************

****************************************************************

hQds7ZdA9yv+yKUYv2e4de8RxX356wYq7r8paBHPXisOkGIVEBYNviMSIbgelkSI
jLQka+ZmC2YOgY/DgGJ82JmFG8mmYCcSooGL4ytVUY9dZa1khfhceg==
-----END RSA PRIVATE KEY-----
"""
with open("enc.txt", 'w') as f:
    f.write(str(key._encrypt(m)))
"""
密文 55149764057291700808946379593274733093556529902852874590948688362865310469901900909075397929997623185589518643636792828743516623112272635512151466304164301360740002369759704802706396320622342771513106879732891498365431042081036698760861996177532930798842690295051476263556258192509634233232717503575429327989
"""
```

</details>

题目给了私钥文件和密文，虽然私钥文件不完整，但也不是完全没有有用的信息；然而，这里的私钥文件进行了加密：

```python
passphrase = str(random.randint(0,999999)).zfill(6).encode()
output = key.export_key(passphrase=passphrase).split(b'\n')
```

因为passphrase的范围是[0,999999]，所以我们可以爆破去找passphrase；但我们还是需要看看加密代码。

翻一下export_key的源代码，发现加密的位置在这：

![image-20240519203812924](./assets/image-20240519203812924.png)

查看此处函数的源代码：

![image-20240519203919740](./assets/image-20240519203919740.png)

对该函数的解释：

> 1，随机生成8bytes的salt
>
> 2，PBKDF1(passphrase, salt, 16, 1, MD5) 得到 key 在末尾并附上PBKDF1(key + passphrase, salt, 8, 1, MD5)（不理解函数的意思也没事，只要知道这里的key是这样的形式就行）
>
> 3，使用3DES进行CBC模式加密（key为第二步的key，iv为salt）：
>
> ​	objenc = DES3.new(key, DES3.MODE_CBC, salt)
>
> ​	data = objenc.encrypt(pad(data, objenc.block_size))

由 `"Proc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,%s\n\n" %tostr(hexlify(salt).upper())`，可以知道私钥文件里的iv（salt）的值为**435BF84C562FE793**（这里可以看看前面的私钥文件）。

前面也提到passphrase可以进行爆破，于是我们可以通过 ”解密前半来判断解密是否成功“ 作为判断条件（比如开头应该是`308202`，e应该是`010001`，即65537）进行爆破：

<details>
    <summary><b>点击展开代码</b></summary>
```python
from binascii import a2b_base64, unhexlify
from Crypto.Hash import MD5
from Crypto.Cipher import DES3
from Crypto.Protocol.KDF import PBKDF1
import tqdm
def solve(data, salt):
    # 爆破一下passphrase
    for i in tqdm.trange(1000000):
        passphrase = str(i).zfill(6).encode()
        # We only support 3DES for encryption
        key = PBKDF1(passphrase, salt, 16, 1, MD5)
        key += PBKDF1(key + passphrase, salt, 8, 1, MD5)
        objenc = DES3.new(key, DES3.MODE_CBC, salt)
        # Encrypt with PKCS#7 padding
        data1 = objenc.decrypt(data).hex()
        if data1[:6] == "308202" and "010001" in data1:
            print("", data1)
            iv = a2b_base64(b"hQds7ZdA9yv+yKUYv2e4de8RxX356wYq7r8paBHPXisOkGIVEBYNviMSIbgelkSIjLQka+ZmC2YOgY/DgGJ82JmFG8mmYCcSooGL4ytVUY9dZa1khfhceg==")[:8]
            objenc = DES3.new(key, DES3.MODE_CBC, iv)
            c1 = a2b_base64(b"hQds7ZdA9yv+yKUYv2e4de8RxX356wYq7r8paBHPXisOkGIVEBYNviMSIbgelkSIjLQka+ZmC2YOgY/DgGJ82JmFG8mmYCcSooGL4ytVUY9dZa1khfhceg==")
            data1 = objenc.decrypt(c1)[8:].hex()
            print(data1)
            return passphrase


salt = unhexlify("435BF84C562FE793")
c = a2b_base64(b"9phAgeyjnJYZ6lgLYflgduBQjdX+V/Ph/fO8QB2ZubhBVOFJMHbwHbtgBaN3eGlhWiEFEdQWoOFvpip0whr4r7aGOhavWhIfRjiqfQVcKZx4/f02W4pcWVYo9/p3otdDig+kofIR9Ky8o9vQk7H1eESNMdq3PPmvd7KTE98ZPqtIIrjbSsJ9XRL+gr5a91gH")
passphrase = solve(c, salt)
print(passphrase)
"""
48%|████████████████████████████████████████████████████████████████████████▊                                                                              | 482292/1000000 [00:33<00:35, 14407.19it/s] 

前半：
3082025c02010002818100a18f011bebacceda1c6812730b9e62720d3cbd6857af2cf8431860f5dc83c5520f242f3be7c9e96d7f96b41898ff000fdb7e43ef6f1e717b2b7900f35660a21d1b16b51849be97a0b0f7cbcf5cfe0f00370cce6193fefa1fed97b37bd367a673565162ce17b0225708c032961d175bbc2c829bf2e16eabc7e0881feca0975c810203010001

后半：
8f2363b340e502405f152c429871a7acdd28be1b643b4652800b88a3d23cc57477d75dd5555b635167616ef5c609d69ce3c2aedcb03b62f929bbcd891cadc0ba031ae6fec8a2116d0808080808080808

b'483584'
"""
```

</details>

然后稍微整理一下（不懂的话，可以在网上搜一下**RSA私钥文件格式**去试着自己拆解一下），可以得到这些信息：

```python
n = 0x00a18f011bebacceda1c6812730b9e62720d3cbd6857af2cf8431860f5dc83c5520f242f3be7c9e96d7f96b41898ff000fdb7e43ef6f1e717b2b7900f35660a21d1b16b51849be97a0b0f7cbcf5cfe0f00370cce6193fefa1fed97b37bd367a673565162ce17b0225708c032961d175bbc2c829bf2e16eabc7e0881feca0975c81
e = 0x010001

dql = 0x8f2363b340e5
qp = 0x5f152c429871a7acdd28be1b643b4652800b88a3d23cc57477d75dd5555b635167616ef5c609d69ce3c2aedcb03b62f929bbcd891cadc0ba031ae6fec8a2116d
```

其中，这里dql只有48bit（因为CBC模式的特点，所以后半部分的前8个bytes我们是没法解密的）

而我们可以知道的是：
$$
e*dq=1+k*(q-1)~\rightarrow k*q=edq+k-1
$$

$$
inv(q,p)*q\equiv1~(mod~p)\rightarrow inv(q,p)*q-1\equiv0~(mod~p)
$$

不过这里有 $k$ 和 $q$ 两个未知量，不过我们知道dql的值，所以我们有下面这样的方程（主要是为了减少要设的未知量）：
$$
X=k*q=e(x+dql)+k-1
$$

$$
inv(q,p)*(k*q)^2-k*(k*q)=inv(q,p)*X^2-k*X\equiv0~(mod~p)
$$

于是我们爆破k，解个copper就行（但比赛的时候调小了。。。问了Dexter师傅才知道得调大点才行）

exp：

<details>
    <summary><b>点击展开代码</b></summary>


```python
from tqdm import *
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
n = 0xa18f011bebacceda1c6812730b9e62720d3cbd6857af2cf8431860f5dc83c5520f242f3be7c9e96d7f96b41898ff000fdb7e43ef6f1e717b2b7900f35660a21d1b16b51849be97a0b0f7cbcf5cfe0f00370cce6193fefa1fed97b37bd367a673565162ce17b0225708c032961d175bbc2c829bf2e16eabc7e0881feca0975c81
e = 65537
dq_leak= 0x8f2363b340e5
inv = 0x5f152c429871a7acdd28be1b643b4652800b88a3d23cc57477d75dd5555b635167616ef5c609d69ce3c2aedcb03b62f929bbcd891cadc0ba031ae6fec8a2116d
c = 55149764057291700808946379593274733093556529902852874590948688362865310469901900909075397929997623185589518643636792828743516623112272635512151466304164301360740002369759704802706396320622342771513106879732891498365431042081036698760861996177532930798842690295051476263556258192509634233232717503575429327989

def coppersmith(k):
    R.<x> = PolynomialRing(Zmod(n))
    tmp = e * (x * 2^48 + dq_leak) + k - 1
    f = inv * tmp^2 - k*tmp
    f = f.monic()
    x0 = f.small_roots(X=2^464,beta=1,epsilon=0.09)
    return x0

for k in trange(1,e):
    x0 = coppersmith(k)
    if x0 != []:
        dq = int(x0[0]) * 2^48 + dq_leak
        q = (e*dq + k - 1) // k
        p = n // q
        d = inverse(e,(p-1)*(q-1))
        m = pow(c,d,n)
        print(long_to_bytes(int(m)))
        break
"""
73%|███████▎  | 47793/65536 [11:46<04:22, 67.62it/s]

b'flag{df4a4054-23eb-4ba4-be5e-15b247d7b819}'
"""
```

</details>

<hr style="border: 0.5px solid black;"/>

## Hash（复现）

**题目：**

<details>
    <summary><b>点击展开代码</b></summary>

```python
#!/usr/bin/python2
# Python 2.7 (64-bit version)
from secret import flag
import os, binascii, hashlib
key = os.urandom(7)
print hash(key)
print int(hashlib.sha384(binascii.hexlify(key)).hexdigest(), 16) ^ int(binascii.hexlify(flag), 16)
"""
7457312583301101235
13903983817893117249931704406959869971132956255130487015289848690577655239262013033618370827749581909492660806312017
"""
```

</details>

### 1，MITM

题目使用了python2.7版本的hash()函数，所以查看一下[源码](https://github.com/neuml/py27hash/blob/master/src/python/py27hash/hash.py))，然后我们找到对应的hash代码（这里要注意——py2.7里，str和bytes不区分；所以在py2.7上，type(bytes型数据) 的返回值是str）：

<details>
    <summary><b>点击展开代码</b></summary>

 ```python
def shash(value):
    """
    Returns a Python 2.7 hash for a string.

    Logic ported from the 2.7 Python branch: cpython/Objects/stringobject.c
    Method: static long string_hash(PyStringObject *a)

    Args:
        value: input string

    Returns:
        Python 2.7 hash
    """

    length = len(value)

    if length == 0:
        return 0

    mask = 0xffffffffffffffff
    x = (Hash.ordinal(value[0]) << 7) & mask
    for c in value:
        x = (1000003 * x) & mask ^ Hash.ordinal(c)

    x ^= length & mask

    # Convert to C long type
    x = ctypes.c_long(x).value

    if x == -1:
        x = -2

    return x

 ```

</details>

其实上述代码只是进行了这样的过程：

> mask = 0xffffffffffffffff
>
> 1，x = (Hash.ordinal(value[0]) << 7) & mask
>
> 2，重复 **len(value)** 次：**x = (1000003 * x) & mask ^ Hash.ordinal(value[0])**
>
> 3，x ^= length & mask

所以我们可以整一下Meet-in-the-middle：**正算三轮的结果存成一个表，逆算四轮的结果去匹配一下，如果匹配上了就说明整对了**。

逆算的操作如下：

> **x = (x ^ Hash.ordinal(value[0]) * inv(1000003, mask+1)) & mask**

最后算key的sha384值去异或密文c得到明文m即可

exp：

<details>
    <summary><b>点击展开代码</b></summary>

```python
from tqdm import *
from Crypto.Util.number import *
import hashlib
def attack(t):
    mask = 0xffffffffffffffff
    table = {}
    for v0 in trange(256):
        x0 = (v0 << 7) & mask
        x0 = (1000003 * x0) & mask ^ v0
        for v1 in range(256):
            x1 = x0
            x1 = (1000003 * x1) & mask ^ v1
            for v2 in range(256):
                x2 = x1
                x2 = (1000003 * x2) & mask ^ v2
                table[x2] = v0*256*256+v1*256+v2
    
    inv=inverse(1000003,mask+1)
    t=t^7
    for v0 in trange(256):
        x= ((t^v0)*inv) & mask
        for v1 in range(256):
            x1 = x
            x1 = ((x1^v1)*inv) & mask
            for v2 in range(256):
                x2 = x1
                x2 = ((x2^v2)*inv) & mask
                for v3 in range(256):
                    x3 = x2
                    x3 = ((x3^v3)*inv) & mask
                    try:
                        return (table[x3],v3,v2,v1,v0)
                        
                    except:
                        continue

t = 7457312583301101235
keys = attack(t)
key = b''
for i in keys:
    key += long_to_bytes(i)
print(key)
c = 13903983817893117249931704406959869971132956255130487015289848690577655239262013033618370827749581909492660806312017
import binascii
key = int(hashlib.sha384(binascii.hexlify(key)).hexdigest(), 16)
print(long_to_bytes(c ^ key))
"""
100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:06<00:00, 39.78it/s] 
 32%|████████████████████████████████████████▋                                                                                      | 82/256 [11:17<23:56,  8.26s/it] 
b']\x8c\xf0?Z\x08R'
b'flag{bdb537aa-87ef-4e95-bea4-2f79259bdd07}'
"""
```

</details>

### 2，Lattice

这个方法还是听鸡块师傅才知道的。

![image-20240519235534408](./assets/image-20240519235534408.png)

不过按自己的理解去造了下，没出结果（后面听别的佬说有类似的题，但这周没空接着整了，有空就接着写这部分）

（**2024/06/06更新**）

因为有别的师傅找我一块整这题的格，所以就接着整了

然后发现：其实我当时的想法是对的，但有个地方理解错了而已（傻了当时）

造格的思路如下：

> 先定义一下key：
> $$
> key={256}^6*v0 + {256}^5*v1 + {256}^4*v2 + {256}^3*v3 + {256}^2*v4 + {256}*v5 + v6
> $$
> 因为异或就是加减256以内的一个数，所以我们这里假设：$(a*x)\oplus v=a*x+b,b\in[-255,255]$
>
> 然后把hash源码转化成下面这样的多项式：
> $$
> Hash(key)\oplus 7=(128a^7 + a^6)b_0 + a^5b_1 + a^4b_2 + a^3b_3 + a^2b_4 + av_5 + b_6~mod~2^{64}
> $$
> 于是，我们便有这样的格：
> $$
> \begin{pmatrix}b_0,b_1,\cdots,b_6,1,k\end{pmatrix}\begin{pmatrix}1&0&\cdots&0&0&128a^7+a^6\\0&1&\cdots&0&0&a^5\\\vdots&\vdots&\ddots&\vdots&\vdots&\vdots\\0&0&\cdots&1&0&1\\0&0&\cdots&0&1&-(Hash(key)\oplus 7)\\0&0&\cdots&0&0&2^{64}\end{pmatrix}=\begin{pmatrix}b_0,b_1,\cdots,b_6,1,0\end{pmatrix}
> $$
> 对这个格进行调平，进行LLL，然后在这些结果中，找到末尾是 **[1，0]** 的那一组，便得到了$\begin{pmatrix}b_0,b_1,\cdots,b_6\end{pmatrix}$

有了b后，我们回到刚刚假设的式子：
$$
1000003x_{i-1}+b=x_{i}=1000003x_{i-1}\oplus v_{i-1}
$$
因为我们根据这个式子，可以有这样的思路：

> 我们手上有：$x_{7}=Hash(key)\oplus 7$ 和 $1000003x_{6}=x_{7}-b_6$；
>
> 所以有：
>
> $v_{6}=(x_{7}-b_6)\oplus x_{7}$
>
> $x_6=(x_{7}-b_6)*{1000003}^{-1}~mod~2^{64}$
>
> 那么依次类推，我们便有这样的循环：
>
> $v_{i-1}=(x_{i}-b_{i-1})\oplus x_{i}$
>
> $x_{i-1}=(x_{i}-b_{i-1})*{1000003}^{-1}~mod~2^{64}$

于是我们可以根据上述式子，逆着循环7次就能还原出key里的所有字符（每次都要记得更新每次所需要的值

最后跟前面一样——算key的sha384值去异或密文c得到明文m即可

exp：

<details>
    <summary><b>点击展开代码</b></summary>


```python
# sage10.3
from Crypto.Util.number import *
from gmpy2 import *
import hashlib, binascii

# 计算多项式的系数
mask = 0xffffffffffffffff
PR.<v0,v1,v2,v3,v4,v5,v6> = PolynomialRing(ZZ)
x = v0*128
for c in [v0,v1,v2,v3,v4,v5,v6]:
    x = 1000003 * x+c
coe = x.coefficients()

#造格
t = (7457312583301101235^^7)&mask
M = identity_matrix(ZZ, 9)
bel=2^200
for i in range(7):
    M[i, -1]=coe[i]*bel
M[-2, -2] = 1
M[-1, -1] = 2**64*bel
M[-2, -1] = -t*bel

'''
调平这里，其实直接调出矩阵的对应部分乘上2**20即可：
M[:,-1:] *= 2^200
'''
res = M.LLL()[:-1]
for i in res:
    if i[-1] == 0 and i[-2]==1:
        res = i[:-2]

# 还原key
a1 = invert(1000003, 2**64)
key = b''
for i in res[::-1]:
    xa = (t-i)%(2^64)
    x = t^^xa
    key += long_to_bytes(x)
    t = (xa * a1)%(2**64)
print(key)
c = 13903983817893117249931704406959869971132956255130487015289848690577655239262013033618370827749581909492660806312017
m = int(hashlib.sha384(binascii.hexlify(key[::-1])).hexdigest(), 16) ^^ c
print(long_to_bytes(m))
# flag{bdb537aa-87ef-4e95-bea4-2f79259bdd07}
```

</details>
