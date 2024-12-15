---
title: NSSCTF-Round16-Crypto-wp
published: 2024-01-13
description: '记录一下当时的做题记录'
image: ''
tags: [Crypto]
category: '比赛记录+复现'
draft: false 
---

## 1，pr

这题的话，因为题目描述有说**CRT**，还给了p和r，那就可以考虑下面这个方程组的CRT：

$\begin{cases}c_p=c1\ mod\ p=m^{e}\ mod\ p\\c_r=c2\ mod\ r=m^{e}\ mod\ r\end{cases}$

这样求出来的就是：$c=m^e\ mod\ p*r$

然后就是正常解个RSA就行。

<details>
    <summary>点击展开代码</summary>


```python
from Crypto.Util.number import *
from gmpy2 import *


c1 = 36918910341116680090654563538246204134840776220077189276689868322808977412566781872132517635399441578464309667998925236488280867210758507758915311644529399878185776345227817559234605958783077866016808605942558810445187434690812992072238407431218047312484354859724174751718700409405142819140636116559320641695
c2 = 15601788304485903964195122196382181273808496834343051747331984997977255326224514191280515875796224074672957848566506948553165091090701291545031857563686815297483181025074113978465751897596411324331847008870832527695258040104858667684793196948970048750296571273364559767074262996595282324974180754813257013752
p = 12101696894052331138951718202838643670037274599483776996203693662637821825873973767235442427190607145999472731101517998719984942030184683388441121181962123
r = 10199001137987151966640837133782537428248507382360655526592866939552984259171772190788036403425837649697437126360866173688083643144865107648483668545682383
cp = c1 % p
cr = c2 % r
pr = invert(p, r)
rp = invert(r, p)
e = 31413537523
cpr = int((cp*r*rp + cr*p*pr) % (p*r))
d = invert(e, (p-1)*(r-1))
m = pow(cpr, d, p*r)
print(long_to_bytes(m))

```

</details>

<hr style="border: 0.5px solid black;"/>

## 2，break

其实这题，主要考了 “手撕证书”——懂pem证书的结构，可以参考[文章1](https://zhuanlan.zhihu.com/p/461349946)或[文章2](https://tover.xyz/p/pem-by-hand/#%E6%89%8B%E6%92%95RSA%E7%A7%81%E9%92%A5)，当然我接下来也会讲的。

首先，对于本题而言，因为看到证书有**-----END PRIVATE KEY-----**，说明给的是证书的后半部分；但具体有多少内容，得”手撕“才知道。

所以得先转换PEM为DER：

<details>
    <summary>点击展开代码</summary>


```python
from base64 import b64decode
import binascii

s = '''Bc8tSTrvGJm2oYuCzIz+Yg4nwwKBgQDiYUawe5Y+rPbFhVOMVB8ZByfMa4LjeSDd
Z23jEGvylBHSeyvFCQq3ISUE40k1D2XmmeaZML3a1nUn6ORIWGaG2phcwrWLkR6n
ubVmb1QJSzgzmFHGnL56KHByZxD9q6DPB+o6gGWt8/6ddBl2NIZU/1btdPQgojfA
XXJFzR92RQKBgQC7qlB0U7m2U4FdG9eelSd+WSKNUVllZAuHji7jgh7Ox6La9xN5
miGZ1yvP44yX218OJ9Zi08o6vIrM6Eil45KzTtGm4iuIn8CMpox+5eUtoxyvxa9r
s2Wu+IRZN9zCME+p+qI8/TG27dIyDzsdgNqcUo8ESls7uW5/FEA7bYTCiQKBgQC7
1KybeB+kZ0zlfIdi8tVOpeI+uaHDbdh3+/5wHUsD3hmfg7VAag0q/2RA1vkB/oG1
QVLVHl0Yu0I/1/u5jyeakrtClAegAsvlrK+3i321rGS4YpTPb3SX1P/f3GZ7o7Ds
touA+NHk8IL9T7xkmJYw5h/RLG32ucH6aU6MXfLR5QKBgD/skfdFxGWxhHk6U1mS
27IM9jJNg9xLz5nxzkqPPhLn+rdgIIuTuQtv++eEjEP++7ZV10rg5yKVJd/bxy8H
2IN7aQo7kZWulHTQDZMFwgOhn0u6glJi+qC8bWzYDFOQSFrY9XQ3vwKMspqm+697
xM+dMUW0LML6oUE9ZjEiAY/5'''

s = b64decode(s)

print(binascii.hexlify(s))
"""
05cf2d493aef1899b6a18b82cc8cfe620e27c302818100e26146b07b963eacf6c585538c541f190727cc6b82e37920dd676de3106bf29411d27b2bc5090ab7212504e349350f65e699e69930bddad67527e8e448586686da985cc2b58b911ea7b9b5666f54094b38339851c69cbe7a2870726710fdaba0cf07ea3a8065adf3fe9d741976348654ff56ed74f420a237c05d7245cd1f764502818100bbaa507453b9b653815d1bd79e95277e59228d515965640b878e2ee3821ecec7a2daf713799a2199d72bcfe38c97db5f0e27d662d3ca3abc8acce848a5e392b34ed1a6e22b889fc08ca68c7ee5e52da31cafc5af6bb365aef8845937dcc2304fa9faa23cfd31b6edd2320f3b1d80da9c528f044a5b3bb96e7f14403b6d84c28902818100bbd4ac9b781fa4674ce57c8762f2d54ea5e23eb9a1c36dd877fbfe701d4b03de199f83b5406a0d2aff6440d6f901fe81b54152d51e5d18bb423fd7fbb98f279a92bb429407a002cbe5acafb78b7db5ac64b86294cf6f7497d4ffdfdc667ba3b0ecb68b80f8d1e4f082fd4fbc64989630e61fd12c6df6b9c1fa694e8c5df2d1e50281803fec91f745c465b184793a535992dbb20cf6324d83dc4bcf99f1ce4a8f3e12e7fab760208b93b90b6ffbe7848c43fefbb655d74ae0e7229525dfdbc72f07d8837b690a3b9195ae9474d00d9305c203a19f4bba825262faa0bc6d6cd80c5390485ad8f57437bf028cb29aa6fbaf7bc4cf9d3145b42cc2faa1413d663122018ff9
"""
```

</details>

那我们怎么“手撕”呢？可以根据一些常见的参数以及密文去 “手撕”，下表里有一些常见的证书参数：

| **数据** | **长度** | **名称** | **含义**                      |
| -------- | -------- | -------- | ----------------------------- |
| 30       | 1        | 标记符   | 代表ASN.1结构的开始           |
| 82       | 1        | 长度类型 | 代表后面跟着一个双字节长度    |
| 025b     | 2        | 长度     | 代表后续内容的总长度为603字节 |
| 02       | 1        | 类型     | 代表整型                      |
| 01       | 1        | 长度     | 代表1字节                     |
| 00       | 1        | 值       | 代表整数0                     |
| 02       | 1        | 类型     | 代表整型                      |
| 81       | 1        | 长度类型 | 代表后面跟着一个单字节长度    |
| 80       | 1        | 长度     | 代表数据长度为128字节         |
| …        | 128      | 值       | 数据值1                       |
| …        |          |          |                               |

当然，我们这里只会用到02、81、80这几个参数哈。

因为密文有点长，所以我就猜了个**0281**开头的是一个数的数据，于是可以拆出这样的形式（因为数据太长了，就只列了个格式）：

```python
05cf2d493aef1899b6a18b82cc8cfe620e27c3
028181 数字1
028181 数字2
028181 数字3
028180 数字4
```

接着，我参考的是[文章1](https://zhuanlan.zhihu.com/p/461349946)，所以可以得到：

```python
05cf2d493aef1899b6a18b82cc8cfe620e27c3
q 028181 数字1
dp 028181 数字2
dq 028181 数字3
q^{-1} mod p 028180 数字4
```

然后，因为有q和dq，所以我是直接猜了个最简单的情况：**m<q**，那么便有：$c^{dq}\ mod\ q=m$；最后还真这样（

脚本如下：

<details>
    <summary>点击展开代码</summary>


```python
# 证书格式转换
"""
from base64 import b64decode
import binascii

s = '''Bc8tSTrvGJm2oYuCzIz+Yg4nwwKBgQDiYUawe5Y+rPbFhVOMVB8ZByfMa4LjeSDd
Z23jEGvylBHSeyvFCQq3ISUE40k1D2XmmeaZML3a1nUn6ORIWGaG2phcwrWLkR6n
ubVmb1QJSzgzmFHGnL56KHByZxD9q6DPB+o6gGWt8/6ddBl2NIZU/1btdPQgojfA
XXJFzR92RQKBgQC7qlB0U7m2U4FdG9eelSd+WSKNUVllZAuHji7jgh7Ox6La9xN5
miGZ1yvP44yX218OJ9Zi08o6vIrM6Eil45KzTtGm4iuIn8CMpox+5eUtoxyvxa9r
s2Wu+IRZN9zCME+p+qI8/TG27dIyDzsdgNqcUo8ESls7uW5/FEA7bYTCiQKBgQC7
1KybeB+kZ0zlfIdi8tVOpeI+uaHDbdh3+/5wHUsD3hmfg7VAag0q/2RA1vkB/oG1
QVLVHl0Yu0I/1/u5jyeakrtClAegAsvlrK+3i321rGS4YpTPb3SX1P/f3GZ7o7Ds
touA+NHk8IL9T7xkmJYw5h/RLG32ucH6aU6MXfLR5QKBgD/skfdFxGWxhHk6U1mS
27IM9jJNg9xLz5nxzkqPPhLn+rdgIIuTuQtv++eEjEP++7ZV10rg5yKVJd/bxy8H
2IN7aQo7kZWulHTQDZMFwgOhn0u6glJi+qC8bWzYDFOQSFrY9XQ3vwKMspqm+697
xM+dMUW0LML6oUE9ZjEiAY/5'''

s = b64decode(s)

print(binascii.hexlify(s))
"""

# 证书拆解
"""
05cf2d493aef1899b6a18b82cc8cfe620e27c3
q 028181 00e26146b07b963eacf6c585538c541f190727cc6b82e37920dd676de3106bf29411d27b2bc5090ab7212504e349350f65e699e69930bddad67527e8e448586686da985cc2b58b911ea7b9b5666f54094b38339851c69cbe7a2870726710fdaba0cf07ea3a8065adf3fe9d741976348654ff56ed74f420a237c05d7245cd1f7645
dp 028181 00bbaa507453b9b653815d1bd79e95277e59228d515965640b878e2ee3821ecec7a2daf713799a2199d72bcfe38c97db5f0e27d662d3ca3abc8acce848a5e392b34ed1a6e22b889fc08ca68c7ee5e52da31cafc5af6bb365aef8845937dcc2304fa9faa23cfd31b6edd2320f3b1d80da9c528f044a5b3bb96e7f14403b6d84c289
dq 028181 00bbd4ac9b781fa4674ce57c8762f2d54ea5e23eb9a1c36dd877fbfe701d4b03de199f83b5406a0d2aff6440d6f901fe81b54152d51e5d18bb423fd7fbb98f279a92bb429407a002cbe5acafb78b7db5ac64b86294cf6f7497d4ffdfdc667ba3b0ecb68b80f8d1e4f082fd4fbc64989630e61fd12c6df6b9c1fa694e8c5df2d1e5
qp 028180 3fec91f745c465b184793a535992dbb20cf6324d83dc4bcf99f1ce4a8f3e12e7fab760208b93b90b6ffbe7848c43fefbb655d74ae0e7229525dfdbc72f07d8837b690a3b9195ae9474d00d9305c203a19f4bba825262faa0bc6d6cd80c5390485ad8f57437bf028cb29aa6fbaf7bc4cf9d3145b42cc2faa1413d663122018ff9
"""
# 解个最简单的情况（
from Crypto.Util.number import *
from gmpy2 import *

q = 0x00e26146b07b963eacf6c585538c541f190727cc6b82e37920dd676de3106bf29411d27b2bc5090ab7212504e349350f65e699e69930bddad67527e8e448586686da985cc2b58b911ea7b9b5666f54094b38339851c69cbe7a2870726710fdaba0cf07ea3a8065adf3fe9d741976348654ff56ed74f420a237c05d7245cd1f7645
dp = 0x00bbaa507453b9b653815d1bd79e95277e59228d515965640b878e2ee3821ecec7a2daf713799a2199d72bcfe38c97db5f0e27d662d3ca3abc8acce848a5e392b34ed1a6e22b889fc08ca68c7ee5e52da31cafc5af6bb365aef8845937dcc2304fa9faa23cfd31b6edd2320f3b1d80da9c528f044a5b3bb96e7f14403b6d84c289
dq = 0x00bbd4ac9b781fa4674ce57c8762f2d54ea5e23eb9a1c36dd877fbfe701d4b03de199f83b5406a0d2aff6440d6f901fe81b54152d51e5d18bb423fd7fbb98f279a92bb429407a002cbe5acafb78b7db5ac64b86294cf6f7497d4ffdfdc667ba3b0ecb68b80f8d1e4f082fd4fbc64989630e61fd12c6df6b9c1fa694e8c5df2d1e5
qp = 0x3fec91f745c465b184793a535992dbb20cf6324d83dc4bcf99f1ce4a8f3e12e7fab760208b93b90b6ffbe7848c43fefbb655d74ae0e7229525dfdbc72f07d8837b690a3b9195ae9474d00d9305c203a19f4bba825262faa0bc6d6cd80c5390485ad8f57437bf028cb29aa6fbaf7bc4cf9d3145b42cc2faa1413d663122018ff9
c = 6081370370545409218106271903400346695565292992689150366474451604281551878507114813906275593034729563149286993189430514737137534129570304832172520820901940874698337733991868650159489601159238582002010625666203730677577976307606665760650563172302688129824842780090723167480409842707790983962415315804311334507726664838464859751689906850572044873633896253285381878416855505301919877714965930289139921111644393144686543207867970807469735534838601255712764863973853116693691206791007433101433703535127367245739289103650669095061417223994665200039533840922696282929063608853551346533188464573323230476645532002621795338655
print(long_to_bytes(pow(c, dq, q)))

```

</details>