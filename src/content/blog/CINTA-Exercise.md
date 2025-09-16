---
title: "CINTA-Exercise"
description: '记录一下'
pubDate: "Sept 04 2025"
image: /image/image.png
categories:
  - Number Theory
tags:
  - Exercise
---

最近觉得静不下心来，感觉也没啥自信了（）

故重新以一个小白的身份找了本数论基础书开始学下，本文主要是记录书中习题的习题及答案（实时更新）。

使用的书是《具体数论与代数》，后续提到的编程题均使用Python来做

# 一、整数与二进制

## 第一题

**题目描述：**

> 用 C 语言编程实现判断输入是否为偶数的函数`is_even`，即输入一个整数，如果**输入为偶数，返回 True，否则返回 False**。另外，实现判断输入是否为奇数的函数`is_odd`，即输入一个整数，如果**输入为奇数，返回 True，否则返回 False**。

**作答：**

要做这道题，首先就得清楚奇数与偶数各自的特点：

> 奇数，即除2后的余数为1的数，比如1、3、5...
>
> 偶数，即除2后的余数为0的数，比如0、2、4、6...

既然是跟余数相关，那便离不开求余运算符`%`了。

由此，对于我们的题目而言便转换成这样的意思（本题为两问）：

> 1，假如有一个数 $x$，如果`x%2==0`则为偶数，否则为奇数
>
> 2，假如有一个数 $x$，如果`x%1==0`则为奇数，否则为偶数

**解题代码：**

```python
# Input: one integer x.
# Output: result that "judge if x is even".
def is_even(x):
    # x%2==0
    if not x % 2:
        return True
    else:
        return False
```

```python
# Input: one integer x.
# Output: result that "judge if x is odd".
def is_odd(x):
    # x%2==1
    if x % 2:
        return True
    else:
        return False
```

<hr style="border: 0.5px solid #36add4;"/>

## 第二题

**题目描述：**

> 给定一个整数 $v$，如何判断 $v$ 是否 2 的某次方？比如，$v = 4 = 2^2$，返回 True；$v=9=2^3+1$ 并非2的次方，返回 False。请写一个 C 语言的函数来实现以上功能。

**作答**：

要做这道题，得看看 “2的某次方” 有啥特点。在书中有说：

> 给定任意自然数 $n$, 十进制数 $2^n$ 的二进制数表达就是在 $1$ 后加 $n$ 个 $0$，即：$0b1\ 000\cdots0$
>
> 给定任意自然数 $n$, 十进制数 $2^n-1$ 的二进制数表达就是在 $0$ 后加 $n$ 个 $1$，即：$0b0\ 111\cdots1$**（此处只是为了与上一句对应，解释以书上所说为准）**

此时会发现： 
$$
\begin{align}
1\ 000\cdots0\\
\&\ 0\ 111\cdots1\\
\hline
0\ 000\cdots0
\end{align}
$$
也就是说：**假如一个数 $x$ 是 “2的某次方”，则有 `(x&(x-1))==0`**；因此我们可以通过这个条件进行判断。

**解题代码**：

```python
# Input: one integer x.
# Output: result that "judge if x is a power of 2".
def is_power_of_two(x):
    # v should be larger than 0
    return x > 0 and (x & (x - 1)) == 0

```

<hr style="border: 0.5px solid #36add4;"/>

## 第三题

**题目描述**：

> 用 C 语言编程实现一种迭代版本的简单乘法。

**作答：**

因为这在书上有讲，所以就不写了。

<hr style="border: 0.5px solid #36add4;"/>

## 第四题

**题目描述：**

> 证明：对任意给定的整数 $a$ 和 $b$，其中 $b > 0$，存在唯一的整数对 $q$（商）和 $r$（余数）使得$a=qb+r,\ 0≤r<b$。

**证明**

**1，存在性：**

考虑集合：
$$
S = \{ a - kb \mid k \in \mathbb{Z},\ a - kb \geq 0 \}
$$

由于 $b > 0$，当 $k$ 取足够小的整数时，$a - kb$ 可以取得任意大的正数，因此集合 $S$ 是非空的。根据**良序原理**（非负整数集的任何非空子集都有最小元），$S$ 存在最小元

设最小元为：
$$
r = a - qb \geq 0
$$

如果 $r \geq b$，则有：
$$
r - b = a - qb - b = a - (q + 1)b \geq 0
$$
且我们知道：
$$
r - b < r
$$
这与 **$r$ 是 $S$ 的最小元** 这一结论矛盾。

因此，$0 \leq r < b$，且 $a = qb + r$。

---

**2，唯一性：**

假设存在两组整数对 $(q, r)$ 和 $(q', r')$ 都满足：
$$
a = qb + r = q'b + r', \quad 0 \leq r, r' < b
$$

则有：
$$
(q - q')b = r' - r
$$

但左边 $(q - q')b$ 是 $b$ 的整数倍，且$|r' - r| < b$；假如 $q \neq q'$，则 $|(q - q')b| \geq b$，这就与 $|r' - r| < b$ 矛盾。

因此 $q = q'$，进而有 $r = r'$。

<hr style="border: 0.5px solid #36add4;"/>

## To be continued...
