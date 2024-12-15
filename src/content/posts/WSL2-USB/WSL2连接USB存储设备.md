---
title: WSL2连接USB存储设备
published: 2024-08-19
updated: 2024-11-17
description: '本文详细介绍了如何在WSL2环境中连接USB存储设备,解决了WSL2无法直接访问宿主机USB设备和内核缺少USB存储设备驱动的问题。通过使用usbipd-win工具和重新编译WSL2内核,实现了USB设备在WSL2中的成功挂载。'
image: './WSL2-USB.webp'
tags: [WSL2, USB]
category: '编程'
draft: false
---
## 问题背景

最近在WSL2上搭建我的开发环境，不过在我尝试将bin文件烧录到SD卡（这里我是通过USB读卡器连接到电脑上）上时，发现SD没有被挂载上，去网上找了下原因。发现主要是以下2个原因导致的：

- **WSL2本质是一个虚拟机，无法直接访问宿主主机的USB设备。**
- **WSL2的内核没有加入USB存储设备的驱动。**

> `WSL2`：WSL2本质上是一个虚拟化技术，它在Windows操作系统上创建了一个轻量级的虚拟机，其中运行了一个完整的Linux内核。这个Linux内核与Windows内核相互隔离，但可以通过WSL2与Windows系统进行通信和交互。WSL2使用了Linux内核虚拟机（VM）技术，通过Hyper-V虚拟化平台来实现，在Windows系统上运行Linux应用程序时提供了更好的性能和兼容性。虽然WSL2在本质上是一个虚拟化技术，但它与传统的虚拟机不同，它并不是运行完整的Linux发行版，它更加轻量级且无需额外的资源分配，提供了一个与Linux兼容的运行时环境。用户可以在WSL2中安装并运行各种Linux发行版，如Ubuntu、Debian、Fedora等。WSL2和Linux发行版之间的关系是，WSL2提供了一个运行Linux发行版的虚拟化环境，用户可以在WSL2中安装和运行各种Linux发行版，以获得Linux环境和运行Linux应用程序的能力。

## 解决方案

为了解决这些问题,我们需要:

1. 使用usbipd-win工具让WSL2连接USB设备
2. 重新编译WSL2内核,加入USB存储设备支持

## 步骤1: 安装usbipd-win

> `usbipd-win`：USB/IP项目旨在开发一种通用的通过IP网络共享USB设备的系统。为了让计算机之间能够共享USB设备并完全发挥它们的功能，USB/IP将“USB I/O消息”封装到TCP/IP数据包中，并在计算机之间传输它们。说白了就是把USB封装在TCP中，通过网络传送。

### 在Windows上安装usbipd-win

1. 打开PowerShell,运行以下命令:

```powershell
winget install --interactive --exact dorssel.usbipd-win
```

2. 按照安装向导完成安装,可能需要重启电脑。
   ![15C1C188-1974-483b-8192-3CE70740A5C5](https://images.oathblade.com/images/2024/09/01/1f7cb115987679f375e9f862e1484bb0.webp)
   ![A840BABB-F957-47d6-8663-E80DFE4C8B55](https://images.oathblade.com/images/2024/09/01/4ede648700ffd07ef3d8f55ea17ecf4b.webp)

### 在WSL2中安装usbipd工具

1. 在WSL2终端中运行:

```bash
sudo apt install linux-tools-generic hwdata
sudo update-alternatives --install /usr/local/bin/usbip usbip /usr/lib/linux-tools/*-generic/usbip 20
```

![D18EBF35-3667-41fd-85AD-A0896A14C6EC](https://images.oathblade.com/images/2024/09/01/57c07cc025918ce5c7d6b6256a72f340.webp)
到这里已经解决掉第一个问题了,完成后先重启电脑以确保更改生效。

## 步骤2: 重新编译WSL2内核

### 准备工作

1. 到[WSL2的内核仓库](https://github.com/microsoft/WSL2-Linux-Kernel)克隆WSL2内核源码:

```bash
git clone https://github.com/microsoft/WSL2-Linux-Kernel.git
```

2. 再把源码解压出来：

```bash
unzip WSL2-Linux-Kernel-linux-msft-wsl-5.15.y
```

![image-20231013180736390](https://images.oathblade.com/images/2024/09/01/2f7deb4e2fd43d37040f8b7e469e4826.webp)
3. 安装必要的工具:

```bash
sud apt install libncurses-dev build-essential flex bison libssl-dev libelf-dev dwarves
```

> `libncurses-dev`：libncurses-dev是一个开发库，用于在Linux系统上开发基于终端的用户界面（TUI）应用程序。它是ncurses库的开发版本，提供了编译和链接TUI应用程序所需的头文件和静态库文件。使用libncurses-dev，开发人员可以利用ncurses库的功能创建具有交互性和可视化效果的终端应用程序。
> `build-essential`、`flex`、`bison`、`libssl-dev`、`libelf-dev`、`dwarves`：这些工具是编译内核所需的常见工具和库。

### 编辑内核配置

1. 运行以下命令:

```bash
make menuconfig KCONFIG_CONFIG=Microsoft/config-wsl
```

2. 在配置界面中:
   进入 `Device Drivers` -> `USB support` -> `Support for Host-side USB` ，选中 `USB Mass Storage support`（ `*` 号是直接编译进内核，`M` 是编译为内核模块，内核模块需要手动加载），把下面弹出来的一堆USB相关的驱动都选上，保存完之后就可以退出了。
   ![5B2688B6-6ED1-4527-959D-4954D9179CF3](https://images.oathblade.com/images/2024/09/01/0bc061c6475bc5c452c1e748f506498d.webp)

### 编译内核

1. 进入源码目录并开始编译:

```bash
cd WSL2-Linux-Kernel-linux-msft-wsl-5.15.y
make -j$(nproc) bzImage KCONFIG_CONFIG=Microsoft/config-wsl
```

> 注意: 编译过程可能需要30分钟到1小时,取决于你的硬件配置。

2. 编译完成后,在 `arch/x86/boot/` 目录下找到 `bzImage` 文件。
   ![image-20231013182814747](https://images.oathblade.com/images/2024/09/01/c0ed2d5b03fac39eaf42ab751b335bb0.webp)

> 大家不嫌弃的话可以使用我编译好的这个：
> [WSL2内核](https://alist.oathblade.com/)

### 配置新内核

1. 将编译好的内核复制到Windows用户目录(`C:\Users\{username}`)。
2. 在用户目录下创建 `.wslconfig` 文件,根据 [微软官方文档](https://docs.microsoft.com/zh-cn/windows/wsl/wsl-config#options-for-wslconfig)内容如下:

```
[wsl2]
kernel=path\\to\\kernel
```

以我的为例：
![9070468D-3F61-4cb3-BD14-B947B9317D5B](https://images.oathblade.com/images/2024/09/01/b7be3960a1be65e038082f70f313a97b.webp)
到这里第二个问题也解决完了。

## 步骤3: 验证和使用

1. 检查内核版本:
   打开powershell运行以下命令来查看内核版本号。

```bash
uname -r
```

![0944BD45-E23A-4b9f-BAC8-A96E95CF021C](https://images.oathblade.com/images/2024/09/01/c94d13319237d05ec10c69c684eaca6e.webp)
可以看到这是更换内核前的版本号是5.15.90.1，然后运行以下命令来关闭WSL2，再重新打开WSL2并运行上面查看内核版本号的命令。

```powershell
wsl --shutdown
```

![97AAF45F-B70A-4aa9-A0F0-38D9A7495B68](https://images.oathblade.com/images/2024/09/01/df78ab6851d11abb27155682462e20fb.webp)
可以看到版本已经变成5.15.133.1了，说明内核更换成功。

2. 使用usbipd-win连接USB设备:
   usbipd-win的使用方法参考[微软官方文档](https://learn.microsoft.com/zh-cn/windows/wsl/connect-usb)，首先打开powershell，使用下面的第一个命令列出所有连接到 Windows 的 USB 设备，找到USB大容量存储设备对应的BUSID，然后使用这个BUSID替换下面第二个命令中的 `<busid>`并运行该命令来使USB设备连接到WSL2，以我的为例：

```powershell
usbipd wsl list
usbipd wsl attach --busid <busid>
```

![6C1F5365-AAF2-4740-A840-3B6E7DC1A73E](https://images.oathblade.com/images/2024/09/01/b27f9b936056cb878f608fef5b911b3f.webp)
3. 在WSL2中验证:
   到WSL2中运行以下2个命令来查看USB设备和SD卡的挂载情况：

```bash
lsusb
ls /dev/sd*
```

![9AB1E88D-E644-4d4f-9187-9376A13B3462](https://images.oathblade.com/images/2024/09/01/b6dd8af1be5eacdbd53eca21c7a84e71.webp)
可以看到WSL2已经成功地连接上了USB设备，SD卡也挂载成功✌️。

## 常见问题解答(FAQ)

Q: 编译内核失败怎么办?
A: 确保已安装所有必要的依赖,并检查错误信息。可能需要更新系统或安装额外的开发工具。

Q: USB设备连接后在WSL2中不可见?
A: 确保usbipd-win正确安装并运行,检查Windows防火墙设置是否阻止了连接。

Q: 新内核无法加载?
A: 检查 `.wslconfig` 文件路径是否正确,确保使用双反斜杠 `\\`。

## 总结

通过以上步骤,我们成功解决了WSL2连接USB存储设备的问题。这个过程涉及到了安装usbipd-win工具和重新编译WSL2内核,虽然步骤较多,但能够显著提升WSL2的功能性。

---

参考连接:
[在WSL2中连接USB设备](https://www.littleqiu.net/access-usb-storage-in-wsl2/)

[HyperV和WSL2的USB直通](https://yadom.in/archives/usb-passthrough-hyper-v-and-wsl2.html)

[WSL2嵌入式开发随笔（2）——使用自己编译的WSL2系统内核](https://zhuanlan.zhihu.com/p/609431551)

[wsl系列内容：WSL2编译和使用自定义内核的方法](https://blog.csdn.net/chubbykkk/article/details/125216332)

[WSL support](https://github.com/dorssel/usbipd-win/wiki/WSL-support#usbip-client-tools)

[连接USB设备](https://learn.microsoft.com/zh-cn/windows/wsl/connect-usb)
