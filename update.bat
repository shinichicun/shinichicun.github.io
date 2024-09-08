#!/bin/bash

# 路径切换到你要操作的git仓库
cd E:/blog/shinichicun.github.io

# 进行空提交
git commit --allow-empty -m "Empty commit for synchronization"

# 添加所有更改的文件
git add .

# 提交更改
git commit -m "Your commit message here"

# 拉取远程更新并合并
git pull origin main

# 推送更改到远程仓库
git push origin main
