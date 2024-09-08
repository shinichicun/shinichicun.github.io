@echo off
setlocal

:: 设置仓库路径
set REPO_DIR=E:\blog\shinichicun.github.io
cd /d %REPO_DIR%

:: 检查是否有更改
git fetch
git status

:: 判断是否有变更需要提交
for /f "delims=" %%i in ('git status --porcelain') do set HAS_CHANGES=1

:: 如果有变更
if defined HAS_CHANGES (
    echo "有新的更改，准备提交并同步..."
    git add .
    git commit -m "自动提交"
    git push origin main
) else (
    echo "没有新的更改，检查是否需要空提交..."
    git commit --allow-empty -m "空提交" 
    git push origin main
)

endlocal
