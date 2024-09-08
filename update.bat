@echo off
:: 设置要操作的目录
cd /d "E:\blog\shinichicun.github.io"

:: 获取当前时间
set TIMESTAMP=%DATE%_%TIME%
set TIMESTAMP=%TIMESTAMP: =_%
set TIMESTAMP=%TIMESTAMP::=-%
set TIMESTAMP=%TIMESTAMP: =_%

:: 检查并暂存所有更改
echo Staging all changes...
git add .
if %ERRORLEVEL% NEQ 0 (
    echo Failed to stage changes. Please check the error message above.
    exit /b %ERRORLEVEL%
)

:: 创建空提交（即使没有更改）
echo Creating empty commit...
git commit --allow-empty -m "Automated empty commit: %TIMESTAMP%"
if %ERRORLEVEL% NEQ 0 (
    echo Failed to create empty commit. Please check the error message above.
    exit /b %ERRORLEVEL%
)

:: 确保没有未提交的更改
echo Checking for uncommitted changes...
git status --porcelain
if %ERRORLEVEL% NEQ 0 (
    echo Error checking status. Please check the error message above.
    exit /b %ERRORLEVEL%
)

:: 确保工作区干净
echo Stashing any local changes...
git stash --include-untracked
if %ERRORLEVEL% NEQ 0 (
    echo Failed to stash changes. Please check the error message above.
    exit /b %ERRORLEVEL%
)

:: 拉取远程更改并合并
echo Pulling latest changes...
git pull origin main --rebase
if %ERRORLEVEL% NEQ 0 (
    echo Failed to pull changes. Please check the error message above.
    exit /b %ERRORLEVEL%
)

:: 推送本地更改到远程
echo Pushing changes to remote...
git push origin main
if %ERRORLEVEL% NEQ 0 (
    echo Failed to push changes. Please check the error message above.
    exit /b %ERRORLEVEL%
)

:: 还原存储的更改
echo Applying stashed changes...
git stash pop
if %ERRORLEVEL% NEQ 0 (
    echo Failed to apply stashed changes. Please check the error message above.
    exit /b %ERRORLEVEL%
)

echo Repository updated and synchronized successfully.
