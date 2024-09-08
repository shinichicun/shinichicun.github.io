@echo off
:: 设置要操作的目录
cd /d "E:\blog\shinichicun.github.io"

:: 提交本地更改
echo Checking for uncommitted changes...
git add .
if %ERRORLEVEL% NEQ 0 (
    echo Failed to stage changes. Please check the error message above.
    exit /b %ERRORLEVEL%
)

echo Committing changes...
git commit -m "Automated commit: %DATE% %TIME%"
if %ERRORLEVEL% NEQ 0 (
    echo No changes to commit. Skipping commit step.
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

echo Repository updated and synchronized successfully.
