@echo off
setlocal

:: Set repository path
set REPO_DIR=E:\blog\shinichicun.github.io
cd /d %REPO_DIR%

echo Current directory: %REPO_DIR%
echo.

:: Check for changes
echo Fetching latest updates from remote...
git fetch
echo.

:: Show current status
echo Current Git status:
git status
echo.

:: Check if there are changes to commit
set HAS_CHANGES=0
for /f "delims=" %%i in ('git status --porcelain') do (
    set HAS_CHANGES=1
    echo Change detected: %%i
)

:: If there are changes
if %HAS_CHANGES%==1 (
    echo.
    echo There are new changes. Preparing to commit and sync...
    git add .
    echo Committing changes...
    git commit -m "Automated commit"
    echo Pushing to remote repository...
    git push origin main
    echo Commit and sync completed.
) else (
    echo.
    echo No new changes. Performing empty commit...
    git commit --allow-empty -m "Empty commit"
    echo Pushing to remote repository...
    git push origin main
    echo Empty commit and sync completed.
)

endlocal
