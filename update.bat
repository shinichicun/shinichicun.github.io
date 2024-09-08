@echo off
setlocal

:: Set TimeStamp
for /f "tokens=1-4 delims=:.," %%a in ("%TIME%") do set timestamp=%%a%%b%%c%%d
for /f "tokens=1-3 delims=/ " %%a in ("%DATE%") do set date=%%a%%b%%c
set datetime=%date%_%timestamp%

:: Set repository path
set REPO_DIR=E:\blog\shinichicun.github.io
cd /d %REPO_DIR%

echo Current directory: %REPO_DIR%
echo.

:: Set Commit
set commit_message=Commit_%datetime%
echo Commit Message: %commit_message%

git add .

echo Committing changes...
git commit -m "%commit_message%"
if %ERRORLEVEL% neq 0 (
    echo Error committing changes. Exiting.
    exit /b %ERRORLEVEL%
)

echo Pushing changes to remote repository...
git push
if %ERRORLEVEL% neq 0 (
    echo Error pushing changes. Exiting.
    exit /b %ERRORLEVEL%
)

echo Done.
endlocal
pause