@echo off
setlocal

:: Set TimeStamp

:: 获取当前日期和时间
for /f "tokens=1-4 delims=:.," %%a in ("%TIME%") do set timestamp=%%a-%%b-%%c.%%d
for /f "tokens=1-3 delims=/ " %%a in ("%DATE%") do set date=%%a/%%b/%%c

REM 获取当前星期几
for /f "tokens=2 delims==" %%a in ('wmic path Win32_LocalTime get DayOfWeek /value') do set weekday=%%a

REM 转换星期几的数字到中文名
set "weekdays=星期日 星期一 星期二 星期三 星期四 星期五 星期六"
for /f "tokens=%weekday% delims= " %%a in ("%weekdays%") do set weekday_name=%%a

:: 拼接日期和时间戳
set datetime=%date%_%weekday_name%__%TIME:~0,2%-%TIME:~3,2%-%TIME:~6,2%.%TIME:~9,2%

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